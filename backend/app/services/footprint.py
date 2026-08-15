"""Digital footprinting — real passive expansion with an honest fallback.

Threat-intel concept: seed a sample's observed infrastructure (its C2 IPs)
and passively expand outward — reverse-DNS resolutions, TLS certificates,
and sibling infrastructure sharing a network — so one sample sketches the
whole campaign's infrastructure.

**The seed is real**: every distinct destination IP across the sample's runs,
aggregated with hit counts, first/last seen, affected runs, and cache-first
reputations from the existing enrichment cache.

**The passive layer is real, keyless, and free** — three providers, each
best-effort and isolated per IP so one provider failing never kills the page:

- *Reverse DNS (PTR)* — `socket.gethostbyaddr`: the hostname registered for
  the seed IP. Fast and reliable; fills the resolution rows.
- *crt.sh Certificate Transparency logs* — queried by the PTR-derived domain
  (`https://crt.sh/?q=<domain>&output=json`) AND by IP for the first two
  sibling hosts (`?q=<sibling-ip>`), so infra beyond the apex domain surfaces
  (names cohosted on the same block, each tagged with the sibling IP it came
  from). No API key. crt.sh is a flaky public provider (502s under load), so
  it is strictly best-effort: when it fails or returns nothing, the
  certificates / passive-DNS cards show an honest empty state.
- *RDAP* (`https://rdap.org/ip/<ip>`, follows the redirect to the owning
  registry) — registration info (network name, CIDR, organization, country)
  plus sibling hosts from the network block ("same operator" hypothesis).

Offline / outage → the passive layer reports `source: "not_configured"` with
empty collections (the pre-provider contract) — never fake intel. `mock=True`
fabricates a deterministic, clearly-labeled synthetic footprint so the webapp
can demo the UI shape; synthetic nodes carry `synthetic: true` and the
response sets `status.generated = "mock"`.

Successful lookups are cached in memory for 24 h (negative results for 1 h)
so repeated page loads don't hammer the free providers.
"""

import asyncio
import hashlib
import ipaddress
import socket
import time
from typing import Any, Optional

import httpx

from ..models import samples as samples_store

# In-memory caches (no schema migration needed): positive 24 h, negative 1 h.
_CACHE: dict[str, tuple[float, dict]] = {}
_FAIL_CACHE: dict[str, float] = {}
_CACHE_TTL = 24 * 3600
_FAIL_TTL = 3600
_CRTSH_TIMEOUT = 20.0
_RDAP_TIMEOUT = 10.0
_UA = "Mozilla/5.0 (X11; Linux x86_64) outpost-footprint/1.0"


def clear_cache() -> None:
    """Reset the in-memory footprint cache (tests + manual refresh)."""
    _CACHE.clear()
    _FAIL_CACHE.clear()


def _seed_ips(conn, sample_name: str) -> list[dict]:
    """Aggregate every distinct destination IP the sample's runs reached.

    Real data, straight from the event store; reputation is a cache-first
    read of the existing enrichment cache (no new external calls here).
    """
    rows = conn.execute(
        """
        SELECT e.dest_ip,
               COUNT(*) AS hits,
               MIN(e.timestamp) AS first_seen,
               MAX(e.timestamp) AS last_seen,
               COUNT(DISTINCT e.run_id) AS run_count
        FROM events e
        JOIN runs r ON r.run_id = e.run_id
        WHERE r.sample_name = ? AND e.dest_ip IS NOT NULL
        GROUP BY e.dest_ip
        ORDER BY hits DESC, e.dest_ip
        """,
        (sample_name,),
    ).fetchall()

    seeds = []
    for row in rows:
        cached = conn.execute(
            "SELECT abuse_score, vt_malicious_count, reputation, checked_at FROM enrichment_cache WHERE ip = ?",
            (row["dest_ip"],),
        ).fetchone()
        seeds.append(
            {
                "ip": row["dest_ip"],
                "hits": row["hits"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "run_count": row["run_count"],
                "reputation": cached["reputation"] if cached else "unknown",
                "abuse_score": cached["abuse_score"] if cached else None,
                "vt_malicious_count": cached["vt_malicious_count"] if cached else None,
                "checked_at": cached["checked_at"] if cached else None,
            }
        )
    return seeds


# ---------------------------------------------------------------------------
# Passive layer — real, keyless providers (PTR → crt.sh + RDAP)
# ---------------------------------------------------------------------------

def _ptr_for_ip(ip: str) -> Optional[str]:
    """Reverse-DNS hostname for an IP (the passive-DNS resolution signal)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _ipv4_neighbors(ip: str, limit: int = 4) -> list[str]:
    """Neighbor hosts in the /24 containing `ip` (baseline sibling set)."""
    try:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        hosts = list(net.hosts())
    except ValueError:
        return []
    try:
        idx = next(i for i, h in enumerate(hosts) if str(h) == ip)
    except StopIteration:
        return []
    picked = []
    for off in (1, 2, 3):
        if idx - off >= 0:
            picked.append(str(hosts[idx - off]))
        if idx + off < len(hosts):
            picked.append(str(hosts[idx + off]))
    return [h for h in picked[:limit] if h != ip]


def _common_prefix_len(a: str, b: str) -> int:
    """Prefix length shared by two IPv4 address strings (for CIDR synthesis)."""
    ia = int(ipaddress.IPv4Address(a))
    ib = int(ipaddress.IPv4Address(b))
    xor = ia ^ ib
    n = 32
    while xor:
        n -= 1
        xor >>= 1
    return n


def _parse_rdap(ip: str, doc: dict) -> dict:
    """Extract registration info + sibling hosts from an RDAP network doc.

    Pure function — unit-testable without the network. Siblings come from the
    RDAP network when it's a /24 or smaller, else the /24 the IP sits in.
    """
    cidr = None
    for c in doc.get("cidr0_cidrs") or []:
        if c.get("v4prefix") and c.get("length"):
            cidr = f"{c['v4prefix']}/{c['length']}"
            break
    if cidr is None:
        start = doc.get("startAddress")
        end = doc.get("endAddress")
        if start and end and "." in start:
            try:
                cidr = f"{ipaddress.IPv4Address(start)}/{_common_prefix_len(start, end)}"
            except ValueError:
                cidr = None
    netname = doc.get("name") or doc.get("handle")
    country = doc.get("country")
    org = None
    for ent in doc.get("entities") or []:
        vcard = ent.get("vcardArray") if isinstance(ent, dict) else None
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if (
                    isinstance(item, list)
                    and len(item) >= 4
                    and item[0] == "fn"
                    and isinstance(item[3], str)
                    and item[3].strip()
                ):
                    org = item[3].strip()
                    break
            if org:
                break

    # Sibling hosts: when RDAP hands us a /24-or-tighter network, take the
    # neighbors from THAT net (the label then matches the hosts); for wider
    # blocks (a big ISP /16) the /24 the IP sits in is the meaningful set.
    # IPv6 seeds get no siblings — `_ipv4_neighbors` is v4-only by design.
    net = None
    if cidr:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            net = None
    if net is not None and net.version == 4 and net.prefixlen >= 24:
        hosts = [str(h) for h in net.hosts()]
        try:
            idx = hosts.index(ip)
        except ValueError:
            idx = -1
        picked = []
        for off in (1, 2, 3):
            if idx - off >= 0:
                picked.append(hosts[idx - off])
            if idx + off < len(hosts):
                picked.append(hosts[idx + off])
        relation = f"same {cidr}"
        siblings = [{"ip": h, "relation": relation, "synthetic": False} for h in picked[:4] if h != ip]
    else:
        siblings = [{"ip": h, "relation": "same /24", "synthetic": False} for h in _ipv4_neighbors(ip)]

    return {
        "cidr": cidr,
        "netname": netname,
        "org": org,
        "country": country,
        "siblings": siblings,
    }


def _parse_crtsh(rows: list[dict]) -> dict:
    """crt.sh `output=json` rows → certificates + passive-DNS names.

    Pure function. Certificates dedupe by CN. The `name_value` SANs are
    aggregated per name across ALL rows into a first→last seen range — that
    span IS the passive-DNS history crt.sh can honestly provide (a name seen
    in a 2026-01 cert and again in a 2026-12 cert has a 01→12 history).
    Wildcard SANs are stripped to the base name for the resolution rows.
    """
    certificates: list[dict] = []
    domains: dict[str, list[str]] = {}
    seen_cn: set[str] = set()
    for r in rows:
        if not isinstance(r, dict):
            continue
        cn = (r.get("common_name") or "").strip()
        issuer = (r.get("issuer_name") or "").strip()
        nb = (r.get("not_before") or "")[:10]
        na = (r.get("not_after") or "")[:10]
        if cn and cn not in seen_cn:
            seen_cn.add(cn)
            certificates.append(
                {"cn": cn, "issuer": issuer, "not_before": nb, "not_after": na, "synthetic": False}
            )
        for name in str(r.get("name_value") or "").split("\n"):
            name = name.strip().lower()
            while name.startswith("*."):  # strip wildcard prefixes precisely
                name = name[2:]
            if not name:
                continue
            span = domains.setdefault(name, ["", ""])
            if nb and (not span[0] or nb < span[0]):
                span[0] = nb
            if na and (na > span[1] or not span[1]):
                span[1] = na
    return {
        "certificates": certificates[:40],
        "domains": [
            {"domain": name, "first_seen": span[0], "last_seen": span[1], "synthetic": False}
            for name, span in sorted(domains.items())
        ][:60],
    }


async def _rdap_lookup(ip: str) -> dict:
    url = f"https://rdap.org/ip/{ip}"
    async with httpx.AsyncClient(
        timeout=_RDAP_TIMEOUT, follow_redirects=True, headers={"User-Agent": _UA}
    ) as client:
        resp = await client.get(url)
        resp.raise_for_status()
    doc = resp.json()
    if not isinstance(doc, dict):
        raise ValueError("bad RDAP payload")
    return _parse_rdap(ip, doc)


def _apex_of(domain: str) -> Optional[str]:
    """The discovery apex of a hostname — strip the leftmost label.

    `mail.example.com` → `example.com`; `a.b.example.com` → `b.example.com`
    (a narrower namespace — still useful); `example.com` → None (stripping
    one label leaves a bare TLD). IP literals / single labels → None. Pure
    and conservative: a wrong guess only costs one crt.sh query that returns
    nothing, and each fetch isolates its own failures.
    """
    name = (domain or "").strip().lower().rstrip(".")
    if "." not in name:
        return None
    labels = name.split(".")
    if all(part.isdigit() for part in labels):  # IP literal — no subdomains
        return None
    apex = ".".join(labels[1:])
    return apex if "." in apex else None


async def _crtsh_query(q: str) -> dict:
    """One crt.sh lookup by raw query string — shared by the domain lookup
    and the `%.<apex>` subdomain enumeration. Best-effort: callers isolate
    their own failures."""
    url = "https://crt.sh/"
    async with httpx.AsyncClient(timeout=_CRTSH_TIMEOUT, headers={"User-Agent": _UA}) as client:
        resp = await client.get(url, params={"q": q, "output": "json"})
        resp.raise_for_status()
    rows = resp.json()
    if not isinstance(rows, list):
        raise ValueError("bad crt.sh payload")
    return _parse_crtsh(rows)


async def _crtsh_lookup(domain: str) -> dict:
    return await _crtsh_query(domain)


async def _crtsh_subdomains(apex: str) -> list[dict]:
    """Subdomains of `apex` via crt.sh's `%.<apex>` wildcard-match query —
    the classic CT-log subdomain enumeration, same free keyless provider as
    the certificate/passive-DNS lookups.

    crt.sh matches superstrings too, so each name is filtered to PROPER
    subdomains of the apex (`name.endswith("." + apex)`, apex itself
    excluded) — wildcards were already stripped by `_parse_crtsh`.
    """
    parsed = await _crtsh_query(f"%.{apex}")
    out: list[dict] = []
    for d in parsed.get("domains", []):
        name = (d["domain"] or "").strip().lower()
        while name.startswith("*."):  # defensive — raw rows may carry wildcards
            name = name[2:]
        if not name or name == apex or not name.endswith("." + apex):
            continue
        row = dict(d)
        row["domain"] = name
        row["apex"] = apex
        out.append(row)
    return out


async def _fetch_ip_passive(seed: dict) -> dict:
    """One seed IP → its passive layer: resolutions, certificates, siblings.

    Each provider is isolated in its own try/except so a crt.sh 502 or a
    missing PTR never discards the RDAP/PTR data this IP did yield.
    """
    ip = seed["ip"]
    ts0 = (seed.get("first_seen") or "")[:10]
    ts1 = (seed.get("last_seen") or "")[:10]
    out = {"resolutions": [], "certificates": [], "passive_dns": [], "sibling_ips": [], "networks": [], "subdomains": []}

    # 1. Reverse DNS — the resolution signal (fast, reliable).
    ptr = _ptr_for_ip(ip)
    if ptr:
        out["resolutions"].append({"domain": ptr, "first_seen": ts0, "last_seen": ts1, "synthetic": False})

    # 2. RDAP — registration info + sibling hosts (reliable).
    reg = {}
    try:
        reg = await _rdap_lookup(ip)
    except Exception:
        reg = {}
    if reg.get("cidr"):
        out["networks"].append(
            {
                "ip": ip,
                "cidr": reg["cidr"],
                "netname": reg.get("netname"),
                "org": reg.get("org"),
                "country": reg.get("country"),
                "synthetic": False,
            }
        )
    out["sibling_ips"] = reg.get("siblings") or [
        {"ip": h, "relation": "same /24", "synthetic": False} for h in _ipv4_neighbors(ip)
    ]

    # 3. crt.sh CT logs for the PTR domain (best-effort — flaky provider).
    if ptr:
        try:
            ct = await _crtsh_lookup(ptr)
        except Exception:
            ct = {"certificates": [], "domains": []}
        out["certificates"] = ct["certificates"]
        # Every hostname crt.sh has seen for this domain — the passive-DNS
        # history (the apex PTR name itself stays in resolutions). Each row
        # is tagged with the seed IP it was observed from.
        out["passive_dns"] = []
        for d in ct["domains"]:
            if d["domain"] != ptr:
                d["source_ip"] = ip
                out["passive_dns"].append(d)

    # 3b. Sibling hosts — crt.sh by IP, so infrastructure beyond the apex
    # domain surfaces (names cohosted on the same block). Bounded to the
    # first two siblings, queried concurrently, deduped against the apex
    # names, and each row tagged with the sibling IP it came from.
    siblings = out["sibling_ips"][:2]
    if siblings:
        try:
            sib_results = await asyncio.gather(
                *[_crtsh_lookup(s["ip"]) for s in siblings], return_exceptions=True
            )
        except Exception:
            sib_results = []
        seen = {d["domain"] for d in out["passive_dns"]}
        for sib, res in zip(siblings, sib_results):
            if not isinstance(res, dict):
                continue
            for d in res.get("domains", []):
                if d["domain"] in seen:
                    continue
                seen.add(d["domain"])
                d["source_ip"] = sib["ip"]
                out["passive_dns"].append(d)

    # 3c. Subdomain discovery — crt.sh `%.<apex>` over the PTR-derived
    # domain: the classic CT-log subdomain enumeration (same keyless
    # provider). Deduped against the passive-DNS names already collected
    # and tagged with the seed IP, so the card shows only NEW infra under
    # the apex, never a repeat of the passive-DNS history.
    if ptr:
        apex = _apex_of(ptr)
        if apex:
            try:
                subs = await _crtsh_subdomains(apex)
            except Exception:
                subs = []
            seen = {d["domain"] for d in out["passive_dns"]}
            for s in subs:
                if s["domain"] in seen:
                    continue
                seen.add(s["domain"])
                s["source_ip"] = ip
                out["subdomains"].append(s)

    # 4. ASN / owner mapping — keyless ip-api.com (free tier, 45 req/min,
    # plenty for a footprint page). RDAP gives registration; this gives the
    # autonomous-system identity that registration sits on.
    try:
        asn = await _asn_lookup(ip)
    except Exception:
        asn = {}
    asn["ip"] = ip
    out["asn"] = asn
    if asn and reg.get("org") and not asn.get("org"):
        asn["org"] = reg["org"]
    return out


async def _asn_lookup(ip: str) -> dict:
    """ASN / organization / country for an IP via ip-api.com (no API key).

    Returns {} on any failure so the footprint card degrades to an honest
    empty state exactly like the other providers.
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,as,asname,org,isp,country,countryCode"
    async with httpx.AsyncClient(timeout=_RDAP_TIMEOUT, headers={"User-Agent": _UA}) as client:
        resp = await client.get(url)
        if resp.status_code != 200:
            raise ValueError("bad ip-api payload")
        doc = resp.json()
    if doc.get("status") != "success":
        raise ValueError("ip-api lookup failed")
    asn_raw = (doc.get("as") or "").split(" ")[0]
    return {
        "asn": asn_raw or None,
        "as_name": doc.get("asname"),
        "org": doc.get("org") or doc.get("isp"),
        "country": doc.get("country"),
        "country_code": doc.get("countryCode"),
    }


async def _cached_fetch(seed: dict) -> dict:
    """`_fetch_ip_passive` behind the in-memory positive/negative cache.

    The cache key is (ip, observation date): the cached payload embeds the
    sample's observed-window timestamps, so two samples that saw the same IP
    on different days must not share one entry (their resolution dates differ).
    """
    ip = seed["ip"]
    key = (ip, (seed.get("first_seen") or "")[:10])
    now = time.monotonic()
    hit = _CACHE.get(key)
    if hit and now - hit[0] < _CACHE_TTL:
        return hit[1]
    if key in _FAIL_CACHE and now - _FAIL_CACHE[key] < _FAIL_TTL:
        return {}
    try:
        data = await _fetch_ip_passive(seed)
    except Exception:
        _FAIL_CACHE[key] = now
        return {}
    _CACHE[key] = (now, data)
    return data


# ---------------------------------------------------------------------------
# Synthetic layer — the labeled demo (mock=True)
# ---------------------------------------------------------------------------

def _mock_resolutions(seed: dict) -> list[dict]:
    """Deterministic fake passive-DNS rows for one seed IP (synthetic)."""
    digest = hashlib.sha256(seed["ip"].encode()).hexdigest()[:8]
    return [
        {
            "domain": f"c2-{digest}.cdn.shelf.example",
            "first_seen": seed["first_seen"],
            "last_seen": seed["last_seen"],
            "synthetic": True,
        },
        {
            "domain": f"update-{digest[:6]}.victim-panel.example",
            "first_seen": seed["first_seen"],
            "last_seen": seed["last_seen"],
            "synthetic": True,
        },
    ]


def _mock_certificates(seed: dict) -> list[dict]:
    digest = hashlib.sha256(seed["ip"].encode()).hexdigest()[:6]
    return [
        {
            "cn": f"*.cdn-{digest}.shelf.example",
            "issuer": "Synthetic CA",
            "not_before": seed["first_seen"],
            "not_after": seed["last_seen"],
            "synthetic": True,
        }
    ]


def _mock_passive_dns(seed: dict) -> list[dict]:
    """Deterministic fake passive-DNS history rows (synthetic)."""
    digest = hashlib.sha256(seed["ip"].encode()).hexdigest()[:6]
    return [
        {
            "domain": f"panel-{digest}.shelf.example",
            "first_seen": seed["first_seen"],
            "last_seen": seed["last_seen"],
            "source_ip": seed["ip"],
            "synthetic": True,
        },
        {
            "domain": f"cdn-{digest}.shelf.example",
            "first_seen": seed["first_seen"],
            "last_seen": seed["last_seen"],
            "source_ip": seed["ip"],
            "synthetic": True,
        },
    ]


def _mock_subdomains(seed: dict) -> list[dict]:
    """Deterministic fake subdomain-discovery rows (synthetic)."""
    digest = hashlib.sha256(seed["ip"].encode()).hexdigest()[:6]
    return [
        {
            "domain": f"dev-{digest}.shelf.example",
            "apex": "shelf.example",
            "first_seen": seed["first_seen"],
            "last_seen": seed["last_seen"],
            "source_ip": seed["ip"],
            "synthetic": True,
        },
        {
            "domain": f"staging-{digest}.shelf.example",
            "apex": "shelf.example",
            "first_seen": seed["first_seen"],
            "last_seen": seed["last_seen"],
            "source_ip": seed["ip"],
            "synthetic": True,
        },
    ]


def _mock_sibling_ips(seed: dict) -> list[dict]:
    """Same-/24 neighbors, synthetically marked — 'shared host' hypothesis."""
    try:
        net = ipaddress.ip_network(f"{seed['ip']}/24", strict=False)
        hosts = list(net.hosts())
    except ValueError:
        return []
    pick = hosts[1:4]  # stable, deterministic neighbors
    return [
        {"ip": str(h), "relation": "same /24", "synthetic": True}
        for h in pick
        if str(h) != seed["ip"]
    ]


# ---------------------------------------------------------------------------
# Passive layer orchestration
# ---------------------------------------------------------------------------

def _dedupe(rows: list[dict], key: str) -> list[dict]:
    seen: set[Any] = set()
    out = []
    for r in rows:
        k = r.get(key)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


async def _passive_layer(seeds: list[dict], mock: bool) -> dict:
    """The passive surface. `mock` fills it with synthetic rows; otherwise the
    top seed IPs are expanded through the real providers concurrently."""
    if mock:
        resolutions = [r for s in seeds for r in _mock_resolutions(s)]
        certificates = [c for s in seeds for c in _mock_certificates(s)]
        passive_dns = [d for s in seeds for d in _mock_passive_dns(s)]
        sibling_ips = [sib for s in seeds for sib in _mock_sibling_ips(s)]
        subdomains = [d for s in seeds for d in _mock_subdomains(s)]
        return {
            "source": "synthetic_demo",
            "resolutions": resolutions,
            "certificates": certificates,
            "passive_dns": passive_dns,
            "sibling_ips": sibling_ips,
            "subdomains": subdomains,
            "networks": [],
            "asn": [],
        }

    # Top 4 seeds by activity — bounds latency and the free providers' load.
    top = sorted(seeds, key=lambda s: (s["hits"], s["ip"]), reverse=True)[:4]
    results = await asyncio.gather(*[_cached_fetch(s) for s in top], return_exceptions=True)

    resolutions: list[dict] = []
    certificates: list[dict] = []
    passive_dns: list[dict] = []
    sibling_ips: list[dict] = []
    networks: list[dict] = []
    asn_rows: list[dict] = []
    subdomains: list[dict] = []
    any_data = False
    for res in results:
        if not isinstance(res, dict):
            continue  # a failed/errored fetch — carry on with the rest
        resolutions += res.get("resolutions", [])
        certificates += res.get("certificates", [])
        passive_dns += res.get("passive_dns", [])
        sibling_ips += res.get("sibling_ips", [])
        networks += res.get("networks", [])
        subdomains += res.get("subdomains", [])
        if res.get("asn"):
            asn_rows.append(res["asn"])
        if (
            res.get("resolutions") or res.get("certificates") or res.get("passive_dns")
            or res.get("sibling_ips") or res.get("networks") or res.get("subdomains")
        ):
            any_data = True

    if not any_data:
        # Offline / every provider failed — honest empty state, never fake.
        return {
            "source": "not_configured",
            "resolutions": [],
            "certificates": [],
            "passive_dns": [],
            "sibling_ips": [],
            "networks": [],
            "asn": [],
            "subdomains": [],
        }

    return {
        "source": "live",
        "resolutions": _dedupe(resolutions, "domain")[:60],
        "certificates": _dedupe(certificates, "cn")[:40],
        "passive_dns": _dedupe(passive_dns, "domain")[:60],
        "sibling_ips": _dedupe(sibling_ips, "ip")[:24],
        "networks": _dedupe(networks, "ip")[:8],
        "asn": _dedupe(asn_rows, "ip")[:8],
        "subdomains": _dedupe(subdomains, "domain")[:40],
    }


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

async def build_footprint(conn, sample_id: str, mock: bool = False) -> Optional[dict]:
    """Build the footprint for an uploaded sample, or None if unknown."""
    sample = samples_store.get_sample(conn, sample_id)
    if not sample:
        return None

    seeds = _seed_ips(conn, sample["original_name"])
    passive = await _passive_layer(seeds, mock)

    return {
        "sample": {
            "sample_id": sample["sample_id"],
            "name": sample["original_name"],
            "sha256": sample["sha256"],
            "platform": sample["detected_platform"],
            "family": sample.get("family"),
        },
        "runs": [
            dict(r)
            for r in conn.execute(
                "SELECT run_id, sample_name, started_at, completed_at FROM runs WHERE sample_name = ? ORDER BY started_at DESC",
                (sample["original_name"],),
            ).fetchall()
        ],
        "seed_ips": seeds,
        "passive": passive,
        "status": {
            "roadmap": passive["source"] != "live",
            "generated": "mock" if mock else None,
        },
    }
