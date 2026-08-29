"""Threat-intel enrichment — AbuseIPDB + VirusTotal + abuse.ch, cache-first.

Logic per docs/02-BACKEND-SPEC.md:
1. Collect distinct dest_ips for a run
2. Check enrichment_cache first (TTL 7 days) — never re-query a cached IP
3. Query AbuseIPDB + VirusTotal, store result
4. Derive reputation label from combined scores
5. Attach to NetworkConnection records

Roadmap 2.2 adds file/hash reputation: `enrich_hash` looks up a SHA-256 on
VirusTotal's file search, cached in `hash_cache` with the same TTL discipline.

docs/08 MVP-tier adds the abuse.ch pair: `enrich_domain` covers hostnames
(DNS queries / TLS SNI) via URLhaus (free, no key) + ThreatFox
(IOC→malware-family), cached in `domain_cache`. ThreatFox also backfills
`malware_family` on hash lookups when VirusTotal returns no name.

If no API keys are configured (empty .env), lookups are skipped and IPs
report "unknown" — the pipeline still works for dev/demo (AGENTS.md rule 5).
"""

import ipaddress
import re
from datetime import datetime, timedelta, timezone

import httpx

from ..core import config
from ..core.api_keys import get_api_key
from ..models.event import get_cache, get_domain_cache, upsert_cache, upsert_domain_cache
from ..models.samples import get_hash_cache, upsert_hash_cache
from ..models.watchlist import get_watchlist

# Rate-limit friendly: both APIs accept one key per request.
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses"
# docs/08 MVP-tier — abuse.ch feeds are free and key-less.
URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


def _reputation_from_scores(abuse_score: int | None, vt_count: int | None) -> str:
    """Derive a reputation label per docs/02 guidance.

    abuse > 50 or vt > 3  -> malicious
    moderate (abuse > 20 or vt > 0) -> suspicious
    else -> clean
    """
    if abuse_score is None and vt_count is None:
        return "unknown"
    if (abuse_score or 0) > 50 or (vt_count or 0) > 3:
        return "malicious"
    if (abuse_score or 0) > 20 or (vt_count or 0) > 0:
        return "suspicious"
    return "clean"


def _cache_fresh(cached: dict) -> bool:
    try:
        checked = datetime.fromisoformat(cached["checked_at"])
    except (ValueError, KeyError):
        return False
    return datetime.now(timezone.utc) - checked < timedelta(days=config.ENRICHMENT_TTL_DAYS)


async def _query_abuseipdb(client: httpx.AsyncClient, ip: str, key: str) -> int | None:
    if not key:
        return None
    try:
        resp = await client.get(
            ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("data", {}).get("abuseConfidenceScore")
    except (httpx.HTTPError, ValueError, KeyError):
        return None


async def _query_virustotal(client: httpx.AsyncClient, ip: str, key: str) -> int | None:
    if not key:
        return None
    try:
        resp = await client.get(
            f"{VIRUSTOTAL_URL}/{ip}",
            headers={"x-apikey": key},
            timeout=10,
        )
        resp.raise_for_status()
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return stats.get("malicious")
    except (httpx.HTTPError, ValueError, KeyError):
        return None


VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/files"


# ---------------------------------------------------------------------------
# abuse.ch — URLhaus (host reputation) + ThreatFox (IOC→malware-family)
# ---------------------------------------------------------------------------

_DOMAIN_LIKE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)


def looks_like_domain(value: str | None) -> bool:
    """Conservative hostname check so DNS queries / TLS SNI values are only
    enriched when they're plausibly domains (not IPs, wildcards, or NXCACHE
    junk). Underscores are allowed inside labels (e.g. _dmarc) via the
    middle-hyphen class being permissive here."""
    if not value:
        return False
    v = value.strip().rstrip(".").lower()
    if not _DOMAIN_LIKE.match(v):
        return False
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return True
    return False


def _strip_family_prefix(malware: str | None) -> str | None:
    """ThreatFox family names arrive as 'win.asyncrat' / 'elf.mirai' — strip
    the platform prefix for display parity with VT's meaningful_name."""
    if not malware:
        return None
    parts = malware.split(".", 1)
    return parts[1] if len(parts) == 2 and len(parts[0]) <= 4 else malware


async def _query_urlhaus(client: httpx.AsyncClient, domain: str) -> dict | None:
    """URLhaus host lookup. Free + key-less; a listed host returns
    url_status ('online'/'offline') plus tags (often a malware family).
    'no_results' means unknown-to-URLhaus → None."""
    try:
        resp = await client.post(
            URLHAUS_HOST_URL,
            data={"host": domain},
            timeout=10,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        doc = resp.json()
        if doc.get("query_status") != "ok":
            return None
        status = doc.get("url_status")
        if not status:
            return None
        tags = [t for t in (doc.get("tags") or []) if t]
        return {"url_status": status, "tags": tags}
    except (httpx.HTTPError, ValueError, KeyError):
        return None


async def _query_threatfox(client: httpx.AsyncClient, term: str) -> dict | None:
    """ThreatFox search_ioc: maps an IP/domain/hash to a known malware family.
    Returns the first match {malware, confidence_level, threat_type} or None."""
    try:
        resp = await client.post(
            THREATFOX_URL,
            json={"query": "search_ioc", "search_term": term},
            timeout=10,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        doc = resp.json()
        rows = doc.get("data")
        if doc.get("query_status") != "ok" or not isinstance(rows, list) or not rows:
            return None
        first = rows[0]
        malware = (first.get("malware") or "").strip() or None
        confidence = first.get("confidence_level")
        try:
            confidence = int(confidence) if confidence is not None else None
        except (TypeError, ValueError):
            confidence = None
        return {
            "malware": malware,
            "confidence_level": confidence,
            "threat_type": (first.get("threat_type") or "").strip() or None,
        }
    except (httpx.HTTPError, ValueError, KeyError):
        return None


def _reputation_from_domain(
    urlhaus: dict | None, threatfox: dict | None
) -> str:
    """Domain verdict bands (docs/08): URLhaus-listed hosts are malicious by
    definition; ThreatFox matches follow its own confidence_level."""
    if urlhaus is not None:
        return "malicious"
    if threatfox is not None:
        conf = threatfox.get("confidence_level")
        return "malicious" if (conf or 0) >= 75 else "suspicious"
    return "unknown"


async def enrich_domain(client: httpx.AsyncClient, conn, domain: str) -> dict:
    """Cache-first enrichment for one observed hostname (docs/08 MVP-tier).

    URLhaus needs no key; both abuse.ch calls fire together (they answer
    different questions: 'is this host bad?' vs 'which family uses it?').
    Without network reachability the result degrades to an honest all-None
    row — same graceful degradation as IP/hash enrichment."""
    d = domain.strip().rstrip(".").lower()
    cached = get_domain_cache(conn, d)
    if cached and _cache_fresh(cached):
        return {
            "domain": d,
            "urlhaus_status": cached["urlhaus_status"],
            "urlhaus_tags": [],
            "malware_family": cached["threatfox_malware"],
            "threatfox_confidence": cached["threatfox_confidence"],
            "reputation": cached["reputation"],
            "checked_at": cached.get("checked_at"),
        }

    # Keyless third-party egress is opt-in (no-config installs make zero
    # external calls); degrade to an honest disabled row instead.
    if not config.ABUSECH_ENABLED:
        return {
            "domain": d,
            "urlhaus_status": None,
            "urlhaus_tags": [],
            "malware_family": None,
            "threatfox_confidence": None,
            "reputation": "unknown",
            "checked_at": None,
            "note": "abuse.ch lookups disabled — set OUTPOST_ABUSECH_ENABLED=1",
        }

    urlhaus = await _query_urlhaus(client, d)
    threatfox = await _query_threatfox(client, d)
    reputation = _reputation_from_domain(urlhaus, threatfox)
    checked_at = upsert_domain_cache(
        conn, d,
        urlhaus["url_status"] if urlhaus else None,
        _strip_family_prefix(threatfox["malware"]) if threatfox else None,
        threatfox["confidence_level"] if threatfox else None,
        reputation,
    )
    return {
        "domain": d,
        "urlhaus_status": urlhaus["url_status"] if urlhaus else None,
        "urlhaus_tags": urlhaus["tags"] if urlhaus else [],
        "malware_family": _strip_family_prefix(threatfox["malware"]) if threatfox else None,
        "threatfox_confidence": threatfox["confidence_level"] if threatfox else None,
        "reputation": reputation,
        "checked_at": checked_at,
    }


async def enrich_run_domains(conn, run_id: str) -> dict[str, dict]:
    """Enrich every distinct observed hostname for a run (DNS `query` +
    Sysmon TLS SNI), domain-shaped only. Returns {domain: enrichment_dict}."""
    rows = conn.execute(
        """
        SELECT DISTINCT value FROM (
            SELECT query AS value FROM events WHERE run_id = ? AND query IS NOT NULL
            UNION
            SELECT tls_sni AS value FROM events WHERE run_id = ? AND tls_sni IS NOT NULL
        )
        """,
        (run_id, run_id),
    ).fetchall()
    domains = [r["value"] for r in rows if looks_like_domain(r["value"])]
    if not domains:
        return {}

    results: dict[str, dict] = {}
    async with httpx.AsyncClient() as client:
        for domain in domains:
            results[domain] = await enrich_domain(client, conn, domain)
    return results


async def enrich_hash(client: httpx.AsyncClient, conn, sha256: str) -> dict:
    """Cache-first VirusTotal reputation for a file SHA-256 (roadmap 2.2).

    Returns {"sha256", "vt_detections", "malware_family"}; without an API key
    the result is an honest all-None row ("no intel configured") rather than
    an error — same graceful degradation as IP enrichment.

    docs/08 MVP-tier: when VirusTotal yields no family name, ThreatFox's
    IOC→malware mapping backfills it (hashes are first-class IOCs there).
    """
    cached = get_hash_cache(conn, sha256)
    if cached and _cache_fresh({"checked_at": cached["checked_at"]}):
        return {
            "sha256": sha256,
            "vt_detections": cached["vt_detections"],
            "malware_family": cached["malware_family"],
        }

    # Effective key: DB-stored (Settings UI) if set, else the env fallback.
    vt_key = get_api_key(conn, "virustotal")

    vt_detections: int | None = None
    family: str | None = None
    if vt_key:
        try:
            resp = await client.get(
                f"{VIRUSTOTAL_FILE_URL}/{sha256}",
                headers={"x-apikey": vt_key},
                timeout=10,
            )
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                vt_detections = stats.get("malicious") or 0
                family = (attrs.get("meaningful_name") or "") or None
                if not family and attrs.get("popular_threat_classification"):
                    fam = attrs["popular_threat_classification"].get("suggested_threat_label")
                    family = fam or None
        except (httpx.HTTPError, ValueError, KeyError):
            pass

    if not family and config.ABUSECH_ENABLED:
        tf = await _query_threatfox(client, sha256)
        if tf:
            family = _strip_family_prefix(tf["malware"])

    upsert_hash_cache(conn, sha256, vt_detections, family)
    return {"sha256": sha256, "vt_detections": vt_detections, "malware_family": family}


async def enrich_ip(client: httpx.AsyncClient, conn, ip: str) -> dict:
    """Cache-first enrichment for a single IP. Returns an enrichment dict
    including `checked_at` (when this verdict was fetched) so the UI can show
    the cache age and offer a targeted TTL-bypassing refresh."""
    cached = get_cache(conn, ip)
    if cached and _cache_fresh(cached):
        return {
            "ip": ip,
            "abuse_score": cached["abuse_score"],
            "vt_malicious_count": cached["vt_malicious_count"],
            "reputation": cached["reputation"],
            "checked_at": cached.get("checked_at"),
        }

    # Effective keys per call — the Settings UI can swap them at runtime with
    # no backend restart (DB overrides the env fallback).
    abuse_key = get_api_key(conn, "abuseipdb")
    vt_key = get_api_key(conn, "virustotal")
    abuse_score = await _query_abuseipdb(client, ip, abuse_key)
    vt_count = await _query_virustotal(client, ip, vt_key)
    reputation = _reputation_from_scores(abuse_score, vt_count)

    checked_at = upsert_cache(conn, ip, abuse_score, vt_count, reputation)
    return {
        "ip": ip,
        "abuse_score": abuse_score,
        "vt_malicious_count": vt_count,
        "reputation": reputation,
        "checked_at": checked_at,
    }


async def enrich_run(conn, run_id: str) -> dict[str, dict]:
    """Enrich every distinct dest_ip for a run. Returns {ip: enrichment_dict}.

    RFC1918 / loopback / link-local / reserved destinations are skipped:
    querying third-party reputation feeds with internal addresses leaks
    topology and burns quota, and their verdicts are meaningless anyway.
    The local watchlist override still applies to every address."""
    rows = conn.execute(
        "SELECT DISTINCT dest_ip FROM events WHERE run_id = ? AND dest_ip IS NOT NULL",
        (run_id,),
    ).fetchall()
    ips = [r["dest_ip"] for r in rows]
    if not ips:
        return {}

    # Internal-topology ranges we never send to third-party feeds (topology
    # leak + quota burn). Deliberately NOT `ipaddress.is_private` — on modern
    # Python that flag also swallows TEST-NET documentation ranges
    # (198.51.100.0/24, 203.0.113.0/24, …) which OutPost's own demo data and
    # test fixtures use as stand-in public addresses.
    _INTERNAL_NETS = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("100.64.0.0/10"),  # CGNAT / carrier-grade NAT
        ipaddress.ip_network("0.0.0.0/8"),  # this-network
        ipaddress.ip_network("fc00::/7"),  # IPv6 unique-local
    )

    def _externally_routable(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False  # hostnames / garbage — nothing to query
        return not (
            addr.is_loopback or addr.is_link_local or addr.is_multicast
            or addr.is_unspecified
            or any(addr in n for n in _INTERNAL_NETS)
        )

    results: dict[str, dict] = {}
    async with httpx.AsyncClient() as client:
        for ip in ips:
            data = (
                await enrich_ip(client, conn, ip)
                if _externally_routable(ip)
                else {
                    "ip": ip,
                    "abuse_score": None,
                    "vt_malicious_count": None,
                    "reputation": None,
                    "checked_at": None,
                    "note": "private/reserved range — not queried externally",
                }
            )
            # Personal watchlist check (Task 26) — independent of external feeds.
            # Overrides a neutral verdict; a user-flagged entry is at least
            # suspicious by definition.
            wl = get_watchlist(conn, ip)
            if wl:
                data["watchlist"] = True
                data["watchlist_label"] = wl["label"]
                if data["reputation"] in (None, "unknown", "clean"):
                    data["reputation"] = "suspicious"
            results[ip] = data
    return results
