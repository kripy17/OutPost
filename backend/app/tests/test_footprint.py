"""Digital footprinting — GET /footprint/{sample_id}.

The seed layer is real (the sample's observed infrastructure). The passive
expansion is real too (reverse-DNS PTR → crt.sh CT logs + RDAP), so every
test patches the network boundary: offline → honest `not_configured` empty
state; live → real-looking rows clearly marked non-synthetic; mock →
labeled synthetic. The RDAP/crt.sh parsers are pure functions and get their
own unit tests against canned payloads; `_fetch_ip_passive` gets a direct
async test for the sibling-host passive-DNS expansion.
"""

import asyncio

import pytest

from ..services import footprint as footprint_service
from .conftest import make_run
from .test_samples import _upload


@pytest.fixture(autouse=True)
def _clear_footprint_cache():
    """The service caches per-IP results in memory — isolate tests."""
    footprint_service.clear_cache()
    yield
    footprint_service.clear_cache()

# Unique PE bytes (distinct SHA from test_samples' MZ) so the idempotent
# upload-by-hash endpoint can't return another test's row with its name.
_PE = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x01\x02\x03\x04\x05"

_NET = "198.51.100.77"
_C2 = "203.0.113.204"


def _ingest(client, run_id, dest_ip, ts):
    client.post(
        "/ingest/batch",
        json=[
            {
                "run_id": run_id,
                "platform": "windows",
                "event_type": "network_connection",
                "timestamp": ts,
                "pid": 1,
                "dest_ip": dest_ip,
                "dest_port": 4444,
                "protocol": "TCP",
            }
        ],
    )


def _sample_with_ips(client, name: str = "footprint.exe", pe: bytes = _PE) -> str:
    """Upload a sample, detonate it twice against shared + unique IPs.

    `name` defaults to the shared fixture name used by the earlier tests;
    export tests pass unique names AND unique bytes so their run aggregation
    is deterministic (uploads are idempotent by hash, and the seed layer
    aggregates per sample name across ALL matching runs).
    """
    sample_id = _upload(client, pe, name).json()["sample_id"]
    run_a = make_run(client, sample_name=name)
    run_b = make_run(client, sample_name=name)
    _ingest(client, run_a, _C2, "2026-08-01T10:00:00Z")
    _ingest(client, run_a, _NET, "2026-08-01T10:00:05Z")
    _ingest(client, run_b, _C2, "2026-08-02T10:00:00Z")
    return sample_id


def test_footprint_seeds_real_ips_from_samples_runs(client, monkeypatch):
    """Offline (every passive fetch fails) → the honest `not_configured` state:
    the seed layer stays real, and no fake intel ever leaks in."""
    async def _offline(seed):
        raise ConnectionError("simulated outage")

    monkeypatch.setattr(footprint_service, "_fetch_ip_passive", _offline)

    sample_id = _sample_with_ips(client)
    data = client.get(f"/footprint/{sample_id}").json()

    assert data["sample"]["name"] == "footprint.exe"
    assert data["status"]["roadmap"] is True
    assert data["status"]["generated"] is None

    by_ip = {s["ip"]: s for s in data["seed_ips"]}
    # The shared C2 across both runs aggregates as the top seed.
    c2 = by_ip[_C2]
    assert c2["hits"] == 2
    assert c2["run_count"] == 2
    assert c2["first_seen"].startswith("2026-08-01")
    assert c2["last_seen"].startswith("2026-08-02")
    assert by_ip[_NET]["run_count"] == 1

    # Offline fallback — no fake intel, honest empty state.
    assert data["passive"]["source"] == "not_configured"
    assert data["passive"]["resolutions"] == []
    assert data["passive"]["certificates"] == []
    assert data["passive"]["passive_dns"] == []
    assert data["passive"]["sibling_ips"] == []
    assert data["passive"]["networks"] == []


def test_footprint_live_passive_layer(client, monkeypatch):
    """Providers reachable → real rows (non-synthetic), registration info,
    and `roadmap` flips off."""
    async def _fake(seed):
        return {
            "resolutions": [
                {"domain": f"host-{seed['ip']}.example.net", "first_seen": "2026-08-01", "last_seen": "2026-08-02", "synthetic": False}
            ],
            "passive_dns": [
                {"domain": f"cdn-{seed['ip']}.example.net", "first_seen": "2026-01-01", "last_seen": "2026-08-02", "synthetic": False},
                {"domain": "panel.example.net", "first_seen": "2026-03-01", "last_seen": "2026-07-01", "synthetic": False},
            ],
            "certificates": [
                {"cn": "*.example.net", "issuer": "C=US, O=Example CA", "not_before": "2026-01-01", "not_after": "2027-01-01", "synthetic": False}
            ],
            "sibling_ips": [
                {"ip": "203.0.113.89", "relation": "same 203.0.113.88/24", "synthetic": False}
            ],
            "networks": [
                {"ip": seed["ip"], "cidr": "203.0.113.88/24", "netname": "TEST-NET-3", "org": "Example Org", "country": "US", "synthetic": False}
            ],
        }

    monkeypatch.setattr(footprint_service, "_fetch_ip_passive", _fake)

    sample_id = _sample_with_ips(client)
    data = client.get(f"/footprint/{sample_id}").json()

    assert data["passive"]["source"] == "live"
    assert data["status"]["roadmap"] is False
    assert data["passive"]["resolutions"][0]["domain"].endswith(".example.net")
    assert data["passive"]["certificates"][0]["synthetic"] is False
    assert data["passive"]["networks"][0]["netname"] == "TEST-NET-3"
    assert data["passive"]["networks"][0]["cidr"] == "203.0.113.88/24"
    # The passive-DNS history aggregates through to the response.
    dns = data["passive"]["passive_dns"]
    assert any(d["domain"] == "panel.example.net" for d in dns), "passive DNS rows reach the client"
    assert all(d["synthetic"] is False for d in dns)
    # Live rows are never synthetic.
    for node in data["passive"]["resolutions"]:
        assert node["synthetic"] is False


def test_parse_rdap_extracts_registration_and_siblings():
    doc = {
        "handle": "NET-203-0-113-0-1",
        "name": "TEST-NET-3",
        "country": "US",
        "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
        "startAddress": "203.0.113.0",
        "endAddress": "203.0.113.255",
        "entities": [
            {
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Org"]]],
            }
        ],
    }
    out = footprint_service._parse_rdap("203.0.113.88", doc)
    assert out["cidr"] == "203.0.113.0/24"
    assert out["netname"] == "TEST-NET-3"
    assert out["org"] == "Example Org"
    assert out["country"] == "US"
    assert out["siblings"], "RDAP net yields sibling hosts"
    assert out["siblings"][0]["synthetic"] is False


def test_parse_rdap_extracts_registrar_and_registration_dates():
    """The WHOIS-style registration timeline comes from the SAME RDAP
    payload — registrar entity + registration / last changed / expiration
    events, no extra provider call."""
    doc = {
        "name": "REG-NET",
        "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
        "startAddress": "203.0.113.0",
        "endAddress": "203.0.113.255",
        "entities": [
            {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar LLC"]]]},
            {"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "noc@example.net"]]]},
        ],
        "events": [
            {"eventAction": "registration", "eventDate": "2021-03-15T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2024-06-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-03-15T00:00:00Z"},
            {"eventAction": "unknown action", "eventDate": "2030-01-01T00:00:00Z"},
        ],
    }
    out = footprint_service._parse_rdap("203.0.113.88", doc)
    assert out["registrar"] == "Example Registrar LLC"
    assert out["created"] == "2021-03-15"
    assert out["updated"] == "2024-06-01"
    assert out["expires"] == "2026-03-15"


def test_parse_rdap_registration_missing_pieces_are_none():
    """No registrar role / no events → None fields, never a crash."""
    doc = {"name": "BARE-NET", "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}]}
    out = footprint_service._parse_rdap("203.0.113.88", doc)
    assert out["registrar"] is None
    assert out["created"] is None
    assert out["updated"] is None
    assert out["expires"] is None


def test_parse_rdap_domain_whois_record():
    """The domain-level RDAP (WHOIS) slice: registrar, created/updated/
    expires, status, and nameservers from the same keyless provider."""
    doc = {
        "handle": "2336799_DOMAIN_COM-VRSN",
        "status": ["client delete prohibited", "client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-08-13T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2026-08-14T00:00:00Z"},
        ],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc"]]]}],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}, {"ldhName": "NS2.EXAMPLE.COM"}],
    }
    out = footprint_service._parse_rdap_domain(doc)
    assert out["registrar"] == "Example Registrar Inc"
    assert out["created"] == "1995-08-14"
    assert out["updated"] == "2026-08-14"
    assert out["expires"] == "2027-08-13"
    assert "client delete prohibited" in out["status"]
    assert out["nameservers"] == ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"]


def test_parse_rdap_domain_missing_pieces_are_empty():
    doc = {"handle": "BARE"}
    out = footprint_service._parse_rdap_domain(doc)
    assert out["registrar"] is None
    assert out["created"] is None and out["updated"] is None and out["expires"] is None
    assert out["status"] == [] and out["nameservers"] == []


def test_parse_breach_response_extracts_names():
    assert footprint_service._parse_breach_response(
        {"breaches": [["XKCD", "LinkedIn", "LinkedIn"], "Zomato", "Alcon"], "status": "success"}
    ) == ["XKCD", "LinkedIn", "Zomato", "Alcon"]


def test_parse_breach_response_clean_email_is_empty():
    assert footprint_service._parse_breach_response({"Error": "Not found", "email": None}) == []
    assert footprint_service._parse_breach_response({"status": "error"}) == []
    assert footprint_service._parse_breach_response({}) == []
    assert footprint_service._parse_breach_response([]) == []


def test_parse_rdap_tight_network_uses_that_net_for_siblings():
    """A /30 RDAP net must yield siblings FROM that /30 — never /24 hosts
    mislabeled as the tighter network (regression from review)."""
    doc = {
        "name": "TIGHT-NET",
        "cidr0_cidrs": [{"v4prefix": "203.0.113.4", "length": 30}],
        "startAddress": "203.0.113.4",
        "endAddress": "203.0.113.7",
    }
    out = footprint_service._parse_rdap("203.0.113.5", doc)
    ips = [s["ip"] for s in out["siblings"]]
    assert ips and all(ip.startswith("203.0.113.") for ip in ips)
    assert all(s["relation"] == "same 203.0.113.4/30" for s in out["siblings"])


def test_fetch_ip_passive_expands_sibling_passive_dns(monkeypatch):
    """The sibling expansion — crt.sh by IP for cohosted hosts — surfaces
    infra beyond the apex domain, tagged with the sibling IP each name came
    from, deduped against the apex names."""
    seed = {"ip": _C2, "first_seen": "2026-08-01T10:00:00Z", "last_seen": "2026-08-02T10:00:00Z"}

    async def _fake_rdap(ip):
        return {
            "cidr": "203.0.113.0/24",
            "netname": "TEST-NET-3",
            "org": "Example Org",
            "country": "US",
            "siblings": [{"ip": "203.0.113.89", "relation": "same 203.0.113.0/24", "synthetic": False}],
        }

    async def _fake_crtsh(q):
        if q == "c2.example.com":  # the apex PTR domain
            return {
                "certificates": [{"cn": "*.example.com", "issuer": "Example CA", "not_before": "2026-01-01", "not_after": "2027-01-01", "synthetic": False}],
                "domains": [
                    {"domain": "c2.example.com", "first_seen": "2026-01-01", "last_seen": "2026-08-01", "synthetic": False},
                    {"domain": "panel.example.com", "first_seen": "2026-02-01", "last_seen": "2026-07-01", "synthetic": False},
                ],
            }
        if q == "203.0.113.89":  # crt.sh by sibling IP
            return {
                "certificates": [],
                "domains": [
                    {"domain": "sibling-panel.example.net", "first_seen": "2026-03-01", "last_seen": "2026-08-01", "synthetic": False},
                    {"domain": "panel.example.com", "first_seen": "2026-01-01", "last_seen": "2026-08-01", "synthetic": False},  # dup of apex
                ],
            }
        raise AssertionError(f"unexpected crt.sh query: {q}")

    async def _fake_asn(ip):
        return {"asn": "AS123", "as_name": "Example AS", "org": "Example Org", "country": "US", "country_code": "US"}

    async def _no_subdomains(apex):
        return []

    monkeypatch.setattr(footprint_service, "_ptr_for_ip", lambda ip: "c2.example.com")
    monkeypatch.setattr(footprint_service, "_rdap_lookup", _fake_rdap)
    monkeypatch.setattr(footprint_service, "_crtsh_lookup", _fake_crtsh)
    monkeypatch.setattr(footprint_service, "_crtsh_subdomains", _no_subdomains)
    monkeypatch.setattr(footprint_service, "_asn_lookup", _fake_asn)

    out = asyncio.run(footprint_service._fetch_ip_passive(seed))
    dns = out["passive_dns"]
    by_name = {d["domain"]: d for d in dns}

    # Apex-derived rows are tagged with the seed IP; the apex PTR name itself
    # stays out (it lives in resolutions).
    assert "panel.example.com" in by_name
    assert by_name["panel.example.com"]["source_ip"] == _C2
    assert "c2.example.com" not in by_name
    # The sibling expansion surfaces the cohosted name, tagged with the
    # sibling IP — and the duplicate apex name is dropped exactly once.
    assert "sibling-panel.example.net" in by_name
    assert by_name["sibling-panel.example.net"]["source_ip"] == "203.0.113.89"
    assert len(dns) == 2, "apex name + shared name deduped to exactly two rows"
    # Certificates stay apex-only; the sibling IP still reaches siblings list.
    assert out["certificates"][0]["cn"] == "*.example.com"
    assert out["sibling_ips"][0]["ip"] == "203.0.113.89"


def test_apex_of():
    """The discovery apex strips exactly one leftmost label and refuses
    hosts with no discoverable subdomain namespace."""
    assert footprint_service._apex_of("mail.example.com") == "example.com"
    assert footprint_service._apex_of("a.b.example.com") == "b.example.com"
    assert footprint_service._apex_of("example.com") is None      # strips to a bare TLD
    assert footprint_service._apex_of("com") is None              # single label
    assert footprint_service._apex_of("127.0.0.1") is None        # IP literal
    assert footprint_service._apex_of("  MAIL.Example.COM. ") == "example.com"  # case/whitespace/dot


def test_crtsh_subdomains_filters_proper_subdomains(monkeypatch):
    """The `%.<apex>` enumeration keeps only PROPER subdomains of the apex
    (crt.sh matches superstrings), strips wildcards, and tags the apex."""
    async def _fake_query(q):
        assert q == "%.example.com", f"expected the wildcard apex query, got {q!r}"
        return {
            "certificates": [],
            "domains": [
                {"domain": "web.example.com", "first_seen": "2026-01-01", "last_seen": "2026-08-01", "synthetic": False},
                {"domain": "*.staging.example.com", "first_seen": "2026-02-01", "last_seen": "2026-07-01", "synthetic": False},  # wildcard stripped by the parser
                {"domain": "example.com", "first_seen": "2026-01-01", "last_seen": "2026-08-01", "synthetic": False},  # apex itself — excluded
                {"domain": "unrelated.net", "first_seen": "2026-01-01", "last_seen": "2026-01-01", "synthetic": False},  # superstring match — excluded
            ],
        }

    monkeypatch.setattr(footprint_service, "_crtsh_query", _fake_query)
    subs = asyncio.run(footprint_service._crtsh_subdomains("example.com"))
    names = sorted(s["domain"] for s in subs)
    assert names == ["staging.example.com", "web.example.com"], names
    assert all(s["apex"] == "example.com" for s in subs)
    assert all(s["synthetic"] is False for s in subs)


def test_fetch_ip_passive_subdomain_enumeration(monkeypatch):
    """Subdomain discovery — crt.sh `%.<apex>` over the PTR-derived domain
    lands in its own collection, deduped against the passive-DNS history and
    tagged with the seed IP."""
    seed = {"ip": _C2, "first_seen": "2026-08-01T10:00:00Z", "last_seen": "2026-08-02T10:00:00Z"}

    async def _fake_rdap(ip):
        return {"cidr": "203.0.113.0/24", "netname": "TEST-NET-3", "org": "Example Org", "country": "US", "siblings": []}

    async def _fake_crtsh_lookup(domain):
        return {"certificates": [], "domains": [{"domain": "panel.example.com", "first_seen": "2026-01-01", "last_seen": "2026-08-01", "synthetic": False}]}

    async def _fake_subdomains(apex):
        assert apex == "example.com"
        return [
            {"domain": "dev.example.com", "apex": "example.com", "first_seen": "2026-03-01", "last_seen": "2026-08-01", "synthetic": False},
            {"domain": "panel.example.com", "apex": "example.com", "first_seen": "2026-01-01", "last_seen": "2026-08-01", "synthetic": False},  # dup of passive DNS
        ]

    async def _fake_asn(ip):
        return {}

    monkeypatch.setattr(footprint_service, "_ptr_for_ip", lambda ip: "mail.example.com")
    monkeypatch.setattr(footprint_service, "_rdap_lookup", _fake_rdap)
    monkeypatch.setattr(footprint_service, "_crtsh_lookup", _fake_crtsh_lookup)
    monkeypatch.setattr(footprint_service, "_crtsh_subdomains", _fake_subdomains)
    monkeypatch.setattr(footprint_service, "_asn_lookup", _fake_asn)

    out = asyncio.run(footprint_service._fetch_ip_passive(seed))
    subs = out["subdomains"]
    assert [s["domain"] for s in subs] == ["dev.example.com"], "the shared name dedupes against passive DNS"
    assert subs[0]["source_ip"] == _C2
    assert subs[0]["apex"] == "example.com"
    assert "panel.example.com" in {d["domain"] for d in out["passive_dns"]}


def test_parse_crtsh_rows_to_certs_and_domains():
    rows = [
        {
            "common_name": "*.example.net",
            "issuer_name": "C=US, O=Example CA, CN=Example CA",
            "name_value": "*.example.net\ncdn.example.net",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2027-01-01T00:00:00",
        }
    ]
    out = footprint_service._parse_crtsh(rows)
    assert out["certificates"][0]["cn"] == "*.example.net"
    assert out["certificates"][0]["synthetic"] is False
    domains = [d["domain"] for d in out["domains"]]
    assert "cdn.example.net" in domains
    assert "*.example.net" not in domains  # wildcard stripped to base name


def test_footprint_unknown_sample_404(client):
    assert client.get("/footprint/nope00000000").status_code == 404


def test_footprint_export_json_structured_payload(client):
    """JSON export — the full structured handoff payload: sample identity,
    seed IPs, and every passive collection (incl. passive DNS)."""
    sample_id = _sample_with_ips(client, name="footprint-export-json.exe", pe=_PE + b"-export-json")
    resp = client.get(f"/footprint/{sample_id}/export?format=json&mock=1")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.headers["content-disposition"].startswith("attachment; filename=\"outpost-footprint-")
    assert resp.headers["content-disposition"].endswith('.json"')

    payload = resp.json()
    assert payload["sample"]["name"] == "footprint-export-json.exe"
    assert payload["status"]["generated"] == "mock"
    by_ip = {s["ip"]: s for s in payload["seed_ips"]}
    assert by_ip[_C2]["run_count"] == 2
    assert payload["passive"]["source"] == "synthetic_demo"
    assert payload["passive"]["passive_dns"], "passive DNS rows ride in the export"
    assert all(d["synthetic"] is True for d in payload["passive"]["passive_dns"])
    assert payload["passive"]["certificates"]


def test_footprint_export_csv_flat_ioc_sheet(client):
    """CSV export — one filterable sheet with a `collection` discriminator:
    seeds lead, then resolutions / passive_dns / certs / siblings / networks."""
    sample_id = _sample_with_ips(client, name="footprint-export-csv.exe", pe=_PE + b"-export-csv")
    resp = client.get(f"/footprint/{sample_id}/export?format=csv&mock=1")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.headers["content-disposition"].endswith('.csv"')

    text = resp.text
    lines = text.strip().splitlines()
    header = lines[0]
    assert header.split(",") == ["collection", "indicator", "source_ip", "detail", "first_seen", "last_seen", "synthetic"]
    assert lines[1].startswith("seed,"), "observed infrastructure leads the sheet"

    body = lines[1:]
    assert any(l.startswith("passive_dns,") for l in body), "passive DNS rows flatten to CSV"
    assert any(l.startswith("certificate,") for l in body)
    # The synthetic flag survives the flatten as a boolean column — mock rows
    # are marked true so a handoff artifact never loses the labeling.
    assert all(l.split(",")[-1] in ("true", "false") for l in body)
    assert any(l.startswith("passive_dns,") and l.endswith(",true") for l in body)
    assert all(not l.startswith("seed,") or l.endswith(",false") for l in body if l.startswith("seed,"))
    # Mock passive-DNS rows carry the seed IP they were observed from.
    assert any(l.startswith("passive_dns,") and l.split(",")[2] == _C2 for l in body)


def test_footprint_export_rejects_bad_format_and_unknown_sample(client):
    sample_id = _sample_with_ips(client)
    assert client.get(f"/footprint/{sample_id}/export?format=xml").status_code == 422
    assert client.get("/footprint/nope00000000/export?format=json").status_code == 404


def test_footprint_mock_fills_passive_layer_clearly_labeled(client):
    sample_id = _sample_with_ips(client)
    data = client.get(f"/footprint/{sample_id}?mock=1").json()

    assert data["status"]["generated"] == "mock"
    assert data["passive"]["source"] == "synthetic_demo"
    assert data["passive"]["resolutions"], "mock must render the UI shape"
    assert data["passive"]["certificates"]
    assert data["passive"]["passive_dns"], "mock passive-DNS history fills the card"
    assert data["passive"]["sibling_ips"]
    # Every synthetic node is labeled so it can never be mistaken for intel.
    for node in data["passive"]["resolutions"]:
        assert node["synthetic"] is True
    for node in data["passive"]["certificates"]:
        assert node["synthetic"] is True
    for node in data["passive"]["passive_dns"]:
        assert node["synthetic"] is True
    for node in data["passive"]["sibling_ips"]:
        assert node["synthetic"] is True


# ---------------------------------------------------------------------------
# Roadmap 2.5 — cross-sample infra topology
# ---------------------------------------------------------------------------

def _ingest_topology(client, run_id, dest_ip, ts):
    client.post(
        "/ingest/batch",
        json=[{
            "run_id": run_id, "platform": "windows", "event_type": "network_connection",
            "timestamp": ts, "pid": 1, "dest_ip": dest_ip, "dest_port": 4444, "protocol": "TCP",
        }],
    )


def test_cross_sample_topology_clusters_shared_infra(client):
    """Two samples touching the same C2 IP cluster; a third touching only its
    own IP stays out — the campaign-correlation hypothesis."""
    shared = "203.0.113.111"
    uniq_a = "198.51.100.11"
    uniq_b = "198.51.100.22"
    uniq_c = "198.51.100.33"

    for name, uniq in (("topo-a.bin", uniq_a), ("topo-b.bin", uniq_b)):
        rid = make_run(client, sample_name=name)
        _ingest_topology(client, rid, shared, "2026-08-01T10:00:00Z")
        _ingest_topology(client, rid, uniq, "2026-08-01T10:00:05Z")
    rid_c = make_run(client, sample_name="topo-c.bin")
    _ingest_topology(client, rid_c, uniq_c, "2026-08-03T10:00:00Z")

    resp = client.get("/footprint/topology")
    assert resp.status_code == 200
    body = resp.json()
    # The session DB carries other tests' samples too — assert on this test's
    # own clusters, not the global total.
    assert body["total_samples"] >= 3

    ips = [c["ip"] for c in body["clusters"]]
    assert shared in ips
    assert uniq_a not in ips and uniq_b not in ips and uniq_c not in ips

    cluster = next(c for c in body["clusters"] if c["ip"] == shared)
    assert cluster["sample_count"] == 2
    names = {m["sample_name"] for m in cluster["members"]}
    assert names == {"topo-a.bin", "topo-b.bin"}
    # Members sorted by hits desc; every member names its run ids.
    for m in cluster["members"]:
        assert m["hits"] >= 1
        assert m["run_ids"]
    assert cluster["reputation"] in ("unknown", "malicious", "clean", "suspicious")


def test_cross_sample_topology_requires_two_distinct_samples(client):
    """One sample alone on an IP is NOT shared infrastructure — the seed IP
    of a single binary is its own footprint, not a cluster. (Asserted on this
    test's unique IP; the session DB holds other tests' shared-IP samples.)"""
    solo_ip = "203.0.113.222"
    rid = make_run(client, sample_name="solo.bin")
    _ingest_topology(client, rid, solo_ip, "2026-08-01T10:00:00Z")

    resp = client.get("/footprint/topology")
    body = resp.json()
    assert body["total_samples"] >= 1
    ips = [c["ip"] for c in body["clusters"]]
    assert solo_ip not in ips


def test_cross_sample_topology_response_shape(client):
    """The endpoint always returns the cluster contract, even with no shared
    infra in the shared session DB."""
    resp = client.get("/footprint/topology")
    assert resp.status_code == 200
    body = resp.json()
    assert "clusters" in body and "total_samples" in body
    assert isinstance(body["clusters"], list)
    assert isinstance(body["total_samples"], int)


# ---------------------------------------------------------------------------
# Roadmap 2.6 — WHOIS record + breach exposure (keyless slices)
# ---------------------------------------------------------------------------

def test_fetch_ip_passive_collects_whois_record(monkeypatch):
    """The PTR-derived domain's RDAP (WHOIS) record rides the same keyless
    provider — registrar, dates, status, nameservers, marked non-synthetic."""
    seed = {"ip": "203.0.113.77", "first_seen": "2026-08-01T10:00:00Z", "last_seen": "2026-08-02T10:00:00Z"}

    async def fake_domain(domain: str):
        return {
            "registrar": "Example Registrar Inc",
            "created": "1995-08-14",
            "updated": "2026-08-14",
            "expires": "2027-08-13",
            "status": ["client transfer prohibited"],
            "nameservers": ["NS1.EXAMPLE.COM"],
        }

    monkeypatch.setattr(footprint_service, "_ptr_for_ip", lambda ip: "srv.example.com")
    monkeypatch.setattr(footprint_service, "_cached_domain_fetch", fake_domain)
    monkeypatch.setattr(footprint_service, "_rdap_lookup", lambda ip: asyncio.coroutine(dict)())
    monkeypatch.setattr(footprint_service, "_asn_lookup", lambda ip: asyncio.coroutine(dict)())
    monkeypatch.setattr(footprint_service, "_crtsh_lookup", lambda d: asyncio.coroutine(lambda: {"certificates": [], "domains": []})())
    monkeypatch.setattr(footprint_service, "_crtsh_subdomains", lambda d: asyncio.coroutine(list)())

    out = asyncio.run(footprint_service._fetch_ip_passive(seed))
    whois = out["whois"]
    assert len(whois) == 1
    row = whois[0]
    assert row["domain"] == "example.com"  # apex of srv.example.com
    assert row["registrar"] == "Example Registrar Inc"
    assert row["created"] == "1995-08-14" and row["expires"] == "2027-08-13"
    assert "client transfer prohibited" in row["status"]
    assert row["nameservers"] == ["NS1.EXAMPLE.COM"]
    assert row["synthetic"] is False


def test_breach_layer_checks_embedded_emails(monkeypatch):
    """Embedded emails from the sample's bytes are checked against the
    keyless breach index; each row carries its breach list, non-synthetic."""
    sample_id = "breach-sample-0001"

    monkeypatch.setattr(footprint_service, "_embedded_emails", lambda sid: ["victim@example.com", "ceo@example.org"])
    async def fake_breach(email: str):
        return ["XKCD", "LinkedIn"] if email == "victim@example.com" else []
    monkeypatch.setattr(footprint_service, "_cached_breach_fetch", fake_breach)

    out = asyncio.run(footprint_service._breach_layer(sample_id, mock=False))
    assert out["source"] == "live"
    rows = {r["email"]: r["breaches"] for r in out["rows"]}
    assert rows["victim@example.com"] == ["XKCD", "LinkedIn"]
    assert rows["ceo@example.org"] == []  # clean email → honest empty
    assert all(r["synthetic"] is False for r in out["rows"])


def test_breach_layer_no_emails_is_honest_empty(monkeypatch):
    monkeypatch.setattr(footprint_service, "_embedded_emails", lambda sid: [])
    out = asyncio.run(footprint_service._breach_layer("sample", mock=False))
    assert out["source"] == "no_emails"
    assert out["rows"] == []


def test_breach_layer_mock_is_labeled_synthetic():
    out = asyncio.run(footprint_service._breach_layer("mock-sample", mock=True))
    assert out["source"] == "synthetic_demo"
    assert out["rows"] and out["rows"][0]["synthetic"] is True


# ---------------------------------------------------------------------------
# Defensive branches + live HTTP wrappers (fake httpx client — no network)
# ---------------------------------------------------------------------------


def test_ptr_for_ip_real_socket_and_failure(monkeypatch):
    """The reverse-DNS probe itself: resolves via the real socket call, and
    degrades to None when the lookup fails."""
    monkeypatch.setattr(footprint_service.socket, "gethostbyaddr", lambda ip: ("host.example.com", [], [ip]))
    assert footprint_service._ptr_for_ip("203.0.113.88") == "host.example.com"

    def _boom(ip):
        raise OSError("no PTR")

    monkeypatch.setattr(footprint_service.socket, "gethostbyaddr", _boom)
    assert footprint_service._ptr_for_ip("203.0.113.88") is None


def test_ipv4_neighbors_defensive_branches():
    """Bad input (ValueError) and an IP that isn't a host in its own net
    (StopIteration) both return [] — never crash."""
    assert footprint_service._ipv4_neighbors("999.999.1.1") == []
    assert footprint_service._ipv4_neighbors("not-an-ip") == []
    # 203.0.113.0 is the network address — hosts() starts at .1
    assert footprint_service._ipv4_neighbors("203.0.113.0") == []


def test_common_prefix_len():
    assert footprint_service._common_prefix_len("203.0.113.0", "203.0.113.255") == 24
    assert footprint_service._common_prefix_len("203.0.113.4", "203.0.113.7") == 30
    assert footprint_service._common_prefix_len("1.1.1.1", "1.1.1.1") == 32
    assert footprint_service._common_prefix_len("10.0.0.1", "11.0.0.1") == 7


def test_entity_org_defensive_branches():
    """A non-list vcard and a vcard without an `fn` entry both return None."""
    assert footprint_service._entity_org({"vcardArray": "not-a-list"}) is None
    assert footprint_service._entity_org({}) is None
    assert footprint_service._entity_org(
        {"vcardArray": ["vcard", [["email", {}, "text", "noc@example.net"]]]}
    ) is None


def test_parse_rdap_synthesizes_cidr_from_start_end():
    """No cidr0_cidrs → the CIDR is synthesized from startAddress/endAddress
    via `_common_prefix_len`."""
    doc = {"startAddress": "203.0.113.0", "endAddress": "203.0.113.255", "name": "SYNTH-NET"}
    out = footprint_service._parse_rdap("203.0.113.5", doc)
    assert out["cidr"] == "203.0.113.0/24"
    assert out["siblings"]


def test_parse_rdap_bad_start_address_keeps_cidr_none():
    """The IPv4Address(start) ValueError branch → cidr stays None and the
    sibling fallback still runs."""
    doc = {"startAddress": "999.999.1.0", "endAddress": "203.0.113.255", "name": "BAD-NET"}
    out = footprint_service._parse_rdap("203.0.113.5", doc)
    assert out["cidr"] is None
    assert out["siblings"]


def test_parse_rdap_invalid_cidr_uses_neighbor_fallback():
    """ip_network(cidr) raises → net is None → siblings come from the /24
    neighbors (never a crash)."""
    doc = {"cidr0_cidrs": [{"v4prefix": "999.999.1.0", "length": 24}], "name": "JUNK-NET"}
    out = footprint_service._parse_rdap("203.0.113.5", doc)
    assert out["siblings"] and out["siblings"][0]["relation"] == "same /24"


def test_parse_rdap_ip_not_in_net_uses_offsets():
    """The hosts.index(ip) ValueError branch (ip is the network address, not
    a host) → idx=-1 → the +1..+3 offsets are still picked."""
    doc = {"cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}], "name": "NET"}
    out = footprint_service._parse_rdap("203.0.113.0", doc)
    ips = [s["ip"] for s in out["siblings"]]
    assert ips and all(ip.startswith("203.0.113.") for ip in ips)


def test_parse_rdap_wide_net_uses_24_neighbors():
    """A /16 RDAP net → prefixlen < 24 → siblings from the /24 the IP sits
    in, labeled `same /24` (never the whole /16)."""
    doc = {"cidr0_cidrs": [{"v4prefix": "10.0.0.0", "length": 16}], "name": "BIG-ISP"}
    out = footprint_service._parse_rdap("10.0.0.5", doc)
    assert out["cidr"] == "10.0.0.0/16"
    assert all(s["relation"] == "same /24" for s in out["siblings"])
    assert all(s["ip"].startswith("10.0.0.") for s in out["siblings"])


def test_parse_crtsh_skips_non_dict_rows():
    """Malformed crt.sh rows (strings, None) are skipped without crashing."""
    rows = ["junk", None, {"common_name": "x.example.com", "issuer_name": "CA", "name_value": "x.example.com", "not_before": "2026-01-01T00:00:00", "not_after": "2026-12-01T00:00:00"}]
    out = footprint_service._parse_crtsh(rows)
    assert len(out["certificates"]) == 1
    assert out["certificates"][0]["cn"] == "x.example.com"


def test_parse_rdap_domain_skips_events_without_action_or_date():
    doc = {"events": [{"eventAction": "registration"}, {"eventDate": "2026-01-01T00:00:00Z"}]}
    out = footprint_service._parse_rdap_domain(doc)
    assert out["created"] is None and out["updated"] is None


def test_rdap_registration_skips_malformed_events():
    """`_rdap_registration`'s own skip branch: an event missing its action OR
    its date is ignored (network-doc registration timeline)."""
    out = footprint_service._rdap_registration(
        {"events": [{"eventAction": "registration"}, {"eventDate": "2026-01-01T00:00:00Z"}, "junk"]}
    )
    assert out["created"] is None and out["updated"] is None and out["expires"] is None


def test_parse_crtsh_skips_empty_names():
    """A name_value that strips to nothing is skipped, never added to the
    domain list."""
    rows = [{"common_name": "x.example.com", "issuer_name": "CA", "name_value": "  \n\n", "not_before": "2026-01-01T00:00:00", "not_after": "2026-12-01T00:00:00"}]
    out = footprint_service._parse_crtsh(rows)
    assert out["certificates"]  # the cert still lands
    assert out["domains"] == []  # but the blank names are dropped


def test_crtsh_lookup_wrapper(monkeypatch):
    """`_crtsh_lookup` delegates to `_crtsh_query` (the thin wrapper)."""
    calls = []

    async def _fake(q):
        calls.append(q)
        return {"certificates": [], "domains": []}

    monkeypatch.setattr(footprint_service, "_crtsh_query", _fake)
    assert asyncio.run(footprint_service._crtsh_lookup("example.com")) == {"certificates": [], "domains": []}
    assert calls == ["example.com"]


def test_embedded_emails_unreadable_bytes_is_empty(monkeypatch, tmp_path):
    """The OSError branch: a stored entry that can't be read (a directory in
    place of the .bin) yields [] — never a crash."""
    from ..core import config as app_config

    monkeypatch.setattr(app_config, "SAMPLES_DIR", tmp_path)
    # A directory where the .bin should be: exists() passes, read_bytes()
    # raises IsADirectoryError (an OSError) → the guard returns [].
    (tmp_path / "dir-as-bin.bin").mkdir()
    assert footprint_service._embedded_emails("dir-as-bin") == []


def test_embedded_emails_lazy_import_failure_is_empty(monkeypatch):
    """The lazy-import guard: if the static-analysis module can't be imported
    (broken install), the embedded-email read degrades to [] instead of
    crashing the whole footprint page."""
    import builtins

    real_import = builtins.__import__

    def _broken_import(name, *args, **kw):
        if name == "app.services.static_analysis" or name.endswith(".static_analysis"):
            raise ImportError("simulated broken install")
        return real_import(name, *args, **kw)

    monkeypatch.setattr(builtins, "__import__", _broken_import)
    assert footprint_service._embedded_emails("anything") == []


class _FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeAClient:
    def __init__(self, handler, **kw):
        self._handler = handler

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, **kw):
        return self._handler(url)


def _patch_httpx(monkeypatch, handler):
    monkeypatch.setattr(footprint_service.httpx, "AsyncClient", lambda **kw: _FakeAClient(handler))


def test_rdap_lookup_http_and_bad_payload(monkeypatch):
    """The live RDAP HTTP wrapper: parses a real payload, and raises on a
    non-dict response."""
    _patch_httpx(
        monkeypatch,
        lambda url: _FakeResp({"name": "HTTP-NET", "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}]}),
    )
    out = asyncio.run(footprint_service._rdap_lookup("203.0.113.88"))
    assert out["netname"] == "HTTP-NET"

    _patch_httpx(monkeypatch, lambda url: _FakeResp(["not", "a", "dict"]))
    with pytest.raises(ValueError, match="bad RDAP payload"):
        asyncio.run(footprint_service._rdap_lookup("203.0.113.88"))


def test_rdap_domain_lookup_http_and_bad_payload(monkeypatch):
    _patch_httpx(monkeypatch, lambda url: _FakeResp({"handle": "H", "status": []}))
    out = asyncio.run(footprint_service._rdap_domain_lookup("example.com"))
    assert out["status"] == []

    _patch_httpx(monkeypatch, lambda url: _FakeResp(["not", "a", "dict"]))
    with pytest.raises(ValueError, match="bad RDAP domain payload"):
        asyncio.run(footprint_service._rdap_domain_lookup("example.com"))


def test_crtsh_query_http_and_bad_payload(monkeypatch):
    _patch_httpx(monkeypatch, lambda url: _FakeResp([{"common_name": "x.example.com", "issuer_name": "CA", "name_value": "x.example.com", "not_before": "2026-01-01T00:00:00", "not_after": "2026-12-01T00:00:00"}]))
    out = asyncio.run(footprint_service._crtsh_query("example.com"))
    assert out["certificates"]

    _patch_httpx(monkeypatch, lambda url: _FakeResp({"not": "a list"}))
    with pytest.raises(ValueError, match="bad crt.sh payload"):
        asyncio.run(footprint_service._crtsh_query("example.com"))


def test_breach_lookup_http_success_and_errors(monkeypatch):
    _patch_httpx(monkeypatch, lambda url: _FakeResp({"breaches": [["XKCD", "LinkedIn"]], "status": "success"}))
    assert asyncio.run(footprint_service._breach_lookup("victim@example.com")) == ["XKCD", "LinkedIn"]

    _patch_httpx(monkeypatch, lambda url: _FakeResp({}, status=500))
    with pytest.raises(ValueError, match="bad breach payload"):
        asyncio.run(footprint_service._breach_lookup("victim@example.com"))


def test_asn_lookup_http_success_and_errors(monkeypatch):
    _patch_httpx(
        monkeypatch,
        lambda url: _FakeResp({"status": "success", "as": "AS15169 Google LLC", "asname": "GOOGLE", "org": "Google", "isp": "Google", "country": "US", "countryCode": "US"}),
    )
    out = asyncio.run(footprint_service._asn_lookup("8.8.8.8"))
    assert out["asn"] == "AS15169" and out["org"] == "Google"

    _patch_httpx(monkeypatch, lambda url: _FakeResp({"status": "fail"}))
    with pytest.raises(ValueError, match="ip-api lookup failed"):
        asyncio.run(footprint_service._asn_lookup("8.8.8.8"))

    _patch_httpx(monkeypatch, lambda url: _FakeResp({}, status=500))
    with pytest.raises(ValueError, match="bad ip-api payload"):
        asyncio.run(footprint_service._asn_lookup("8.8.8.8"))


# -- Cache layers: positive hit / fail cache / exception ---------------------------


def test_cached_fetch_positive_cache_serves_second_call(monkeypatch):
    calls = []

    async def _fake(seed):
        calls.append(seed["ip"])
        return {"resolutions": [{"domain": "x.example.com"}]}

    monkeypatch.setattr(footprint_service, "_fetch_ip_passive", _fake)
    seed = {"ip": "203.0.113.90", "first_seen": "2026-08-01T00:00:00Z"}
    first = asyncio.run(footprint_service._cached_fetch(seed))
    second = asyncio.run(footprint_service._cached_fetch(seed))
    assert first == second
    assert len(calls) == 1, "the second call must hit the cache, not re-fetch"


def test_cached_fetch_fail_cache_skips_repeat_attempts(monkeypatch):
    calls = []

    async def _boom(seed):
        calls.append(seed["ip"])
        raise ConnectionError("simulated outage")

    monkeypatch.setattr(footprint_service, "_fetch_ip_passive", _boom)
    seed = {"ip": "203.0.113.91", "first_seen": "2026-08-01T00:00:00Z"}
    assert asyncio.run(footprint_service._cached_fetch(seed)) == {}
    assert asyncio.run(footprint_service._cached_fetch(seed)) == {}
    assert len(calls) == 1, "the fail cache must absorb the second call"


def test_cached_domain_fetch_positive_and_fail(monkeypatch):
    calls = []

    async def _fake(domain):
        calls.append(domain)
        return {"registrar": "R", "created": "2020-01-01"}

    monkeypatch.setattr(footprint_service, "_rdap_domain_lookup", _fake)
    a = asyncio.run(footprint_service._cached_domain_fetch("example.com"))
    b = asyncio.run(footprint_service._cached_domain_fetch("example.com"))
    assert a == b and len(calls) == 1

    async def _boom(domain):
        raise ConnectionError("down")

    monkeypatch.setattr(footprint_service, "_rdap_domain_lookup", _boom)
    assert asyncio.run(footprint_service._cached_domain_fetch("broken.example")) == {}
    assert asyncio.run(footprint_service._cached_domain_fetch("broken.example")) == {}


def test_cached_breach_fetch_positive_and_fail(monkeypatch):
    calls = []

    async def _fake(email):
        calls.append(email)
        return ["XKCD"]

    monkeypatch.setattr(footprint_service, "_breach_lookup", _fake)
    a = asyncio.run(footprint_service._cached_breach_fetch("a@example.com"))
    b = asyncio.run(footprint_service._cached_breach_fetch("a@example.com"))
    assert a == b == ["XKCD"] and len(calls) == 1

    async def _boom(email):
        raise ConnectionError("down")

    monkeypatch.setattr(footprint_service, "_breach_lookup", _boom)
    assert asyncio.run(footprint_service._cached_breach_fetch("b@example.com")) == []
    assert asyncio.run(footprint_service._cached_breach_fetch("b@example.com")) == []


def test_fetch_ip_passive_isolates_sibling_and_subdomain_failures(monkeypatch):
    """A failing sibling crt.sh lookup is skipped (continue), and a raising
    subdomain enumeration degrades to [] — each provider isolated."""
    seed = {"ip": "203.0.113.77", "first_seen": "2026-08-01T10:00:00Z", "last_seen": "2026-08-02T10:00:00Z"}

    async def _rdap(ip):
        return {"cidr": "203.0.113.0/24", "netname": "T", "org": "O", "country": "US", "siblings": []}

    async def _crtsh_apex(q):
        return {"certificates": [], "domains": [{"domain": "c2.example.com"}]}

    async def _crtsh_sibling(q):
        raise ConnectionError("sibling lookup down")

    async def _subs(apex):
        raise ConnectionError("subdomain query down")

    monkeypatch.setattr(footprint_service, "_ptr_for_ip", lambda ip: "c2.example.com")
    monkeypatch.setattr(footprint_service, "_rdap_lookup", _rdap)
    monkeypatch.setattr(footprint_service, "_crtsh_lookup", lambda q: _crtsh_sibling(q) if q != "c2.example.com" else _crtsh_apex(q))
    monkeypatch.setattr(footprint_service, "_crtsh_subdomains", _subs)
    monkeypatch.setattr(footprint_service, "_asn_lookup", lambda ip: asyncio.coroutine(dict)())
    monkeypatch.setattr(footprint_service, "_cached_domain_fetch", lambda d: asyncio.coroutine(dict)())

    out = asyncio.run(footprint_service._fetch_ip_passive(seed))
    assert out["passive_dns"] == []
    assert out["subdomains"] == []
    assert out["certificates"] == []


def test_embedded_emails_reads_stored_bytes(monkeypatch, tmp_path):
    """The real SAMPLES_DIR read: emails embedded in the stored .bin surface
    (extract_iocs runs on the actual bytes)."""
    from ..core import config as app_config

    monkeypatch.setattr(app_config, "SAMPLES_DIR", tmp_path)
    (tmp_path / "abc123.bin").write_bytes(b"contact support@example.com for details")
    emails = footprint_service._embedded_emails("abc123")
    assert emails and emails[0] == "support@example.com"
    assert footprint_service._embedded_emails("missing000") == []


def test_mock_sibling_ips_bad_ip_returns_empty():
    assert footprint_service._mock_sibling_ips({"ip": "999.999.1.1"}) == []


def test_passive_layer_collects_asn_and_skips_errored_fetches(monkeypatch):
    """`_passive_layer` runs the seeds concurrently: an errored fetch is
    skipped (continue) while successful ones contribute asn rows."""
    async def _cached(seed):
        if seed["ip"] == "198.51.100.1":
            raise ConnectionError("boom")
        return {
            "resolutions": [{"domain": f"h-{seed['ip']}.example.net", "first_seen": "2026-08-01", "last_seen": "2026-08-02", "synthetic": False}],
            "asn": {"ip": seed["ip"], "asn": "AS1"},
        }

    monkeypatch.setattr(footprint_service, "_cached_fetch", _cached)
    seeds = [
        {"ip": "203.0.113.10", "hits": 5, "first_seen": "2026-08-01", "last_seen": "2026-08-02"},
        {"ip": "198.51.100.1", "hits": 4, "first_seen": "2026-08-01", "last_seen": "2026-08-02"},
    ]
    out = asyncio.run(footprint_service._passive_layer(seeds, mock=False))
    assert out["source"] == "live"
    assert len(out["resolutions"]) == 1
    assert [a["asn"] for a in out["asn"]] == ["AS1"]
