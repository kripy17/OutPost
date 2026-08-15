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

from .conftest import make_run
from .test_samples import _upload
from ..services import footprint as footprint_service


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
