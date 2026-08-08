"""Digital footprinting — GET /footprint/{sample_id}.

The seed layer is real (the sample's observed infrastructure). The passive
expansion is real too (reverse-DNS PTR → crt.sh CT logs + RDAP), so every
test patches the network boundary: offline → honest `not_configured` empty
state; live → real-looking rows clearly marked non-synthetic; mock →
labeled synthetic. The RDAP/crt.sh parsers are pure functions and get their
own unit tests against canned payloads.
"""

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


def _sample_with_ips(client) -> str:
    """Upload a sample, detonate it twice against shared + unique IPs."""
    sample_id = _upload(client, _PE, "footprint.exe").json()["sample_id"]
    run_a = make_run(client, sample_name="footprint.exe")
    run_b = make_run(client, sample_name="footprint.exe")
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


def test_footprint_mock_fills_passive_layer_clearly_labeled(client):
    sample_id = _sample_with_ips(client)
    data = client.get(f"/footprint/{sample_id}?mock=1").json()

    assert data["status"]["generated"] == "mock"
    assert data["passive"]["source"] == "synthetic_demo"
    assert data["passive"]["resolutions"], "mock must render the UI shape"
    assert data["passive"]["certificates"]
    assert data["passive"]["sibling_ips"]
    # Every synthetic node is labeled so it can never be mistaken for intel.
    for node in data["passive"]["resolutions"]:
        assert node["synthetic"] is True
    for node in data["passive"]["certificates"]:
        assert node["synthetic"] is True
    for node in data["passive"]["sibling_ips"]:
        assert node["synthetic"] is True
