"""Digital footprinting (roadmap) — GET /footprint/{sample_id}.

The seed layer is real (the sample's observed infrastructure); the passive
expansion is a stub. These tests lock both halves: real seed aggregation
from the event store, the 404 contract, and the clearly-labeled synthetic
mock that powers the webapp's demo of the UI shape.
"""

from .conftest import make_run
from .test_samples import _upload

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


def test_footprint_seeds_real_ips_from_samples_runs(client):
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

    # Passive layer is a stub by default — no fake intel, honest empty state.
    assert data["passive"]["source"] == "not_configured"
    assert data["passive"]["resolutions"] == []
    assert data["passive"]["certificates"] == []
    assert data["passive"]["sibling_ips"] == []


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
