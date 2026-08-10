"""Tests for the C-batch operations surface: threat-intel feed import
(POST /intel/import) and self-metrics (GET /metrics, Prometheus text)."""

import json

from .conftest import make_run


def _ts(offset_seconds: int = 0) -> str:
    import datetime

    return (
        datetime.datetime(2026, 8, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        + datetime.timedelta(seconds=offset_seconds)
    ).isoformat()


def _net(run_id: str, ip: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "network_connection",
        "timestamp": _ts(ts), "pid": 100, "process_name": "evil.exe",
        "dest_ip": ip, "dest_port": 4444, "protocol": "TCP",
    }


def _ingest(client, run_id: str, events: list[dict]) -> None:
    resp = client.post("/ingest/batch", json=events)
    assert resp.status_code == 202, resp.text


def _watchlist(client) -> set[str]:
    return {e["value"] for e in client.get("/watchlist").json()}


# -- Intel feed import --------------------------------------------------------


def test_intel_import_stix_bundle_seeds_watchlist_and_flags_runs(client):
    run = make_run(client, sample_name="intel-a.bin")
    _ingest(client, run, [_net(run, "203.0.113.240", ts=1)])

    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.240']"},
            {"type": "indicator", "pattern": "[domain-name:value = 'evil.example.com']"},
            {"type": "indicator", "pattern": "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"},
            {"type": "domain-name", "value": "evil2.example.com"},
        ],
    }
    resp = client.post("/intel/import", json={"source": "stix", "content": json.dumps(bundle)})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["imported"] >= 4
    assert data["source"] == "intel:stix"

    entries = _watchlist(client)
    assert "203.0.113.240" in entries
    assert "evil.example.com" in entries
    assert "evil2.example.com" in entries
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in entries
    assert "203.0.113.240" in data["matched_runs"]
    assert data["matched_runs"]["203.0.113.240"] == [run]


def test_intel_import_text_list_classifies_kinds(client):
    resp = client.post(
        "/intel/import",
        json={"source": "text", "content": "# feed comment\n198.51.100.90\nbad-domain.example.com\n" + "f" * 64},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["imported"] == 3
    assert data["kinds"]["ip"] == 1
    assert data["kinds"]["domain"] == 1
    assert data["kinds"]["hash"] == 1
    entries = _watchlist(client)
    assert "198.51.100.90" in entries
    assert "f" * 64 in entries


def test_intel_import_rejects_empty_and_garbage(client):
    assert client.post("/intel/import", json={"source": "text", "content": ""}).status_code == 422
    assert client.post("/intel/import", json={"source": "text", "content": "### nothing\n"}).status_code == 422
    # Plain text without braces is auto-detected as a text list — a real value.
    assert client.post("/intel/import", json={"content": "not json"}).status_code == 200
    # But a STIX-typed bundle that isn't JSON is rejected.
    assert client.post("/intel/import", json={"source": "stix", "content": "not json"}).status_code == 422
    assert client.post("/intel/import", json={}).status_code == 422


def test_intel_import_upserts_idempotently(client):
    payload = {"source": "text", "content": "203.0.113.241\n"}
    first = client.post("/intel/import", json=payload).json()
    second = client.post("/intel/import", json=payload).json()
    assert first["imported"] == 1 and second["imported"] == 1
    rows = client.get("/watchlist").json()
    assert sum(1 for e in rows if e["value"] == "203.0.113.241") == 1


# -- Metrics ------------------------------------------------------------------


def test_metrics_prometheus_text_format(client):
    resp = client.get("/metrics")
    assert resp.status_code == 200
    text = resp.text
    assert "text/plain" in resp.headers["content-type"]
    assert "# HELP outpost_runs_total" in text
    assert "# TYPE outpost_runs_total gauge" in text
    assert "outpost_alerts_open" in text
    assert "outpost_events_ingested_last_hour" in text
    assert "outpost_demo_mode 0" in text


def test_metrics_counts_are_sane(client):
    run = make_run(client, sample_name="metrics-a.bin")
    _ingest(client, run, [_net(run, "198.51.100.55", ts=1)])
    text = client.get("/metrics").text
    runs = int(next(l for l in text.splitlines() if l.startswith("outpost_runs_total ")).split()[-1])
    events = int(next(l for l in text.splitlines() if l.startswith("outpost_events_total ")).split()[-1])
    assert runs >= 1
    assert events >= 1
