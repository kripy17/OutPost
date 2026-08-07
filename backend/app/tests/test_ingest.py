"""POST /ingest/batch, POST /runs, POST /runs/{id}/complete — Task 3 acceptance."""

from .conftest import make_run


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_create_run_and_ingest_batch(client):
    run_id = make_run(client)
    events = [
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T10:00:00Z",
            "pid": 100,
            "ppid": 1,
            "process_name": "sample.exe",
            "command_line": r"C:\temp\sample.exe",
        },
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "network_connection",
            "timestamp": "2026-08-01T10:00:02Z",
            "pid": 100,
            "dest_ip": "8.8.8.8",
            "dest_port": 443,
            "protocol": "TCP",
        },
    ]
    resp = client.post("/ingest/batch", json=events)
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 2

    # Events are in the DB (query via the runs detail endpoint).
    detail = client.get(f"/runs/{run_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["run"]["process_count"] == 1
    assert body["run"]["unique_ips"] == 1
    assert len(body["timeline"]) == 2


def test_ingest_unknown_run_rejected(client):
    events = [
        {
            "run_id": "does-not-exist",
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T10:00:00Z",
            "pid": 1,
        }
    ]
    resp = client.post("/ingest/batch", json=events)
    assert resp.status_code == 404


def test_complete_run_sets_completed_at(client):
    run_id = make_run(client)
    resp = client.post(f"/runs/{run_id}/complete")
    assert resp.status_code == 200
    assert resp.json()["completed_at"] is not None
    assert resp.json()["highest_severity"] is None


def test_ingest_validation_rejects_bad_event(client):
    run_id = make_run(client)
    bad = [
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "not-a-real-type",
            "timestamp": "not-a-date",
        }
    ]
    resp = client.post("/ingest/batch", json=bad)
    assert resp.status_code == 422
