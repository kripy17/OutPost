"""POST /ingest/batch, POST /runs, POST /runs/{id}/complete — Task 3 acceptance."""

from .conftest import make_run


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_platform_detects_host_os(client):
    """GET /platform — the webapp's auto-OS source (no manual picker)."""
    resp = client.get("/platform")
    assert resp.status_code == 200
    body = resp.json()
    assert body["os"] in {"windows", "linux", "macos"}
    assert body["collector"] in {"sysmon", "auditd", "unsupported"}
    assert body["name"] and body["release"] and body["machine"]
    # The backend host's identity — the Overview compares it to the fleet to
    # answer "is THIS host monitored?" (auto-OS front door).
    assert body["hostname"]


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


def test_active_live_run_claims_newest_open_session(client):
    """GET /runs/active-live — the run a host collector should stream into."""
    # Nothing open yet → 404
    assert client.get("/runs/active-live").status_code == 404

    live_a = make_run(client, session_type="live")
    live_b = make_run(client, session_type="live")
    make_run(client, session_type="analysis")  # must never be claimed

    hit = client.get("/runs/active-live").json()
    assert hit["run_id"] == live_b  # newest open live session wins
    assert hit["session_type"] == "live"
    assert hit["completed_at"] is None

    # Completing the newest one falls back to the next open live session.
    client.post(f"/runs/{live_b}/complete")
    hit2 = client.get("/runs/active-live").json()
    assert hit2["run_id"] == live_a

    client.post(f"/runs/{live_a}/complete")
    assert client.get("/runs/active-live").status_code == 404


def test_ingest_dedupes_within_batch_and_across_retries(client):
    """A collector retry (or a duplicated feed line) stores each event once.

    If duplicates were stored, beaconing/rename-burst windows would count the
    same connection/write twice and could false-fire. The response's
    `accepted` count must reflect only genuinely-new events.
    """
    from datetime import datetime, timedelta, timezone

    run_id = make_run(client)
    base = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)

    def _conn(i: int) -> dict:
        return {
            "run_id": run_id, "platform": "windows", "event_type": "network_connection",
            "timestamp": (base + timedelta(seconds=10 * i)).isoformat(),
            "pid": 900, "dest_ip": "203.0.113.44", "dest_port": 443, "protocol": "TCP",
        }

    # Within-batch duplicate: [A, A, B] → only 2 unique events stored.
    resp = client.post("/ingest/batch", json=[_conn(0), _conn(0), _conn(1)])
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 2

    # A full retry of the same events must store nothing new (and must not
    # bump the event count that beaconing windows read from).
    resp = client.post("/ingest/batch", json=[_conn(0), _conn(1)])
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 0

    # The run still sees exactly the two unique connections.
    detail = client.get(f"/runs/{run_id}").json()
    assert detail["run"]["unique_ips"] == 1
    assert len(detail["timeline"]) == 2


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
