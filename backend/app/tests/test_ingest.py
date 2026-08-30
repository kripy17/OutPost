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


def test_runs_list_hides_synthetic_by_default(client, conn):
    """GET /runs — the archive reads as real telemetry first.

    Synthetic provenance (seed / webapp-demo / legacy monitor / sandbox:demo)
    is hidden unless `include_synthetic=true`; live host sessions, CLI runs,
    and real sandbox providers stay visible either way.
    """
    real = make_run(client, sample_name="realish.bin", source="live")
    cli_run = make_run(client, sample_name="clirun.bin", source="cli")
    prov = make_run(client, sample_name="prov.bin", source="sandbox:anyrun")
    seed = make_run(client, sample_name="seeded.bin", source="seed")
    demo = make_run(client, sample_name="demoed.bin", source="webapp-demo")
    legacy = make_run(client, sample_name="oldmon.bin", source="monitor")
    sand = make_run(client, sample_name="sand.bin", source="sandbox:demo")
    try:
        def names(rows: list[dict]) -> set[str]:
            return {r["sample_name"] for r in rows}

        hidden = names(client.get("/runs").json())
        assert {"realish.bin", "clirun.bin", "prov.bin"} <= hidden
        for s in ("seeded.bin", "demoed.bin", "oldmon.bin", "sand.bin"):
            assert s not in hidden, f"{s} should be hidden by default"

        shown = names(client.get("/runs?include_synthetic=true").json())
        for s in ("realish.bin", "clirun.bin", "prov.bin", "seeded.bin", "demoed.bin", "oldmon.bin", "sand.bin"):
            assert s in shown
    finally:
        for rid in (real, cli_run, prov, seed, demo, legacy, sand):
            conn.execute("DELETE FROM runs WHERE run_id = ?", (rid,))
        conn.commit()


def test_ingest_batch_gzip_compressed(client):
    import gzip
    import json
    from datetime import datetime, timezone

    run_id = make_run(client)
    now_iso = datetime.now(timezone.utc).isoformat()
    events = [
        {
            "run_id": run_id,
            "platform": "linux",
            "event_type": "process_create",
            "timestamp": now_iso,
            "pid": 2048,
            "ppid": 1,
            "process_name": "gzip_test_proc",
            "command_line": "/usr/bin/gzip_test_proc --daemon",
        }
    ]
    raw = json.dumps(events).encode("utf-8")
    compressed = gzip.compress(raw)

    resp = client.post(
        "/ingest/batch",
        content=compressed,
        headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
    )
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 1


def test_ingest_batch_deflate_compressed(client):
    import zlib
    import json
    from datetime import datetime, timezone

    run_id = make_run(client)
    now_iso = datetime.now(timezone.utc).isoformat()
    events = [
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "network_connection",
            "timestamp": now_iso,
            "pid": 4096,
            "dest_ip": "198.51.100.77",
            "dest_port": 8443,
            "protocol": "tcp",
        }
    ]
    raw = json.dumps(events).encode("utf-8")
    compressed = zlib.compress(raw)

    resp = client.post(
        "/ingest/batch",
        content=compressed,
        headers={"Content-Encoding": "deflate", "Content-Type": "application/json"},
    )
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 1

