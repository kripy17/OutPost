"""Tests for OutPost P3.5 Operational Reality & Provenance Enforcement."""

from datetime import datetime, timezone

from app.core.db import db_session
from app.core.schema import Alert
from app.models import event as event_store

from .conftest import make_run


def test_live_views_strictly_exclude_synthetic_and_simulation(client):
    """Ensure that all live queries (include_synthetic=False) exclude simulation,
    seed, webapp-demo, monitor, and sandbox:demo records by default.
    """
    run_live = make_run(client, sample_name="host-agent.bin", platform="linux", session_type="live", source="live")
    client.post(
        "/ingest/batch",
        json=[{
            "run_id": run_live,
            "platform": "linux",
            "event_type": "process_create",
            "timestamp": "2026-08-23T10:00:00Z",
            "pid": 1001,
            "ppid": 1,
            "process_name": "bash-prov",
            "command_line": "/bin/bash",
            "host_id": "prod-host-prov",
        }],
    )

    run_sim = make_run(client, sample_name="c2-beacon-exfil.bin", platform="linux", session_type="analysis", source="simulation")
    client.post(
        "/ingest/batch",
        json=[{
            "run_id": run_sim,
            "platform": "linux",
            "event_type": "network_connection",
            "timestamp": "2026-08-23T10:05:00Z",
            "pid": 2002,
            "dest_ip": "203.0.113.88",
            "dest_port": 443,
            "protocol": "tcp",
            "host_id": "lab-host",
        }],
    )

    # 1. GET /events default (include_synthetic=False) must only show live events
    r_live = client.get("/events")
    assert r_live.status_code == 200
    data = r_live.json()
    run_ids = [e["run_id"] for e in data["events"]]
    assert run_live in run_ids
    assert run_sim not in run_ids

    # 2. GET /events with include_synthetic=true shows simulation as well
    r_all = client.get("/events?include_synthetic=true")
    assert r_all.status_code == 200
    all_run_ids = [e["run_id"] for e in r_all.json()["events"]]
    assert run_sim in all_run_ids

    # 3. GET /runs default excludes simulation
    r_runs = client.get("/runs?include_synthetic=false")
    assert r_runs.status_code == 200
    runs = r_runs.json()
    assert all(r["source"] not in ("simulation", "seed", "webapp-demo", "monitor", "sandbox:demo") for r in runs)
    assert any(r["run_id"] == run_live for r in runs)


def test_process_summary_returns_comprehensive_context(client):
    """Verify that /events/process-summary extracts PPID, children, network sockets,
    file writes, and linked findings directly from persisted events."""
    run_ctx = make_run(client, sample_name="test-app.bin", platform="linux", session_type="live", source="live")
    with db_session() as conn:
        # Parent process create
        event_store.insert_event(
            conn,
            {
                "run_id": run_ctx,
                "platform": "linux",
                "event_type": "process_create",
                "timestamp": "2026-08-23T10:10:00Z",
                "pid": 5500,
                "ppid": 100,
                "process_name": "python-worker",
                "command_line": "python server.py",
                "host_id": "prod-host-01",
            },
        )
        # Child process spawned
        event_store.insert_event(
            conn,
            {
                "run_id": run_ctx,
                "platform": "linux",
                "event_type": "process_create",
                "timestamp": "2026-08-23T10:10:02Z",
                "pid": 5501,
                "ppid": 5500,
                "process_name": "curl",
                "command_line": "curl -s http://198.51.100.2",
                "host_id": "prod-host-01",
            },
        )
        # Network socket opened by PID 5500
        event_store.insert_event(
            conn,
            {
                "run_id": run_ctx,
                "platform": "linux",
                "event_type": "network_connection",
                "timestamp": "2026-08-23T10:10:03Z",
                "pid": 5500,
                "dest_ip": "198.51.100.2",
                "dest_port": 80,
                "protocol": "tcp",
                "host_id": "prod-host-01",
            },
        )
        # File write by PID 5500
        event_store.insert_event(
            conn,
            {
                "run_id": run_ctx,
                "platform": "linux",
                "event_type": "file_write",
                "timestamp": "2026-08-23T10:10:04Z",
                "pid": 5500,
                "file_path": "/tmp/payload.sh",
                "host_id": "prod-host-01",
            },
        )
        # Alert associated with PID 5500
        event_store.insert_alert(
            conn,
            Alert(
                run_id=run_ctx,
                rule_id="curl-pipe-bash",
                rule_name="Suspicious Script Download",
                severity="suspicious",
                triggered_at=datetime.now(timezone.utc),
                related_pid=5500,
                details="Process spawned curl to remote host",
            ),
        )

    res = client.get("/events/process-summary?pid=5500")
    assert res.status_code == 200
    ctx = res.json()
    assert ctx["pid"] == 5500
    assert ctx["ppid"] == 100
    assert ctx["process_name"] == "python-worker"
    assert ctx["command_line"] == "python server.py"
    assert len(ctx["children"]) == 1
    assert ctx["children"][0]["pid"] == 5501
    assert len(ctx["network_connections"]) == 1
    assert ctx["network_connections"][0]["dest_ip"] == "198.51.100.2"
    assert ctx["files_written"] == ["/tmp/payload.sh"]
    assert ctx["alert_count"] == 1
    assert ctx["findings"][0]["rule_id"] == "curl-pipe-bash"


def test_network_and_file_summary_extract_context(client):
    """Verify that /events/network-summary and /events/file-summary extract
    accurate persisted context: hosts, processes, ports, and correlated findings.
    """
    run_net = make_run(client, sample_name="network-worker.bin", platform="linux", session_type="live", source="live")
    with db_session() as conn:
        event_store.insert_event(
            conn,
            {
                "run_id": run_net,
                "platform": "linux",
                "event_type": "network_connection",
                "timestamp": "2026-08-23T11:00:00Z",
                "pid": 7700,
                "process_name": "beacon-client",
                "command_line": "./beacon-client --c2 198.51.100.222",
                "dest_ip": "198.51.100.222",
                "dest_port": 8443,
                "protocol": "tcp",
                "host_id": "host-alpha",
            },
        )
        event_store.insert_event(
            conn,
            {
                "run_id": run_net,
                "platform": "linux",
                "event_type": "file_write",
                "timestamp": "2026-08-23T11:00:05Z",
                "pid": 7700,
                "process_name": "beacon-client",
                "command_line": "./beacon-client --c2 198.51.100.222",
                "file_path": "/var/log/stealth-unique.log",
                "host_id": "host-alpha",
            },
        )

    # 1. Network summary
    r_net = client.get("/events/network-summary?ip=198.51.100.222")
    assert r_net.status_code == 200
    net_data = r_net.json()
    assert net_data["dest_ip"] == "198.51.100.222"
    assert net_data["event_count"] >= 1
    assert "host-alpha" in net_data["hosts"]
    assert any(p["pid"] == 7700 for p in net_data["processes"])
    assert any(p["dest_port"] == 8443 for p in net_data["ports"])

    # 2. File summary
    r_file = client.get("/events/file-summary?path=/var/log/stealth-unique.log")
    assert r_file.status_code == 200
    file_data = r_file.json()
    assert file_data["file_path"] == "/var/log/stealth-unique.log"
    assert file_data["event_count"] >= 1
    assert "host-alpha" in file_data["hosts"]
    assert any(p["pid"] == 7700 for p in file_data["processes"])
