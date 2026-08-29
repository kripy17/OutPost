"""Intel-evidence join on alert surfaces (services/alert_context.py).

Guarantees: findings linked to enriched IOCs ship `intel` rows on every read
surface (queue/query_findings, dashboard feed, run alerts); unlinked findings
ship an empty list; the join never breaks surfaces when the tables are empty.
"""

from __future__ import annotations

import pytest

from app.core.schema import Alert
from app.models import event as event_store
from app.models import run as run_store
from app.services.alert_context import intel_for_finding


@pytest.fixture()
def linked_finding(conn):
    """One run + one alert + one enriched IOC linked via ioc_findings."""
    from datetime import datetime, timezone

    run_id = "inteljoin01"
    run_store.create_run(
        conn, run_id=run_id, sample_name="intel-join.bin",
        platform="windows", session_type="live", source="seed",
    )
    alert_id = event_store.insert_alert(
        conn,
        Alert(
            run_id=run_id,
            rule_id="beaconing",
            rule_name="C2-style beaconing",
            severity="suspicious",
            triggered_at=datetime.now(timezone.utc),
            related_ip="198.51.100.20",
            details="6 connections at ~30s intervals",
        ),
    )
    conn.execute(
        "INSERT INTO iocs (ioc_id, value, type, disposition, reputation,"
        " abuse_score, vt_malicious_count, checked_at, first_seen)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        ("iocinteljoin1", "198.51.100.20", "ip", "enriched", "malicious", 91, 12,
         "2026-08-25T00:00:00+00:00", "2026-08-25T00:00:00+00:00"),
    )
    conn.execute(
        "INSERT INTO ioc_findings (ioc_id, finding_id) VALUES (?, ?)",
        ("iocinteljoin1", alert_id),
    )
    conn.commit()
    yield {"run_id": run_id, "alert_id": alert_id}
    # Session-scoped DB hygiene — child rows first. alert_id/run_id stay in
    # scope from the setup block above.
    for stmt, arg in (
        ("DELETE FROM ioc_findings WHERE finding_id = ?", (alert_id,)),
        ("DELETE FROM alerts WHERE run_id = ?", (run_id,)),
        ("DELETE FROM events WHERE run_id = ?", (run_id,)),
        ("DELETE FROM runs WHERE run_id = ?", (run_id,)),
        ("DELETE FROM iocs WHERE ioc_id = 'iocinteljoin1'", ()),
    ):
        try:
            conn.execute(stmt, arg)
        except Exception:
            pass
    conn.commit()


def test_intel_for_finding_joins_enrichment(conn, linked_finding):
    rows = intel_for_finding(conn, linked_finding["alert_id"])
    assert len(rows) == 1
    ev = rows[0]
    assert ev["value"] == "198.51.100.20"
    assert ev["reputation"] == "malicious"
    assert ev["abuse_score"] == 91
    assert ev["vt_malicious_count"] == 12


def test_unlinked_finding_has_empty_intel(conn):
    from datetime import datetime, timezone

    run_id = "inteljoin02"
    run_store.create_run(
        conn, run_id=run_id, sample_name="bare.bin", platform="windows",
        session_type="live", source="seed",
    )
    alert_id = event_store.insert_alert(
        conn,
        Alert(
            run_id=run_id, rule_id="unusual-port", rule_name="x",
            severity="suspicious",
            triggered_at=datetime.now(timezone.utc), details="d",
        ),
    )
    conn.commit()
    try:
        assert intel_for_finding(conn, alert_id) == []
    finally:
        for stmt in ("DELETE FROM alerts WHERE run_id = ?", "DELETE FROM runs WHERE run_id = ?"):
            conn.execute(stmt, (run_id,))
        conn.commit()


def test_feed_and_queue_and_run_alerts_carry_intel(client, conn, linked_finding):
    feed = client.get("/alerts?limit=50").json()
    row = next(a for a in feed if a["id"] == linked_finding["alert_id"])
    assert row["intel"] and row["intel"][0]["value"] == "198.51.100.20"

    queue = client.get("/alerts/queue?status=all").json()
    qrow = next(a for a in queue["alerts"] if a["id"] == linked_finding["alert_id"])
    assert qrow["intel"][0]["reputation"] == "malicious"

    run_alerts = client.get(f"/runs/{linked_finding['run_id']}/alerts").json()
    assert any(a.get("intel") for a in run_alerts)
