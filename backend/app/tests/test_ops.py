"""Tier-1 ops gaps — audit trail, retention & backup, and the FP feedback loop.

- Alert triage transitions and logins land in /audit with the acting identity.
- Retention set + prune deletes old runs (cascading) and nothing else.
- Backup streams a valid SQLite file; restore swaps it back (with a safety
  copy) and re-initializes.
- Marking an alert as a false positive resolves it, counts per rule, and
  returns actionable threshold + suppression suggestions.
"""

import importlib
from datetime import datetime, timedelta, timezone

import pytest

from .conftest import make_run


def _ts(dt: datetime) -> str:
    return dt.isoformat()


def _conn(run_id: str, ip: str, ts: datetime, pid: int = 1) -> dict:
    return {
        "run_id": run_id,
        "platform": "windows",
        "event_type": "network_connection",
        "timestamp": _ts(ts),
        "pid": pid,
        "dest_ip": ip,
        "dest_port": 4444,
    }


# -- Audit trail ---------------------------------------------------------------


def test_alert_triage_lands_in_audit(client):
    run_id = make_run(client, sample_name="audit.bin")
    client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.88", datetime.now(timezone.utc))])
    alert_id = client.get(f"/runs/{run_id}/alerts").json()[0]["id"]

    client.patch(f"/alerts/{alert_id}", json={"status": "acknowledged", "comment": "dev box"})
    ev = client.get("/audit").json()["events"]
    hit = next(e for e in ev if e["action"] == "alert.status" and e["target_id"] == str(alert_id))
    assert hit["actor"] == "local"  # zero-config default
    assert "open → acknowledged" in hit["detail"]
    assert "dev box" in hit["detail"]


@pytest.fixture()
def _auth_env(monkeypatch):
    """Enable a role password so login actually runs (zero-config default
    404s before the limiter/audit code is reached)."""
    monkeypatch.setenv("OUTPOST_ADMIN_PASSWORD", "admin-secret")
    from ..core import auth as auth_mod

    importlib.reload(auth_mod)
    auth_mod.login_limiter.reset()
    yield
    monkeypatch.delenv("OUTPOST_ADMIN_PASSWORD", raising=False)


def test_failed_login_lands_in_audit(_auth_env):
    from fastapi.testclient import TestClient

    from ..main import app

    c = TestClient(app)
    c.post("/auth/login", json={"password": "wrong"})
    # /audit is gated once auth is on — sign in to read the trail.
    token = c.post("/auth/login", json={"password": "admin-secret"}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    ev = c.get("/audit", headers=h).json()["events"]
    hit = next(e for e in ev if e["action"] == "auth.login.failed")
    assert hit["actor"] == "testclient"
    assert hit["target_id"] == "testclient"


def test_audit_action_filter(client):
    run_id = make_run(client, sample_name="audit-f.bin")
    client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.88", datetime.now(timezone.utc))])
    alert_id = client.get(f"/runs/{run_id}/alerts").json()[0]["id"]
    client.patch(f"/alerts/{alert_id}", json={"status": "resolved"})
    only = client.get("/audit", params={"action": "alert.status"}).json()["events"]
    assert only and all(e["action"] == "alert.status" for e in only)


# -- Channel backfill -----------------------------------------------------------


def test_backfill_channels_endpoint_stamps_legacy_events(client):
    """POST /admin/backfill-channels runs the startup migration on demand:
    legacy live-run events with a real host get their channel inferred
    (linux→auditd, windows→sysmon), and a second call returns 0 — the
    idempotent no-op that doubles as a health check. Audited."""
    lin = make_run(client, sample_name="bfc-lin.bin", platform="linux", session_type="live")
    win = make_run(client, sample_name="bfc-win.bin", platform="windows", session_type="live")

    now = datetime.now(timezone.utc)
    for run_id, platform, name in ((lin, "linux", "bfc-lin.exe"), (win, "windows", "bfc-win.exe")):
        client.post(
            "/ingest/batch",
            json=[{
                "run_id": run_id, "platform": platform, "event_type": "process_create",
                "timestamp": _ts(now), "pid": 1, "host_id": "bfc-host", "process_name": name,
            }],
        )

    # Pre-backfill: neither event carries a channel.
    assert client.get("/events", params={"source": "auditd", "q": "bfc-lin.exe"}).json()["total"] == 0
    assert client.get("/events", params={"source": "sysmon", "q": "bfc-win.exe"}).json()["total"] == 0

    out = client.post("/admin/backfill-channels").json()
    # Only this test's two events match the backfill scope in the shared DB
    # (NULL log_source + live run + real host) — the file convention's
    # per-scope assertion.
    assert out["updated"] == 2

    assert client.get("/events", params={"source": "auditd", "q": "bfc-lin.exe"}).json()["total"] == 1
    assert client.get("/events", params={"source": "sysmon", "q": "bfc-win.exe"}).json()["total"] == 1

    # Idempotent — nothing left to stamp.
    assert client.post("/admin/backfill-channels").json()["updated"] == 0

    # The mutation landed in the audit trail.
    ev = client.get("/audit").json()["events"]
    assert any(e["action"] == "admin.backfill-channels" for e in ev)

    # Close the live runs so /runs/active-live's 404 contract holds.
    client.post(f"/runs/{lin}/complete")
    client.post(f"/runs/{win}/complete")


# -- Retention & backup --------------------------------------------------------


def test_retention_set_and_prune(client, conn):
    old = make_run(client, sample_name="old-run.bin")
    client.post("/ingest/batch", json=[_conn(old, "203.0.113.250", datetime.now(timezone.utc))])
    old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    conn.execute("UPDATE runs SET started_at = ? WHERE run_id = ?", (old_ts, old))
    conn.commit()
    fresh = make_run(client, sample_name="fresh-run.bin")

    assert client.post("/admin/retention", json={"retention_days": 7}).status_code == 200
    assert client.get("/admin/retention").json()["retention_days"] == 7

    out = client.post("/admin/prune", json={}).json()
    assert out["deleted_runs"] >= 1  # the 10-day-old run (others may age out too)

    remaining = [r["run_id"] for r in client.get("/runs", params={"include_synthetic": "true"}).json()]
    assert old not in remaining and fresh in remaining
    # Cascading: the old run's events are gone too (unique IP, no cross-test noise).
    assert client.get("/events", params={"q": "203.0.113.250"}).json()["total"] == 0
    # Audit row for the prune.
    assert any(e["action"] == "retention.prune" for e in client.get("/audit").json()["events"])


def test_prune_refuses_zero_retention(client):
    make_run(client, sample_name="keep.bin")
    out = client.post("/admin/prune", json={"days": 0})
    assert out.status_code == 422  # retention is 0 (keep forever)


def test_backup_and_restore_roundtrip(client):
    run_id = make_run(client, sample_name="backup.bin")
    client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.9", datetime.now(timezone.utc))])

    backup = client.get("/admin/backup")
    assert backup.status_code == 200
    assert backup.content[:16] == b"SQLite format 3\x00"

    # Mutate the live store, then restore the backup over it.
    make_run(client, sample_name="after-backup.bin")
    assert any(r["sample_name"] == "after-backup.bin" for r in client.get("/runs", params={"include_synthetic": "true"}).json())

    resp = client.post("/admin/restore", content=backup.content, headers={"Content-Type": "application/octet-stream"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["restored"] is True and body["safety_copy"]

    names = [r["sample_name"] for r in client.get("/runs", params={"include_synthetic": "true"}).json()]
    assert "backup.bin" in names and "after-backup.bin" not in names
    assert any(e["action"] == "restore.apply" for e in client.get("/audit").json()["events"])


def test_restore_rejects_non_sqlite(client):
    resp = client.post("/admin/restore", content=b"not a database at all", headers={"Content-Type": "application/octet-stream"})
    assert resp.status_code == 422


# -- False-positive feedback loop ----------------------------------------------


def test_mark_fp_resolves_counts_and_suggests(client):
    # Beaconing fires BEACON_MIN_CONNECTIONS — a rule WITH an int tunable, so
    # the FP loop can suggest a concrete threshold nudge.
    run_id = make_run(client, sample_name="fp.bin")
    now = datetime.now(timezone.utc)
    for i in range(6):
        client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.88", now + timedelta(seconds=2 * i), pid=7)])
    alerts = client.get(f"/runs/{run_id}/alerts").json()
    alert_id = next(a["id"] for a in alerts if a["rule_id"] == "beaconing")

    out = client.post(f"/alerts/{alert_id}/false-positive", json={"comment": "our own scanner"}).json()
    assert out["fp_count"] == 1
    assert out["rule_id"] == "beaconing"
    kinds = {s["kind"] for s in out["suggestions"]}
    assert "suppress" in kinds  # every rule gets a per-run suppression suggestion
    assert "threshold" in kinds  # beaconing has BEACON_MIN_CONNECTIONS
    nudge = next(s for s in out["suggestions"] if s["kind"] == "threshold")
    assert nudge["param"] == "BEACON_MIN_CONNECTIONS"
    assert nudge["suggested"] > nudge["current"]

    # The alert is resolved with an FP comment.
    updated = client.get(f"/runs/{run_id}/alerts").json()
    fp_alert = next(a for a in updated if a["id"] == alert_id)
    assert fp_alert["status"] == "resolved"
    assert "FP" in (fp_alert["status_comment"] or "")

    # Two more FPs bump the counter.
    client.post(f"/alerts/{alert_id}/false-positive", json={})
    out2 = client.post(f"/alerts/{alert_id}/false-positive", json={}).json()
    assert out2["fp_count"] == 3

    # Audit trail records the marks.
    ev = client.get("/audit", params={"action": "alert.false-positive"}).json()["events"]
    assert any("FP#" in e["detail"] for e in ev)


def test_mark_fp_unknown_alert_404(client):
    assert client.post("/alerts/999999/false-positive", json={}).status_code == 404


# -- Rule FP surface (Rules page tuning panel) ---------------------------------


def _beaconing_run(client) -> tuple[str, int]:
    """A run that fires beaconing and returns (run_id, alert_id)."""
    run_id = make_run(client, sample_name="fp-rules.bin")
    now = datetime.now(timezone.utc)
    for i in range(6):
        client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.88", now + timedelta(seconds=2 * i), pid=7)])
    alerts = client.get(f"/runs/{run_id}/alerts").json()
    alert_id = next(a["id"] for a in alerts if a["rule_id"] == "beaconing")
    return run_id, alert_id


def _fp_count(client, rule_id: str) -> int:
    data = client.get("/rules/fp").json()
    return next(r["count"] for r in data["rules"] if r["rule_id"] == rule_id)


def test_rule_fp_surface_and_threshold_suggestion(client):
    # The shared DB may already hold beaconing FPs from other tests, so the
    # assertions are relative: pin the threshold above the current count first.
    _, alert_id = _beaconing_run(client)
    client.post(f"/alerts/{alert_id}/false-positive", json={"comment": "noise"})
    before = _fp_count(client, "beaconing")
    assert before >= 1

    client.put("/rules/fp-threshold", json={"threshold": 100})
    data = client.get("/rules/fp").json()
    assert data["threshold"] == 100
    row = next(r for r in data["rules"] if r["rule_id"] == "beaconing")
    assert row["over_threshold"] is False and row["suggestion"] is None

    # Cross the threshold → a ready-to-apply raise for the int tunable appears.
    client.put("/rules/fp-threshold", json={"threshold": before})
    data = client.get("/rules/fp").json()
    row = next(r for r in data["rules"] if r["rule_id"] == "beaconing")
    assert row["over_threshold"] is True
    assert row["suggestion"]["param"] == "BEACON_MIN_CONNECTIONS"
    assert row["suggestion"]["suggested"] > row["suggestion"]["current"]

    client.delete("/rules/fp-threshold")  # back to the default for other tests


def test_fp_threshold_tunable_audited_and_validated(client):
    assert client.put("/rules/fp-threshold", json={"threshold": 0}).status_code == 422
    assert client.put("/rules/fp-threshold", json={"threshold": 5}).status_code == 200
    assert client.get("/rules/fp").json()["threshold"] == 5
    assert any(e["action"] == "rules.fp-threshold" for e in client.get("/audit").json()["events"])
    assert client.delete("/rules/fp-threshold").status_code == 204
    assert client.get("/rules/fp").json()["threshold"] == 3  # default restored


# -- Auto-prune scheduler ------------------------------------------------------


def _backdate_run(client, conn, sample: str, days_old: int = 10) -> str:
    run_id = make_run(client, sample_name=sample)
    ts = (datetime.now(timezone.utc) - timedelta(days=days_old)).isoformat()
    conn.execute("UPDATE runs SET started_at = ? WHERE run_id = ?", (ts, run_id))
    conn.commit()
    return run_id


def test_auto_prune_runs_on_schedule(client, conn):
    from ..api.routes_admin import _maybe_auto_prune

    old = _backdate_run(client, conn, "auto-old.bin")
    fresh = make_run(client, sample_name="auto-fresh.bin")

    out = client.post("/admin/retention", json={"retention_days": 7, "auto_prune": "daily"}).json()
    assert out["auto_prune"] == "daily"
    status = client.get("/admin/retention").json()
    assert status["auto_prune"] == "daily" and status["auto_prune_enabled"] is True

    result = _maybe_auto_prune()
    assert result is not None and result["deleted_runs"] >= 1
    remaining = [r["run_id"] for r in client.get("/runs", params={"include_synthetic": "true"}).json()]
    assert old not in remaining and fresh in remaining

    # Audited with the system actor; last-run + next-run bookkeeping updated.
    ev = client.get("/audit").json()["events"]
    assert any(e["action"] == "retention.prune" and e["actor"] == "system" for e in ev)
    status = client.get("/admin/retention").json()
    assert status["last_prune_at"] is not None
    assert status["next_prune_in_seconds"] is not None

    # A second tick inside the daily interval is a no-op.
    assert _maybe_auto_prune() is None

    # Back to manual mode so other tests are unaffected.
    client.post("/admin/retention", json={"retention_days": 0, "auto_prune": "off"})


def test_auto_prune_off_never_prunes(client, conn):
    from ..api.routes_admin import _maybe_auto_prune

    old = _backdate_run(client, conn, "auto-off.bin")
    client.post("/admin/retention", json={"retention_days": 7, "auto_prune": "off"})
    assert _maybe_auto_prune() is None
    remaining = [r["run_id"] for r in client.get("/runs", params={"include_synthetic": "true"}).json()]
    assert old in remaining


def test_history_hides_soak_runs_by_default(client):
    """Soak-named collector baselines (soak-<platform>-<host>-<date>) are
    hidden from the default archive — the History page and CLI only see them
    with include_soak=true. Critical non-regression: a REAL agent session
    (agent-<host>-<date>, the same naming the soak used to fake) is never
    caught by the soak filter."""
    soak = make_run(client, sample_name="soak-linux-arch-2026-08-13", source="live")
    real_agent = make_run(client, sample_name="agent-arch-2026-08-13", source="live")
    normal = make_run(client, sample_name="normal.bin", source="live")

    default = {r["run_id"]: r["sample_name"] for r in client.get("/runs").json()}
    assert soak not in default
    assert default[real_agent] == "agent-arch-2026-08-13"  # never hidden
    assert default[normal] == "normal.bin"

    with_soak = {r["run_id"]: r["sample_name"] for r in client.get("/runs", params={"include_soak": "true"}).json()}
    assert with_soak[soak] == "soak-linux-arch-2026-08-13"

    # The q + host filters keep the exclusion too.
    q_hits = client.get("/runs", params={"q": "soak-linux", "include_synthetic": "true"}).json()
    assert q_hits == []
    q_hits_on = client.get("/runs", params={"q": "soak-linux", "include_soak": "true", "include_synthetic": "true"}).json()
    assert [r["run_id"] for r in q_hits_on] == [soak]


def test_auto_prune_requires_retention_window(client):
    from ..api.routes_admin import _maybe_auto_prune

    client.post("/admin/retention", json={"retention_days": 0, "auto_prune": "daily"})
    assert _maybe_auto_prune() is None  # keep-forever → nothing to prune
    assert client.post("/admin/retention", json={"retention_days": 7, "auto_prune": "weekly"}).status_code == 422
