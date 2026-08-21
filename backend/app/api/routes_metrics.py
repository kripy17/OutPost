"""GET /metrics — Prometheus text format, so the tool watches itself.

The SOC console expects the product to expose its own health the same way it
monitors hosts: ingest rate, alerts/hour, active sessions, queue depth, and
the demo-mode flag. Text format 0.0.4, no dependencies (hand-rolled counters
are more honest than pulling in a prometheus client for five gauges).

Unscraped — this is a monitoring endpoint, like /health, not a data surface.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Response

from ..core.db import db_session

router = APIRouter(tags=["metrics"])


@router.get("/metrics", include_in_schema=False)
def metrics() -> Response:
    now = datetime.now(timezone.utc)
    hour_ago = (now - timedelta(hours=1)).isoformat()
    day_ago = (now - timedelta(days=1)).isoformat()

    from ..models.run import SYNTHETIC_SOURCES

    with db_session() as conn:
        runs_total = conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()["n"] or 0
        events_total = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"] or 0
        alerts_total = conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"] or 0
        marks = ",".join("?" for _ in SYNTHETIC_SOURCES)
        runs_real = conn.execute(
            f"SELECT COUNT(*) AS n FROM runs WHERE source NOT IN ({marks})", SYNTHETIC_SOURCES
        ).fetchone()["n"] or 0
        events_real = conn.execute(
            f"SELECT COUNT(*) AS n FROM events WHERE run_id IN (SELECT run_id FROM runs WHERE source NOT IN ({marks}))",
            SYNTHETIC_SOURCES,
        ).fetchone()["n"] or 0
        alerts_real = conn.execute(
            f"SELECT COUNT(*) AS n FROM alerts WHERE run_id IN (SELECT run_id FROM runs WHERE source NOT IN ({marks}))",
            SYNTHETIC_SOURCES,
        ).fetchone()["n"] or 0
        events_hour = conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE timestamp >= ?", (hour_ago,)
        ).fetchone()["n"] or 0
        alerts_hour = conn.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE triggered_at >= ?", (hour_ago,)
        ).fetchone()["n"] or 0
        alerts_open = conn.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE status = 'open'"
        ).fetchone()["n"] or 0
        live_sessions = conn.execute(
            "SELECT COUNT(*) AS n FROM runs WHERE session_type = 'live' AND completed_at IS NULL"
        ).fetchone()["n"] or 0
        active_hosts = conn.execute(
            "SELECT COUNT(DISTINCT host_id) AS n FROM events WHERE timestamp >= ?", (day_ago,)
        ).fetchone()["n"] or 0
        demo = conn.execute("SELECT value FROM settings WHERE key = 'demo_mode'").fetchone()
        samples_total = conn.execute("SELECT COUNT(*) AS n FROM samples").fetchone()["n"] or 0

    def g(name: str, help_: str, value, labels: str = "") -> str:
        out = f"# HELP outpost_{name} {help_}\n# TYPE outpost_{name} gauge\n"
        if labels:
            out += f"outpost_{name}{{{labels}}} {value}\n"
        else:
            out += f"outpost_{name} {value}\n"
        return out

    body = "".join([
        g("runs_total", "Total runs recorded.", runs_total),
        g("runs_real", "Real telemetry runs recorded (excluding demo/synthetic).", runs_real),
        g("events_total", "Total events ingested.", events_total),
        g("events_real", "Real telemetry events ingested.", events_real),
        g("alerts_total", "Total alerts fired.", alerts_total),
        g("alerts_real", "Real telemetry alerts fired.", alerts_real),
        g("events_ingested_last_hour", "Events ingested in the last hour.", events_hour),
        g("alerts_fired_last_hour", "Alerts fired in the last hour.", alerts_hour),
        g("alerts_open", "Alerts still in the open triage state.", alerts_open),
        g("live_sessions", "Live sessions currently running.", live_sessions),
        g("active_hosts_last_24h", "Distinct hosts that shipped events in the last 24h.", active_hosts),
        g("samples_total", "Samples in the vault.", samples_total),
        g("demo_mode", "Whether seeded demo data is present and labeled.", 1 if demo and demo["value"] == "1" else 0),
    ])
    return Response(content=body, media_type="text/plain; version=0.0.4")
