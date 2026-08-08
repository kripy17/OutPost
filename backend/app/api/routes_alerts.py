"""Alert surfaces.

- GET /runs/{run_id}/alerts — detection hits for one run (polled by the CLI's
  live stream and the webapp's alert banner).
- GET /alerts               — newest hits across ALL runs (dashboard feed).
- GET /alerts/export        — CSV of recent alerts across all runs.
- PATCH /alerts/{id}        — triage: open → acknowledged → resolved, with an
                              optional analyst comment (analyst workflow).
- POST /alerts/bulk         — same triage applied to many alerts at once
                              (bulk ack / bulk resolve from the run detail).
"""

import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel

from ..core.db import db_session
from ..core.schema import Alert, AlertStatusIn
from ..models import event as event_store
from ..models.event import _parse_related_pids
from ..models import run as run_store

router = APIRouter(tags=["alerts"])


@router.get("/runs/{run_id}/alerts", response_model=list[Alert])
def get_alerts(run_id: str) -> list[Alert]:
    with db_session() as conn:
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        rows = event_store.list_alerts_for_run(conn, run_id)
    return [Alert(**row) for row in rows]


@router.patch("/alerts/{alert_id}", response_model=Alert)
def update_alert_status(alert_id: int, body: AlertStatusIn) -> Alert:
    """Move one alert through the triage lifecycle. `comment` is optional and
    recorded at the transition; an empty comment is stored as NULL."""
    comment = (body.comment or "").strip() or None
    with db_session() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Unknown alert id: {alert_id}")
        conn.execute(
            "UPDATE alerts SET status = ?, status_comment = ?, status_at = ? WHERE id = ?",
            (body.status, comment, datetime.now(timezone.utc).isoformat(), alert_id),
        )
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    d = dict(row)
    _parse_related_pids(d)
    return Alert(**d)


@router.get("/alerts/export", response_model=None)
def export_alerts(limit: int = 5000):
    """CSV of the newest alerts across every run (with the owning sample name)
    — for spreadsheets / sharing. `limit` defaults to the bulk export bound.
    """
    alerts = list_recent_alerts(limit=limit)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "timestamp", "run_id", "sample_name", "rule_id", "rule_name", "severity", "status", "related_pid", "related_ip", "details"])
    for a in alerts:
        writer.writerow([
            a["id"], a["triggered_at"], a["run_id"], a["sample_name"],
            a["rule_id"], a["rule_name"], a["severity"], a["status"],
            a["related_pid"], a["related_ip"], a["details"],
        ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="outpost-alerts.csv"'},
    )


class BulkStatusIn(BaseModel):
    ids: list[int]
    status: str
    comment: str = ""


@router.post("/alerts/bulk", response_model=None)
def bulk_update_alert_status(body: BulkStatusIn) -> dict:
    """Apply one triage transition to many alerts (bulk ack / bulk resolve).

    Only alerts that actually exist are updated; the response reports the
    count. An invalid status (not open/acknowledged/resolved) is rejected
    up front — the same constraint PATCH enforces per row.
    """
    if body.status not in ("open", "acknowledged", "resolved"):
        raise HTTPException(status_code=422, detail="status must be open, acknowledged, or resolved")
    if not body.ids:
        return {"updated": 0}
    comment = (body.comment or "").strip() or None
    now = datetime.now(timezone.utc).isoformat()
    placeholders = ",".join("?" * len(body.ids))
    with db_session() as conn:
        conn.execute(
            f"UPDATE alerts SET status = ?, status_comment = ?, status_at = ? WHERE id IN ({placeholders})",
            [body.status, comment, now, *body.ids],
        )
        updated = conn.execute(
            f"SELECT COUNT(*) AS n FROM alerts WHERE id IN ({placeholders})",
            body.ids,
        ).fetchone()["n"]
    return {"updated": updated}


@router.get("/alerts")
def list_recent_alerts(limit: int = 20) -> list[dict]:
    """Newest alerts across every run, with the owning sample name.

    Powers the dashboard's live-findings feed. `limit` is clamped to keep the
    payload bounded.
    """
    limit = max(1, min(limit, 200))
    with db_session() as conn:
        rows = conn.execute(
            """
            SELECT a.*, r.sample_name
            FROM alerts a
            JOIN runs r ON r.run_id = a.run_id
            ORDER BY a.triggered_at DESC, a.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    out = [dict(r) for r in rows]
    for d in out:
        _parse_related_pids(d)
    return out
