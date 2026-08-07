"""Alert surfaces.

- GET /runs/{run_id}/alerts — detection hits for one run (polled by the CLI's
  live stream and the webapp's alert banner).
- GET /alerts               — newest hits across ALL runs (dashboard feed).
"""

from fastapi import APIRouter, HTTPException

from ..core.db import db_session
from ..core.schema import Alert
from ..models import event as event_store
from ..models import run as run_store

router = APIRouter(tags=["alerts"])


@router.get("/runs/{run_id}/alerts", response_model=list[Alert])
def get_alerts(run_id: str) -> list[Alert]:
    with db_session() as conn:
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        rows = event_store.list_alerts_for_run(conn, run_id)
    return [Alert(**row) for row in rows]


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
    return [dict(r) for r in rows]
