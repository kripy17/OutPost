"""Host aggregate timeline (P0.6) — GET /hosts/{host_id}/timeline.

A pure read model: hosts are derived (events.host_id + agent_heartbeats +
host_snapshots), so the timeline merges the existing event / finding /
session / IOC / investigation data into one chronological feed. No
host-timeline table exists or is created. Unknown hosts 404 (matching the
fleet's identity union and the /hosts/{host_id}/watch convention).
"""

from fastapi import APIRouter, HTTPException, Query

from ..core.db import db_session
from ..core.schema import HostTimelineDTO
from ..models import hosts as host_store

router = APIRouter(tags=["hosts"])

_TIMELINE_KINDS = ("event", "finding", "session", "ioc", "investigation")


@router.get("/hosts/{host_id}/timeline", response_model=HostTimelineDTO)
def get_host_timeline(
    host_id: str,
    kind: str | None = Query(None, description="Restrict to one resource kind: event | finding | session | ioc | investigation"),
    event_type: str | None = Query(None, description="Narrow the event rows to this event type"),
    q: str | None = Query(None, max_length=500, description="Match the display fields of every kind (process, ip, rule name, ioc value, case title…)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> HostTimelineDTO:
    """The host's aggregate timeline — every resource tied to it, merged
    chronologically (newest first). `kind` / `event_type` / `q` filter the
    feed; `total` is the honest count across all searched kinds after the
    filters, and `limit`/`offset` paginate the merged page."""
    if kind is not None and kind not in _TIMELINE_KINDS:
        raise HTTPException(
            status_code=422,
            detail=f"kind must be one of: {', '.join(_TIMELINE_KINDS)}",
        )
    with db_session() as conn:
        if not host_store.host_exists(conn, host_id):
            raise HTTPException(status_code=404, detail=f"Unknown host: {host_id}")
        out = host_store.host_timeline(
            conn,
            host_id,
            kind=kind,
            event_type=event_type,
            q=(q or "").strip() or None,
            limit=limit,
            offset=offset,
        )
    return HostTimelineDTO(**out)
