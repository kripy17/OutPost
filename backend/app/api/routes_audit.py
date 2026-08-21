"""Audit trail (Tier-1 gap #4) — who did what, when.

GET /audit — newest analyst actions first: triage transitions, FP marks,
logins, rotation, allowlist/suppression edits, retention prunes, backups.
With auth on this route is gated like every other non-public endpoint, so the
trail itself is only visible to signed-in analysts/admins.
"""

from fastapi import APIRouter, Query

from ..core.db import db_session
from ..models import audit

router = APIRouter(tags=["audit"])


@router.get("/audit", response_model=None)
def list_audit(
    limit: int = Query(200, ge=1, le=1000),
    action: str = Query("", max_length=64),
) -> dict:
    """Newest audit entries; `?action=alert.status` filters to one kind."""
    with db_session() as conn:
        events = audit.list_events(conn, limit=limit, action=action.strip() or None)
    return {
        "total": len(events),
        "limit": limit,
        "action": action.strip() or None,
        "events": events,
    }
