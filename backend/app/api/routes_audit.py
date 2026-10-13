"""Audit trail — verifiable, tamper-evident record of all operational actions.

GET  /audit                    — newest analyst actions first with pagination & action filter
GET  /audit/verify             — verify full cryptographic hash-chain integrity
POST /audit/checkpoint         — sign a periodic checkpoint with local key
GET  /audit/checkpoints        — list recent signed checkpoints
GET  /audit/checkpoint/export  — export verifiable checkpoint bundle for out-of-band storage
"""

from typing import Any

from fastapi import APIRouter, Query, Response

from ..core.db import db_session
from ..models import audit

router = APIRouter(tags=["audit"])


@router.get("/audit", response_model=None)
def list_audit(
    limit: int = Query(200, ge=1, le=1000),
    action: str = Query("", max_length=64),
) -> dict[str, Any]:
    """Newest audit entries; `?action=alert.status` filters to one kind."""
    with db_session() as conn:
        events = audit.list_events(conn, limit=limit, action=action.strip() or None)
    return {
        "total": len(events),
        "limit": limit,
        "action": action.strip() or None,
        "events": events,
    }


@router.get("/audit/verify", response_model=None)
def verify_audit() -> dict[str, Any]:
    """Verify the cryptographic hash-chain integrity of the tamper-evident audit log."""
    with db_session() as conn:
        report = audit.verify_audit_chain(conn)
    return {
        "valid": report["valid"],
        "intact": report["intact"],
        "entries_verified": report["entries_verified"],
        "verified_through": report["verified_through"],
        "total_entries": report["total_entries"],
        "status": report["status"],
        "first_break": report["first_break"],
        "error": report["error"],
        "verified_at": report["verified_at"],
    }


@router.post("/audit/checkpoint", response_model=None, status_code=201)
def create_checkpoint_endpoint() -> dict[str, Any]:
    """Generate a signed cryptographic checkpoint over the active audit chain head."""
    with db_session() as conn:
        checkpoint = audit.create_checkpoint(conn)
    return {
        "status": "created",
        "checkpoint": checkpoint,
    }


@router.get("/audit/checkpoints", response_model=None)
def list_checkpoints_endpoint(limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    """List recent signed audit checkpoints."""
    with db_session() as conn:
        items = audit.list_checkpoints(conn, limit=limit)
    return {
        "total": len(items),
        "checkpoints": items,
    }


@router.get("/audit/checkpoint/export", response_model=None)
def export_checkpoint_bundle() -> Response:
    """Export the latest signed audit checkpoint bundle for out-of-band storage."""
    with db_session() as conn:
        report = audit.verify_audit_chain(conn)
        checkpoint = audit.create_checkpoint(conn)
        items = audit.list_checkpoints(conn, limit=5)

    bundle = {
        "outpost_audit_verification": report,
        "latest_checkpoint": checkpoint,
        "recent_checkpoints": items,
        "disclaimer": (
            "This signed checkpoint verifies that the audit log chain was intact up to "
            f"audit ID {checkpoint['last_audit_id']}. Store this checkpoint bundle in an "
            "out-of-band repository (print, cold storage, remote immutable log) to prove "
            "the log was not rewritten after this time."
        ),
    }

    import json
    content = json.dumps(bundle, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=outpost-audit-checkpoint-seq{checkpoint['checkpoint_seq']}.json",
            "x-outpost-checkpoint-sig": checkpoint["signature"],
        },
    )
