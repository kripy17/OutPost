"""Audit logging model (cryptographic audit chain is parked)."""

import json
from datetime import datetime, timezone


def _serialize_field(val):
    if val is None:
        return None
    if isinstance(val, (dict, list)):
        return json.dumps(val)
    return str(val)


def log(
    conn,
    actor: str = "analyst",
    action: str = "unknown",
    target_type: str | None = None,
    target_id: str | None = None,
    detail: str | None = None,
    outcome: str = "success",
    source_ip: str | None = None,
    before_state: str | dict | None = None,
    after_state: str | dict | None = None,
    reason: str | None = None,
    *args,
    **kwargs,
) -> None:
    """Log an audit event directly to the audit_log table.

    Does not swallow database exceptions so callers and operators are aware
    of persistence failures. Serializes structured state to JSON.
    """
    ts = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO audit_log (ts, actor, action, target_type, target_id, detail, outcome, source_ip, before_state, after_state, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ts,
            actor or "analyst",
            action,
            target_type,
            target_id,
            _serialize_field(detail),
            outcome or "success",
            source_ip,
            _serialize_field(before_state),
            _serialize_field(after_state),
            reason,
        ),
    )


def checkpoint(*args, **kwargs):
    """No-op checkpoint for parked Merkle tree."""
    pass
