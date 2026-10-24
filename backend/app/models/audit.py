"""Audit logging stub (cryptographic audit chain is parked)."""

from datetime import datetime, timezone


def log(
    conn,
    actor: str = "analyst",
    action: str = "unknown",
    target_type: str | None = None,
    target_id: str | None = None,
    detail: str | None = None,
    outcome: str = "success",
    source_ip: str | None = None,
    before_state: str | None = None,
    after_state: str | None = None,
    reason: str | None = None,
    *args,
    **kwargs,
) -> None:
    try:
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
                detail,
                outcome or "success",
                source_ip,
                before_state,
                after_state,
                reason,
            ),
        )
    except Exception:
        pass


def checkpoint(*args, **kwargs):
    pass
