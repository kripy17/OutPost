"""Analyst audit trail — who did what, when.

Every analyst-relevant mutation (triage transitions, FP marks, logins,
rotation, allowlist/suppression edits, retention prunes, backups) writes one
row via `log()`. `actor` is the role when auth is on, 'local' for the
zero-config default, or a source label for non-web writers ('cli', 'agent',
'system'). Read back with `list_events()` for the webapp /audit page.
"""

import sqlite3
from datetime import datetime, timezone

ACTIONS = (
    "alert.status",      # triage transition (open/acknowledged/resolved)
    "alert.false-positive",
    "auth.login",        # success
    "auth.login.failed",
    "auth.password",     # rotation / bootstrap
    "allowlist.add",
    "allowlist.remove",
    "suppression.add",
    "suppression.remove",
    "retention.prune",
    "backup.create",
    "restore.apply",
    "snapshot.ingest",
)


def log(
    conn: sqlite3.Connection,
    actor: str,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: str | None = None,
) -> None:
    """Append one audit entry. Call inside an existing transaction so the log
    row commits (or rolls back) with the mutation it describes."""
    conn.execute(
        "INSERT INTO audit_log (ts, actor, action, target_type, target_id, detail) VALUES (?, ?, ?, ?, ?, ?)",
        (datetime.now(timezone.utc).isoformat(), actor, action, target_type, target_id, detail),
    )


def list_events(conn: sqlite3.Connection, limit: int = 200, action: str | None = None) -> list[dict]:
    """Newest audit entries first; `action` optionally filters to one action."""
    limit = max(1, min(limit, 1000))
    if action:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT ?",
            (action, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]
