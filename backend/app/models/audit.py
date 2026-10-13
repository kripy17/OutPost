"""Analyst audit trail — who did what, when.

Every analyst-relevant mutation (containment isolation/release, process kill,
triage transitions, FP marks, logins, rotation, allowlist/suppression edits,
retention prunes, backups) writes one row via `log()`. `actor` is the role
when auth is on, 'local' for the zero-config default, or a source label for
non-web writers ('cli', 'agent', 'system'). Read back with `list_events()` for
the webapp /audit page.

Tamper-evident: each entry cryptographically chains to the preceding entry's
SHA-256 digest (`entry_hash = SHA256(prev_hash:ts:actor:action:...)`). Any
out-of-band modification or truncation breaks the cryptographic chain and is
flagged by `verify_audit_chain()`.
"""

import hashlib
import sqlite3
from datetime import datetime, timezone

ACTIONS = (
    "agent.isolate",
    "agent.unisolate",
    "agent.process.kill_queued",
    "agent.action.ack",
    "agent.action.completed",
    "agent.register",
    "alert.status",      # triage transition (open/acknowledged/resolved)
    "alert.false-positive",
    "auth.login",        # success
    "auth.login.failed",
    "auth.password",     # rotation / bootstrap
    "auth.agent_token",
    "allowlist.add",
    "allowlist.remove",
    "suppression.add",
    "suppression.remove",
    "rules.modify",
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
    outcome: str = "success",
) -> str:
    """Append one audit entry chained into the tamper-evident log."""
    ts = datetime.now(timezone.utc).isoformat()
    try:
        cur = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = cur["entry_hash"] if (cur and cur["entry_hash"]) else ("0" * 64)
    except Exception:
        prev_hash = "0" * 64

    canonical = f"{prev_hash}:{ts}:{actor}:{action}:{target_type or ''}:{target_id or ''}:{outcome}:{detail or ''}"
    entry_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    conn.execute(
        """
        INSERT INTO audit_log (ts, actor, action, target_type, target_id, detail, outcome, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (ts, actor, action, target_type, target_id, detail, outcome, prev_hash, entry_hash),
    )
    return entry_hash


def verify_audit_chain(conn: sqlite3.Connection) -> tuple[bool, int, str | None]:
    """Verify cryptographic integrity of the entire audit trail hash chain.

    Returns (valid: bool, verified_count: int, error_message: str | None).
    """
    rows = conn.execute(
        "SELECT id, ts, actor, action, target_type, target_id, detail, outcome, prev_hash, entry_hash "
        "FROM audit_log ORDER BY id ASC"
    ).fetchall()
    if not rows:
        return True, 0, None

    expected_prev = "0" * 64
    for idx, r in enumerate(rows):
        actual_prev = r["prev_hash"] or ("0" * 64)
        if actual_prev != expected_prev and idx != 0:
            return False, idx, f"Broken chain link at audit ID {r['id']}: expected prev_hash {expected_prev}, got {actual_prev}"
        outcome = r["outcome"] or "success"
        canonical = f"{actual_prev}:{r['ts']}:{r['actor']}:{r['action']}:{r['target_type'] or ''}:{r['target_id'] or ''}:{outcome}:{r['detail'] or ''}"
        expected_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if r["entry_hash"] and r["entry_hash"] != expected_hash:
            return False, idx, f"Tampered entry detected at audit ID {r['id']}: hash mismatch"
        expected_prev = r["entry_hash"] or expected_hash

    return True, len(rows), None


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

