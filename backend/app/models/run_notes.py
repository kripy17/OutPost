"""Data access for the `run_notes` table (Tier 2 #7 — docs/10).

Free-text analyst notes attached to a run: your own observations,
hypotheses, or reminders for a later report.
"""

import sqlite3
from datetime import datetime, timezone


def list_notes(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT id, run_id, note, created_at FROM run_notes "
        "WHERE run_id = ? ORDER BY created_at ASC, id ASC",
        (run_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def add_note(conn: sqlite3.Connection, run_id: str, note: str) -> dict:
    created_at = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO run_notes (run_id, note, created_at) VALUES (?, ?, ?)",
        (run_id, note, created_at),
    )
    return {"id": cur.lastrowid or 0, "run_id": run_id, "note": note, "created_at": created_at}
