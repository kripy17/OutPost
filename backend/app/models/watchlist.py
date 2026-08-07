"""Data access for the `watchlist` table (Phase 6 Task 26 — docs/10 #6).

Personal IOC watchlist, independent of AbuseIPDB/VirusTotal: entries are
checked against every run's connections during enrichment.
"""

import sqlite3
from datetime import datetime, timezone
from typing import Optional


def list_watchlist(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT value, label, added_at FROM watchlist ORDER BY added_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def get_watchlist(conn: sqlite3.Connection, value: str) -> Optional[dict]:
    row = conn.execute("SELECT * FROM watchlist WHERE value = ?", (value,)).fetchone()
    return dict(row) if row else None


def add_watchlist(conn: sqlite3.Connection, value: str, label: str) -> None:
    conn.execute(
        """
        INSERT INTO watchlist (value, label, added_at) VALUES (?, ?, ?)
        ON CONFLICT(value) DO UPDATE SET
            label = excluded.label,
            added_at = excluded.added_at
        """,
        (value, label, datetime.now(timezone.utc).isoformat()),
    )


def remove_watchlist(conn: sqlite3.Connection, value: str) -> bool:
    cur = conn.execute("DELETE FROM watchlist WHERE value = ?", (value,))
    return cur.rowcount > 0
