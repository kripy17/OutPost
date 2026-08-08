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


# Event fields whose values are checked against the watchlist, mapped to the
# IOC kind label used in notifications (the enrichment check is exact-value
# too — watchlist entries are literal strings, not substrings).
_IOC_FIELDS = {
    "dest_ip": "ip",
    "process_name": "process",
    "file_path": "file",
    "registry_key": "registry",
}


def match_events(conn: sqlite3.Connection, events: list[dict]) -> list[dict]:
    """Watchlist hits among a batch of stored events.

    Matching is case-insensitive (Windows registry keys and process names are
    case-insensitive in practice) — the watchlist value and the event value are
    compared lowercased, while the returned `ioc_value` keeps the event's own
    casing for display.

    Returns one match per distinct (ioc_type, ioc_value) seen in the batch:
    each carries the watchlist label and the first event that triggered it, so
    a watched IP touched by five connections toasts once, not five times.

        [{"ioc_type": "ip", "ioc_value": "203.0.113.88", "label": "C2",
          "event_type": "network_connection", "timestamp": "…"}, ...]
    """
    entries = {r["value"].lower(): (r["label"] or r["value"]) for r in list_watchlist(conn)}
    if not entries:
        return []

    matches: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for ev in events:
        for field, ioc_type in _IOC_FIELDS.items():
            value = ev.get(field)
            if not value:
                continue
            label = entries.get(value.lower())
            if label is None:
                continue
            key = (ioc_type, value.lower())
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                {
                    "ioc_type": ioc_type,
                    "ioc_value": value,
                    "label": label,
                    "event_type": ev.get("event_type"),
                    "timestamp": ev.get("timestamp"),
                }
            )
    return matches


def record_hits(conn: sqlite3.Connection, run_id: str, matches: list[dict]) -> list[dict]:
    """Persist first-seen-per-run watchlist hits; return only the *new* ones.

    Live alerting should fire the moment a watched IOC appears **in a run**,
    not on every batch that touches it — a live session beaming to a watched
    C2 IP must webhook/toast once, not forever. Each (run, ioc) is recorded on
    first appearance (INSERT OR IGNORE); only rows that actually inserted are
    returned for dispatch.
    """
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    fresh: list[dict] = []
    for m in matches:
        cur = conn.execute(
            "INSERT OR IGNORE INTO watchlist_hits (run_id, ioc_type, ioc_value, first_seen) "
            "VALUES (?, ?, ?, ?)",
            (run_id, m["ioc_type"], m["ioc_value"], now),
        )
        if cur.rowcount > 0:
            fresh.append(m)
    return fresh
