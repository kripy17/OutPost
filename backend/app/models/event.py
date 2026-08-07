"""Data access for `events`, `alerts`, and `enrichment_cache` tables."""

import sqlite3
from typing import Optional

from ..core.schema import Alert


def insert_event(conn: sqlite3.Connection, event: dict) -> None:
    conn.execute(
        """
        INSERT INTO events (
            run_id, platform, event_type, timestamp, pid, ppid, process_name,
            command_line, dest_ip, dest_port, protocol, file_path, registry_key
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event["run_id"],
            event["platform"],
            event["event_type"],
            event["timestamp"],
            event.get("pid"),
            event.get("ppid"),
            event.get("process_name"),
            event.get("command_line"),
            event.get("dest_ip"),
            event.get("dest_port"),
            event.get("protocol"),
            event.get("file_path"),
            event.get("registry_key"),
        ),
    )


def list_events_for_run(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM events WHERE run_id = ? ORDER BY timestamp ASC",
        (run_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def insert_alert(conn: sqlite3.Connection, alert: Alert) -> int:
    cur = conn.execute(
        """
        INSERT INTO alerts (run_id, rule_id, rule_name, severity, triggered_at, related_pid, related_ip, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert.run_id,
            alert.rule_id,
            alert.rule_name,
            alert.severity,
            alert.triggered_at.isoformat(),
            alert.related_pid,
            alert.related_ip,
            alert.details,
        ),
    )
    return cur.lastrowid or 0


def list_alerts_for_run(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM alerts WHERE run_id = ? ORDER BY triggered_at ASC",
        (run_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_cache(conn: sqlite3.Connection, ip: str) -> Optional[dict]:
    row = conn.execute("SELECT * FROM enrichment_cache WHERE ip = ?", (ip,)).fetchone()
    return dict(row) if row else None


def upsert_cache(conn: sqlite3.Connection, ip: str, abuse_score, vt_malicious_count, reputation) -> None:
    from datetime import datetime, timezone

    checked_at = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO enrichment_cache (ip, abuse_score, vt_malicious_count, reputation, checked_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            abuse_score = excluded.abuse_score,
            vt_malicious_count = excluded.vt_malicious_count,
            reputation = excluded.reputation,
            checked_at = excluded.checked_at
        """,
        (ip, abuse_score, vt_malicious_count, reputation, checked_at),
    )
