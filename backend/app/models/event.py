"""Data access for `events`, `alerts`, and `enrichment_cache` tables."""

import json
import sqlite3

from ..core.schema import Alert


def insert_event(conn: sqlite3.Connection, event: dict) -> int:
    cur = conn.execute(
        """
        INSERT INTO events (
            run_id, platform, event_type, timestamp, pid, ppid, process_name,
            command_line, exe_path, dest_ip, dest_port, protocol, file_path, registry_key,
            host_id, raw_record, log_source, query, tls_sni,
            source_event_id, boot_id, process_start_time,
            user, parent_image, parent_command_line, hashes,
            integrity_level, session_id, connection_status, process_guid
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            event.get("exe_path"),
            event.get("dest_ip"),
            event.get("dest_port"),
            event.get("protocol"),
            event.get("file_path"),
            event.get("registry_key"),
            event.get("host_id", "local"),
            event.get("raw_record"),
            event.get("log_source"),
            event.get("query"),
            event.get("tls_sni"),
            event.get("source_event_id"),
            event.get("boot_id"),
            event.get("process_start_time"),
            event.get("user"),
            event.get("parent_image"),
            event.get("parent_command_line"),
            event.get("hashes"),
            event.get("integrity_level"),
            event.get("session_id"),
            event.get("connection_status"),
            event.get("process_guid"),
        ),
    )
    return cur.lastrowid or 0


def list_events_for_run(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM events WHERE run_id = ? ORDER BY timestamp ASC",
        (run_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def insert_alert(conn: sqlite3.Connection, alert: Alert) -> int:
    last_seen = alert.last_seen_at.isoformat() if alert.last_seen_at else alert.triggered_at.isoformat()
    cur = conn.execute(
        """
        INSERT INTO alerts (
            run_id, rule_id, rule_name, severity, triggered_at, related_pid,
            related_ip, related_pids, details, confidence, evidence_event_ids,
            rule_condition, occurrence_count, last_seen_at, entity_key, pid_fallback
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert.run_id,
            alert.rule_id,
            alert.rule_name,
            alert.severity,
            alert.triggered_at.isoformat(),
            alert.related_pid,
            alert.related_ip,
            json.dumps(alert.related_pids),
            alert.details,
            alert.confidence,
            json.dumps(alert.evidence_event_ids or []),
            alert.rule_condition,
            alert.occurrence_count or 1,
            last_seen,
            alert.entity_key,
            1 if alert.pid_fallback else 0,
        ),
    )
    alert_id = cur.lastrowid or 0
    if alert_id and alert.evidence_event_ids:
        now_iso = alert.triggered_at.isoformat()
        for ev_id in alert.evidence_event_ids:
            conn.execute(
                """
                INSERT OR IGNORE INTO finding_evidence_events (
                    finding_id, event_id, rule_condition, matched_at
                ) VALUES (?, ?, ?, ?)
                """,
                (alert_id, ev_id, alert.rule_condition, now_iso),
            )
    return alert_id


def list_alerts_for_run(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM alerts WHERE run_id = ? ORDER BY triggered_at ASC",
        (run_id,),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        _parse_related_pids(d)
        _parse_evidence_event_ids(d)
        out.append(d)
    return out


def _parse_related_pids(d: dict) -> None:
    """related_pids is stored as a JSON text column — restore the list, or
    default to [] for rows predating the column (missing/NULL/None)."""
    raw = d.get("related_pids")
    if isinstance(raw, list):
        return
    try:
        d["related_pids"] = json.loads(raw) if raw else []
    except (ValueError, TypeError):
        d["related_pids"] = []


def _parse_evidence_event_ids(d: dict) -> None:
    raw = d.get("evidence_event_ids")
    if isinstance(raw, list):
        return
    try:
        d["evidence_event_ids"] = json.loads(raw) if raw else []
    except (ValueError, TypeError):
        d["evidence_event_ids"] = []


def get_cache(conn: sqlite3.Connection, ip: str) -> dict | None:
    row = conn.execute("SELECT * FROM enrichment_cache WHERE ip = ?", (ip,)).fetchone()
    return dict(row) if row else None


def upsert_cache(conn: sqlite3.Connection, ip: str, abuse_score, vt_malicious_count, reputation) -> str:
    """Store/refresh an IP's enrichment row. Returns the checked_at stamp the
    row now carries (callers surface it as the cache age on run detail)."""
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
    return checked_at
