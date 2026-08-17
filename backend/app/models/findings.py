"""Finding-layer data access over the physical `alerts` table (P0.2).

The alerts table is the single store; `findings` is the semantic resource.
This module holds the ONE queue implementation that both `/alerts/queue`
(backward-compatible) and `/findings` (with the P0 filters) share, plus the
analyst-authored finding create path (`source='analyst'`).

Unread semantics: `status = 'open' AND seen_at IS NULL`. `seen_at` is only
ever written by an explicit `mark_seen` page — reads never mutate.
"""

import json
import sqlite3
from datetime import datetime, timezone

from ..core.schema import FindingIn
from ..models.run import SYNTHETIC_SOURCES


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_related_pids(d: dict) -> None:
    raw = d.get("related_pids")
    if isinstance(raw, list):
        return
    try:
        d["related_pids"] = json.loads(raw) if raw else []
    except (ValueError, TypeError):
        d["related_pids"] = []


def _row(d: dict) -> dict:
    _parse_related_pids(d)
    return d


def get_finding(conn: sqlite3.Connection, alert_id: int) -> dict | None:
    """One finding row (superset of Alert) or None."""
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return _row(dict(row)) if row else None


def create_analyst_finding(conn: sqlite3.Connection, body: FindingIn) -> dict:
    """Insert an analyst-authored finding. `source` is always 'analyst' — the
    detection engine is the only writer of 'detection'. Returns the new row.
    """
    now = _now()
    cur = conn.execute(
        """
        INSERT INTO alerts (
            run_id, rule_id, rule_name, severity, triggered_at, related_pid,
            related_ip, related_pids, details, status, status_comment, status_at,
            source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, 'analyst')
        """,
        (
            body.run_id,
            body.rule_id.strip() or "analyst-finding",
            body.rule_name.strip() or "Analyst finding",
            body.severity,
            now,
            body.related_pid,
            body.related_ip,
            json.dumps(body.related_pids or []),
            body.details.strip(),
            (body.comment or "").strip() or None,
            now,
        ),
    )
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (cur.lastrowid,)).fetchone()
    return _row(dict(row))


def query_findings(
    conn: sqlite3.Connection,
    *,
    status: str = "open",
    source: str | None = None,
    disposition: str | None = None,
    confidence: str | None = None,
    unread_only: bool = False,
    rule_id: str | None = None,
    severity: str | None = None,
    host_id: str | None = None,
    assignee: str | None = None,
    campaign: str | None = None,
    provenance: str | None = None,
    q: str | None = None,
    sort: str = "aging",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """The ONE finding-queue query — shared by /alerts/queue and /findings.

    `status` scopes the returned page; the per-status tab badges are live
    totals across the non-status filters no matter which view is active. The
    P0 filters (source / disposition / confidence / unread_only) behave like
    the other non-status filters. `unread_only` additionally pins the page to
    `status='open' AND seen_at IS NULL` (the unread definition), so an
    'all' view with unread_only still shows only unread open findings.

    Returns the queue envelope (`total` / per-status counts / page rows) plus
    `_page_ids` (the ids of the rows on THIS page) for the caller's optional
    `mark_seen` pass — reads never mutate here.
    """
    where: list[str] = []
    params: list = []
    if source:
        where.append("a.source = ?")
        params.append(source)
    if disposition:
        where.append("a.disposition = ?")
        params.append(disposition)
    if confidence:
        where.append("a.confidence = ?")
        params.append(confidence)
    if rule_id:
        where.append("a.rule_id = ?")
        params.append(rule_id)
    if severity:
        where.append("a.severity = ?")
        params.append(severity)
    if host_id:
        where.append("a.run_id IN (SELECT DISTINCT run_id FROM events WHERE host_id = ?)")
        params.append(host_id)
    if assignee:
        where.append("a.assignee = ?")
        params.append(assignee)
    if campaign:
        where.append(
            "a.run_id IN (SELECT DISTINCT run_id FROM events WHERE dest_ip = ? OR file_path = ? OR registry_key = ? OR process_name = ?)"
        )
        params.extend([campaign] * 4)
    if provenance:
        marks = ",".join("?" for _ in SYNTHETIC_SOURCES)
        op = "IN" if provenance == "synthetic" else "NOT IN"
        where.append(f"r.source {op} ({marks})")
        params += list(SYNTHETIC_SOURCES)
    if unread_only:
        # The unread definition is BOTH conditions — an acknowledged-but-unseen
        # alert is not unread. Applied to counts too so the tab badges agree.
        where.append("a.status = 'open' AND a.seen_at IS NULL")
    if q:
        like = f"%{q}%"
        where.append("(r.sample_name LIKE ? OR a.rule_id LIKE ? OR a.rule_name LIKE ? OR a.details LIKE ? OR a.related_ip LIKE ?)")
        params.extend([like] * 5)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    if status != "all":
        row_where = "WHERE " + " AND ".join(["a.status = ?", *where]) if where else "WHERE a.status = ?"
        row_params: list = [status, *params]
    else:
        row_where = where_sql
        row_params = list(params)

    order = "a.triggered_at ASC, a.id ASC" if sort == "aging" else "a.triggered_at DESC, a.id DESC"

    counts = conn.execute(
        f"""
        SELECT a.status, COUNT(*) AS n
        FROM alerts a JOIN runs r ON r.run_id = a.run_id
        {where_sql}
        GROUP BY a.status
        """,
        params,
    ).fetchall()
    total = conn.execute(
        f"SELECT COUNT(*) FROM alerts a JOIN runs r ON r.run_id = a.run_id {row_where}",
        row_params,
    ).fetchone()[0]
    rows = conn.execute(
        f"""
        SELECT a.*, r.sample_name,
               (SELECT GROUP_CONCAT(DISTINCT host_id) FROM events e
                WHERE e.run_id = a.run_id) AS host_ids
        FROM alerts a
        JOIN runs r ON r.run_id = a.run_id
        {row_where}
        ORDER BY {order}
        LIMIT ? OFFSET ?
        """,
        [*row_params, limit, offset],
    ).fetchall()

    total_by_status = {c["status"]: c["n"] for c in counts}
    out = []
    page_ids: list[int] = []
    for r in rows:
        d = _row(dict(r))
        d["host_ids"] = [h for h in (d.pop("host_ids") or "").split(",") if h]
        out.append(d)
        page_ids.append(d["id"])
    return {
        "total": total,
        "open": total_by_status.get("open", 0),
        "acknowledged": total_by_status.get("acknowledged", 0),
        "resolved": total_by_status.get("resolved", 0),
        "sort": sort,
        "limit": limit,
        "offset": offset,
        "alerts": out,
        "_page_ids": page_ids,
    }


def mark_page_seen(conn: sqlite3.Connection, page_ids: list[int]) -> int:
    """Bounded, idempotent unread stamp: set seen_at on exactly the rows of
    the returned page that are still NULL. Returns the rows newly marked."""
    if not page_ids:
        return 0
    marks = ",".join("?" * len(page_ids))
    cur = conn.execute(
        f"UPDATE alerts SET seen_at = ? WHERE id IN ({marks}) AND seen_at IS NULL",
        [_now(), *page_ids],
    )
    return cur.rowcount
