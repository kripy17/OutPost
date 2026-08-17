"""Host aggregate timeline (P0.6) — a pure read model over the existing
tables, no host-timeline storage.

The P0 spec flagged the host-scoped timeline as a MISSING PIECE and asked for
the smallest additive read model. Hosts are DERIVED (they have no table of
their own — identity comes from `events.host_id` + `agent_heartbeats` +
`host_snapshots`), so this module builds one chronological feed per host by
merging five existing sources:

  event        — events.host_id = host
  finding      — alerts whose run has events from the host
  session      — runs whose run has events from the host (kind
                 monitoring_session / analysis_job)
  ioc          — iocs linked via provenance refs to events on the host or to
                 findings on the host's runs
  investigation— investigations linked via alerts.investigation_id on the
                 host's runs

Every source is queried with the same kind filters, counted for the honest
`total`, and merged by timestamp. Pagination is applied after the merge, so
`total` is the count across ALL kinds (not just the page) and ordering is the
unified chronological feed the workspace needs.
"""

import sqlite3
from typing import Any

# Canonical kind order for equal-timestamp tie-breaking (events first, then
# the derived/analytic layers).
_KIND_RANK = {"event": 0, "finding": 1, "session": 2, "ioc": 3, "investigation": 4}


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def host_exists(conn: sqlite3.Connection, host_id: str) -> bool:
    """A host is 'known' if any event, heartbeat, or snapshot carries its id
    (the same identity union the fleet view uses)."""
    row = conn.execute(
        "SELECT (SELECT COUNT(*) FROM events WHERE host_id = ?) "
        "     + (SELECT COUNT(*) FROM agent_heartbeats WHERE host_id = ?) "
        "     + (SELECT COUNT(*) FROM host_snapshots WHERE host_id = ?) AS n",
        (host_id, host_id, host_id),
    ).fetchone()
    return bool(row and row["n"])


def _host_platform(conn: sqlite3.Connection, host_id: str) -> str | None:
    hb = conn.execute(
        "SELECT platform FROM agent_heartbeats WHERE host_id = ?", (host_id,)
    ).fetchone()
    if hb and hb["platform"]:
        return hb["platform"]
    row = conn.execute(
        "SELECT platform FROM events WHERE host_id = ? AND platform IS NOT NULL "
        "ORDER BY timestamp DESC LIMIT 1",
        (host_id,),
    ).fetchone()
    return row["platform"] if row else None


def _host_last_heartbeat(conn: sqlite3.Connection, host_id: str) -> str | None:
    row = conn.execute(
        "SELECT last_heartbeat FROM agent_heartbeats WHERE host_id = ?", (host_id,)
    ).fetchone()
    return row["last_heartbeat"] if row else None


def _findings_for_host(
    conn: sqlite3.Connection, host_id: str, *, q: str | None, limit: int
) -> list[dict]:
    where = "a.run_id IN (SELECT DISTINCT run_id FROM events WHERE host_id = ?)"
    params: list = [host_id]
    if q:
        like = f"%{_escape_like(q)}%"
        where += " AND (a.rule_name LIKE ? ESCAPE '\\' OR a.details LIKE ? ESCAPE '\\' OR a.related_ip LIKE ? ESCAPE '\\')"
        params.extend([like] * 3)
    rows = conn.execute(
        f"""SELECT a.id, a.rule_name, a.severity, a.status, a.triggered_at, a.related_ip,
                  a.details, a.run_id, r.sample_name, a.investigation_id
           FROM alerts a JOIN runs r ON r.run_id = a.run_id
           WHERE {where}
           ORDER BY a.triggered_at DESC, a.id DESC
           LIMIT ?""",
        (*params, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def _iocs_for_host(
    conn: sqlite3.Connection, host_id: str, *, q: str | None, limit: int
) -> list[dict]:
    """IOCs touching the host: provenance refs to events on the host or to
    findings on the host's runs. Each IOC appears once, at its earliest
    first_seen among the host's refs."""
    where = (
        "((p.ref_type = 'event' AND p.ref_id IN (SELECT CAST(id AS TEXT) FROM events WHERE host_id = ?)) "
        "OR (p.ref_type = 'finding' AND p.ref_id IN "
        "(SELECT CAST(id AS TEXT) FROM alerts a WHERE a.run_id IN "
        "(SELECT DISTINCT run_id FROM events WHERE host_id = ?))))"
    )
    params: list = [host_id, host_id]
    if q:
        like = f"%{_escape_like(q)}%"
        where += " AND (i.value LIKE ? ESCAPE '\\' OR i.label LIKE ? ESCAPE '\\')"
        params.extend([like, like])
    rows = conn.execute(
        f"""SELECT i.ioc_id, i.value, i.type, i.disposition, i.reputation, i.label,
                  MIN(p.first_seen) AS first_seen, COUNT(*) AS ref_count
           FROM ioc_provenance p JOIN iocs i ON i.ioc_id = p.ioc_id
           WHERE {where}
           GROUP BY i.ioc_id
           ORDER BY first_seen DESC
           LIMIT ?""",
        (*params, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def _investigations_for_host(
    conn: sqlite3.Connection, host_id: str, *, q: str | None, limit: int
) -> list[dict]:
    where = (
        "i.id IN (SELECT DISTINCT a.investigation_id FROM alerts a "
        "WHERE a.investigation_id IS NOT NULL AND a.run_id IN "
        "(SELECT DISTINCT run_id FROM events WHERE host_id = ?))"
    )
    params: list = [host_id]
    if q:
        like = f"%{_escape_like(q)}%"
        where += " AND i.title LIKE ? ESCAPE '\\'"
        params.append(like)
    rows = conn.execute(
        f"""SELECT i.id, i.title, i.status, i.severity, i.created_at, i.updated_at,
                  i.closed_at,
                  (SELECT COUNT(*) FROM alerts a WHERE a.investigation_id = i.id) AS finding_count
           FROM investigations i
           WHERE {where}
           ORDER BY i.created_at DESC
           LIMIT ?""",
        (*params, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def _sessions_for_host(
    conn: sqlite3.Connection, host_id: str, *, q: str | None, limit: int
) -> list[dict]:
    where = "run_id IN (SELECT DISTINCT run_id FROM events WHERE host_id = ?)"
    params: list = [host_id]
    if q:
        like = f"%{_escape_like(q)}%"
        where += " AND (sample_name LIKE ? ESCAPE '\\' OR run_id LIKE ? ESCAPE '\\')"
        params.extend([like, like])
    rows = conn.execute(
        f"""SELECT r.run_id, r.sample_name, r.platform, r.kind, r.session_type,
                  r.started_at, r.completed_at, r.source
           FROM runs r
           WHERE {where}
           ORDER BY r.started_at DESC
           LIMIT ?""",
        (*params, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def _events_for_host(
    conn: sqlite3.Connection,
    host_id: str,
    *,
    event_type: str | None,
    q: str | None,
    limit: int,
) -> list[dict]:
    where = "e.host_id = ?"
    params: list = [host_id]
    if event_type:
        where += " AND e.event_type = ?"
        params.append(event_type)
    if q:
        like = f"%{_escape_like(q)}%"
        where += " AND (e.process_name LIKE ? ESCAPE '\\' OR e.command_line LIKE ? ESCAPE '\\' OR e.dest_ip LIKE ? ESCAPE '\\' OR e.file_path LIKE ? ESCAPE '\\' OR e.registry_key LIKE ? ESCAPE '\\' OR e.run_id LIKE ? ESCAPE '\\')"
        params.extend([like] * 6)
    rows = conn.execute(
        f"""SELECT e.id, e.timestamp, e.event_type, e.pid, e.process_name,
                   e.command_line, e.dest_ip, e.file_path, e.registry_key, e.run_id,
                   r.sample_name, e.host_id
            FROM events e JOIN runs r ON r.run_id = e.run_id
            WHERE {where}
            ORDER BY e.timestamp DESC, e.id DESC
            LIMIT ?""",
        (*params, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def _count_events(conn: sqlite3.Connection, host_id: str, *, event_type: str | None, q: str | None) -> int:
    where = "host_id = ?"
    params: list = [host_id]
    if event_type:
        where += " AND event_type = ?"
        params.append(event_type)
    if q:
        like = f"%{_escape_like(q)}%"
        where += " AND (process_name LIKE ? ESCAPE '\\' OR command_line LIKE ? ESCAPE '\\' OR dest_ip LIKE ? ESCAPE '\\' OR file_path LIKE ? ESCAPE '\\' OR registry_key LIKE ? ESCAPE '\\' OR run_id LIKE ? ESCAPE '\\')"
        params.extend([like] * 6)
    return conn.execute(f"SELECT COUNT(*) FROM events WHERE {where}", params).fetchone()[0]


def _count_findings(conn: sqlite3.Connection, host_id: str, *, q: str | None) -> int:
    where = "a.run_id IN (SELECT DISTINCT run_id FROM events WHERE host_id = ?)"
    params: list = [host_id]
    if q:
        like = f"%{_escape_like(q)}%"
        where += " AND (a.rule_name LIKE ? ESCAPE '\\' OR a.details LIKE ? ESCAPE '\\' OR a.related_ip LIKE ? ESCAPE '\\')"
        params.extend([like] * 3)
    return conn.execute(
        f"SELECT COUNT(*) FROM alerts a JOIN runs r ON r.run_id = a.run_id WHERE {where}", params
    ).fetchone()[0]


def _count_sessions(conn: sqlite3.Connection, host_id: str, *, q: str | None) -> int:
    where = "run_id IN (SELECT DISTINCT run_id FROM events WHERE host_id = ?)"
    params: list = [host_id]
    if q:
        like = f"%{_escape_like(q)}%"
        where += " AND (sample_name LIKE ? ESCAPE '\\' OR run_id LIKE ? ESCAPE '\\')"
        params.extend([like, like])
    return conn.execute(f"SELECT COUNT(*) FROM runs WHERE {where}", params).fetchone()[0]


def _count_iocs(conn: sqlite3.Connection, host_id: str, *, q: str | None) -> int:
    where = (
        "((p.ref_type = 'event' AND p.ref_id IN (SELECT CAST(id AS TEXT) FROM events WHERE host_id = ?)) "
        "OR (p.ref_type = 'finding' AND p.ref_id IN "
        "(SELECT CAST(id AS TEXT) FROM alerts a WHERE a.run_id IN "
        "(SELECT DISTINCT run_id FROM events WHERE host_id = ?))))"
    )
    params: list = [host_id, host_id]
    if q:
        like = f"%{_escape_like(q)}%"
        where += " AND (i.value LIKE ? ESCAPE '\\' OR i.label LIKE ? ESCAPE '\\')"
        params.extend([like, like])
    return conn.execute(
        f"SELECT COUNT(DISTINCT i.ioc_id) FROM ioc_provenance p JOIN iocs i ON i.ioc_id = p.ioc_id WHERE {where}",
        params,
    ).fetchone()[0]


def _count_investigations(conn: sqlite3.Connection, host_id: str, *, q: str | None) -> int:
    where = (
        "i.id IN (SELECT DISTINCT a.investigation_id FROM alerts a "
        "WHERE a.investigation_id IS NOT NULL AND a.run_id IN "
        "(SELECT DISTINCT run_id FROM events WHERE host_id = ?))"
    )
    params: list = [host_id]
    if q:
        like = f"%{_escape_like(q)}%"
        where += " AND i.title LIKE ? ESCAPE '\\'"
        params.append(like)
    return conn.execute(
        f"SELECT COUNT(*) FROM investigations i WHERE {where}", params
    ).fetchone()[0]


def host_timeline(
    conn: sqlite3.Connection,
    host_id: str,
    *,
    kind: str | None = None,
    event_type: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Build the merged host timeline.

    Filters: `kind` restricts to one resource kind; `event_type` narrows the
    event rows; `q` matches the display fields of every kind. `total` is the
    honest count across all searched kinds after filters; the page is the
    chronological merge (descending by timestamp) sliced by offset/limit.

    The page window is fetched per-kind (offset + limit) then merged, so the
    merge always has enough rows to serve the requested page — the totals
    come from independent COUNT queries, never from the page window.
    """
    if kind not in (None, "event", "finding", "session", "ioc", "investigation"):
        raise ValueError(f"unknown timeline kind: {kind}")

    window = offset + limit

    # COUNT per searched kind — the honest totals, using the SAME filtered
    # WHERE the fetchers use (so total and page agree).
    totals: dict[str, int] = {k: 0 for k in ("event", "finding", "session", "ioc", "investigation")}

    if kind in (None, "event"):
        totals["event"] = _count_events(conn, host_id, event_type=event_type, q=q)
    if kind in (None, "finding"):
        totals["finding"] = _count_findings(conn, host_id, q=q)
    if kind in (None, "session"):
        totals["session"] = _count_sessions(conn, host_id, q=q)
    if kind in (None, "ioc"):
        totals["ioc"] = _count_iocs(conn, host_id, q=q)
    if kind in (None, "investigation"):
        totals["investigation"] = _count_investigations(conn, host_id, q=q)

    total = sum(totals.values())

    # Fetch the page window per kind, then merge chronologically.
    entries: list[dict[str, Any]] = []
    if kind in (None, "event"):
        for r in _events_for_host(conn, host_id, event_type=event_type, q=q, limit=window):
            entries.append(
                {
                    "kind": "event",
                    "timestamp": r["timestamp"],
                    "id": str(r["id"]),
                    "title": r["event_type"].replace("_", " "),
                    "subtitle": r["process_name"] or r["command_line"] or r["dest_ip"] or None,
                    "payload": {
                        "event_id": r["id"],
                        "run_id": r["run_id"],
                        "event_type": r["event_type"],
                        "pid": r["pid"],
                        "process_name": r["process_name"],
                        "command_line": r["command_line"],
                        "dest_ip": r["dest_ip"],
                        "file_path": r["file_path"],
                        "registry_key": r["registry_key"],
                        "host_id": r["host_id"],
                    },
                }
            )
    if kind in (None, "finding"):
        for r in _findings_for_host(conn, host_id, q=q, limit=window):
            entries.append(
                {
                    "kind": "finding",
                    "timestamp": r["triggered_at"],
                    "id": str(r["id"]),
                    "title": r["rule_name"],
                    "subtitle": f"{r['severity']} · {r['status']} · {r['sample_name'] or r['run_id']}",
                    "payload": {
                        "alert_id": r["id"],
                        "run_id": r["run_id"],
                        "severity": r["severity"],
                        "status": r["status"],
                        "related_ip": r["related_ip"],
                        "investigation_id": r["investigation_id"],
                        "triggered_at": r["triggered_at"],
                    },
                }
            )
    if kind in (None, "session"):
        for r in _sessions_for_host(conn, host_id, q=q, limit=window):
            entries.append(
                {
                    "kind": "session",
                    "timestamp": r["started_at"],
                    "id": r["run_id"],
                    "title": r["sample_name"] or r["run_id"],
                    "subtitle": f"{r['kind']} · {r['platform']} · {'completed' if r['completed_at'] else 'active'}",
                    "payload": {
                        "run_id": r["run_id"],
                        "kind": r["kind"],
                        "session_type": r["session_type"],
                        "platform": r["platform"],
                        "started_at": r["started_at"],
                        "completed_at": r["completed_at"],
                        "source": r["source"],
                    },
                }
            )
    if kind in (None, "ioc"):
        for r in _iocs_for_host(conn, host_id, q=q, limit=window):
            entries.append(
                {
                    "kind": "ioc",
                    "timestamp": r["first_seen"],
                    "id": r["ioc_id"],
                    "title": r["value"],
                    "subtitle": f"{r['type']} · {r['disposition']} · {r['ref_count']} refs",
                    "payload": {
                        "ioc_id": r["ioc_id"],
                        "value": r["value"],
                        "type": r["type"],
                        "disposition": r["disposition"],
                        "reputation": r["reputation"],
                        "first_seen": r["first_seen"],
                    },
                }
            )
    if kind in (None, "investigation"):
        for r in _investigations_for_host(conn, host_id, q=q, limit=window):
            entries.append(
                {
                    "kind": "investigation",
                    "timestamp": r["created_at"],
                    "id": r["id"],
                    "title": r["title"],
                    "subtitle": f"{r['status']} · {r['finding_count']} findings",
                    "payload": {
                        "investigation_id": r["id"],
                        "status": r["status"],
                        "severity": r["severity"],
                        "created_at": r["created_at"],
                        "updated_at": r["updated_at"],
                        "closed_at": r["closed_at"],
                        "finding_count": r["finding_count"],
                    },
                }
            )

    # Chronological merge, descending by timestamp (newest first). Ties break
    # by kind rank then id for a stable order.
    entries.sort(key=lambda e: (e["timestamp"], _KIND_RANK.get(e["kind"], 9), e["id"]), reverse=True)
    page = entries[offset : offset + limit]

    return {
        "host_id": host_id,
        "platform": _host_platform(conn, host_id),
        "last_heartbeat": _host_last_heartbeat(conn, host_id),
        "total": total,
        "limit": limit,
        "offset": offset,
        "timeline": page,
    }

