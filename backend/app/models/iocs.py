"""IOC entity data access (P0.2) — the canonical `iocs` table plus its
provenance / finding links.

Identity is `UNIQUE(value, type)` after normalization (lowercase + strip for
ip/domain/hash/email — the case-insensitive indicator kinds; everything else
is stripped only). Runs and hosts on the detail payload are DERIVED from
provenance refs — never fabricated: an event ref resolves to its run via
`events`, a finding ref via `alerts`, and an artifact ref is reported as the
(deferred) sample id only, since P0 defers the artifacts table.
"""

import sqlite3
import uuid
from datetime import datetime, timezone

from ..core.schema import IocType

_CASE_INSENSITIVE_TYPES = {"ip", "domain", "hash", "email"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_value(value: str, ioc_type: str) -> str:
    """The P0 normalization rule: lowercase + strip for ip/domain/hash/email,
    strip only for the rest."""
    value = value.strip()
    if ioc_type in _CASE_INSENSITIVE_TYPES:
        return value.lower()
    return value


def create_ioc(conn: sqlite3.Connection, value: str, ioc_type: IocType, label: str | None = None) -> dict:
    """Insert a normalized IOC; idempotent on UNIQUE(value, type) — a repeat
    insert returns the EXISTING row unchanged (dedupe, not an error)."""
    normalized = normalize_value(value, ioc_type)
    now = _now()
    conn.execute(
        "INSERT OR IGNORE INTO iocs (ioc_id, value, type, disposition, label, first_seen, last_seen, source) "
        "VALUES (?, ?, ?, 'candidate', ?, ?, ?, 'analyst')",
        (uuid.uuid4().hex[:12], normalized, ioc_type, (label or "").strip() or None, now, now),
    )
    row = conn.execute(
        "SELECT * FROM iocs WHERE value = ? AND type = ?", (normalized, ioc_type)
    ).fetchone()
    return dict(row)


def get_ioc(conn: sqlite3.Connection, ioc_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM iocs WHERE ioc_id = ?", (ioc_id,)).fetchone()
    return dict(row) if row else None


def list_iocs(
    conn: sqlite3.Connection,
    q: str = "",
    ioc_type: str | None = None,
    disposition: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[int, list[dict]]:
    """Paged IOC search over the entity. `q` matches value/type/label; `type`
    and `disposition` are exact filters. Escaped LIKE (literal matching)."""
    where: list[str] = []
    params: list = []
    if q:
        escaped = q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like = f"%{escaped}%"
        where.append("(value LIKE ? ESCAPE '\\' OR type LIKE ? ESCAPE '\\' OR label LIKE ? ESCAPE '\\')")
        params.extend([like] * 3)
    if ioc_type:
        where.append("type = ?")
        params.append(ioc_type)
    if disposition:
        where.append("disposition = ?")
        params.append(disposition)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM iocs {where_sql}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM iocs {where_sql} ORDER BY first_seen DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    return total, [dict(r) for r in rows]


def set_disposition(
    conn: sqlite3.Connection, ioc_id: str, disposition: str, label: str | None = None
) -> dict | None:
    """Apply an analyst verdict + optional label. Returns the updated row (or
    None when the IOC doesn't exist). Callers audit the mutation."""
    sets = ["disposition = ?", "last_seen = ?"]
    values: list = [disposition, _now()]
    if label is not None:
        sets.append("label = ?")
        values.append(label.strip() or None)
    cur = conn.execute(
        f"UPDATE iocs SET {', '.join(sets)} WHERE ioc_id = ?", [*values, ioc_id]
    )
    if cur.rowcount == 0:
        return None
    return dict(conn.execute("SELECT * FROM iocs WHERE ioc_id = ?", (ioc_id,)).fetchone())


def provenance_rows(conn: sqlite3.Connection, ioc_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT ref_type, ref_id, first_seen FROM ioc_provenance WHERE ioc_id = ? ORDER BY first_seen ASC",
        (ioc_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def linked_findings(conn: sqlite3.Connection, ioc_id: str) -> list[dict]:
    from .event import _parse_related_pids

    rows = conn.execute(
        """
        SELECT a.*, r.sample_name
        FROM ioc_findings f
        JOIN alerts a ON a.id = f.finding_id
        JOIN runs r ON r.run_id = a.run_id
        WHERE f.ioc_id = ?
        ORDER BY a.triggered_at ASC
        """,
        (ioc_id,),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        _parse_related_pids(d)
        out.append(d)
    return out


def related_runs(conn: sqlite3.Connection, ioc_id: str) -> list[dict]:
    """Runs that observed this IOC — derived ONLY from provenance refs:
    event refs resolve through `events.run_id`, finding refs through
    `alerts.run_id`. No provenance → no runs (nothing is fabricated)."""
    run_ids: set[str] = set()
    for p in provenance_rows(conn, ioc_id):
        if p["ref_type"] == "event":
            row = conn.execute("SELECT run_id FROM events WHERE id = ?", (p["ref_id"],)).fetchone()
            if row:
                run_ids.add(row["run_id"])
        elif p["ref_type"] == "finding":
            row = conn.execute("SELECT run_id FROM alerts WHERE id = ?", (p["ref_id"],)).fetchone()
            if row:
                run_ids.add(row["run_id"])
        # ref_type == 'artifact' is the deferred artifacts table — the ref_id
        # is a sample id; run linkage would be fabricated, so it is skipped.
    if not run_ids:
        return []
    marks = ",".join("?" * len(run_ids))
    rows = conn.execute(
        f"SELECT run_id, sample_name, platform, started_at FROM runs WHERE run_id IN ({marks}) ORDER BY started_at DESC",
        sorted(run_ids),
    ).fetchall()
    return [dict(r) for r in rows]


def related_hosts(conn: sqlite3.Connection, ioc_id: str) -> list[str]:
    """Hosts whose events touched the IOC's runs — the distinct host_ids of
    the derived runs' events (empty when the IOC has no event provenance)."""
    runs = related_runs(conn, ioc_id)
    if not runs:
        return []
    marks = ",".join("?" * len(runs))
    rows = conn.execute(
        f"SELECT DISTINCT host_id FROM events WHERE run_id IN ({marks}) AND host_id IS NOT NULL ORDER BY host_id",
        [r["run_id"] for r in runs],
    ).fetchall()
    return [r["host_id"] for r in rows]
