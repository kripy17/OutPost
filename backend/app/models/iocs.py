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
    insert returns the EXISTING row unchanged (dedupe, not an error).

    Since detection auto-populates entities (P3.1), an analyst POST may land
    on a row the engine already created. The response stays the canonical
    entity either way, and an analyst label backfills onto it when none is
    set — the label must not vanish just because detection saw the value
    first."""
    normalized = normalize_value(value, ioc_type)
    now = _now()
    cur = conn.execute(
        "INSERT OR IGNORE INTO iocs (ioc_id, value, type, disposition, label, first_seen, last_seen, source) "
        "VALUES (?, ?, ?, 'candidate', ?, ?, ?, 'analyst')",
        (uuid.uuid4().hex[:12], normalized, ioc_type, (label or "").strip() or None, now, now),
    )
    row = conn.execute(
        "SELECT * FROM iocs WHERE value = ? AND type = ?", (normalized, ioc_type)
    ).fetchone()
    if cur.rowcount == 0 and (label or "").strip():
        conn.execute(
            "UPDATE iocs SET label = ? WHERE ioc_id = ? AND label IS NULL",
            (label.strip(), row["ioc_id"]),
        )
        row = conn.execute("SELECT * FROM iocs WHERE ioc_id = ?", (row["ioc_id"],)).fetchone()
    return dict(row)


def observe_ioc(conn: sqlite3.Connection, value: str, ioc_type: IocType, source: str = "detection") -> dict:
    """Detection-side observation of an indicator: insert-or-reuse by the
    canonical identity, stamping the observation source and bumping
    `last_seen` on reuse. The manual API keeps `create_ioc` (analyst source,
    label support); this path is for what the engine itself saw."""
    normalized = normalize_value(value, ioc_type)
    now = _now()
    cur = conn.execute(
        "INSERT OR IGNORE INTO iocs (ioc_id, value, type, disposition, label, first_seen, last_seen, source) "
        "VALUES (?, ?, ?, 'candidate', NULL, ?, ?, ?)",
        (uuid.uuid4().hex[:12], normalized, ioc_type, now, now, source),
    )
    ioc = dict(
        conn.execute("SELECT * FROM iocs WHERE value = ? AND type = ?", (normalized, ioc_type)).fetchone()
    )
    if cur.rowcount == 0:
        conn.execute("UPDATE iocs SET last_seen = ? WHERE ioc_id = ?", (now, ioc["ioc_id"]))
        ioc["last_seen"] = now
    return ioc


def add_provenance(conn: sqlite3.Connection, ioc_id: str, ref_type: str, ref_id: int | str) -> None:
    """Record where an IOC was observed (event / finding / artifact ref).
    Idempotent on UNIQUE(ioc_id, ref_type, ref_id)."""
    conn.execute(
        "INSERT OR IGNORE INTO ioc_provenance (ioc_id, ref_type, ref_id, first_seen) VALUES (?, ?, ?, ?)",
        (ioc_id, ref_type, str(ref_id), _now()),
    )


def link_finding(conn: sqlite3.Connection, ioc_id: str, finding_id: int) -> None:
    """Persist the finding ↔ IOC relationship. Idempotent on the PK."""
    conn.execute(
        "INSERT OR IGNORE INTO ioc_findings (ioc_id, finding_id) VALUES (?, ?)",
        (ioc_id, int(finding_id)),
    )


def purge_for_runs(conn: sqlite3.Connection, run_ids: list[str]) -> dict:
    """Retention/reset cleanup for IOC linkage tied to doomed runs.

    Removes finding links and provenance rows pointing at the runs'
    findings/events — BEFORE those tables are pruned, since ioc_findings
    carries a real FK to alerts. Then drops detection-derived candidate
    entities left with no provenance at all: they were derived telemetry,
    their source is gone. Analyst-created or dispositioned entities survive
    (an analyst decision is evidence, not derived data).
    """
    if not run_ids:
        return {}
    marks = ",".join("?" * len(run_ids))
    counts: dict[str, int] = {}
    counts["ioc_findings"] = conn.execute(
        f"DELETE FROM ioc_findings WHERE finding_id IN "
        f"(SELECT id FROM alerts WHERE run_id IN ({marks}))",
        run_ids,
    ).rowcount
    counts["provenance"] = (
        conn.execute(
            f"DELETE FROM ioc_provenance WHERE ref_type = 'finding' AND ref_id IN "
            f"(SELECT CAST(id AS TEXT) FROM alerts WHERE run_id IN ({marks}))",
            run_ids,
        ).rowcount
        + conn.execute(
            f"DELETE FROM ioc_provenance WHERE ref_type = 'event' AND ref_id IN "
            f"(SELECT CAST(id AS TEXT) FROM events WHERE run_id IN ({marks}))",
            run_ids,
        ).rowcount
    )
    counts["orphaned_iocs"] = conn.execute(
        "DELETE FROM iocs WHERE source = 'detection' AND disposition = 'candidate' "
        "AND NOT EXISTS (SELECT 1 FROM ioc_provenance p WHERE p.ioc_id = iocs.ioc_id)"
    ).rowcount
    return counts


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
