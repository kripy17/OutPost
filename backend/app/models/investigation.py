"""Investigation data access (P0.3) — the optional cross-workflow case anchor.

The four P0.1 tables (`investigations`, `investigation_notes`,
`investigation_tags`, `investigation_refs`) are the whole store: findings
stay in `alerts` (linked through `alerts.investigation_id`, never copied),
and refs are pointers (never copies). Severity is DERIVED from the attached
findings (max of the canonical suspicious/malicious vocabulary; NULL when no
findings are attached) — it is computed on read, not persisted redundantly.

Lifecycle: created → triage → active → contained → resolved → closed.
Close requires a conclusion; reopen returns to `active` and clears
`closed_at`. Forward-only transitions on PATCH; backward moves go through
close/reopen.
"""

import sqlite3
import uuid
from datetime import datetime, timezone

from ..core.schema import _SEVERITY_RANK

# Lifecycle order — forward-only transitions on PATCH (a backward move is a
# close/reopen decision, not a silent patch).
_STATUS_ORDER = ("created", "triage", "active", "contained", "resolved", "closed")
_REOPEN_TARGET = "active"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tags_for(conn: sqlite3.Connection, investigation_id: str) -> list[str]:
    rows = conn.execute(
        "SELECT tag FROM investigation_tags WHERE investigation_id = ? ORDER BY tag",
        (investigation_id,),
    ).fetchall()
    return [r["tag"] for r in rows]


def _normalize_tags(tags: list[str] | None) -> list[str]:
    """Lowercase, strip, dedupe, drop empties — the tag normalization rule."""
    if not tags:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for t in tags:
        t = (t or "").strip().lower()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def create(conn: sqlite3.Connection, title: str, created_by: str | None, tags: list[str] | None = None) -> dict:
    """Create an investigation in `created` state. Title is pre-validated by
    the route (non-blank); tags are normalized + deduped here."""
    inv_id = uuid.uuid4().hex[:12]
    now = _now()
    conn.execute(
        "INSERT INTO investigations (id, title, status, created_by, created_at, updated_at) "
        "VALUES (?, ?, 'created', ?, ?, ?)",
        (inv_id, title, created_by, now, now),
    )
    for tag in _normalize_tags(tags):
        conn.execute(
            "INSERT OR IGNORE INTO investigation_tags (investigation_id, tag) VALUES (?, ?)",
            (inv_id, tag),
        )
    return get(conn, inv_id)


def _derived_severity(conn: sqlite3.Connection, investigation_id: str) -> str | None:
    """Max severity of the attached findings (canonical vocabulary); NULL when
    no findings are attached. Deterministic on every read — never persisted."""
    rows = conn.execute(
        "SELECT DISTINCT a.severity FROM alerts a WHERE a.investigation_id = ?",
        (investigation_id,),
    ).fetchall()
    sevs = [r["severity"] for r in rows if r["severity"] in _SEVERITY_RANK]
    if not sevs:
        return None
    return max(sevs, key=lambda s: _SEVERITY_RANK[s])


def _hydrate(conn: sqlite3.Connection, row: dict) -> dict:
    """Attach the derived fields every investigation DTO carries: severity
    (derived), finding_count, ref_count, tags."""
    inv_id = row["id"]
    row["severity"] = _derived_severity(conn, inv_id)
    row["finding_count"] = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE investigation_id = ?", (inv_id,)
    ).fetchone()[0]
    row["ref_count"] = conn.execute(
        "SELECT COUNT(*) FROM investigation_refs WHERE investigation_id = ?", (inv_id,)
    ).fetchone()[0]
    row["tags"] = _tags_for(conn, inv_id)
    return row


def get(conn: sqlite3.Connection, investigation_id: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM investigations WHERE id = ?", (investigation_id,)
    ).fetchone()
    return _hydrate(conn, dict(row)) if row else None


def list_investigations(
    conn: sqlite3.Connection,
    status: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[int, list[dict]]:
    """Paged investigation list. `status` exact-filter; `q` searches title,
    tags, and notes (the searchable fields of the P0 model)."""
    where: list[str] = []
    params: list = []
    if status:
        where.append("i.status = ?")
        params.append(status)
    if q:
        like = f"%{q.strip()}%"
        where.append(
            "(i.title LIKE ? OR EXISTS (SELECT 1 FROM investigation_tags t "
            "WHERE t.investigation_id = i.id AND t.tag LIKE ?) "
            "OR EXISTS (SELECT 1 FROM investigation_notes n "
            "WHERE n.investigation_id = i.id AND n.note LIKE ?))"
        )
        params.extend([like, like, like])
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(
        f"SELECT COUNT(*) FROM investigations i {where_sql}", params
    ).fetchone()[0]
    rows = conn.execute(
        f"SELECT i.* FROM investigations i {where_sql} ORDER BY i.created_at DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    return total, [_hydrate(conn, dict(r)) for r in rows]


def update(
    conn: sqlite3.Connection,
    investigation_id: str,
    *,
    title: str | None = None,
    status: str | None = None,
    conclusion: str | None = None,
    tags: list[str] | None = None,
) -> dict:
    """Apply a PATCH: only the provided fields are written. `tags` replaces
    the tag set (normalized + deduped). `status` must be a legal forward (or
    same-state) transition — validated by the caller's policy check against
    the current row. `conclusion=None` here means "not provided"; explicit
    clear is not part of the P0 contract."""
    sets: list[str] = ["updated_at = ?"]
    values: list = [_now()]
    if title is not None:
        sets.append("title = ?")
        values.append(title)
    if status is not None:
        sets.append("status = ?")
        values.append(status)
    if conclusion is not None:
        sets.append("conclusion = ?")
        values.append(conclusion)
    conn.execute(
        f"UPDATE investigations SET {', '.join(sets)} WHERE id = ?",
        [*values, investigation_id],
    )
    if tags is not None:
        conn.execute(
            "DELETE FROM investigation_tags WHERE investigation_id = ?", (investigation_id,)
        )
        for tag in _normalize_tags(tags):
            conn.execute(
                "INSERT OR IGNORE INTO investigation_tags (investigation_id, tag) VALUES (?, ?)",
                (investigation_id, tag),
            )
    return get(conn, investigation_id)


def close(conn: sqlite3.Connection, investigation_id: str, conclusion: str) -> dict:
    """Close with a conclusion: status → closed, closed_at + updated_at now."""
    now = _now()
    conn.execute(
        "UPDATE investigations SET status = 'closed', conclusion = ?, closed_at = ?, updated_at = ? "
        "WHERE id = ?",
        (conclusion, now, now, investigation_id),
    )
    return get(conn, investigation_id)


def reopen(conn: sqlite3.Connection, investigation_id: str) -> dict:
    """Reopen a closed investigation on new evidence: status → active (the
    approved active lifecycle state), closed_at cleared, updated_at now."""
    now = _now()
    conn.execute(
        "UPDATE investigations SET status = ?, closed_at = NULL, updated_at = ? "
        "WHERE id = ?",
        (_REOPEN_TARGET, now, investigation_id),
    )
    return get(conn, investigation_id)


# -- refs --------------------------------------------------------------------


def add_ref(conn: sqlite3.Connection, investigation_id: str, ref_type: str, ref_id: str) -> dict | None:
    """Add one evidence ref (a pointer — never a copy). Idempotent on
    UNIQUE(investigation_id, ref_type, ref_id): a duplicate returns the
    existing ref unchanged. Returns the ref dict (or None if the
    investigation is gone)."""
    if not get(conn, investigation_id):
        return None
    conn.execute(
        "INSERT OR IGNORE INTO investigation_refs (investigation_id, ref_type, ref_id, added_at) "
        "VALUES (?, ?, ?, ?)",
        (investigation_id, ref_type, ref_id, _now()),
    )
    row = conn.execute(
        "SELECT investigation_id, ref_type, ref_id, added_at FROM investigation_refs "
        "WHERE investigation_id = ? AND ref_type = ? AND ref_id = ?",
        (investigation_id, ref_type, ref_id),
    ).fetchone()
    return dict(row) if row else None


def remove_ref(conn: sqlite3.Connection, investigation_id: str, ref_id: str) -> bool:
    """Remove every ref of this investigation pointing at ref_id. Returns
    True when at least one was removed."""
    cur = conn.execute(
        "DELETE FROM investigation_refs WHERE investigation_id = ? AND ref_id = ?",
        (investigation_id, ref_id),
    )
    return cur.rowcount > 0


def list_refs(conn: sqlite3.Connection, investigation_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT investigation_id, ref_type, ref_id, added_at FROM investigation_refs "
        "WHERE investigation_id = ? ORDER BY added_at ASC, id ASC",
        (investigation_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def ref_exists(conn: sqlite3.Connection, investigation_id: str, ref_type: str, ref_id: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM investigation_refs WHERE investigation_id = ? AND ref_type = ? AND ref_id = ?",
        (investigation_id, ref_type, ref_id),
    ).fetchone() is not None


# -- notes -------------------------------------------------------------------


def add_note(conn: sqlite3.Connection, investigation_id: str, note: str, actor: str) -> dict | None:
    """Append an analyst note. Returns the note dict (None if the
    investigation is gone)."""
    if not get(conn, investigation_id):
        return None
    now = _now()
    cur = conn.execute(
        "INSERT INTO investigation_notes (investigation_id, note, actor, created_at) "
        "VALUES (?, ?, ?, ?)",
        (investigation_id, note, actor, now),
    )
    row = conn.execute(
        "SELECT id, investigation_id, note, actor, created_at FROM investigation_notes WHERE id = ?",
        (cur.lastrowid,),
    ).fetchone()
    return dict(row) if row else None


def list_notes(conn: sqlite3.Connection, investigation_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT id, investigation_id, note, actor, created_at FROM investigation_notes "
        "WHERE investigation_id = ? ORDER BY created_at ASC, id ASC",
        (investigation_id,),
    ).fetchall()
    return [dict(r) for r in rows]


# -- findings -----------------------------------------------------------------


def attach_finding(conn: sqlite3.Connection, alert_id: int, investigation_id: str) -> None:
    """Attach a finding to an investigation (the finding lives in `alerts`;
    only the nullable link changes). Touches the investigation's updated_at."""
    conn.execute(
        "UPDATE alerts SET investigation_id = ? WHERE id = ?", (investigation_id, alert_id)
    )
    conn.execute(
        "UPDATE investigations SET updated_at = ? WHERE id = ?", (_now(), investigation_id)
    )


def detach_finding(conn: sqlite3.Connection, alert_id: int) -> str | None:
    """Detach the finding from whatever investigation it belonged to.
    Returns the previous investigation_id (for audit + updated_at touch), or
    None if it wasn't attached."""
    row = conn.execute(
        "SELECT investigation_id FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    prev = row["investigation_id"] if row else None
    if prev:
        conn.execute(
            "UPDATE alerts SET investigation_id = NULL WHERE id = ?", (alert_id,)
        )
        conn.execute(
            "UPDATE investigations SET updated_at = ? WHERE id = ?", (_now(), prev)
        )
    return prev


def finding_investigation(conn: sqlite3.Connection, alert_id: int) -> str | None:
    row = conn.execute(
        "SELECT investigation_id FROM alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    return row["investigation_id"] if row else None


def findings_for_investigation(conn: sqlite3.Connection, investigation_id: str) -> list[dict]:
    """The attached findings — the canonical alerts rows, never duplicated."""
    from .event import _parse_related_pids

    rows = conn.execute(
        "SELECT a.*, r.sample_name FROM alerts a "
        "JOIN runs r ON r.run_id = a.run_id "
        "WHERE a.investigation_id = ? ORDER BY a.triggered_at ASC, a.id ASC",
        (investigation_id,),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        _parse_related_pids(d)
        out.append(d)
    return out
