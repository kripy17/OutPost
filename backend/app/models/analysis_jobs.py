"""Persisted analysis-job data access (P0.2) — the `analysis_jobs` table.

`run_id` is the job id (PK → runs). The table persists job state across
backend restarts — the pre-P0 sandbox tasks were in-memory only; these rows
are the durable record. Job status follows queued → running → completed /
failed / canceled (cancel is only legal from queued/running).
"""

import json
import sqlite3
from datetime import datetime, timezone

QUEUED = "queued"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
CANCELED = "canceled"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_result(d: dict) -> dict:
    if d.get("result") and not isinstance(d["result"], dict):
        try:
            d["result"] = json.loads(d["result"])
        except (ValueError, TypeError):
            d["result"] = None
    return d


def create_job(
    conn: sqlite3.Connection,
    run_id: str,
    backend: str,
    *,
    status: str = QUEUED,
    timeout_seconds: int | None = None,
    started_at: str | None = None,
    finished_at: str | None = None,
    result: dict | None = None,
    progress: int = 0,
) -> dict:
    conn.execute(
        "INSERT INTO analysis_jobs (run_id, backend, status, timeout_seconds, started_at, finished_at, error, progress, result) "
        "VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)",
        (
            run_id, backend, status, timeout_seconds, started_at, finished_at,
            progress, json.dumps(result) if result is not None else None,
        ),
    )
    return get_job(conn, run_id)


def get_job(conn: sqlite3.Connection, run_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM analysis_jobs WHERE run_id = ?", (run_id,)).fetchone()
    return _parse_result(dict(row)) if row else None


def list_jobs(
    conn: sqlite3.Connection,
    backend: str | None = None,
    status: str | None = None,
    run_ids: list[str] | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[int, list[dict]]:
    where: list[str] = []
    params: list = []
    if backend:
        where.append("backend = ?")
        params.append(backend)
    if status:
        where.append("status = ?")
        params.append(status)
    if run_ids:
        marks = ",".join("?" * len(run_ids))
        where.append(f"run_id IN ({marks})")
        params += run_ids
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM analysis_jobs {where_sql}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM analysis_jobs {where_sql} ORDER BY started_at DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    return total, [_parse_result(dict(r)) for r in rows]


def set_status(
    conn: sqlite3.Connection,
    run_id: str,
    status: str,
    *,
    error: str | None = None,
    progress: int | None = None,
    result: dict | None = None,
) -> dict | None:
    """Transition a job's status, stamping finished_at on terminal states.
    `result` (when given) replaces the JSON payload — the terminal write that
    persists the executor's output alongside the final status. Returns the
    updated row (None when the job doesn't exist)."""
    sets = ["status = ?"]
    values: list = [status]
    if status in (COMPLETED, FAILED, CANCELED):
        sets.append("finished_at = ?")
        values.append(_now())
    if error is not None:
        sets.append("error = ?")
        values.append(error)
    if progress is not None:
        sets.append("progress = ?")
        values.append(progress)
    if result is not None:
        sets.append("result = ?")
        values.append(json.dumps(result))
    cur = conn.execute(
        f"UPDATE analysis_jobs SET {', '.join(sets)} WHERE run_id = ?", [*values, run_id]
    )
    if cur.rowcount == 0:
        return None
    return get_job(conn, run_id)
