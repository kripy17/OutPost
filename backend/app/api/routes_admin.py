"""Retention & backup (Tier-1 gap #3) — the store can't grow forever.

- GET /admin/retention          — current retention (0 = keep forever) + the
                                  auto-prune schedule and next-run estimate
- POST /admin/retention         — set retention days and/or the auto-prune
                                  schedule (off / hourly / daily)
- POST /admin/prune             — delete runs (and their events/alerts/notes/
                                  allowlists) older than N days; uses the
                                  stored retention when no days are given
- POST /admin/backfill-channels  — stamp log_source on legacy collector
                                  events (the startup migration, on demand)
- GET  /admin/backup            — download a SQLite backup of the whole store
- POST /admin/restore           — replace the store from an uploaded backup
                                  (a safety copy of the pre-restore DB is kept)

With a schedule set, a background loop (started in main.py's lifespan, tick
interval AUTO_PRUNE_TICK_SECONDS) runs the prune automatically — no restart
needed. All mutations land in the audit trail. With auth on,
retention/prune/restore require the admin role (analyst is read-only anyway);
backup is readable by any authenticated role.
"""

import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from ..core import auth
from ..core.config import DATA_DIR, DATABASE_PATH, DATABASE_URL
from ..core.db import _backfill_events_log_source, db_session, init_db
from ..models import audit
from ..models import iocs as iocs_store

router = APIRouter(tags=["admin"])

RETENTION_KEY = "RETENTION_DAYS"
AUTO_PRUNE_SCHEDULE_KEY = "AUTO_PRUNE_SCHEDULE"
AUTO_PRUNE_LAST_RUN_KEY = "AUTO_PRUNE_LAST_RUN"
_SCHEDULES = ("off", "hourly", "daily")
AUTO_PRUNE_TICK_SECONDS = 60  # loop wake-up; the schedule decides actual runs
_SQLITE_MAGIC = b"SQLite format 3\x00"


def _actor(request: Request) -> str:
    return auth.role_from_request(request)


def _require_admin(request: Request) -> str:
    """Admin-only mutations: with auth on only the admin role passes; with the
    zero-config default everything is 'local' and allowed."""
    actor = _actor(request)
    if auth.auth_enabled() and actor != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return actor


def _retention_days(conn) -> int:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (RETENTION_KEY,)).fetchone()
    try:
        return max(0, int(row["value"])) if row else 0
    except (TypeError, ValueError):
        return 0


def _auto_prune_schedule(conn) -> str:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (AUTO_PRUNE_SCHEDULE_KEY,)).fetchone()
    schedule = row["value"] if row else "off"
    return schedule if schedule in _SCHEDULES else "off"


def _setting(conn, key: str) -> str | None:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def _interval_seconds(schedule: str) -> int:
    return 3600 if schedule == "hourly" else 86400


# -- Retention -----------------------------------------------------------------


@router.get("/admin/retention", response_model=None)
def get_retention() -> dict:
    """Current retention window, the auto-prune schedule, and — when enabled —
    an estimate of when the next automatic prune runs."""
    with db_session() as conn:
        schedule = _auto_prune_schedule(conn)
        last = _setting(conn, AUTO_PRUNE_LAST_RUN_KEY)
        next_in = None
        if schedule != "off" and _retention_days(conn) > 0:
            last_dt = None
            if last:
                try:
                    last_dt = datetime.fromisoformat(last)
                except ValueError:
                    last_dt = None
            elapsed = (datetime.now(timezone.utc) - last_dt).total_seconds() if last_dt else None
            next_in = max(0, int(_interval_seconds(schedule) - (elapsed if elapsed is not None else 0)))
        return {
            "retention_days": _retention_days(conn),
            "auto_prune": schedule,
            "auto_prune_enabled": schedule != "off",
            "last_prune_at": last,
            "next_prune_in_seconds": next_in,
        }


class RetentionIn(BaseModel):
    retention_days: int = 0
    auto_prune: str = "off"


@router.post("/admin/retention", response_model=None)
def set_retention(body: RetentionIn, request: Request) -> dict:
    """Set the retention window in days (0 keeps everything) and the
    auto-prune schedule: off (manual only), hourly, or daily. The background
    loop picks the change up on its next tick — no restart needed."""
    if body.retention_days < 0:
        raise HTTPException(status_code=422, detail="retention_days must be >= 0")
    if body.auto_prune not in _SCHEDULES:
        raise HTTPException(status_code=422, detail=f"auto_prune must be one of {_SCHEDULES}")
    _require_admin(request)
    with db_session() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (RETENTION_KEY, str(body.retention_days)),
        )
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (AUTO_PRUNE_SCHEDULE_KEY, body.auto_prune),
        )
        audit.log(
            conn, _actor(request), "retention.prune",
            target_type="settings", target_id=RETENTION_KEY,
            detail=f"retention set to {body.retention_days}d · auto-prune {body.auto_prune}",
        )
    return {"retention_days": body.retention_days, "auto_prune": body.auto_prune}


class PruneIn(BaseModel):
    days: int | None = None


@router.post("/admin/backfill-channels", response_model=None)
def backfill_channels(request: Request) -> dict:
    """Stamp `log_source` on legacy collector events WITHOUT a restart — the
    same idempotent inference the startup migration runs (linux live-run
    events with a real host → auditd, windows → sysmon; webapp-'local'
    events are never touched). Returns how many events were newly tagged;
    once the channel data is complete it returns 0, so the command doubles
    as a health check. Admin-only when auth is on; audited."""
    actor = _require_admin(request)
    with db_session() as conn:
        updated = _backfill_events_log_source(conn)
        audit.log(
            conn,
            actor,
            "admin.backfill-channels",
            target_type="events",
            detail=f"{updated} event(s) stamped" if updated else "no legacy events to stamp (channels complete)",
        )
    return {"updated": updated}


def _prune(conn, days: int, actor: str) -> dict:
    """Shared prune implementation — used by the manual endpoint and the
    background auto-prune loop. Returns the result dict; raises 422-ish
    ValueError when retention is 0."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    doomed = [r["run_id"] for r in conn.execute(
        "SELECT run_id FROM runs WHERE started_at < ?", (cutoff,)
    ).fetchall()]
    if not doomed:
        audit.log(conn, actor, "retention.prune", target_type="runs", detail=f"nothing older than {days}d")
        return {"deleted_runs": 0, "days": days, "cutoff": cutoff}

    placeholders = ",".join("?" * len(doomed))
    counts = {}
    # IOC linkage first — ioc_findings has an FK into alerts, and provenance
    # would otherwise outlive the evidence it points at (P3.1).
    counts.update(iocs_store.purge_for_runs(conn, doomed))
    for table, pk in (
        ("events", "run_id"),
        ("alerts", "run_id"),
        ("run_notes", "run_id"),
        ("watchlist_hits", "run_id"),
        ("run_allowlist", "run_id"),
    ):
        cur = conn.execute(f"DELETE FROM {table} WHERE {pk} IN ({placeholders})", doomed)
        counts[table] = cur.rowcount
    cur = conn.execute(f"DELETE FROM runs WHERE run_id IN ({placeholders})", doomed)
    counts["runs"] = cur.rowcount
    audit.log(
        conn, actor, "retention.prune",
        target_type="runs", target_id=f"{len(doomed)} runs",
        detail=f"older than {days}d (cutoff {cutoff}) · {counts}",
    )
    return {"deleted_runs": len(doomed), "days": days, "cutoff": cutoff, "rows": counts}


@router.post("/admin/prune", response_model=None)
def prune(body: PruneIn, request: Request) -> dict:
    """Delete runs older than N days (falling back to the stored retention),
    cascading through events, alerts, notes, watchlist hits, and allowlists.
    Samples in the vault are untouched — only session telemetry ages out."""
    actor = _require_admin(request)
    with db_session() as conn:
        days = body.days if body.days is not None else _retention_days(conn)
        if days <= 0:
            raise HTTPException(status_code=422, detail="retention is 0 (keep forever) — set retention days or pass ?days=")
        return _prune(conn, days, actor)


# -- Auto-prune background loop ------------------------------------------------


def _maybe_auto_prune() -> dict | None:
    """One scheduler tick — run the prune if the schedule says so and the
    interval has elapsed. Safe to call from tests directly."""
    with db_session() as conn:
        schedule = _auto_prune_schedule(conn)
        if schedule == "off":
            return None
        days = _retention_days(conn)
        if days <= 0:
            return None  # keep-forever — nothing to prune
        last = _setting(conn, AUTO_PRUNE_LAST_RUN_KEY)
        now = datetime.now(timezone.utc)
        if last:
            try:
                last_dt = datetime.fromisoformat(last)
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=timezone.utc)
                if (now - last_dt).total_seconds() < _interval_seconds(schedule):
                    return None
            except ValueError:
                pass  # corrupt timestamp — treat as never run
        result = _prune(conn, days, "system")
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (AUTO_PRUNE_LAST_RUN_KEY, now.isoformat()),
        )
        return result


async def auto_prune_loop() -> None:
    """Background task (started by main.py's lifespan) that wakes every
    AUTO_PRUNE_TICK_SECONDS and lets _maybe_auto_prune decide. Never crashes
    the app: a bad prune is logged and the loop keeps ticking."""
    while True:
        try:
            _maybe_auto_prune()
        except Exception:
            pass
        await asyncio.sleep(AUTO_PRUNE_TICK_SECONDS)


# -- Backup / restore -----------------------------------------------------------


@router.get("/admin/backup", response_model=None)
def backup(request: Request) -> FileResponse:
    """Stream a consistent SQLite backup (the online-backup API, safe while
    the server is running). Named outpost-backup-<ts>.db for restores."""
    _actor(request)  # requires a valid session when auth is on
    if DATABASE_URL:
        raise HTTPException(
            status_code=400,
            detail="Backup is SQLite-only — on a Postgres deployment use pg_dump (docs/16).",
        )
    tmp = DATA_DIR / f"outpost-backup-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.db"
    src = sqlite3.connect(DATABASE_PATH)
    dst = sqlite3.connect(tmp)
    with dst:
        src.backup(dst)
    dst.close()
    src.close()
    with db_session() as conn:
        audit.log(conn, _actor(request), "backup.create", target_type="store", detail=f"→ {tmp.name}")
    return FileResponse(tmp, media_type="application/octet-stream", filename=tmp.name)


@router.post("/admin/restore", response_model=None)
async def restore(request: Request) -> dict:
    """Replace the store from an uploaded backup. The client sends the raw
    .db bytes (`Content-Type: application/octet-stream`) — no multipart
    dependency needed. The current DB is safety-copied to
    data/outpost-backup-pre-restore-<ts>.db first; the uploaded file is
    validated as SQLite before it replaces the live one, and the schema is
    re-initialized (idempotent migrations) on the restored store."""
    actor = _require_admin(request)
    data = await request.body()
    if DATABASE_URL:
        raise HTTPException(
            status_code=400,
            detail="Restore is SQLite-only — on a Postgres deployment use pg_restore (docs/16).",
        )
    if not data.startswith(_SQLITE_MAGIC):
        raise HTTPException(status_code=422, detail="Not a SQLite database file")
    db_path = Path(DATABASE_PATH)
    original = db_path.read_bytes() if db_path.exists() else b""

    # Checkpoint + close current state so the swap is clean (no stray -wal).
    try:
        with sqlite3.connect(DATABASE_PATH) as c:
            c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.Error:
        pass  # journal mode may not be WAL — the file copy below is still fine

    # Safety copy of the pre-restore store (copy, not move — the live DB stays
    # in place until the new bytes are written; a failed swap never orphans it).
    safety = DATA_DIR / f"outpost-backup-pre-restore-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.db"
    if original:
        safety.write_bytes(original)
    for suffix in ("-wal", "-shm"):
        side = Path(f"{db_path}{suffix}")
        if side.exists():
            side.unlink()

    db_path.write_bytes(data)
    try:
        init_db()  # apply any schema migrations the backup predates
    except Exception:
        # The uploaded store is bad — put the original bytes back.
        db_path.write_bytes(original or data)
        raise HTTPException(status_code=422, detail="Backup failed to initialize — restored the previous store")

    with db_session() as conn:
        audit.log(conn, actor, "restore.apply", target_type="store", detail=f"safety copy → {safety.name}")
    return {"restored": True, "safety_copy": safety.name, "size": len(data)}
