"""Ingestion endpoints.

- POST /ingest/batch        — validate, store, run detection on every event
- POST /runs                — create a run (live or analysis), return run_id
- POST /runs/{id}/complete  — mark complete; trigger tree build + enrichment
"""

import asyncio
import uuid

import httpx
from fastapi import APIRouter, HTTPException

from ..core.db import db_session
from ..core.schema import Alert, EventIn, RunCreate
from ..models import event as event_store
from ..models import run as run_store
from ..services import detection
from ..services import normalizer

router = APIRouter(tags=["ingest"])


@router.post("/ingest/batch", status_code=202)
async def ingest_batch(events: list[EventIn]) -> dict:
    """Accept a batch of events, store them, and run detection on each."""
    if not events:
        return {"accepted": 0, "alerts": 0}

    # A batch must belong to exactly one run (collectors ship per-run batches).
    run_ids = {e.run_id for e in events}
    if len(run_ids) != 1:
        raise HTTPException(status_code=422, detail="All events in a batch must share one run_id")
    run_id = next(iter(run_ids))

    accepted = 0
    new_alerts: list[Alert] = []
    watchlist_matches: list[dict] = []
    run_meta: dict = {}
    with db_session() as conn:
        # A run must exist before events are stored (FK constraint).
        run_row = run_store.get_run(conn, run_id)
        if not run_row:
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        run_meta = {"sample_name": run_row["sample_name"], "platform": run_row["platform"]}

        # Dedup on a natural key: a collector retry (or a duplicated line in
        # the source feed) must not double-store an event — otherwise
        # beaconing/rename-burst windows count the same connection/write twice
        # and can false-fire. Keys already stored for this run (one query,
        # bounded to rows at least as new as the batch's oldest event so a
        # long live session never re-hashes its whole history per batch) plus
        # anything seen earlier in this batch are dropped before storage AND
        # before detection.
        # The store keeps timestamps as ISO strings (mode="json"), so derive
        # the bound in that exact format — binding a datetime object would
        # trip sqlite3's deprecated datetime adapter on Python 3.12+.
        batch_min_ts = min((e.model_dump(mode="json")["timestamp"] for e in events), default=None)
        if batch_min_ts is not None:
            rows = conn.execute(
                "SELECT event_type, timestamp, pid, process_name, command_line, "
                "dest_ip, dest_port, file_path, registry_key FROM events "
                "WHERE run_id = ? AND timestamp >= ?",
                (run_id, batch_min_ts),
            ).fetchall()
            seen = {
                (r["event_type"], r["timestamp"], r["pid"], r["process_name"], r["command_line"],
                 r["dest_ip"], r["dest_port"], r["file_path"], r["registry_key"])
                for r in rows
            }
        else:
            seen = set()
        stored_events: list[dict] = []
        for event_in in events:
            # mode="json" serializes datetimes to ISO strings — sqlite-safe.
            normalized = normalizer.normalize_event(event_in.model_dump(mode="json"))
            key = (
                normalized.get("event_type"),
                normalized.get("timestamp"),
                normalized.get("pid"),
                normalized.get("process_name"),
                normalized.get("command_line"),
                normalized.get("dest_ip"),
                normalized.get("dest_port"),
                normalized.get("file_path"),
                normalized.get("registry_key"),
            )
            if key in seen:
                continue
            seen.add(key)
            event_store.insert_event(conn, normalized)
            stored_events.append(normalized)
            accepted += 1

        # Detection runs on the stored (deduped, normalized) batch — this is
        # what makes live monitoring actually "live" (docs/02).
        new_alerts = detection.evaluate_batch(conn, run_id, stored_events)

        # Live watchlist alerting: any stored event whose value (IP, process,
        # file path, registry key) matches a watchlist entry is a hit — fired
        # from the same session so the read is consistent with the batch.
        # First-seen-per-run dedup: only *new* (run, ioc) hits dispatch, so a
        # live session that keeps touching a watched IP alerts once, not per
        # batch (the session commit persists the watchlist_hits rows).
        from ..models import watchlist as watchlist_store

        watchlist_matches = watchlist_store.record_hits(
            conn, run_id, watchlist_store.match_events(conn, stored_events)
        )

    # Roadmap 3.1 — fire-and-forget webhook for malicious alerts. Dispatched
    # as a background task so ingestion never waits on a slow/unreachable
    # webhook, and runs after the transaction commits so a failure can't
    # roll back ingestion.
    from ..services import notifications as notify

    async def _dispatch() -> None:
        try:
            await notify.notify_new_alerts(new_alerts)
        except Exception:
            pass  # notification failure must never surface into ingestion

    asyncio.create_task(_dispatch())

    # Watchlist hits — same webhook channel, distinct `outpost.watchlist`
    # event, fired the moment a watched IOC appears in a new batch.
    async def _dispatch_watchlist() -> None:
        try:
            await notify.notify_watchlist_hits(
                run_id, run_meta["sample_name"], run_meta["platform"], watchlist_matches
            )
        except Exception:
            pass  # notification failure must never surface into ingestion

    if watchlist_matches:
        asyncio.create_task(_dispatch_watchlist())

    # Live SSE push — fan out to open /events/stream connections (no-op when
    # nobody is listening; the webapp polls as its fallback).
    from ..services import events_stream

    events_stream.publish_alerts(new_alerts)
    if watchlist_matches:
        events_stream.publish_watchlist(
            run_id, run_meta["sample_name"], run_meta["platform"], watchlist_matches
        )

    return {"accepted": accepted, "alerts": len(new_alerts)}


@router.post("/runs", status_code=201)
def create_run(body: RunCreate) -> dict:
    run_id = uuid.uuid4().hex[:12]
    with db_session() as conn:
        run_store.create_run(
            conn,
            run_id=run_id,
            sample_name=body.sample_name,
            platform=body.platform,
            session_type=body.session_type,
        )
    return {"run_id": run_id, "session_type": body.session_type}


@router.post("/runs/{run_id}/complete")
def complete_run(run_id: str) -> dict:
    with db_session() as conn:
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        run_store.complete_run(conn, run_id)
        summary = run_store.to_summary(conn, run_store.get_run(conn, run_id))
    return summary.model_dump()
