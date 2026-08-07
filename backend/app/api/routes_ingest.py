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
    with db_session() as conn:
        # A run must exist before events are stored (FK constraint).
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")

        for event_in in events:
            # mode="json" serializes datetimes to ISO strings — sqlite-safe.
            normalized = normalizer.normalize_event(event_in.model_dump(mode="json"))
            event_store.insert_event(conn, normalized)
            accepted += 1

        # Detection runs on the full new batch (rules 1-6, docs/11) — this is
        # what makes live monitoring actually "live" (docs/02).
        # model_dump(mode="json") keeps timestamps as ISO strings for the rules.
        new_alerts = detection.evaluate_batch(conn, run_id, [e.model_dump(mode="json") for e in events])

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

    # Live SSE push — fan out to open /events/stream connections (no-op when
    # nobody is listening; the webapp polls as its fallback).
    from ..services import events_stream

    events_stream.publish_alerts(new_alerts)

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
