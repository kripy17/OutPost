"""Ingestion and run lifecycle endpoints for analysis sessions.

- POST /ingest/batch        — validate, store, run detection on an analysis event batch
- POST /runs                — create an analysis run, return run_id
- POST /runs/{id}/complete  — mark complete; trigger tree build + enrichment
"""

import json
import uuid

from fastapi import APIRouter, HTTPException

from ..core.db import db_session
from ..core.schema import Alert, EventIn, RunCreate
from ..models import event as event_store
from ..models import run as run_store
from ..services import detection, normalizer

router = APIRouter(tags=["ingest"])


@router.post("/ingest/batch", status_code=202)
async def ingest_batch(events: list[EventIn]) -> dict:
    """Accept a batch of events, store them, and run detection on each."""
    if not events:
        return {"accepted": 0, "alerts": 0}

    # A batch must belong to exactly one run.
    run_ids = {e.run_id for e in events}
    if len(run_ids) != 1:
        raise HTTPException(status_code=422, detail="All events in a batch must share one run_id")
    run_id = next(iter(run_ids))

    accepted = 0
    new_alerts: list[Alert] = []
    watchlist_matches: list[dict] = []
    run_meta: dict = {}
    with db_session() as conn:
        run_row = run_store.get_run(conn, run_id)
        if not run_row:
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        run_meta = {"sample_name": run_row["sample_name"], "platform": run_row["platform"]}

        batch_min_ts = min((e.model_dump(mode="json")["timestamp"] for e in events), default=None)
        if batch_min_ts is not None:
            rows = conn.execute(
                "SELECT event_type, timestamp, pid, process_name, command_line, "
                "dest_ip, dest_port, file_path, registry_key, host_id, source_event_id FROM events "
                "WHERE run_id = ? AND timestamp >= ?",
                (run_id, batch_min_ts),
            ).fetchall()
            seen_natural = {
                (r["event_type"], r["timestamp"], r["pid"], r["process_name"], r["command_line"],
                 r["dest_ip"], r["dest_port"], r["file_path"], r["registry_key"], r["host_id"])
                for r in rows
            }
            seen_source_ids = {
                r["source_event_id"]
                for r in rows
                if r["source_event_id"]
            }
        else:
            seen_natural = set()
            seen_source_ids = set()

        stored_events: list[dict] = []
        known_proc_starts: dict[tuple[str, str, int], list[str]] = {}

        for event_in in events:
            raw_payload = event_in.model_dump(mode="json")
            normalized = normalizer.normalize_event(raw_payload)

            p_host = normalized.get("host_id", "local")
            p_boot = normalized.get("boot_id", "default")
            p_pid = normalized.get("pid")
            ev_ts = normalized.get("timestamp") or ""

            if p_pid is not None and p_pid != 0:
                compound_p_key = (p_host, p_boot, p_pid)
                if normalized.get("event_type") == "process_create" and normalized.get("process_start_time"):
                    starts = known_proc_starts.setdefault(compound_p_key, [])
                    if normalized["process_start_time"] not in starts:
                        starts.append(normalized["process_start_time"])
                        starts.sort()
                    normalized["missing_process_start_time"] = False
                elif not normalized.get("process_start_time"):
                    matched_pst = None
                    if compound_p_key in known_proc_starts:
                        starts = known_proc_starts[compound_p_key]
                        candidates = [s for s in starts if not ev_ts or s <= ev_ts]
                        if candidates:
                            matched_pst = candidates[-1]
                        elif starts:
                            matched_pst = starts[0]

                    if not matched_pst:
                        row = conn.execute(
                            "SELECT process_start_time FROM events WHERE run_id = ? AND host_id = ? AND boot_id = ? AND pid = ? AND event_type = 'process_create' AND (timestamp <= ? OR ? = '') AND process_start_time IS NOT NULL ORDER BY timestamp DESC LIMIT 1",
                            (run_id, p_host, p_boot, p_pid, ev_ts, ev_ts),
                        ).fetchone()
                        if row and row["process_start_time"]:
                            matched_pst = row["process_start_time"]
                            known_proc_starts.setdefault(compound_p_key, []).append(matched_pst)

                    if matched_pst:
                        normalized["process_start_time"] = matched_pst
                        normalized["missing_process_start_time"] = False
                else:
                    normalized["missing_process_start_time"] = False

            if not normalized.get("raw_record"):
                normalized["raw_record"] = json.dumps(raw_payload)

            src_id = normalized.get("source_event_id")
            if src_id:
                if src_id in seen_source_ids:
                    continue
                seen_source_ids.add(src_id)
            else:
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
                    normalized.get("host_id", "local"),
                )
                if key in seen_natural:
                    continue
                seen_natural.add(key)

            normalized["id"] = event_store.insert_event(conn, normalized)
            stored_events.append(normalized)
            accepted += 1

        new_alerts = detection.evaluate_batch(conn, run_id, stored_events)

        from ..models import watchlist as watchlist_store
        watchlist_matches = watchlist_store.record_hits(
            conn, run_id, watchlist_store.match_events(conn, stored_events)
        )

    # Live SSE push
    from ..services import events_stream
    events_stream.publish_alerts(new_alerts)
    if watchlist_matches:
        events_stream.publish_watchlist(
            run_id, run_meta["sample_name"], run_meta["platform"], watchlist_matches
        )
    events_stream.publish_run_update(run_id, accepted)

    return {"accepted": accepted, "alerts": len(new_alerts)}


@router.post("/runs", status_code=201)
def create_run(body: RunCreate) -> dict:
    run_id = uuid.uuid4().hex[:12]
    source = "live" if body.session_type == "live" else body.source
    with db_session() as conn:
        run_store.create_run(
            conn,
            run_id=run_id,
            sample_name=body.sample_name,
            platform=body.platform,
            session_type=body.session_type,
            source=source,
        )
    return {"run_id": run_id, "session_type": body.session_type}


@router.post("/runs/{run_id}/complete")
def complete_run(run_id: str) -> dict:
    from ..services.detection import evict_run_process_map, persist_run_process_map

    with db_session() as conn:
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        run_store.complete_run(conn, run_id)
        persist_run_process_map(conn, run_id)
        summary = run_store.to_summary(conn, run_store.get_run(conn, run_id))
    evict_run_process_map(run_id)

    from ..services import events_stream
    events_stream.publish_run_update(run_id, 0, completed=True)
    return summary.model_dump()
