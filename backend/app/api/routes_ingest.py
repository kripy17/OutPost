"""Ingestion endpoints.

- POST /ingest/batch        — validate, store, run detection on every event
- POST /runs                — create a run (live or analysis), return run_id
- POST /runs/{id}/complete  — mark complete; trigger tree build + enrichment
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from ..core.db import db_session
from ..core.schema import Alert, EventIn, RunCreate
from ..models import event as event_store
from ..models import run as run_store
from ..services import detection, normalizer

router = APIRouter(tags=["ingest"])


@router.post("/ingest/snapshot", response_model=None)
async def ingest_snapshot(snapshot: dict) -> dict:
    """Store a live system snapshot (processes + listening ports) for a host.
    The collectors ship these on an interval while an agent runs; the Agents
    page and Live Monitor render the latest one as the 'running now' view.
    Only the newest snapshot per host is kept (PK upsert)."""
    import json as _json

    host_id = str(snapshot.get("host_id") or "local").strip()
    if not host_id:
        raise HTTPException(status_code=422, detail="host_id is required")
    with db_session() as conn:
        conn.execute(
            "INSERT INTO host_snapshots (host_id, payload, collected_at) VALUES (?, ?, ?) "
            "ON CONFLICT(host_id) DO UPDATE SET payload = excluded.payload, collected_at = excluded.collected_at",
            (host_id, _json.dumps(snapshot), snapshot.get("collected_at") or datetime.now(timezone.utc).isoformat()),
        )
    return {
        "stored": True,
        "host_id": host_id,
        "processes": len(snapshot.get("processes", [])),
        "listening": len(snapshot.get("listening", [])),
    }


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
            # mode="json" serializes datetimes to ISO strings — sqlite-safe.
            raw_payload = event_in.model_dump(mode="json")
            normalized = normalizer.normalize_event(raw_payload)

            # Propagate compound process_start_time to non-process events sharing (host_id, boot_id, pid)
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

            # Keep the original source as the event's raw record (Event Viewer
            # "raw record" pane — pivot from a normalized row to the source).
            # Collectors ship the raw auditd/Sysmon line themselves; webapp /
            # sandbox / seed events fall back to the normalized payload JSON.
            # The payload always carries the field (EventIn default None), so
            # fall back only when the collector left it empty.
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

            # The row id rides on the dict so detection can record event-level
            # IOC provenance (P3.1) — composite rules stay finding-ref only.
            normalized["id"] = event_store.insert_event(conn, normalized)
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

    # Baseline anomalies page the same fleet channel: they're suspicious
    # severity, so the malicious-only alert notifier skips them — but a
    # first-time process/IP on an established host is exactly what on-call
    # wants to hear about.
    baseline_hits = [a for a in new_alerts if a.rule_id == "baseline-anomaly"]

    async def _dispatch_baseline() -> None:
        try:
            for a in baseline_hits:
                host = "unknown"
                if "on host " in a.details:
                    host = a.details.split("on host ", 1)[1].split(":", 1)[0].strip()
                await notify.notify_fleet_event("baseline-anomaly", host, a.details)
        except Exception:
            pass  # notification failure must never surface into ingestion

    if baseline_hits:
        asyncio.create_task(_dispatch_baseline())

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
    # Run-level push: the Monitor / Event Log live views refresh the moment a
    # batch lands (new events in the tree/table/feed) instead of waiting for
    # the next poll tick. Polling remains the fallback when SSE is off.
    events_stream.publish_run_update(run_id, accepted)

    return {"accepted": accepted, "alerts": len(new_alerts)}


@router.post("/runs", status_code=201)
def create_run(body: RunCreate) -> dict:
    run_id = uuid.uuid4().hex[:12]
    # A live session is always host-telemetry provenance, whatever the client
    # sent; analysis sessions carry the client's marker (webapp-demo / cli / …).
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
    # Write-through: persist the run's process map inside the same session,
    # then free the in-memory copy — a restarted backend restores the map
    # warm for any late batch.
    from ..services.detection import evict_run_process_map, persist_run_process_map

    with db_session() as conn:
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        run_store.complete_run(conn, run_id)
        persist_run_process_map(conn, run_id)
        summary = run_store.to_summary(conn, run_store.get_run(conn, run_id))
    evict_run_process_map(run_id)

    # Push the completion so open live views stop streaming immediately
    # (the Monitor's poll stops once completed_at is set — push covers the
    # gap for a run completed by an external client / collector timeout).
    from ..services import events_stream

    events_stream.publish_run_update(run_id, 0, completed=True)
    return summary.model_dump()
