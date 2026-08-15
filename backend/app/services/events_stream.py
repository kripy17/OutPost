"""In-process SSE broadcast — live alert push over polling (roadmap polish).

A tiny pub/sub over asyncio.Queues: ingestion publishes fired alerts, and
every open `/events/stream` connection receives them as Server-Sent Events.
No external broker — single-process FastAPI, so an in-memory set of subscriber
queues is the correct scope. If nothing is subscribed, publish is a no-op and
ingestion is unaffected (the webapp still polls as a fallback).

Keepalive: a `: ping` comment is emitted every 15 s so proxies and the
browser don't drop idle connections; EventSource auto-reconnects on drop.
"""

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

_subscribers: set["asyncio.Queue[tuple[str, dict]]"] = set()
_MAX_QUEUE = 128


def publish(event: str, data: dict) -> int:
    """Fan out an event to every open connection. Returns fan-out count."""
    sent = 0
    for q in list(_subscribers):
        try:
            q.put_nowait((event, data))
            sent += 1
        except asyncio.QueueFull:
            pass  # slow consumer — drop rather than block ingestion
    return sent


async def stream_events() -> AsyncIterator[str]:
    """SSE generator: one `event:`/`data:` frame per published alert, plus a
    keepalive comment every 15 s. Unsubscribes on disconnect."""
    q: asyncio.Queue[tuple[str, dict]] = asyncio.Queue(maxsize=_MAX_QUEUE)
    _subscribers.add(q)
    try:
        yield "retry: 3000\n\n"
        while True:
            try:
                event, data = await asyncio.wait_for(q.get(), timeout=15.0)
                yield f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"
            except asyncio.TimeoutError:
                yield ": ping\n\n"
    finally:
        _subscribers.discard(q)


def publish_alerts(alerts: list[Any]) -> int:
    """Publish a batch of fired alerts (roadmap-3.1 payload shape). The Alert
    model only admits suspicious/malicious severities, so every alert is a
    finding worth pushing."""
    sent = 0
    for a in alerts:
        sent += publish(
            "alert",
            {
                "rule_id": a.rule_id,
                "rule_name": a.rule_name,
                "severity": a.severity,
                "run_id": a.run_id,
                "details": a.details,
                "triggered_at": a.triggered_at.isoformat(),
                # The live Monitor reads this to highlight the exact processes
                # behind composite rules (e.g. enumeration-burst's recon sweep)
                # without waiting for the next run-detail poll.
                "related_pids": list(getattr(a, "related_pids", []) or []),
            },
        )
    return sent


def publish_run_update(run_id: str, event_count: int, completed: bool = False) -> int:
    """Publish a run-level update (new events ingested, or the run completed).

    The Monitor and Event Log subscribe to this so process trees, network
    tables, and the live feed refresh the moment a batch lands instead of
    waiting for the next poll tick — polling stays as the fallback.
    """
    return publish(
        "run-update",
        {"run_id": run_id, "events": event_count, "completed": completed},
    )


def publish_fleet_update(host_id: str, online: bool, silent: bool, last_heartbeat: str | None = None) -> int:
    """Publish a fleet-status change (agent heartbeat landed, or a host went
    silent). The Agents page and the Overview host panel invalidate their
    fleet queries on this — a heartbeat flips the UI live without waiting for
    the 15-30 s poll; polling stays as the fallback.
    """
    return publish(
        "fleet-update",
        {
            "host_id": host_id,
            "online": online,
            "silent": silent,
            "last_heartbeat": last_heartbeat,
        },
    )


def publish_watchlist(run_id: str, sample_name: str, platform: str, matches: list[dict]) -> int:
    """Publish a watched-IOC hit (live watchlist alerting).

    Distinct from the `alert` event so the webapp can toast watchlist hits
    with their own visual language — and on any page, not just the Monitor.
    """
    return publish(
        "watchlist",
        {
            "run_id": run_id,
            "sample_name": sample_name,
            "platform": platform,
            "matches": matches,
        },
    )
