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
from typing import Any, AsyncIterator

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
    q: "asyncio.Queue[tuple[str, dict]]" = asyncio.Queue(maxsize=_MAX_QUEUE)
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
            },
        )
    return sent
