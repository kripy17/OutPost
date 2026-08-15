"""Fleet health (roadmap 4.x) — page when a host goes silent.

The background loop (wired into main.py's lifespan, same pattern as the
auto-prune scheduler) watches `agent_heartbeats`: a host whose heartbeat is
older than the silent window and that hasn't already been paged for this
episode gets one `outpost.host-silent` notification. The heartbeat endpoint
clears the page flag when the host comes back, so the *next* silent episode
pages again — one page per incident, no hourly nag.

Baseline anomalies page through the same channel from ingestion: they are
`suspicious` severity, so the malicious-only `notify_new_alerts` skips them,
but a first-time process/IP on an established host is exactly the kind of
deviation an on-call analyst wants to hear about.
"""

import asyncio
from datetime import datetime, timedelta, timezone

SILENT_WINDOW_SECONDS = 600
CHECK_INTERVAL_SECONDS = 60

_NOTIFIED_PREFIX = "silent_notified:"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def notified_key(host_id: str) -> str:
    return f"{_NOTIFIED_PREFIX}{host_id}"


def find_silent_hosts(conn) -> list[dict]:
    """Hosts past the silent window that haven't been paged for this episode."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=SILENT_WINDOW_SECONDS)).isoformat()
    rows = conn.execute(
        "SELECT host_id, last_heartbeat, platform FROM agent_heartbeats WHERE last_heartbeat < ?",
        (cutoff,),
    ).fetchall()
    out = []
    for r in rows:
        already = conn.execute(
            "SELECT 1 FROM settings WHERE key = ?", (notified_key(r["host_id"]),)
        ).fetchone()
        if not already:
            out.append(dict(r))
    return out


def mark_notified(conn, host_id: str) -> None:
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (notified_key(host_id), _now()),
    )


def clear_notified(conn, host_id: str) -> None:
    """The host heartbeated again — the episode is over; the next silence pages."""
    conn.execute("DELETE FROM settings WHERE key = ?", (notified_key(host_id),))


async def fleet_health_loop_once() -> list[str]:
    """One pass: find silent hosts, page each, mark notified. Returns the
    hosts paged — the seam tests drive directly."""
    from ..core.db import db_session
    from ..services import notifications as notify

    with db_session() as conn:
        silent = find_silent_hosts(conn)
        for h in silent:
            mark_notified(conn, h["host_id"])

    paged: list[str] = []
    for h in silent:
        try:
            await notify.notify_fleet_event(
                "host-silent",
                h["host_id"],
                (
                    f"Host {h['host_id']} stopped heartbeating more than "
                    f"{SILENT_WINDOW_SECONDS}s ago — collector down, uninstalled, "
                    "or the network path broke"
                ),
            )
            paged.append(h["host_id"])
            # Live fleet push: flip the host to silent the moment the loop
            # notices (the Agents page re-reads its fleet instantly).
            from ..services import events_stream

            events_stream.publish_fleet_update(
                h["host_id"], online=False, silent=True, last_heartbeat=h.get("last_heartbeat")
            )
        except Exception:
            pass
    return paged


async def fleet_health_loop() -> None:
    """Background task (started by main.py's lifespan). Never crashes the app:
    a bad pass is swallowed and the loop keeps ticking."""
    while True:
        try:
            await fleet_health_loop_once()
        except Exception:
            pass
        await asyncio.sleep(CHECK_INTERVAL_SECONDS)
