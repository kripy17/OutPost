"""Fleet health — page when a heartbeat-enabled host goes silent.

One notification per silent *episode*: the watcher pages a host whose
heartbeat is past the window and marks it notified; the heartbeat endpoint
clears the mark on recovery, so the next silence pages fresh. Baseline
anomalies page through the same fleet channel from ingestion (they're
suspicious, so the malicious-only alert notifier skips them).
"""

import asyncio
import time
from datetime import datetime, timedelta, timezone

import pytest

from .conftest import make_run

SILENT_WINDOW = 600


def _hb(client, host_id: str, platform: str = "linux") -> None:
    client.post(f"/agents/{host_id}/heartbeat", json={"platform": platform})


def _backdate(conn, host_id: str, minutes: int = 30) -> None:
    old = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    conn.execute("UPDATE agent_heartbeats SET last_heartbeat = ? WHERE host_id = ?", (old, host_id))
    conn.commit()


def _page_once(monkeypatch, conn, host_ids: list[str]):
    """Run one fleet-health pass with a captured notifier; returns pages."""
    from ..services import fleet_health

    paged: list[tuple[str, str, str]] = []

    async def fake_event(kind: str, host_id: str, detail: str) -> list[str]:
        paged.append((kind, host_id, detail))
        return ["webhook"]

    monkeypatch.setattr("app.services.notifications.notify_fleet_event", fake_event)
    asyncio.run(fleet_health.fleet_health_loop_once())
    return paged


def test_silent_host_pages_once_per_episode(client, conn, monkeypatch):
    _hb(client, "fh-alpha")
    _backdate(conn, "fh-alpha")

    first = _page_once(monkeypatch, conn, ["fh-alpha"])
    assert [p[1] for p in first] == ["fh-alpha"]
    assert first[0][0] == "host-silent"
    assert "fh-alpha" in first[0][2]

    # Second pass: already paged for this episode → nothing.
    assert _page_once(monkeypatch, conn, []) == []


def test_recovery_clears_episode_and_next_silence_pages_again(client, conn, monkeypatch):
    _hb(client, "fh-beta")
    _backdate(conn, "fh-beta")
    assert len(_page_once(monkeypatch, conn, [])) == 1

    # Fresh heartbeat = recovered; the episode flag is cleared (settings row
    # deleted by the heartbeat endpoint).
    _hb(client, "fh-beta")
    from ..core.db import get_connection
    from ..services import fleet_health

    c = get_connection()
    row = c.execute("SELECT 1 FROM settings WHERE key = ?", (fleet_health.notified_key("fh-beta"),)).fetchone()
    c.close()
    assert row is None

    # The host goes silent again → pages again (new episode).
    _backdate(conn, "fh-beta")
    assert len(_page_once(monkeypatch, conn, [])) == 1


def test_heartbeat_publishes_fleet_update(client, monkeypatch):
    """A heartbeat push flips the host live in the UI — the Agents page and
    Overview host panel invalidate their fleet queries on this event."""
    from ..services import events_stream

    calls: list[dict] = []

    def fake(host_id: str, online: bool, silent: bool, last_heartbeat=None) -> int:
        calls.append({"host_id": host_id, "online": online, "silent": silent})
        return 1

    monkeypatch.setattr(events_stream, "publish_fleet_update", fake)
    _hb(client, "fh-push-live", platform="windows")
    assert calls and calls[0] == {"host_id": "fh-push-live", "online": True, "silent": False}


def test_silent_host_publishes_fleet_update(client, conn, monkeypatch):
    """The fleet-health pass pushes the silent transition live too."""
    from ..services import events_stream

    pushes: list[dict] = []

    def fake(host_id: str, online: bool, silent: bool, last_heartbeat=None) -> int:
        pushes.append({"host_id": host_id, "online": online, "silent": silent})
        return 1

    monkeypatch.setattr(events_stream, "publish_fleet_update", fake)
    _hb(client, "fh-push-silent")
    _backdate(conn, "fh-push-silent")

    _page_once(monkeypatch, conn, ["fh-push-silent"])
    # The heartbeat pushed online=True first; the loop's silent transition
    # must follow.
    assert {"host_id": "fh-push-silent", "online": False, "silent": True} in pushes


def test_fresh_heartbeat_host_is_not_silent(client, conn, monkeypatch):
    _hb(client, "fh-gamma")  # heartbeat just now
    assert _page_once(monkeypatch, conn, []) == []


def test_baseline_anomaly_dispatches_fleet_notification(client, monkeypatch):
    """Ingestion pages the fleet channel the moment a baseline anomaly fires."""
    captured: list[tuple[str, str, str]] = []

    async def fake_event(kind: str, host_id: str, detail: str) -> list[str]:
        captured.append((kind, host_id, detail))
        return ["webhook"]

    monkeypatch.setattr("app.services.notifications.notify_fleet_event", fake_event)

    run_id = make_run(client, sample_name="fh-bl.bin", platform="linux")
    ts = "2026-08-09T12:00:00+00:00"

    def proc(i: int, name: str) -> dict:
        return {
            "run_id": run_id, "platform": "linux", "event_type": "process_create",
            "timestamp": ts, "pid": 5000 + i, "ppid": 1, "process_name": name,
            "command_line": name, "host_id": "fh-bl-host",
        }

    # Establish the baseline (105 observations crosses the 100 gate).
    client.post("/ingest/batch", json=[proc(i, f"fh-known-{i:03d}") for i in range(105)])
    # Novel process → baseline-anomaly fires → fleet channel pages.
    client.post("/ingest/batch", json=[proc(999, "fh-novel")])

    deadline = time.time() + 3
    while not captured and time.time() < deadline:
        time.sleep(0.05)

    assert captured, "baseline-anomaly should have paged the fleet channel"
    kind, host, detail = captured[0]
    assert kind == "baseline-anomaly"
    assert host == "fh-bl-host"
    assert "fh-novel" in detail
