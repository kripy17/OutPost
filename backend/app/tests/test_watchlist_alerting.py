"""Tests for watchlist-triggered live alerting (webhook + SSE on IOC hit).

The watchlist is checked against every new batch's stored events; a hit fires
an `outpost.watchlist` webhook POST and an SSE `watchlist` event. These tests
lock the matching semantics (exact value, distinct per IOC) and the webhook
contract (silent when unconfigured, quiet on failure).
"""

import asyncio

from ..models import watchlist as watchlist_store


def _event(**kw) -> dict:
    base = {
        "run_id": "r", "platform": "windows", "event_type": "network_connection",
        "timestamp": "2026-08-08T12:00:00Z", "pid": 1,
        "dest_ip": None, "process_name": None, "file_path": None, "registry_key": None,
    }
    base.update(kw)
    return base


def test_match_events_finds_distinct_hits(client, conn):
    client.post("/watchlist", json={"value": "203.0.113.50", "label": "shared C2"})
    client.post("/watchlist", json={"value": "powershell.exe", "label": ""})

    events = [
        _event(dest_ip="203.0.113.50", timestamp="2026-08-08T12:00:01Z"),
        _event(dest_ip="203.0.113.50", timestamp="2026-08-08T12:00:02Z"),  # dup — one match
        _event(event_type="process_create", process_name="powershell.exe", timestamp="2026-08-08T12:00:03Z"),
        _event(dest_ip="8.8.8.8", file_path=r"C:\tmp\clean.bin"),  # no hits
    ]
    matches = watchlist_store.match_events(conn, events)

    assert len(matches) == 2
    by_value = {m["ioc_value"]: m for m in matches}
    assert by_value["203.0.113.50"]["ioc_type"] == "ip"
    assert by_value["203.0.113.50"]["label"] == "shared C2"
    assert by_value["powershell.exe"]["ioc_type"] == "process"
    # Empty label falls back to the value itself.
    assert by_value["powershell.exe"]["label"] == "powershell.exe"


def test_match_events_covers_registry_and_file(client, conn):
    client.post("/watchlist", json={"value": r"HKEY_CURRENT_USER\Software\Evil", "label": "run key"})
    client.post("/watchlist", json={"value": r"C:\Users\victim\Documents\invoice_000.enc", "label": ""})

    matches = watchlist_store.match_events(conn, [
        _event(event_type="registry_write", registry_key=r"HKEY_CURRENT_USER\Software\Evil"),
        _event(event_type="file_write", file_path=r"C:\Users\victim\Documents\invoice_000.enc"),
    ])
    kinds = {m["ioc_type"] for m in matches}
    assert {"registry", "file"} <= kinds


def test_match_events_is_case_insensitive(client, conn):
    client.post("/watchlist", json={"value": "powershell.exe", "label": "lolbin"})
    client.post("/watchlist", json={"value": r"HKLM\Software\Evil", "label": "run key"})

    matches = watchlist_store.match_events(conn, [
        _event(event_type="process_create", process_name="PowerShell.exe"),
        _event(event_type="registry_write", registry_key=r"hklm\software\evil"),
    ])
    kinds = {m["ioc_type"]: m["ioc_value"] for m in matches}
    assert kinds["process"] == "PowerShell.exe"  # event's own casing, not the entry's
    assert kinds["registry"] == r"hklm\software\evil"


def test_record_hits_fires_once_per_run(client, conn):
    client.post("/watchlist", json={"value": "203.0.113.55", "label": "tracked"})
    run_x = client.post("/runs", json={"sample_name": "first-seen-x.bin", "platform": "linux"}).json()["run_id"]
    run_y = client.post("/runs", json={"sample_name": "first-seen-y.bin", "platform": "linux"}).json()["run_id"]
    events = [_event(dest_ip="203.0.113.55")]

    first = watchlist_store.record_hits(conn, run_x, watchlist_store.match_events(conn, events))
    assert len(first) == 1 and first[0]["ioc_value"] == "203.0.113.55"

    # Same run, same IOC again → no new hit (a live session keeps touching it).
    again = watchlist_store.record_hits(conn, run_x, watchlist_store.match_events(conn, events))
    assert again == []

    # A different run seeing the same IOC is a genuinely new hit.
    other = watchlist_store.record_hits(conn, run_y, watchlist_store.match_events(conn, events))
    assert len(other) == 1


def test_match_events_empty_watchlist_returns_empty(client, conn):
    # The session DB is shared — clear rows other tests added so this one
    # actually exercises the empty-watchlist path.
    conn.execute("DELETE FROM watchlist")
    conn.commit()
    assert watchlist_store.match_events(conn, [_event(dest_ip="203.0.113.50")]) == []


def _capture_webhook(monkeypatch):
    """Monkeypatch httpx.AsyncClient to capture POSTs; returns the list."""
    captured: list[dict] = []

    class FakeResp:
        def raise_for_status(self):
            return None

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None):
            captured.append({"url": url, "json": json})
            return FakeResp()

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    return captured


def test_watchlist_webhook_payload_shape(client, monkeypatch):
    client.put("/notifications/settings", json={"webhook_url": "http://hook.test/watch"})
    captured = _capture_webhook(monkeypatch)

    from ..services.notifications import notify_watchlist_hits

    matches = [{"ioc_type": "ip", "ioc_value": "203.0.113.50", "label": "shared C2",
                "event_type": "network_connection", "timestamp": "2026-08-08T12:00:01Z"}]
    urls = asyncio.run(notify_watchlist_hits("run123", "evil.exe", "windows", matches))

    assert urls == ["http://hook.test/watch"]
    assert len(captured) == 1
    body = captured[0]["json"]
    assert body["event"] == "outpost.watchlist"
    assert body["run_id"] == "run123" and body["sample_name"] == "evil.exe"
    assert body["platform"] == "windows"
    assert body["matches"] == matches
    assert "sent_at" in body


def test_watchlist_webhook_silent_without_url(client, conn, monkeypatch):
    # Clear the webhook URL another test may have set (shared session DB).
    conn.execute("DELETE FROM settings WHERE key = 'NOTIFY_WEBHOOK_URL'")
    conn.commit()
    captured = _capture_webhook(monkeypatch)

    from ..services.notifications import notify_watchlist_hits

    urls = asyncio.run(notify_watchlist_hits(
        "run123", "evil.exe", "windows",
        [{"ioc_type": "ip", "ioc_value": "203.0.113.50", "label": "C2", "event_type": "net"}],
    ))
    assert urls == []
    assert captured == []


def test_watchlist_webhook_silent_without_matches(client, monkeypatch):
    client.put("/notifications/settings", json={"webhook_url": "http://hook.test/watch"})
    captured = _capture_webhook(monkeypatch)

    from ..services.notifications import notify_watchlist_hits

    urls = asyncio.run(notify_watchlist_hits("run123", "evil.exe", "windows", []))
    assert urls == []
    assert captured == []


def test_ingest_with_watched_ioc_succeeds(client, conn):
    """A batch touching a watched IOC ingests normally (202) and the hit is
    visible to match_events — the wiring doesn't disturb ingestion."""
    client.post("/watchlist", json={"value": "203.0.113.60", "label": "tracked"})
    run_id = client.post("/runs", json={"sample_name": "wl-live.bin", "platform": "linux"}).json()["run_id"]

    resp = client.post("/ingest/batch", json=[{
        "run_id": run_id, "platform": "linux", "event_type": "network_connection",
        "timestamp": "2026-08-08T12:00:00Z", "pid": 1, "dest_ip": "203.0.113.60", "dest_port": 4444,
    }])
    assert resp.status_code == 202

    rows = conn.execute("SELECT * FROM events WHERE run_id = ?", (run_id,)).fetchall()
    matches = watchlist_store.match_events(conn, [dict(r) for r in rows])
    assert any(m["ioc_value"] == "203.0.113.60" for m in matches)
