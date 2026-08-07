"""Tests for roadmap 1.1 — the global Events feed (Event Viewer).

The test DB is shared across the whole session, so every assertion scopes its
counts with a unique marker string (never asserts global totals).
"""

import datetime

from .conftest import make_run


def _ts(offset_seconds: int = 0) -> str:
    return (
        datetime.datetime(2026, 8, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        + datetime.timedelta(seconds=offset_seconds)
    ).isoformat()


def _ingest(client, run_id: str, events: list[dict]) -> None:
    resp = client.post("/ingest/batch", json=events)
    assert resp.status_code == 202, resp.text


def _event(run_id: str, event_type: str, platform: str, **kw) -> dict:
    base = {
        "run_id": run_id, "platform": platform, "event_type": event_type,
        "timestamp": _ts(0), "pid": 1, "ppid": 0,
    }
    base.update(kw)
    return base


def test_events_feed_shape_and_pagination(client):
    marker = "feedshape-"
    a = make_run(client, sample_name="feed-a.bin")
    _ingest(client, a, [
        _event(a, "process_create", "windows", process_name=f"{marker}one.exe", timestamp=_ts(1)),
        _event(a, "network_connection", "linux", dest_ip="198.51.100.4", command_line=marker, timestamp=_ts(2)),
    ])

    data = client.get("/events", params={"q": marker}).json()
    assert data["total"] == 2 and data["returned"] == 2
    assert all("sample_name" in e and "run_severity" in e for e in data["events"])
    types = {e["event_type"] for e in data["events"]}
    assert types == {"process_create", "network_connection"}

    # Pagination within the scoped set.
    page1 = client.get("/events", params={"q": marker, "limit": 1, "offset": 0}).json()
    page2 = client.get("/events", params={"q": marker, "limit": 1, "offset": 1}).json()
    assert page1["returned"] == 1 and page2["returned"] == 1
    assert page1["events"][0]["id"] != page2["events"][0]["id"]
    assert client.get("/events", params={"q": marker, "offset": 5}).json()["returned"] == 0


def test_events_filter_by_type_and_platform(client):
    marker = "feedfilter-"
    a = make_run(client, sample_name="feed-c.bin")
    _ingest(client, a, [
        _event(a, "process_create", "windows", process_name=f"{marker}x.exe", timestamp=_ts(1)),
        _event(a, "network_connection", "windows", dest_ip="198.51.100.5", command_line=marker, timestamp=_ts(2)),
    ])

    only_net = client.get("/events", params={"q": marker, "event_type": "network_connection"}).json()
    assert only_net["total"] == 1
    assert {e["event_type"] for e in only_net["events"]} == {"network_connection"}

    only_lnx = client.get("/events", params={"q": marker, "platform": "linux"}).json()
    assert only_lnx["total"] == 0  # both events are windows — scoped marker is safe


def test_events_severity_filter_limits_to_findings_runs(client):
    marker = "feedsev-"
    clean = make_run(client, sample_name="feed-clean.bin")
    dirty = make_run(client, sample_name="feed-dirty.bin")
    _ingest(client, clean, [
        _event(clean, "file_write", "windows", file_path=f"C:\\tmp\\{marker}a.txt", timestamp=_ts(1)),
    ])
    # A malicious LOLBin write makes the whole run "malicious-severity".
    _ingest(client, dirty, [
        {
            "run_id": dirty, "platform": "windows", "event_type": "process_create",
            "timestamp": _ts(2), "pid": 1, "ppid": 0, "process_name": "powershell.exe",
            "command_line": f"powershell.exe -enc {marker}",  # marker so BOTH dirty events match q
        },
        _event(dirty, "file_write", "windows", file_path=f"C:\\tmp\\{marker}b.txt", timestamp=_ts(3)),
    ])

    resp = client.get("/events", params={"q": marker, "severity": "malicious"})
    data = resp.json()
    assert data["total"] == 2  # only the dirty run's two events
    assert {e["run_id"] for e in data["events"]} == {dirty}
    assert all(e["run_severity"] == "malicious" for e in data["events"])


def test_events_free_text_search(client):
    a = make_run(client, sample_name="feed-d.bin")
    _ingest(client, a, [
        _event(a, "process_create", "windows", process_name="totally-unique-proc.exe", timestamp=_ts(1)),
        _event(a, "file_write", "windows", file_path=r"C:\Users\victim\Documents\report.docx", timestamp=_ts(2)),
        _event(a, "network_connection", "windows", dest_ip="198.51.100.77", timestamp=_ts(3)),
    ])

    assert client.get("/events", params={"q": "totally-unique-proc.exe"}).json()["total"] == 1
    assert client.get("/events", params={"q": "report.docx"}).json()["total"] == 1
    assert client.get("/events", params={"q": "198.51.100.77"}).json()["total"] == 1
    # Partial-IP substring must stay unique to THIS test: /events is a global
    # feed and the session DB is shared, so other tests' IPs (.4/.5/.201) would
    # legitimately match a broader "198.51.100" search.
    assert client.get("/events", params={"q": "51.100.77"}).json()["total"] == 1  # partial IP
    assert client.get("/events", params={"q": "no-such-thing"}).json()["total"] == 0


def test_events_invalid_filters_422(client):
    assert client.get("/events", params={"event_type": "bogus"}).status_code == 422
    assert client.get("/events", params={"platform": "plan9"}).status_code == 422
    assert client.get("/events", params={"severity": "fatal"}).status_code == 422
    assert client.get("/events", params={"limit": 0}).status_code == 422
