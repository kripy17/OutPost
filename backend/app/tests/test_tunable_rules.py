"""The recent rules' thresholds are operator-tunable (Rules page), not code.

- DNS tunnel / RDP brute / fan-out knobs live in /rules/tuning (defaults shown).
- The anti-forensics pattern tables (log-service-stop / log-clearing) are
  editable per platform via /rules/log-patterns, exactly like enumeration.
Both apply to the next ingested batch — no backend restart. Each test restores
the store (DELETE the knob / pattern key) so nothing leaks across the suite.
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


def _net(run_id: str, ip: str, port: int, pid: int, ts: int = 0, query: str | None = None) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "network_connection",
        "timestamp": _ts(ts), "pid": pid, "process_name": "evil.exe",
        "dest_ip": ip, "dest_port": port, "protocol": "TCP", "query": query,
    }


def _proc(run_id: str, cmd: str, ts: int = 0, platform: str = "windows") -> dict:
    return {
        "run_id": run_id, "platform": platform, "event_type": "process_create",
        "timestamp": _ts(ts), "pid": 100, "ppid": 1, "process_name": "cmd.exe",
        "command_line": cmd,
    }


def _alerts(client, run_id: str) -> list[dict]:
    return client.get(f"/runs/{run_id}/alerts").json()


def _tune(client, param: str, value: str) -> None:
    resp = client.put(f"/rules/tuning/{param}", json={"value": value})
    assert resp.status_code == 200, resp.text


def _untune(client, param: str) -> None:
    resp = client.delete(f"/rules/tuning/{param}")
    assert resp.status_code == 204, resp.text


# -- Numeric knobs ------------------------------------------------------------


def test_new_knobs_are_exposed_with_defaults(client):
    knobs = {k["param"]: k for k in client.get("/rules/tuning").json()["knobs"]}
    for param, default in [
        ("DNS_TUNNEL_WINDOW_SECONDS", 300),
        ("DNS_TUNNEL_MIN_DISTINCT", 6),
        ("DNS_LONG_LABEL_LEN", 24),
        ("RDP_BRUTE_WINDOW_SECONDS", 60),
        ("RDP_BRUTE_MIN_CONNECTIONS", 4),
        ("FANOUT_WINDOW_SECONDS", 300),
        ("FANOUT_MIN_PROCESSES", 5),
    ]:
        assert param in knobs, param
        assert knobs[param]["default"] == default, param
        assert knobs[param]["tuned"] is False, param


def test_dns_tunnel_min_distinct_tunable(client):
    # Default 6: three tunnel queries stay quiet.
    run = make_run(client, sample_name="tune-dns-a.exe")
    _ingest(client, run, [
        _net(run, "198.51.100.86", 53, 100, ts=i, query=f"{'a' * 20}{i}.tune.example.com")
        for i in range(3)
    ])
    assert [a for a in _alerts(client, run) if a["rule_id"] == "dns-tunneling"] == []

    try:
        _tune(client, "DNS_TUNNEL_MIN_DISTINCT", "3")
        run2 = make_run(client, sample_name="tune-dns-b.exe")
        _ingest(client, run2, [
            _net(run2, "198.51.100.87", 53, 100, ts=i, query=f"{'b' * 20}{i}.tune.example.com")
            for i in range(3)
        ])
        fired = [a for a in _alerts(client, run2) if a["rule_id"] == "dns-tunneling"]
        assert len(fired) == 1
    finally:
        _untune(client, "DNS_TUNNEL_MIN_DISTINCT")


def test_rdp_brute_min_connections_tunable(client):
    try:
        _tune(client, "RDP_BRUTE_MIN_CONNECTIONS", "2")
        run = make_run(client, sample_name="tune-rdp.exe")
        _ingest(client, run, [
            _net(run, "10.0.0.20", 3389, pid=100, ts=i) for i in range(2)
        ])
        fired = [a for a in _alerts(client, run) if a["rule_id"] == "rdp-brute-force"]
        assert len(fired) == 1
    finally:
        _untune(client, "RDP_BRUTE_MIN_CONNECTIONS")


# -- Anti-forensics pattern tables -------------------------------------------


def _current_log_patterns(client) -> dict:
    return client.get("/rules/log-patterns").json()


def test_log_patterns_editable_and_apply_live(client):
    base = _current_log_patterns(client)
    assert "service_stop" in base["kinds"] and "log_clear" in base["kinds"]
    assert any("wevtutil" in p["pattern"] for p in base["kinds"]["log_clear"]["windows"])

    custom = {"pattern": r"del\s+/[fq]+\s+/q\s+C:\\Windows\\System32\\winevt\\Logs", "label": "event log store deleted (del)"}
    patterns = {kind: base["kinds"][kind] for kind in base["kinds"]}
    patterns["log_clear"]["windows"] = [*patterns["log_clear"]["windows"], custom]
    try:
        resp = client.put("/rules/log-patterns", json={"patterns": patterns})
        assert resp.status_code == 200, resp.text

        run = make_run(client, sample_name="tune-del.exe")
        _ingest(client, run, [
            _proc(run, "del /f /q C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", ts=1),
        ])
        fired = [a for a in _alerts(client, run) if a["rule_id"] == "log-clearing"]
        assert len(fired) == 1
        assert "del" in fired[0]["details"]
    finally:
        assert client.delete("/rules/log-patterns").status_code == 204


def test_log_patterns_reject_unknown_kind(client):
    resp = client.put("/rules/log-patterns", json={"patterns": {"bogus_kind": {}}})
    assert resp.status_code == 422


# -- Factory reset ------------------------------------------------------------


def test_factory_reset_clears_everything(client):
    # Set state across every surface: tuning override, suppression, FP
    # threshold, enum-pattern edit, log-pattern edit.
    _tune(client, "DNS_TUNNEL_MIN_DISTINCT", "3")
    client.post("/rules/suppressions", json={"rule_id": "beaconing", "run_id": None, "reason": "reset-test"})
    client.put("/rules/fp-threshold", json={"threshold": 7})
    enum = client.get("/rules/enum-patterns").json()
    enum["platforms"]["windows"] = [
        *enum["platforms"]["windows"],
        {"pattern": r"reset-probe", "label": "reset probe"},
    ]
    client.put("/rules/enum-patterns", json={"patterns": enum["platforms"]})
    logs = client.get("/rules/log-patterns").json()
    logs["kinds"]["log_clear"]["windows"] = [
        *logs["kinds"]["log_clear"]["windows"],
        {"pattern": r"reset-probe-log", "label": "reset probe"},
    ]
    client.put("/rules/log-patterns", json={"patterns": logs["kinds"]})

    resp = client.delete("/rules/reset")
    assert resp.status_code == 200
    data = resp.json()
    assert data["tuning_cleared"] >= 1
    assert data["suppressions_cleared"] >= 1
    assert data["settings_cleared"] >= 3  # enum + log + fp-threshold keys

    # Everything back to stock.
    knobs = client.get("/rules/tuning").json()["knobs"]
    assert all(not k["tuned"] for k in knobs)
    assert client.get("/rules/suppressions").json() == []
    enum_after = client.get("/rules/enum-patterns").json()
    assert all("reset-probe" not in p["pattern"] for p in enum_after["platforms"]["windows"])
    logs_after = client.get("/rules/log-patterns").json()
    assert all("reset-probe-log" not in p["pattern"] for p in logs_after["kinds"]["log_clear"]["windows"])
    fp_after = client.get("/rules/fp").json()
    assert fp_after["threshold"] == fp_after["default_threshold"]


def test_factory_reset_idempotent(client):
    data = client.delete("/rules/reset").json()
    assert data == {"tuning_cleared": 0, "suppressions_cleared": 0, "settings_cleared": 0}


# -- Explainability: effective-tuning snapshot ---------------------------------


def test_effective_tuning_snapshot_tuned_run(client):
    try:
        _tune(client, "RDP_BRUTE_MIN_CONNECTIONS", "2")
        run = make_run(client, sample_name="tune-snap.exe")
        _ingest(client, run, [_net(run, "10.0.0.30", 3389, 100, ts=1)])

        detail = client.get(f"/runs/{run}").json()
        assert detail["effective_tuning"] == {"RDP_BRUTE_MIN_CONNECTIONS": 2}

        exported = client.get(f"/runs/{run}/export").json()
        assert exported["effective_tuning"] == {"RDP_BRUTE_MIN_CONNECTIONS": 2}
    finally:
        _untune(client, "RDP_BRUTE_MIN_CONNECTIONS")


def test_effective_tuning_snapshot_stock_run_is_empty(client):
    run = make_run(client, sample_name="tune-snap-stock.exe")
    _ingest(client, run, [_net(run, "198.51.100.89", 53, 100, ts=1, query="www.example.com")])

    detail = client.get(f"/runs/{run}").json()
    assert detail["effective_tuning"] == {}
    assert client.get(f"/runs/{run}/export").json()["effective_tuning"] == {}


# -- Storm guard: per-rule per-run alert caps ---------------------------------


def test_first_seen_storm_cap_holds_and_records_suppressed(client):
    """25 novel script-host-spawned processes → exactly FIRST_SEEN_MAX_ALERTS
    (20) fire; the 5 held back are recorded on the run as suppressed_alerts
    and flow into the JSON export (the cap is visible, not silent)."""
    run = make_run(client, sample_name="storm-cap.exe")
    # Script-host parent (powershell) so first-seen novelty is meaningful.
    _ingest(client, run, [{
        "run_id": run, "platform": "windows", "event_type": "process_create",
        "timestamp": _ts(0), "pid": 100, "ppid": 1,
        "process_name": "powershell.exe", "command_line": "powershell.exe -nop",
    }])
    events = []
    for i in range(25):
        events.append({
            "run_id": run, "platform": "windows", "event_type": "process_create",
            "timestamp": _ts(i + 1), "pid": 1000 + i, "ppid": 100,
            "process_name": f"xq-storm-{i:04d}.bin", "command_line": f"xq-storm-{i:04d}.bin",
        })
    _ingest(client, run, events)

    fired = [a for a in _alerts(client, run) if a["rule_id"] == "first-seen-process"]
    assert len(fired) == 20

    detail = client.get(f"/runs/{run}").json()
    assert detail["suppressed_alerts"] == {"first-seen-process": 5}
    exported = client.get(f"/runs/{run}/export").json()
    assert exported["suppressed_alerts"] == {"first-seen-process": 5}


def test_storm_cap_respects_lowered_tunable(client):
    """Lowering FIRST_SEEN_MAX_ALERTS to 2 caps earlier — knobs drive the cap."""
    try:
        _tune(client, "FIRST_SEEN_MAX_ALERTS", "2")
        run = make_run(client, sample_name="storm-cap-tuned.exe")
        _ingest(client, run, [{
            "run_id": run, "platform": "windows", "event_type": "process_create",
            "timestamp": _ts(0), "pid": 100, "ppid": 1,
            "process_name": "powershell.exe", "command_line": "powershell.exe -nop",
        }])
        events = []
        for i in range(5):
            events.append({
                "run_id": run, "platform": "windows", "event_type": "process_create",
                "timestamp": _ts(i + 1), "pid": 2000 + i, "ppid": 100,
                "process_name": f"xq-storm-tuned-{i}.bin", "command_line": "x",
            })
        _ingest(client, run, events)

        fired = [a for a in _alerts(client, run) if a["rule_id"] == "first-seen-process"]
        assert len(fired) == 2
        assert client.get(f"/runs/{run}").json()["suppressed_alerts"] == {"first-seen-process": 3}
    finally:
        _untune(client, "FIRST_SEEN_MAX_ALERTS")


def test_first_seen_storm_cap_applies_on_macos(client):
    """The cap is rule-based, not platform-based — a Mac session with a bash
    script-host parent hits the same 20-alert ceiling."""
    run = make_run(client, sample_name="storm-mac.sh", platform="macos")
    _ingest(client, run, [{
        "run_id": run, "platform": "macos", "event_type": "process_create",
        "timestamp": _ts(0), "pid": 100, "ppid": 1,
        "process_name": "bash", "command_line": "/bin/bash -c payload",
    }])
    events = []
    for i in range(25):
        events.append({
            "run_id": run, "platform": "macos", "event_type": "process_create",
            "timestamp": _ts(i + 1), "pid": 3000 + i, "ppid": 100,
            "process_name": f"xq-storm-mac-{i:04d}.bin", "command_line": "x",
        })
    _ingest(client, run, events)
    fired = [a for a in _alerts(client, run) if a["rule_id"] == "first-seen-process"]
    assert len(fired) == 20
    assert client.get(f"/runs/{run}").json()["suppressed_alerts"] == {"first-seen-process": 5}


def _beacon_burst(run: str, ip: str, base_ts: int, pid: int) -> list[dict]:
    """Five connections to one IP at ~10s intervals (low variance → beacon)."""
    return [
        {"run_id": run, "platform": "windows", "event_type": "network_connection",
         "timestamp": _ts(base_ts + 10 * j), "pid": pid, "process_name": "evil.exe",
         "dest_ip": ip, "dest_port": 4444, "protocol": "TCP"}
        for j in range(5)
    ]


def test_beaconing_storm_cap(client):
    """20 beacon destinations all inside the 30-min window →
    BEACONING_MAX_ALERTS (15) fire, 5 held back."""
    run = make_run(client, sample_name="storm-beacon.exe")
    events = []
    for i in range(20):
        # base_ts keeps every burst inside the 30-min beaconing window
        # (cutoff anchors to the batch's newest event).
        events += _beacon_burst(run, f"198.51.100.{100 + i}", base_ts=1000 + i * 40, pid=1000 + i)
    _ingest(client, run, events)
    fired = [a for a in _alerts(client, run) if a["rule_id"] == "beaconing"]
    assert len(fired) == 15
    assert client.get(f"/runs/{run}").json()["suppressed_alerts"] == {"beaconing": 5}


def test_fanout_storm_cap(client):
    """Fan-out flags one destination per batch (deduped per IP), so 11
    batches each with a fresh fan-out IP → FANOUT_MAX_ALERTS (10), 1 held
    back — the cap holds across the batches of a live session."""
    run = make_run(client, sample_name="storm-fanout.exe")
    for i in range(11):
        events = []
        for j in range(5):
            events.append({
                "run_id": run, "platform": "windows", "event_type": "network_connection",
                # 400s apart keeps each batch's fan-out outside the 300s
                # window of the previous batch — each batch sees only itself.
                "timestamp": _ts(1000 + i * 400 + j),
                "pid": 4000 + i * 10 + j, "process_name": f"p{i}.exe",
                "dest_ip": f"198.51.100.{200 + i}", "dest_port": 443, "protocol": "TCP",
            })
        _ingest(client, run, events)
    fired = [a for a in _alerts(client, run) if a["rule_id"] == "fanout-contact"]
    assert len(fired) == 10
    assert client.get(f"/runs/{run}").json()["suppressed_alerts"] == {"fanout-contact": 1}


def test_default_cap_applies_to_uncapped_rules(client):
    """Every rule gets ALERT_CAP_DEFAULT (25) — e.g. 30 distinct LOLBin
    invocations cap at 25 with 5 recorded suppressed."""
    run = make_run(client, sample_name="storm-lolbin.exe")
    events = []
    for i in range(30):
        events.append({
            "run_id": run, "platform": "windows", "event_type": "process_create",
            "timestamp": _ts(i), "pid": 5000 + i, "ppid": 1,
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgAAGhBdAA=",
        })
    _ingest(client, run, events)
    fired = [a for a in _alerts(client, run) if a["rule_id"] == "lolbin-abuse"]
    assert len(fired) == 25
    assert client.get(f"/runs/{run}").json()["suppressed_alerts"] == {"lolbin-abuse": 5}


def test_storm_cap_holds_across_ingest_batches(client):
    """24 novel processes arriving in 3 batches → still exactly 20 (the cap
    counter is seeded from persisted alerts, not reset per batch)."""
    run = make_run(client, sample_name="storm-multibatch.exe")
    _ingest(client, run, [{
        "run_id": run, "platform": "windows", "event_type": "process_create",
        "timestamp": _ts(0), "pid": 100, "ppid": 1,
        "process_name": "powershell.exe", "command_line": "powershell.exe -nop",
    }])
    for batch in range(3):
        events = []
        for i in range(8):
            idx = batch * 8 + i
            events.append({
                "run_id": run, "platform": "windows", "event_type": "process_create",
                "timestamp": _ts(idx + 1), "pid": 6000 + idx, "ppid": 100,
                "process_name": f"xq-storm-mb-{idx:04d}.bin", "command_line": "x",
            })
        _ingest(client, run, events)
    fired = [a for a in _alerts(client, run) if a["rule_id"] == "first-seen-process"]
    assert len(fired) == 20
    assert client.get(f"/runs/{run}").json()["suppressed_alerts"] == {"first-seen-process": 4}