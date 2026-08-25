"""Agent fleet — /agents groups events by host_id.

- Events without a host (webapp detonations) normalize to 'local' and show up
  as that host in the fleet.
- Collectors stamp their host, so multi-host attribution works end to end.
- The online flag follows the heartbeat window; alert_count joins through the
  run the events belong to.

The test DB is session-scoped across every test file, so absolute totals are
never asserted — only per-unique-host rows, which can't collide with other
tests.
"""

from datetime import datetime, timedelta, timezone

from .conftest import make_run


def _ts(dt: datetime) -> str:
    return dt.isoformat()


def _event(run_id: str, platform: str, host_id: str | None = None, ts: datetime | None = None, kind: str = "file_write") -> dict:
    ev = {
        "run_id": run_id,
        "platform": platform,
        "event_type": kind,
        "timestamp": _ts(ts or datetime.now(timezone.utc)),
        "pid": 1,
        "file_path": "/tmp/x.txt",
    }
    if host_id is not None:
        ev["host_id"] = host_id
    return ev


def test_fleet_groups_hosts_with_counts_and_online_flag(client):
    a = make_run(client, sample_name="agent-a.bin", platform="linux")
    b = make_run(client, sample_name="agent-b.bin", platform="windows")

    now = datetime.now(timezone.utc)
    client.post("/ingest/batch", json=[_event(a, "linux", "host-alpha", ts=now - timedelta(seconds=5))])
    client.post("/ingest/batch", json=[_event(a, "linux", "host-alpha", ts=now - timedelta(seconds=4))])
    client.post("/ingest/batch", json=[_event(b, "windows", "host-beta", ts=now - timedelta(minutes=30))])

    data = client.get("/agents").json()
    by_host = {ag["host_id"]: ag for ag in data["agents"]}

    alpha = by_host["host-alpha"]
    assert alpha["event_count"] == 2
    assert alpha["online"] is True
    assert alpha["platforms"] == ["linux"]

    beta = by_host["host-beta"]
    assert beta["event_count"] == 1
    assert beta["online"] is False
    assert beta["platforms"] == ["windows"]


def test_event_only_hosts_are_webapp_identity_with_channels(client):
    """Hosts with events but no heartbeat (webapp detonations / sandbox
    runs) read identity=webapp, channels=['webapp']; a collector-stamped
    channel (auditd) surfaces in channels."""
    a = make_run(client, sample_name="chan-a.bin", platform="linux")
    client.post("/ingest/batch", json=[_event(a, "linux", "web-only", ts=datetime.now(timezone.utc))])
    client.post(
        "/ingest/batch",
        json=[{**_event(a, "linux", "collector-host", ts=datetime.now(timezone.utc)), "log_source": "auditd"}],
    )

    data = client.get("/agents").json()
    by_host = {ag["host_id"]: ag for ag in data["agents"]}

    web = by_host["web-only"]
    assert web["identity"] == "webapp"
    assert web["last_auth_role"] is None
    assert web["last_auth_at"] is None
    assert web["channels"] == ["webapp"]

    col = by_host["collector-host"]
    assert col["identity"] == "webapp"  # events alone don't prove a collector
    assert col["channels"] == ["auditd"]


def test_fleet_reports_per_channel_event_volume(client):
    """channel_counts splits each host's telemetry by channel (auditd vs
    sysmon vs webapp), so the Agents page shows the MIX — the counts must
    sum to event_count and the distinct channels must agree with `channels`."""
    a = make_run(client, sample_name="mix-a.bin", platform="linux")
    now = datetime.now(timezone.utc)
    # Distinct timestamps so the ingest dedup (which intentionally ignores
    # log_source — a retry re-stamps the same channel) keeps all four events.
    client.post(
        "/ingest/batch",
        json=[
            {**_event(a, "linux", "mix-host", ts=now), "log_source": "auditd"},
            {**_event(a, "linux", "mix-host", ts=now - timedelta(seconds=1)), "log_source": "auditd"},
            {**_event(a, "linux", "mix-host", ts=now - timedelta(seconds=2)), "log_source": "sysmon"},
            {**_event(a, "linux", "mix-host", ts=now - timedelta(seconds=3))},  # no stamp → webapp
        ],
    )

    data = client.get("/agents").json()
    by_host = {ag["host_id"]: ag for ag in data["agents"]}
    host = by_host["mix-host"]
    assert host["event_count"] == 4
    assert host["channels"] == ["auditd", "sysmon", "webapp"]
    assert host["channel_counts"] == {"auditd": 2, "sysmon": 1, "webapp": 1}
    assert sum(host["channel_counts"].values()) == host["event_count"]

    # Heartbeat-only hosts (no events yet) report an empty mix, not a missing key.
    client.post("/agents/mix-hb/heartbeat", json={"platform": "linux", "version": "outpost-collector/1.0"})
    hb = {ag["host_id"]: ag for ag in client.get("/agents").json()["agents"]}["mix-hb"]
    assert hb["channel_counts"] == {}


# ---------------------------------------------------------------------------
# Heartbeat liveness
# ---------------------------------------------------------------------------


def test_identity_filter_narrows_fleet(client):
    """?identity=collector|webapp|silent filters the same fleet rows the
    Agents page uses (filter-in-URL parity), with totals scoped to the result."""
    a = make_run(client, sample_name="filt-a.bin", platform="linux")
    now = datetime.now(timezone.utc)
    # Event-only host → webapp identity.
    client.post("/ingest/batch", json=[_event(a, "linux", "filt-web", ts=now - timedelta(seconds=5))])
    # Collector host → heartbeats + events.
    client.post("/agents/filt-col/heartbeat", json={"platform": "linux", "version": "outpost-collector/1.0"})
    client.post("/ingest/batch", json=[_event(a, "linux", "filt-col", ts=now - timedelta(seconds=3))])

    # Session DB is shared across files — assert per-host rows + cross-
    # exclusion, never absolute totals (file convention).
    all_ = client.get("/agents").json()
    assert all_["identity"] is None
    ids = {a["host_id"] for a in all_["agents"]}
    assert "filt-web" in ids and "filt-col" in ids

    cols = client.get("/agents", params={"identity": "collector"}).json()
    assert cols["identity"] == "collector"
    col_ids = {a["host_id"] for a in cols["agents"]}
    assert "filt-col" in col_ids and "filt-web" not in col_ids
    assert all(a["identity"] == "collector" for a in cols["agents"])

    webs = client.get("/agents", params={"identity": "webapp"}).json()
    web_ids = {a["host_id"] for a in webs["agents"]}
    assert "filt-web" in web_ids and "filt-col" not in web_ids
    assert all(a["identity"] == "webapp" for a in webs["agents"])

    # Unknown value → 422 (the pattern whitelists exactly the three views).
    assert client.get("/agents", params={"identity": "bogus"}).status_code == 422


def test_heartbeat_marks_host_online_and_reports_age(client):
    """A fresh heartbeat makes a host online even with no events, and the
    fleet reports last_heartbeat + age + version."""
    resp = client.post(
        "/agents/hb-alpha/heartbeat",
        json={"platform": "linux", "version": "outpost-collector/1.0"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

    data = client.get("/agents").json()
    by_host = {ag["host_id"]: ag for ag in data["agents"]}
    alpha = by_host["hb-alpha"]
    assert alpha["online"] is True
    assert alpha["silent"] is False
    assert alpha["last_heartbeat"] is not None
    assert alpha["heartbeat_age_seconds"] is not None and alpha["heartbeat_age_seconds"] < 60
    assert alpha["heartbeat_version"] == "outpost-collector/1.0"
    assert alpha["event_count"] == 0  # online on heartbeat alone

    # Last-auth context: with auth off (zero-config default) the heartbeat
    # carries no credential — role 'local'; identity is collector because a
    # heartbeat only ever comes from the real shipper.
    assert alpha["identity"] == "collector"
    assert alpha["last_auth_role"] == "local"
    assert alpha["last_auth_at"] is not None
    assert alpha["channels"] == []
    # This host is not silent — the fleet-wide silent count may be > 0 from
    # other tests' backdated hosts (shared session DB).


def test_heartbeat_upserts_single_row_per_host(client, conn):
    """Repeated pings never duplicate the host row."""
    for _ in range(3):
        client.post("/agents/hb-beta/heartbeat", json={"platform": "windows"})
    rows = conn.execute("SELECT COUNT(*) FROM agent_heartbeats WHERE host_id = 'hb-beta'").fetchone()[0]
    assert rows == 1
    data = client.get("/agents").json()
    assert len([a for a in data["agents"] if a["host_id"] == "hb-beta"]) == 1


def test_host_gone_silent_is_flagged(client, conn):
    """A host that heartbeated but hasn't for > silent_window reads silent and
    offline — the dead-agent flag."""
    client.post("/agents/hb-gamma/heartbeat", json={"platform": "linux"})
    # Backdate the heartbeat past the default 600s silent window.
    old = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
    conn.execute(
        "UPDATE agent_heartbeats SET last_heartbeat = ? WHERE host_id = 'hb-gamma'",
        (old,),
    )
    conn.commit()

    data = client.get("/agents").json()
    by_host = {ag["host_id"]: ag for ag in data["agents"]}
    gamma = by_host["hb-gamma"]
    assert gamma["online"] is False
    assert gamma["silent"] is True
    assert gamma["heartbeat_age_seconds"] >= 30 * 60
    assert data["silent"] >= 1

    # The same host with a fresh heartbeat is no longer silent.
    client.post("/agents/hb-gamma/heartbeat")
    data = client.get("/agents").json()
    gamma = {ag["host_id"]: ag for ag in data["agents"]}["hb-gamma"]
    assert gamma["online"] is True
    assert gamma["silent"] is False


def test_events_without_host_default_to_local(client):
    run_id = make_run(client, sample_name="local-attr.bin")
    client.post("/ingest/batch", json=[_event(run_id, "windows")])  # no host_id

    data = client.get("/agents").json()
    local = next((a for a in data["agents"] if a["host_id"] == "local"), None)
    assert local is not None, "events without a host must attribute to 'local'"
    assert local["event_count"] >= 1


def test_alert_count_rolls_up_from_host_runs(client):
    run_id = make_run(client, sample_name="dirty-host.bin")
    now = datetime.now(timezone.utc)
    client.post(
        "/ingest/batch",
        json=[
            {
                "run_id": run_id,
                "platform": "windows",
                "event_type": "process_create",
                "timestamp": _ts(now),
                "pid": 1,
                "ppid": 0,
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc SQBFAFgAAGgBdAA=",
                "host_id": "host-gamma",
            }
        ],
    )

    data = client.get("/agents").json()
    gamma = next(a for a in data["agents"] if a["host_id"] == "host-gamma")
    assert gamma["alert_count"] == 1  # the LOLBin fired a malicious alert
    assert gamma["run_count"] == 1


def test_events_feed_carries_and_searches_host_id(client):
    run_id = make_run(client, sample_name="feed-host.bin", platform="linux")
    client.post("/ingest/batch", json=[_event(run_id, "linux", "host-delta")])

    ev = client.get("/events", params={"q": "host-delta"}).json()["events"]
    assert ev and ev[0]["host_id"] == "host-delta"


def test_run_summary_carries_host_ids(client):
    run_id = make_run(client, sample_name="multi-host.bin", platform="linux")
    now = datetime.now(timezone.utc)
    client.post("/ingest/batch", json=[_event(run_id, "linux", "host-one", ts=now)])
    client.post("/ingest/batch", json=[_event(run_id, "linux", "host-two", ts=now)])

    run = client.get(f"/runs/{run_id}").json()["run"]
    assert set(run["host_ids"]) == {"host-one", "host-two"}


def test_runs_filter_by_host(client):
    a = make_run(client, sample_name="host-a-run.bin", platform="windows")
    b = make_run(client, sample_name="host-b-run.bin", platform="linux")
    now = datetime.now(timezone.utc)
    client.post("/ingest/batch", json=[_event(a, "windows", "host-echo", ts=now)])
    client.post("/ingest/batch", json=[_event(b, "linux", "host-foxtrot", ts=now)])

    hits = client.get("/runs", params={"host": "host-echo", "include_synthetic": "true"}).json()
    assert [r["run_id"] for r in hits] == [a]
    assert client.get("/runs", params={"host": "host-foxtrot", "include_synthetic": "true"}).json()[0]["run_id"] == b
    # Runs with no matching events are excluded.
    assert client.get("/runs", params={"host": "no-such-host", "include_synthetic": "true"}).json() == []


def test_agents_list_recent_run_ids(client):
    run_id = make_run(client, sample_name="recent-host.bin", platform="linux")
    now = datetime.now(timezone.utc)
    client.post("/ingest/batch", json=[_event(run_id, "linux", "host-golf", ts=now)])

    data = client.get("/agents").json()
    golf = next(a for a in data["agents"] if a["host_id"] == "host-golf")
    assert run_id in golf["recent_run_ids"]


def test_snapshot_ingest_and_read_back(client):
    """POST /ingest/snapshot stores the latest payload per host; the fleet
    reports last_snapshot_at and GET /agents/{host}/snapshot returns it."""
    snap = {
        "host_id": "host-snap",
        "platform": "linux",
        "collected_at": "2026-08-08T15:00:00Z",
        "processes": [{"pid": 1, "name": "systemd", "user": "0", "cmdline": "/usr/lib/systemd/systemd"}],
        "listening": [{"proto": "tcp", "addr": "0.0.0.0", "port": 443, "pid": 1}],
    }
    resp = client.post("/ingest/snapshot", json=snap)
    assert resp.status_code == 200
    assert resp.json()["stored"] is True
    assert resp.json()["processes"] == 1 and resp.json()["listening"] == 1

    got = client.get("/agents/host-snap/snapshot").json()
    assert got["processes"][0]["name"] == "systemd"
    assert got["listening"][0]["port"] == 443
    assert got["stored_at"] == "2026-08-08T15:00:00Z"

    data = client.get("/agents").json()
    snap_host = next(a for a in data["agents"] if a["host_id"] == "host-snap")
    assert snap_host["last_snapshot_at"] == "2026-08-08T15:00:00Z"

    # Newer snapshot replaces the old one.
    snap["processes"].append({"pid": 2, "name": "nginx", "user": "0", "cmdline": ""})
    client.post("/ingest/snapshot", json=snap)
    assert len(client.get("/agents/host-snap/snapshot").json()["processes"]) == 2


def test_snapshot_unknown_host_404(client):
    assert client.get("/agents/no-such-host/snapshot").status_code == 404


# ---------------------------------------------------------------------------
# Host watch — the Monitor's 'watch a host' mode
# ---------------------------------------------------------------------------


def test_host_watch_returns_newest_run_for_host(client):
    """GET /hosts/{host}/watch opens the host's newest session (open live
    runs first, else the most recent) — what the Monitor streams when an
    operator picks a fleet host."""
    a = make_run(client, sample_name="watch-a.bin", platform="windows")
    b = make_run(client, sample_name="watch-b.bin", platform="linux")
    now = datetime.now(timezone.utc)
    client.post("/ingest/batch", json=[_event(a, "windows", "host-watch", ts=now - timedelta(minutes=10))])
    client.post("/ingest/batch", json=[_event(b, "linux", "host-watch", ts=now)])

    resp = client.get("/hosts/host-watch/watch")
    assert resp.status_code == 200
    data = resp.json()
    assert data["run_id"] == b  # the newest session from this host
    assert data["run"]["sample_name"] == "watch-b.bin"
    assert data["run"]["host_ids"] == ["host-watch"]
    assert "open" in data

    # Runs with no events from this host are never returned.
    assert client.get("/hosts/no-such-host/watch").status_code == 404


def test_host_watch_prefers_open_live_session(client):
    """An in-progress live session wins over an older completed run — the
    'watch it now' semantics."""
    old = make_run(client, sample_name="watch-old.bin", platform="linux")
    now = datetime.now(timezone.utc)
    client.post("/ingest/batch", json=[_event(old, "linux", "host-live", ts=now - timedelta(minutes=20))])
    client.post(f"/runs/{old}/complete", json={})

    live = make_run(client, sample_name="watch-live.bin", platform="linux", session_type="live")
    client.post("/ingest/batch", json=[_event(live, "linux", "host-live", ts=now - timedelta(seconds=5))])

    data = client.get("/hosts/host-live/watch").json()
    assert data["run_id"] == live
    assert data["open"] is True
    assert data["run"]["session_type"] == "live"

    # Don't leak an open live session into the shared test DB — the ingest
    # tests assert /runs/active-live falls back to 404 when nothing is open.
    client.post(f"/runs/{live}/complete", json={})


def test_agent_bootstrap_scripts_and_commands(client):
    """Assert bootstrap script endpoints return valid scripts and commands."""
    res_sh = client.get("/agents/install.sh")
    assert res_sh.status_code == 200
    assert "OUTPOST_API_URL" in res_sh.text
    assert "#!/usr/bin/env bash" in res_sh.text

    res_ps1 = client.get("/agents/install.ps1")
    assert res_ps1.status_code == 200
    assert "OUTPOST_API_URL" in res_ps1.text

    res_cmd = client.get("/agents/bootstrap-command")
    assert res_cmd.status_code == 200
    data = res_cmd.json()
    assert "linux_command" in data
    assert "curl" in data["linux_command"]
    assert "windows_command" in data


def test_host_containment_isolation_and_kill(client):
    """Assert active host isolation and process kill actions work and reflect in heartbeat."""
    host = "host-contain-test"
    # Initially uncontained
    res = client.get(f"/agents/{host}/containment")
    assert res.status_code == 200
    assert res.json()["isolated"] is False

    # Isolate host
    iso_res = client.post(f"/agents/{host}/isolate", json={"isolated": True, "reason": "Suspected Ransomware"})
    assert iso_res.status_code == 200
    assert iso_res.json()["isolated"] is True

    # Queue process kill
    kill_res = client.post(f"/agents/{host}/kill-process", json={"pid": 9999, "process_name": "badware.exe"})
    assert kill_res.status_code == 200
    assert kill_res.json()["status"] == "queued"

    # Verify containment endpoint reflects state
    cont_res = client.get(f"/agents/{host}/containment").json()
    assert cont_res["isolated"] is True
    assert cont_res["reason"] == "Suspected Ransomware"
    assert len(cont_res["pending_actions"]) == 1
    assert cont_res["pending_actions"][0]["pid"] == 9999

    # Heartbeat receives containment instructions
    hb_res = client.post(f"/agents/{host}/heartbeat", json={"platform": "linux", "version": "0.1.0"}).json()
    assert hb_res["isolated"] is True
    assert len(hb_res["pending_actions"]) == 1

    # Un-isolate
    uniso_res = client.post(f"/agents/{host}/isolate", json={"isolated": False})
    assert uniso_res.status_code == 200
    assert uniso_res.json()["isolated"] is False
