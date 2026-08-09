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

    hits = client.get("/runs", params={"host": "host-echo"}).json()
    assert [r["run_id"] for r in hits] == [a]
    assert client.get("/runs", params={"host": "host-foxtrot"}).json()[0]["run_id"] == b
    # Runs with no matching events are excluded.
    assert client.get("/runs", params={"host": "no-such-host"}).json() == []


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
