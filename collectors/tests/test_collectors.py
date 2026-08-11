"""Collector verification (roadmap 2.1) — parser + shipper unit tests.

The collectors are the least-tested part of the codebase; these tests lock
the parsing and shipping behavior so a fresh checkout can trust them without
an auditd/Sysmon host. Pure functions only — no root, no real telemetry.
"""

import json
import sys
from pathlib import Path

import pytest

_COMMON = Path(__file__).resolve().parent.parent / "common"
_LINUX = Path(__file__).resolve().parent.parent / "linux"
_WINDOWS = Path(__file__).resolve().parent.parent / "windows"
sys.path.insert(0, str(_COMMON))
sys.path.insert(0, str(_LINUX))
sys.path.insert(0, str(_WINDOWS))

from shipper import Shipper, _default_host_id, agent_run_name, claim_active_live_run, resolve_live_run_id  # noqa: E402
from collector_linux import _parse_saddr, parse_audit_line  # noqa: E402


# ---------------------------------------------------------------------------
# Linux (auditd) parser
# ---------------------------------------------------------------------------


def test_linux_parse_execve_event():
    # Real auditd: type=EXECVE carries the program args (a0=…), no pid.
    line = 'type=EXECVE msg=audit(1721234567.890:123): argc=2 a0="/bin/bash" a1="-c"'
    ev = parse_audit_line(line, {})
    assert ev is not None
    assert ev["event_type"] == "process_create"
    assert ev["platform"] == "linux"
    assert ev["process_name"] == "/bin/bash"


def test_linux_parse_connect_event():
    # saddr hex: family 02, port 0x115C (4444), addr C0A87158 (192.168.113.88).
    line = 'type=SYSCALL msg=audit(1721234568.000:124): arch=c000003e syscall=42 success=yes pid=1002 comm="curl" saddr=0200115CC0A87158'
    ev = parse_audit_line(line, {})
    assert ev is not None
    assert ev["event_type"] == "network_connection"
    assert ev["dest_ip"] == "192.168.113.88"
    assert ev["dest_port"] == 4444
    assert ev["protocol"] == "TCP"


def test_linux_saddr_parser_decodes_hex():
    # port 80 (0x50), IP 1.2.3.4
    assert _parse_saddr("saddr=02000050" + "01020304") == ("1.2.3.4", 80)
    assert _parse_saddr("nope") == (None, None)
    assert _parse_saddr("saddr=02") == (None, None)  # too short


def test_linux_parse_ignores_non_audit_lines():
    assert parse_audit_line("hello world", {}) is None
    assert parse_audit_line("", {}) is None


def test_linux_execve_dedup_per_pid():
    line = 'type=SYSCALL msg=audit(1721234567.890:1): arch=c000003e syscall=59 success=yes pid=99 comm="x" exe="/bin/x"'
    cache = {}
    assert parse_audit_line(line, cache) is not None
    assert parse_audit_line(line, cache) is None  # deduped


# ---------------------------------------------------------------------------
# Windows (Sysmon) parser — exercised through a stub record
# ---------------------------------------------------------------------------


class _StubRecord:
    """Minimal stand-in for a win32evtlog record."""

    def __init__(self, event_id, data, ts=1721234567.0):
        self.EventID = event_id
        self.Data = data
        self.TimeGenerated = _StubTime(ts)


class _StubTime:
    def __init__(self, ts):
        self._ts = ts

    def timestamp(self):
        return self._ts


def test_windows_sysmon_process_create():
    from collector_win import parse_sysmon_event

    rec = _StubRecord(
        1,
        [
            "Image", "C:\\Windows\\System32\\cmd.exe",
            "CommandLine", "cmd.exe /c whoami",
            "ProcessId", "4200",
            "ParentProcessId", "4199",
        ],
    )
    ev = parse_sysmon_event(rec)
    assert ev is not None
    assert ev["event_type"] == "process_create"
    assert ev["platform"] == "windows"
    assert ev["process_name"] == "cmd.exe"
    assert ev["pid"] == 4200
    assert ev["ppid"] == 4199
    assert ev["command_line"] == "cmd.exe /c whoami"


def test_windows_sysmon_network_connection():
    from collector_win import parse_sysmon_event

    rec = _StubRecord(
        3,
        [
            "Image", "C:\\Tools\\evil.exe",
            "DestinationIp", "203.0.113.88",
            "DestinationPort", "4444",
            "Protocol", "tcp",
        ],
    )
    ev = parse_sysmon_event(rec)
    assert ev["event_type"] == "network_connection"
    assert ev["dest_ip"] == "203.0.113.88"
    assert ev["dest_port"] == 4444
    assert ev["process_name"] == "evil.exe"


def test_windows_sysmon_registry_write():
    from collector_win import parse_sysmon_event

    rec = _StubRecord(
        13,
        ["Image", "C:\\x.exe", "TargetObject", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater"],
    )
    ev = parse_sysmon_event(rec)
    assert ev["event_type"] == "registry_write"
    assert "CurrentVersion\\Run" in ev["registry_key"]


def test_windows_sysmon_ignores_unmapped_event_id():
    from collector_win import parse_sysmon_event

    assert parse_sysmon_event(_StubRecord(99, [])) is None


# ---------------------------------------------------------------------------
# Shared shipper
# ---------------------------------------------------------------------------


def test_shipper_batches_at_batch_size(monkeypatch, tmp_path):
    posted: list[list[dict]] = []

    class FakeResp:
        def raise_for_status(self):
            return None

    def fake_post(url, json=None, timeout=None, headers=None):
        posted.append(json or [])
        return FakeResp()

    monkeypatch.setattr("shipper.requests.post", fake_post)
    sh = Shipper("http://backend", "run-1", batch_size=3, flush_interval=999, spool_path=str(tmp_path / "s.jsonl"))
    for i in range(5):
        sh.add({"event_type": "process_create", "pid": i})
    # 3 events flushed at batch size, 2 remain buffered.
    assert len(posted) == 1
    assert len(posted[0]) == 3
    assert all(e["run_id"] == "run-1" for e in posted[0])


def test_shipper_stamps_log_channel_from_platform(monkeypatch, tmp_path):
    """Every shipped event carries its exact log channel (auditd / sysmon),
    stamped from its own platform — the Event Log's source tabs split the
    collector stream by this tag, not by inference."""
    posted: list[list[dict]] = []

    class FakeResp:
        def raise_for_status(self):
            return None

    def fake_post(url, json=None, timeout=None, headers=None):
        posted.append(json or [])
        return FakeResp()

    monkeypatch.setattr("shipper.requests.post", fake_post)
    sh = Shipper("http://backend", "run-chan", batch_size=2, flush_interval=999, spool_path=str(tmp_path / "c.jsonl"))
    sh.add({"event_type": "process_create", "platform": "linux", "pid": 1})
    sh.add({"event_type": "process_create", "platform": "windows", "pid": 2})
    sh.add({"event_type": "file_write", "file_path": "/tmp/x"})  # no platform → untagged
    sh.flush()

    all_events = [e for batch in posted for e in batch]
    tagged = {e["platform"]: e.get("log_source") for e in all_events if "platform" in e}
    assert tagged == {"linux": "auditd", "windows": "sysmon"}
    # Untagged events (no platform) stay untagged — the tag is never guessed.
    assert all(e.get("log_source") is None for e in all_events if "platform" not in e)


def test_shipper_spools_when_backend_down(monkeypatch, tmp_path):
    import requests

    def fake_post(url, json=None, timeout=None, headers=None):
        raise requests.ConnectionError("down")

    monkeypatch.setattr("shipper.requests.post", fake_post)
    spool = tmp_path / "spool.jsonl"
    sh = Shipper("http://down", "run-2", batch_size=2, flush_interval=999, max_retries=1, spool_path=str(spool))
    sh.add({"event_type": "file_write", "file_path": "/etc/crontab"})
    sh.add({"event_type": "file_write", "file_path": "/etc/rc.local"})
    sh.flush()
    assert spool.exists()
    lines = [json.loads(l) for l in spool.read_text().splitlines() if l.strip()]
    assert len(lines) == 2
    assert lines[0]["file_path"] == "/etc/crontab"


def test_claim_returns_newest_open_live_run(monkeypatch):
    """--auto flow: claim returns the run id the backend names."""

    class FakeResp:
        def __init__(self, status=200):
            self.status_code = status

        @property
        def ok(self):
            return self.status_code == 200

        def json(self):
            return {"run_id": "abc123def456", "session_type": "live"}

    monkeypatch.setattr("shipper.requests.get", lambda *a, **k: FakeResp())
    assert claim_active_live_run("http://backend:8001") == "abc123def456"


def test_claim_errors_cleanly_when_no_live_session(monkeypatch):
    """The human-facing message is the feature's UX contract."""

    class _404:
        status_code = 404
        ok = False

    monkeypatch.setattr("shipper.requests.get", lambda *a, **k: _404())
    with pytest.raises(RuntimeError, match="No active live session"):
        claim_active_live_run("http://backend:8001")


def test_claim_errors_when_backend_unreachable(monkeypatch):
    import requests

    def boom(*a, **k):
        raise requests.ConnectionError("down")

    monkeypatch.setattr("shipper.requests.get", boom)
    with pytest.raises(RuntimeError, match="not reachable"):
        claim_active_live_run("http://backend:8001")


def test_shipper_replays_spool_after_recovery(monkeypatch, tmp_path):
    posted: list[list[dict]] = []
    calls = {"n": 0}

    class FakeResp:
        def raise_for_status(self):
            return None

    def fake_post(url, json=None, timeout=None, headers=None):
        import requests

        calls["n"] += 1
        if calls["n"] == 1:
            raise requests.ConnectionError("down")
        posted.append(json or [])
        return FakeResp()

    monkeypatch.setattr("shipper.requests.post", fake_post)
    spool = tmp_path / "spool.jsonl"
    sh = Shipper("http://backend", "run-3", batch_size=10, flush_interval=999, max_retries=1, spool_path=str(spool))
    sh.add({"event_type": "process_create", "process_name": "bash"})
    sh.flush()  # fails → spooled
    assert spool.exists()
    sh.flush()  # now reachable → replay + clear
    assert not spool.exists()
    assert posted and any("bash" in str(e) for batch in posted for e in batch)


def test_snapshot_collect_shapes_and_ships(monkeypatch, tmp_path):
    """The Linux snapshot has the fixed schema (processes + listening), and
    the shipper POSTs it to /ingest/snapshot best-effort without dying."""
    import snapshot as snap_mod  # collectors/common on sys.path (see imports)

    payload = snap_mod.collect_snapshot("host-1", platform="linux")
    assert set(payload.keys()) == {"host_id", "platform", "collected_at", "processes", "listening"}
    assert isinstance(payload["processes"], list) and isinstance(payload["listening"], list)
    if payload["processes"]:
        assert {"pid", "name", "user", "cmdline"} <= set(payload["processes"][0].keys())

    posted = {}

    class FakeResp:
        def raise_for_status(self):
            return None

    def fake_post(url, json=None, timeout=None, headers=None):
        posted["url"] = url
        posted["json"] = json
        return FakeResp()

    monkeypatch.setattr("shipper.requests.post", fake_post)
    sh = Shipper("http://backend", "run-snap", spool_path=str(tmp_path / "s.jsonl"))
    sh.ship_snapshot(platform="linux")
    assert posted["url"] == "http://backend/ingest/snapshot"
    assert posted["json"]["host_id"] == sh.host_id


def test_snapshot_ship_failure_is_best_effort(monkeypatch, tmp_path):
    """A down backend must never raise out of ship_snapshot — the event loop
    keeps running even when the snapshot can't ship."""
    import requests

    def boom(url, json=None, timeout=None):
        raise requests.ConnectionError("down")

    monkeypatch.setattr("shipper.requests.post", boom)
    sh = Shipper("http://down", "run-x", spool_path=str(tmp_path / "s.jsonl"))
    assert sh.ship_snapshot(platform="linux") is None


def test_heartbeat_pings_once_per_interval(monkeypatch, tmp_path):
    """Liveness: the shipper pings /agents/{host}/heartbeat at most once per
    interval (a quiet host still reads online) and is best-effort — a down
    backend never raises out of the loop."""
    import requests

    posted: list[tuple] = []

    def fake_post(url, json=None, timeout=None, headers=None):
        if url.endswith("/heartbeat"):
            posted.append((url, json))

        class _R:
            def raise_for_status(self):
                return None

        return _R()

    monkeypatch.setattr("shipper.requests.post", fake_post)
    sh = Shipper("http://backend:8001", "run-hb", host_id="hb-host", spool_path=str(tmp_path / "s.jsonl"))

    sh.maybe_heartbeat(platform="linux", interval=60.0)
    sh.maybe_heartbeat(platform="linux", interval=60.0)  # within interval → no-op
    assert len(posted) == 1
    url, body = posted[0]
    assert url == "http://backend:8001/agents/hb-host/heartbeat"
    assert body["platform"] == "linux"
    assert body["version"] == "outpost-collector/1.0"

    # Interval elapsed → pings again.
    sh.maybe_heartbeat(platform="linux", interval=0.0)
    assert len(posted) == 2

    # Down backend: silent failure, next tick retries.
    def boom(url, json=None, timeout=None):
        raise requests.ConnectionError("down")

    monkeypatch.setattr("shipper.requests.post", boom)
    sh.maybe_heartbeat(platform="linux", interval=0.0)  # must not raise
    assert len(posted) == 2  # nothing new posted
    assert sh._last_heartbeat > 0  # retry bookkeeping still advances


def test_shipper_sends_agent_token_when_configured(monkeypatch, tmp_path):
    """With OUTPOST_AGENT_TOKEN set, every shipped request carries it as
    `Authorization: Bearer` — the collector authenticates against a
    fail-closed backend (OUTPOST_AUTH_REQUIRED=1). Without it, no header."""
    seen: list[dict] = []

    class FakeResp:
        def raise_for_status(self):
            return None

    def fake_post(url, json=None, timeout=None, headers=None):
        seen.append(headers or {})
        return FakeResp()

    monkeypatch.setattr("shipper.requests.post", fake_post)
    monkeypatch.setenv("OUTPOST_AGENT_TOKEN", "agent-secret")

    sh = Shipper("http://backend", "run-auth", batch_size=2, flush_interval=999, spool_path=str(tmp_path / "s.jsonl"))
    sh.add({"event_type": "process_create", "pid": 1})
    sh.add({"event_type": "file_write", "file_path": "/tmp/x"})
    sh.flush()
    assert seen and seen[0].get("Authorization") == "Bearer agent-secret"

    # Unset → no Authorization header at all.
    monkeypatch.delenv("OUTPOST_AGENT_TOKEN", raising=False)
    seen.clear()
    sh2 = Shipper("http://backend", "run-noauth", batch_size=2, flush_interval=999, spool_path=str(tmp_path / "s2.jsonl"))
    sh2.add({"event_type": "process_create", "pid": 2})
    sh2.add({"event_type": "process_create", "pid": 3})
    sh2.flush()
    assert all("Authorization" not in (h or {}) for h in seen)


# ---------------------------------------------------------------------------
# Standalone live session resolution (systemd service — no webapp needed)
# ---------------------------------------------------------------------------


def test_agent_run_name_is_one_session_per_host_per_day():
    import datetime as dt

    when = dt.datetime(2026, 8, 9, 12, 0, tzinfo=dt.timezone.utc)
    assert agent_run_name("archlinux", when) == "agent-archlinux-2026-08-09"


def _resp(ok=True, status=200, data=None):
    # Class bodies don't close over enclosing function locals — thread the
    # values through __init__ instead.
    class _R:
        def __init__(self, ok, status, data):
            self.ok = ok
            self.status_code = status
            self._data = data

        def json(self):
            return self._data

        def raise_for_status(self):
            if not self.ok:
                raise RuntimeError(f"HTTP {self.status_code}")

    return _R(ok, status, data)


def test_resolve_claims_webapp_live_session_first(monkeypatch):
    """Precedence 1: the webapp's open live session wins (Live Monitor parity)."""
    monkeypatch.setattr(
        "shipper.requests.get",
        lambda *a, **k: _resp(data={"run_id": "webapp-live", "session_type": "live"}),
    )
    assert resolve_live_run_id("http://backend:8001", "linux") == "webapp-live"


def test_resolve_reuses_todays_open_agent_run(monkeypatch):
    """Precedence 2: crash-restart of the service reuses today's run — the
    daily FP measurement stays one session per host per day."""
    # The run name uses the REAL host id (_default_host_id), not a fixed
    # value — a hardcoded "archlinux" matched only on the dev box and fell
    # through to an unpatched POST on CI hosts, failing with a DNS error.
    today = agent_run_name(_default_host_id())
    calls = {"n": 0}

    def fake_get(url, timeout=None, headers=None):
        calls["n"] += 1
        if "/runs/active-live" in url:
            return _resp(ok=False, status=404)
        return _resp(data=[
            {"run_id": "old-run", "sample_name": "agent-archlinux-2026-08-08", "session_type": "live", "completed_at": None},
            {"run_id": "today-run", "sample_name": today, "session_type": "live", "completed_at": None},
        ])

    monkeypatch.setattr("shipper.requests.get", fake_get)
    assert resolve_live_run_id("http://backend:8001", "linux") == "today-run"


def test_resolve_creates_fresh_run_when_none_open(monkeypatch):
    """Precedence 3: no webapp session and no today run → the service creates
    its own live session (source=agent)."""
    posted = {}

    def fake_get(url, timeout=None, headers=None):
        if "/runs/active-live" in url:
            return _resp(ok=False, status=404)
        return _resp(data=[])

    def fake_post(url, json=None, timeout=None, headers=None):
        posted["url"] = url
        posted["json"] = json
        return _resp(status=201, data={"run_id": "brand-new"})

    monkeypatch.setattr("shipper.requests.get", fake_get)
    monkeypatch.setattr("shipper.requests.post", fake_post)
    rid = resolve_live_run_id("http://backend:8001", "linux")
    assert rid == "brand-new"
    assert posted["url"] == "http://backend:8001/runs"
    assert posted["json"]["session_type"] == "live"
    assert posted["json"]["source"] == "agent"
    assert posted["json"]["sample_name"].startswith("agent-")
