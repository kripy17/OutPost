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

from shipper import Shipper, claim_active_live_run  # noqa: E402
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

    def fake_post(url, json=None, timeout=None):
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


def test_shipper_spools_when_backend_down(monkeypatch, tmp_path):
    import requests

    def fake_post(url, json=None, timeout=None):
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

    def fake_post(url, json=None, timeout=None):
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
