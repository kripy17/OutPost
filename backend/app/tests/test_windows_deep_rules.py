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


def _alerts(client, run_id: str) -> list[dict]:
    return client.get(f"/runs/{run_id}/alerts").json()


def test_windows_shadow_copy_deletion(client):
    run_id = make_run(client, sample_name="lockbit_ransom.exe", platform="windows")
    _ingest(client, run_id, [
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "process_create",
            "timestamp": _ts(1),
            "pid": 2048,
            "ppid": 1024,
            "process_name": "vssadmin.exe",
            "command_line": "vssadmin.exe delete shadows /all /quiet",
        }
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "shadow-copy-deletion"]
    assert len(fired) == 1
    assert fired[0]["severity"] == "malicious"
    assert "vssadmin deleting shadow copies" in fired[0]["details"]


def test_windows_remote_thread_injection(client):
    run_id = make_run(client, sample_name="inject_beacon.exe", platform="windows")
    _ingest(client, run_id, [
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "remote_thread",
            "timestamp": _ts(1),
            "pid": 3000,
            "process_name": "explorer.exe",
            "file_path": "C:\\Windows\\explorer.exe",
        }
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "remote-thread-injection"]
    assert len(fired) == 1
    assert fired[0]["severity"] == "malicious"
    assert "explorer.exe" in fired[0]["details"]


def test_windows_ifeo_persistence(client):
    run_id = make_run(client, sample_name="persist_hook.exe", platform="windows")
    _ingest(client, run_id, [
        {
            "run_id": run_id,
            "platform": "windows",
            "event_type": "registry_write",
            "timestamp": _ts(1),
            "pid": 4000,
            "registry_key": "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger",
        }
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "ifeo-persistence"]
    assert len(fired) == 1
    assert fired[0]["severity"] == "malicious"
