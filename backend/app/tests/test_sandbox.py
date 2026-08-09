"""Sandbox detonation adapter (roadmap 3.3).

Covers the demo detonation pipeline end-to-end (upload → detonate → run with
real alerts), the platform override, per-provider report normalizers (pure
functions, no network), the provider registry listing, and the error paths
(unknown sample / bad provider / unconfigured live provider / unknown task).
"""

import datetime

from ..services import sandbox as sandbox_service

MZ = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x53\x41\x4e\x44\x42\x4f\x58\x2d\x4d\x5a"


def _upload(client, name: str, body: bytes = MZ):
    resp = client.post(f"/samples?name={name}", content=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


# -- Demo detonation pipeline --------------------------------------------------


def test_demo_detonation_full_pipeline(client):
    sample = _upload(client, "sandbox-demo.exe")
    resp = client.post(
        "/sandbox/detonate",
        json={"sample_id": sample["sample_id"], "provider": "demo"},
    )
    assert resp.status_code == 202, resp.text
    task = resp.json()

    # Demo resolves inline — already completed with a real run behind it.
    assert task["status"] == "completed"
    assert task["provider"] == "demo"
    assert task["sample_name"] == "sandbox-demo.exe"
    assert task["platform"] == "windows"
    assert task["events"] >= 10
    assert task["alerts"] >= 3
    assert task["risk_score"] > 0
    assert task["highest_severity"] in ("suspicious", "malicious")

    # The run exists, is completed, and its detail carries the tree + alerts.
    run = client.get(f"/runs/{task['run_id']}").json()
    assert run["run"]["completed_at"] is not None
    # One root (the sample) with the cmd → powershell chain nested beneath it.
    assert len(run["process_tree"]) >= 1
    assert run["process_tree"][0]["children"], "expected a child process under the root"
    assert run["run"]["risk_score"] > 0

    # Same shape via the task status poll.
    again = client.get(f"/sandbox/tasks/{task['task_id']}").json()
    assert again["status"] == "completed"
    assert again["run_id"] == task["run_id"]


def test_demo_platform_override_runs_linux_scenario(client):
    sample = _upload(client, "cross-os.exe")
    resp = client.post(
        "/sandbox/detonate",
        json={"sample_id": sample["sample_id"], "provider": "demo", "platform": "linux"},
    )
    assert resp.status_code == 202, resp.text
    task = resp.json()
    assert task["platform"] == "linux"
    assert task["status"] == "completed"

    run = client.get(f"/runs/{task['run_id']}").json()
    assert run["run"]["platform"] == "linux"
    # The linux demo fires the LOLBin reverse-shell rule.
    rule_ids = {a["rule_id"] for a in run["alerts"]}
    assert "lolbin-abuse" in rule_ids
    # A reverse-shell connection to the C2 port is in the timeline.
    ips = {e["dest_ip"] for e in run["timeline"] if e["dest_ip"]}
    assert "198.51.100.10" in ips


def test_auto_resolves_to_demo_when_no_provider_configured(client):
    sample = _upload(client, "auto-demo.bin")
    resp = client.post(
        "/sandbox/detonate",
        json={"sample_id": sample["sample_id"], "provider": "auto"},
    )
    assert resp.status_code == 202, resp.text
    assert resp.json()["provider"] == "demo"


# -- Error paths ---------------------------------------------------------------


def test_unknown_sample_404(client):
    resp = client.post("/sandbox/detonate", json={"sample_id": "nope00000000", "provider": "demo"})
    assert resp.status_code == 404


def test_bad_provider_422(client):
    sample = _upload(client, "bad-prov.bin")
    resp = client.post("/sandbox/detonate", json={"sample_id": sample["sample_id"], "provider": "mysterybox"})
    assert resp.status_code == 422
    assert "Unknown sandbox provider" in resp.json()["detail"]


def test_unconfigured_live_provider_422(client):
    sample = _upload(client, "nokey.bin")
    resp = client.post("/sandbox/detonate", json={"sample_id": sample["sample_id"], "provider": "anyrun"})
    assert resp.status_code == 422
    assert "ANYRUN_API_KEY" in resp.json()["detail"]


def test_unknown_task_404(client):
    resp = client.get("/sandbox/tasks/doesnotexist99")
    assert resp.status_code == 404


# -- Provider registry ---------------------------------------------------------


def test_providers_listing(client):
    data = client.get("/sandbox/providers").json()
    ids = [p["id"] for p in data["providers"]]
    assert ids == ["anyrun", "triage", "joe", "demo"]
    assert data["mode"] == "demo"  # no API keys in the test env
    assert data["active"] == ""


# -- Report normalizers (pure functions, no network) ---------------------------


def _base():
    return datetime.datetime(2026, 8, 8, 12, 0, 0, tzinfo=datetime.timezone.utc)


def test_normalize_anyrun_report():
    report = {
        "process": [
            {"pid": 1, "ppid": 0, "processName": "evil.exe", "commandLine": r"C:\temp\evil.exe"},
            {"pid": 2, "ppid": 1, "processName": "powershell.exe", "commandLine": "powershell.exe -enc QUJD"},
        ],
        "files": [{"path": r"C:\Users\victim\Documents\invoice.enc"}],
        "registry": [{"path": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Bad"}],
    }
    net_report = {
        "network": [{"protocol": "TCP", "remoteHost": "203.0.113.99", "remotePort": 4444, "processPid": 2}]
    }
    report.update(net_report)
    events = sandbox_service.normalize_anyrun(report, "r1", "windows", _base())
    types = [e["event_type"] for e in events]
    assert types.count("process_create") == 2
    assert types.count("network_connection") == 1
    assert types.count("file_write") == 1
    assert types.count("registry_write") == 1
    net = next(e for e in events if e["event_type"] == "network_connection")
    assert net["dest_ip"] == "203.0.113.99" and net["dest_port"] == 4444
    proc = next(e for e in events if e["pid"] == 2)
    assert proc["process_name"] == "powershell.exe"


def test_normalize_triage_report_pid_keyed_processes():
    report = {
        "processes": {
            "10": {"pid": 10, "ppid": 1, "process_name": "bash", "command_line": "bash -i"},
            "11": {"pid": 11, "ppid": 10, "process_name": "curl", "command_line": "curl http://x"},
        },
        "network": {"tcp": [{"dst_ip": "198.51.100.7", "dst_port": 8080}]},
        "files": ["/tmp/staged.enc"],
    }
    events = sandbox_service.normalize_triage(report, "r2", "linux", _base())
    procs = [e for e in events if e["event_type"] == "process_create"]
    assert len(procs) == 2
    assert {p["pid"] for p in procs} == {10, 11}
    net = next(e for e in events if e["event_type"] == "network_connection")
    assert net["dest_ip"] == "198.51.100.7"
    assert any(e["file_path"] == "/tmp/staged.enc" for e in events)


def test_normalize_joe_report_nested_data():
    report = {
        "data": {
            "processes": [
                {"name": "svchost.exe", "pid": 3, "parent_pid": 1, "command_line": r"C:\Windows\System32\svchost.exe"}
            ],
            "network": {"udp": [{"dst_ip": "1.1.1.1", "dst_port": 53}]},
            "filesystem": [{"path": r"C:\temp\out.dat"}],
            "registry": [{"path": r"HKCU\Software\Run\Upd"}],
        }
    }
    events = sandbox_service.normalize_joe(report, "r3", "windows", _base())
    assert any(e["event_type"] == "process_create" and e["process_name"] == "svchost.exe" for e in events)
    assert any(e["event_type"] == "network_connection" and e["dest_ip"] == "1.1.1.1" for e in events)
    assert any(e["event_type"] == "registry_write" for e in events)


def test_normalize_report_dispatch_unknown_provider():
    try:
        sandbox_service.normalize_report("mysterybox", {}, "r", "windows", _base())
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_demo_events_are_normalized_shape():
    events = sandbox_service.demo_events("r9", "windows", "demo.exe", _base())
    assert events
    for ev in events:
        assert set(ev) == {
            "run_id", "platform", "event_type", "timestamp", "pid", "ppid",
            "process_name", "command_line", "dest_ip", "dest_port", "protocol",
            "file_path", "registry_key",
        }
        assert ev["run_id"] == "r9" and ev["platform"] == "windows"
