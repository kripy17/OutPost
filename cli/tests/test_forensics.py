"""Tests for the Deep Host Forensics CLI commands and TUI views."""

from rich.console import Console
from typer.testing import CliRunner

from outpost.commands.forensics import app
from outpost.lib import api_client
from outpost.tui import OutPostTUI, console

runner = CliRunner()


def test_forensics_snapshot_cli(monkeypatch):
    monkeypatch.setattr(
        api_client,
        "get_forensics_snapshot",
        lambda: {
            "metrics": {
                "cpu_percent": 12.5,
                "memory_used_mb": 4096.0,
                "memory_total_mb": 8192.0,
                "memory_percent": 50.0,
                "platform": "linux",
                "timestamp": "2026-08-30T10:00:00Z",
            },
            "processes": [
                {"pid": 101, "name": "python", "user": "kripy", "cpu_percent": 2.5, "memory_mb": 120.0, "cmdline": "python app.py"}
            ],
            "process_count": 1,
            "socket_count": 0,
        },
    )

    res = runner.invoke(app, ["snapshot"])
    assert res.exit_code == 0
    assert "Host Telemetry Snapshot" in res.stdout
    assert "LINUX" in res.stdout
    assert "python" in res.stdout


def test_forensics_process_cli(monkeypatch):
    monkeypatch.setattr(
        api_client,
        "get_forensics_process",
        lambda pid: {
            "pid": pid,
            "ppid": 1,
            "name": "target_proc",
            "status": "running",
            "exe": "/usr/bin/target_proc",
            "cmdline": "target_proc --daemon",
            "user": "root",
            "cpu_percent": 1.0,
            "memory_mb": 50.0,
            "threads": 4,
            "lineage": [{"pid": 1, "name": "systemd", "relation": "ancestor"}, {"pid": pid, "name": "target_proc", "relation": "self"}],
            "sockets": [{"protocol": "TCP", "local_ip": "127.0.0.1", "local_port": 8080, "remote_ip": None, "remote_port": None, "status": "LISTEN"}],
        },
    )

    res = runner.invoke(app, ["process", "101"])
    assert res.exit_code == 0
    assert "Process Forensic Dossier" in res.stdout
    assert "target_proc" in res.stdout
    assert "8080" in res.stdout


def test_forensics_baseline_and_diff_cli(monkeypatch):
    monkeypatch.setattr(
        api_client,
        "capture_forensics_baseline",
        lambda: {"message": "Baseline established", "process_count": 150, "socket_count": 10},
    )
    monkeypatch.setattr(
        api_client,
        "get_forensics_diff",
        lambda: {
            "summary": {"new_processes_count": 1, "removed_processes_count": 0, "new_sockets_count": 1},
            "new_processes": [{"pid": 999, "name": "beacon", "user": "kripy", "cmdline": "./beacon"}],
        },
    )

    b_res = runner.invoke(app, ["baseline"])
    assert b_res.exit_code == 0
    assert "Captured host baseline" in b_res.stdout

    d_res = runner.invoke(app, ["diff"])
    assert d_res.exit_code == 0
    assert "Differential Baseline Delta" in d_res.stdout
    assert "beacon" in d_res.stdout


def test_tui_forensics_subview(monkeypatch):
    monkeypatch.setattr(
        api_client,
        "get_forensics_snapshot",
        lambda: {
            "metrics": {
                "cpu_percent": 5.0,
                "memory_used_mb": 2048.0,
                "memory_total_mb": 8192.0,
                "memory_percent": 25.0,
                "platform": "linux",
            },
            "processes": [{"pid": 1, "name": "systemd", "user": "0", "cpu_percent": 0.1, "memory_mb": 10.0, "cmdline": "/sbin/init"}],
            "process_count": 1,
            "socket_count": 0,
        },
    )

    tui = OutPostTUI()
    tui.current_screen = "monitor"
    tui.active_sub_view = "Deep Forensics"

    with console.capture() as capture:
        tui.render_sub_view()
    out = capture.get()

    assert "DEEP FORENSICS" in out
    assert "systemd" in out


def test_forensics_fds_cli(monkeypatch):
    monkeypatch.setattr(
        api_client,
        "get_forensics_process",
        lambda pid: {
            "pid": pid,
            "name": "malware_proc",
            "detailed_fds": [
                {"fd": 3, "path": "/memfd:pulseaudio (deleted)", "kind": "memfd", "access": "DELETED", "is_deleted": True, "is_memfd": True},
                {"fd": 4, "path": "/dev/shm/.stealth", "kind": "shm", "access": "READ", "is_deleted": False, "is_memfd": False},
            ],
        },
    )

    res = runner.invoke(app, ["fds", "101"])
    assert res.exit_code == 0
    assert "Open File Descriptors & Memory Inodes" in res.stdout
    assert "DELETED" in res.stdout
    assert "MEMFD" in res.stdout


def test_forensics_devices_cli(monkeypatch):
    monkeypatch.setattr(
        api_client,
        "get_forensics_snapshot",
        lambda: {
            "processes": [{"pid": 505, "name": "audio_app", "user": "kripy"}],
        },
    )
    monkeypatch.setattr(
        api_client,
        "get_forensics_process",
        lambda pid: {
            "pid": pid,
            "name": "audio_app",
            "user": "kripy",
            "device_access": {
                "microphone": True,
                "camera": False,
                "screen_capture": False,
                "gpu": True,
                "gpu_clients_count": 2,
            },
        },
    )

    res = runner.invoke(app, ["devices"])
    assert res.exit_code == 0
    assert "Active Hardware Device & Sensor Handles" in res.stdout
    assert "audio_app" in res.stdout
    assert "ACTIVE" in res.stdout


def test_forensics_caps_cli(monkeypatch):
    monkeypatch.setattr(
        api_client,
        "get_forensics_process",
        lambda pid: {
            "pid": pid,
            "name": "pcap_sniffer",
            "security": {
                "seccomp": "Filtered",
                "capabilities_effective": [
                    {"name": "CAP_NET_RAW", "raw_name": "NET_RAW", "is_dangerous": True},
                ],
            },
        },
    )

    res = runner.invoke(app, ["caps", "202"])
    assert res.exit_code == 0
    assert "Linux Security Capabilities" in res.stdout
    assert "CAP_NET_RAW" in res.stdout
    assert "DANGEROUS" in res.stdout


def test_forensics_io_cli(monkeypatch):
    monkeypatch.setattr(
        api_client,
        "get_forensics_process",
        lambda pid: {
            "pid": pid,
            "name": "encryptor",
            "disk_io": {
                "read_bytes": 10485760,
                "write_bytes": 52428800,
                "read_mb": 10.0,
                "write_mb": 50.0,
                "syscr": 1200,
                "syscw": 5400,
            },
        },
    )

    res = runner.invoke(app, ["io", "303"])
    assert res.exit_code == 0
    assert "Disk I/O Velocity & Throughput" in res.stdout
    assert "10.00 MB" in res.stdout
    assert "50.00 MB" in res.stdout


def test_forensics_probes_cli(monkeypatch):
    monkeypatch.setattr(
        api_client,
        "get_forensic_probes",
        lambda host_id="local": [
            {
                "id": "test_probe",
                "name": "Test Probe",
                "tactic": "Persistence",
                "technique": "T1053.003",
                "description": "Test probe description",
            }
        ],
    )
    res = runner.invoke(app, ["probes"])
    assert res.exit_code == 0
    assert "Live Host Forensic Hunt Probes" in res.stdout
    assert "test_probe" in res.stdout
    assert "Test Probe" in res.stdout


def test_forensics_hunt_cli(monkeypatch):
    monkeypatch.setattr(
        api_client,
        "run_forensic_probe",
        lambda probe_id, host_id="local": {
            "probe_id": probe_id,
            "name": "Test Probe",
            "tactic": "Persistence",
            "technique": "T1053.003",
            "total_items": 10,
            "anomalies_count": 1,
            "findings": [{"key": "canary_val", "details": "Found suspicious item"}],
        },
    )
    res = runner.invoke(app, ["hunt", "test_probe"])
    assert res.exit_code == 0
    assert "Live Host Forensic Hunt Results" in res.stdout
    assert "Test Probe" in res.stdout
    assert "Discovered Hunt Findings" in res.stdout
    assert "canary_val" in res.stdout


