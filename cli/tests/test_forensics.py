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
