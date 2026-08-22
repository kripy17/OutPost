"""Tests for the interactive SOC Terminal User Interface (OutPostTUI)."""

import pytest
from rich.console import Console

from outpost.lib import api_client
from outpost.tui import OutPostTUI, console


def test_tui_main_screen_render(monkeypatch):
    monkeypatch.setattr(api_client, "list_runs", lambda: [
        {"run_id": "run123456789", "sample_name": "malware.exe", "platform": "windows", "risk_score": 85, "highest_severity": "critical", "alert_count": 3}
    ])
    monkeypatch.setattr(api_client, "get_alert_queue", lambda status="all", limit=50: {
        "alerts": [{"id": 1, "rule_name": "LOLBin Execution", "severity": "malicious", "details": "powershell.exe -enc"}]
    })
    monkeypatch.setattr(api_client, "get_agents", lambda: {"agents": [{"host_id": "host-01", "platform": "linux", "online": True}], "online": 1})
    monkeypatch.setattr(api_client, "list_investigations", lambda: {"investigations": []})

    tui = OutPostTUI()
    with console.capture() as capture:
        tui.render_main_screen()
    out = capture.get()

    assert "OUTPOST" in out
    assert "Monitor" in out
    assert "Analyze" in out
    assert "LOLBin Execution" in out


def test_tui_navigation_and_category_enter():
    tui = OutPostTUI()
    assert tui.current_screen == "main"

    # Navigate down
    tui.handle_input("down")
    assert tui.main_selected == 1

    # Jump to Analyze (key 2)
    tui.handle_input("2")
    assert tui.current_screen == "analyze"
    assert tui.sub_selected == 0

    # Back
    tui.handle_input("b")
    assert tui.current_screen == "main"


def test_tui_playbook_detonation(monkeypatch):
    monkeypatch.setattr(api_client, "get_playbooks", lambda: [
        {"id": "ransomware-stager", "name": "Ransomware Pre-Encryption", "platform": "windows", "severity": "critical", "tactics": ["Impact"]}
    ])
    monkeypatch.setattr(api_client, "detonate_playbook", lambda pid: {
        "run_id": "detonated123", "name": "Ransomware Pre-Encryption", "alert_count": 2
    })
    monkeypatch.setattr(api_client, "get_run", lambda rid: {
        "run": {"run_id": rid, "sample_name": "ransomware.exe", "risk_score": 90, "highest_severity": "critical"},
        "alerts": [{"rule_name": "Shadow Copy Deletion", "severity": "malicious", "details": "vssadmin delete shadows"}],
        "process_tree": [],
        "network_connections": [],
    })
    monkeypatch.setattr(api_client, "get_rules", lambda rid, fmt: "title: OutPost Synthesized Rule")

    tui = OutPostTUI()
    tui.current_screen = "analyze"
    tui.active_sub_view = "Attack Playbooks"
    tui.detail_selected = 0

    # Trigger detonation with Enter
    tui.handle_input("enter")
    assert tui.current_screen == "run_detail"
    assert tui.selected_run_id == "detonated123"

    with console.capture() as capture:
        tui.render_run_detail()
    out = capture.get()
    assert "Shadow Copy Deletion" in out
    assert "detonated123" in out

    # Generate rule suite with 'g'
    tui.handle_input("g")
    assert tui.generated_rules_text is not None
    with console.capture() as capture:
        tui.render_run_detail()
    out = capture.get()
    assert "Auto-Generated Detection Rules" in out
