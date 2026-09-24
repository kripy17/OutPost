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


def test_tui_help_modal():
    tui = OutPostTUI()
    assert tui.modal_content is None

    tui.handle_input("?")
    assert tui.modal_content is not None
    assert "OPERATOR MANUAL" in tui.modal_content

    with console.capture() as capture:
        tui.render_modal()
    out = capture.get()
    assert "OPERATOR MANUAL" in out

    # Dismiss modal with esc
    tui.handle_input("esc")
    assert tui.modal_content is None


def test_tui_command_prompt(monkeypatch):
    tui = OutPostTUI()
    monkeypatch.setattr(tui, "prompt_input", lambda prompt: "doctor")
    tui.prompt_command()

    assert tui.modal_content is not None
    assert "Diagnostic" in tui.modal_content
    assert "Command: doctor" in tui.modal_title

    # Dismiss modal
    tui.handle_input("enter")
    assert tui.modal_content is None


def test_tui_alert_triage(monkeypatch):
    monkeypatch.setattr(api_client, "get_alert_queue", lambda status="all", limit=50: {
        "alerts": [{"id": 42, "rule_name": "Test Alert", "severity": "suspicious", "status": "open"}]
    })
    triage_called = {}

    def mock_update_alert(aid, st):
        triage_called["id"] = aid
        triage_called["status"] = st
        return {"id": aid, "status": st}

    monkeypatch.setattr(api_client, "update_alert_status", mock_update_alert)

    tui = OutPostTUI()
    tui.current_screen = "monitor"
    tui.active_sub_view = "Findings"
    tui.detail_selected = 0

    monkeypatch.setattr(tui, "prompt_input", lambda prompt: "2")  # 2: Resolved
    tui.handle_subview_key("t")

    assert triage_called.get("id") == 42
    assert triage_called.get("status") == "resolved"
    assert "RESOLVED" in tui.status_msg


def test_tui_investigation_creation(monkeypatch):
    created = {}

    def mock_create(title):
        created["title"] = title
        return {"id": "INC-TEST-1", "title": title}

    monkeypatch.setattr(api_client, "create_investigation", mock_create)

    tui = OutPostTUI()
    tui.current_screen = "investigate"
    responses = iter(["Adversary C2 Beaconing", "high"])
    monkeypatch.setattr(tui, "prompt_input", lambda prompt: next(responses))

    tui.handle_subview_key("c")
    assert created.get("title") == "Adversary C2 Beaconing"
    assert "INC-TEST-1" in tui.status_msg


def test_tui_watchlist_management(monkeypatch):
    added = {}
    removed = []

    def mock_add(val, label):
        added["val"] = val
        added["label"] = label
        return {"value": val, "label": label}

    def mock_remove(val):
        removed.append(val)

    monkeypatch.setattr(api_client, "watchlist_add", mock_add)
    monkeypatch.setattr(api_client, "watchlist_remove", mock_remove)
    monkeypatch.setattr(api_client, "watchlist_list", lambda: [{"value": "1.2.3.4", "label": "Bad IP"}])
    monkeypatch.setattr(api_client, "get_watchlist", lambda: [{"value": "1.2.3.4", "label": "Bad IP"}])


    tui = OutPostTUI()
    tui.current_screen = "iocs"

    # Test Add
    responses = iter(["5.6.7.8", "Malicious Node"])
    monkeypatch.setattr(tui, "prompt_input", lambda prompt: next(responses))
    tui.handle_subview_key("a")
    assert added.get("val") == "5.6.7.8"

    # Test Delete
    tui.detail_selected = 0
    tui.handle_subview_key("d")
    assert "1.2.3.4" in removed


def test_tui_host_containment_toggle(monkeypatch):
    monkeypatch.setattr(api_client, "get_agents", lambda: {
        "agents": [{"host_id": "victim-01", "platform": "linux", "isolated": False}],
        "online": 1
    })
    iso_called = {}

    def mock_isolate(hid, iso, reason=""):
        iso_called["host_id"] = hid
        iso_called["isolated"] = iso
        return {"host_id": hid, "isolated": iso}

    monkeypatch.setattr(api_client, "isolate_agent", mock_isolate)

    tui = OutPostTUI()
    tui.current_screen = "hosts"
    tui.active_sub_view = "Online Fleet"
    tui.detail_selected = 0

    tui.handle_subview_key("i")
    assert iso_called.get("host_id") == "victim-01"
    assert iso_called.get("isolated") is True
    assert "ISOLATED" in tui.status_msg


def test_tui_tools_subview(monkeypatch):
    tui = OutPostTUI()
    # Direct jump to SOC Tools with 0
    tui.handle_input("0")
    assert tui.current_screen == "tools"

    with console.capture() as capture:
        tui.render_category_screen("tools")
    out = capture.get()
    assert "Cyber Decoder" in out
    assert "Forensics Triage Pack" in out
    assert "System Security Audit" in out

