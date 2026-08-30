"""Unit tests for macOS detection rules: TCC tampering, LaunchAgent persistence, DYLD injection, Gatekeeper bypass."""

import sqlite3
from app.services.detection import (
    check_macos_tcc_bypass,
    check_macos_launchagent_persistence,
    check_macos_dylib_hijack,
    check_macos_gatekeeper_bypass,
    evaluate_batch,
)
from app.services.risk import RULE_META, compute_risk_score


def test_check_macos_tcc_bypass():
    # Malicious access to TCC.db by python script
    event = {
        "run_id": "test_mac_1",
        "platform": "macos",
        "event_type": "file_open",
        "pid": 500,
        "process_name": "python3",
        "file_path": "/Users/victim/Library/Application Support/com.apple.TCC/TCC.db",
    }
    alert = check_macos_tcc_bypass(event)
    assert alert is not None
    assert alert.rule_id == "macos-tcc-bypass"
    assert alert.severity == "malicious"

    # Benign access by tccd
    benign = {
        "run_id": "test_mac_1",
        "platform": "macos",
        "event_type": "file_open",
        "pid": 100,
        "process_name": "tccd",
        "file_path": "/Library/Application Support/com.apple.TCC/TCC.db",
    }
    assert check_macos_tcc_bypass(benign) is None


def test_check_macos_launchagent_persistence():
    event = {
        "run_id": "test_mac_2",
        "platform": "macos",
        "event_type": "file_write",
        "pid": 600,
        "process_name": "curl",
        "file_path": "/Library/LaunchDaemons/com.malicious.miner.plist",
    }
    alert = check_macos_launchagent_persistence(event)
    assert alert is not None
    assert alert.rule_id == "macos-launchagent-persistence"
    assert alert.severity == "suspicious"


def test_check_macos_dylib_hijack():
    event = {
        "run_id": "test_mac_3",
        "platform": "macos",
        "event_type": "process_create",
        "pid": 700,
        "process_name": "target_app",
        "command_line": "DYLD_INSERT_LIBRARIES=/tmp/evil.dylib /Applications/App.app/Contents/MacOS/App",
    }
    alert = check_macos_dylib_hijack(event)
    assert alert is not None
    assert alert.rule_id == "macos-dylib-hijack"
    assert alert.severity == "malicious"


def test_check_macos_gatekeeper_bypass():
    event = {
        "run_id": "test_mac_4",
        "platform": "macos",
        "event_type": "process_create",
        "pid": 800,
        "process_name": "bash",
        "command_line": "xattr -d com.apple.quarantine /tmp/dropped_payload.app",
    }
    alert = check_macos_gatekeeper_bypass(event)
    assert alert is not None
    assert alert.rule_id == "macos-gatekeeper-bypass"
    assert alert.severity == "malicious"


def test_macos_rules_in_rule_meta():
    assert "macos-tcc-bypass" in RULE_META
    assert "macos-launchagent-persistence" in RULE_META
    assert "macos-dylib-hijack" in RULE_META
    assert "macos-gatekeeper-bypass" in RULE_META

    score = compute_risk_score(["macos-tcc-bypass", "macos-launchagent-persistence"])
    assert score == 36
