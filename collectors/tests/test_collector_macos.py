"""Tests for macOS EndpointSecurity/OpenBSM collector normalization."""

import sys
from pathlib import Path

_MACOS = Path(__file__).resolve().parent.parent / "macos"
sys.path.insert(0, str(_MACOS))

try:
    from collectors.macos.collector_macos import parse_bsm_line, parse_eslogger_json
except ModuleNotFoundError:
    from collector_macos import parse_bsm_line, parse_eslogger_json


def test_parse_bsm_execve():
    line = "header,150,2,execve(2),0,0,1724300000.123,process,501,501,501,501,501,1234,5678,path,/usr/bin/osascript,cmdline,osascript -e display dialog hello"
    event = parse_bsm_line(line, "run_macos_test")
    assert event is not None
    assert event["event_type"] == "process_create"
    assert event["platform"] == "macos"
    assert event["pid"] == 1234
    assert event["ppid"] == 5678
    assert event["process_name"] == "osascript"
    assert event["exe_path"] == "/usr/bin/osascript"
    assert "osascript -e" in event["command_line"]


def test_parse_bsm_connect():
    line = "header,120,2,connect(2),0,0,1724300001.456,process,501,501,501,501,501,1234,sock_inet,AF_INET,443,198.51.100.99"
    event = parse_bsm_line(line, "run_macos_test")
    assert event is not None
    assert event["event_type"] == "network_connection"
    assert event["platform"] == "macos"
    assert event["pid"] == 1234
    assert event["dest_ip"] == "198.51.100.99"
    assert event["dest_port"] == 443
    assert event["protocol"] == "tcp"


def test_parse_bsm_loopback_ignored():
    line = "header,120,2,connect(2),0,0,1724300001.456,process,501,501,501,501,501,1234,sock_inet,AF_INET,8080,127.0.0.1"
    event = parse_bsm_line(line, "run_macos_test")
    assert event is None


def test_parse_eslogger_exec():
    record = {
        "event": {
            "exec": {
                "target": {
                    "audit_token": {"pid": 4321},
                    "ppid": 1000,
                    "executable": {"path": "/Applications/Safari.app/Contents/MacOS/Safari"},
                    "args": ["Safari", "-psn_0_12345"],
                    "signing_info": {"signing_id": "com.apple.Safari"},
                }
            }
        },
        "process": {"audit_token": {"pid": 1000}},
    }
    event = parse_eslogger_json(record, "run_macos_esf")
    assert event is not None
    assert event["event_type"] == "process_create"
    assert event["platform"] == "macos"
    assert event["pid"] == 4321
    assert event["ppid"] == 1000
    assert event["process_name"] == "Safari"
    assert event["code_sign_id"] == "com.apple.Safari"


def test_parse_eslogger_connect():
    record = {
        "event": {
            "connect": {
                "remote_address": {"ip": "203.0.113.55", "port": 4444}
            }
        },
        "process": {"audit_token": {"pid": 4321}},
    }
    event = parse_eslogger_json(record, "run_macos_esf")
    assert event is not None
    assert event["event_type"] == "network_connection"
    assert event["dest_ip"] == "203.0.113.55"
    assert event["dest_port"] == 4444


def test_parse_eslogger_file_write():
    record = {
        "event": {
            "create": {
                "destination": {
                    "new_path": {"dir": "/Library/LaunchAgents", "filename": "com.persistence.plist"}
                }
            }
        },
        "process": {"audit_token": {"pid": 999}, "executable": {"path": "/bin/bash"}},
    }
    event = parse_eslogger_json(record, "run_macos_esf")
    assert event is not None
    assert event["event_type"] == "file_write"
    assert event["file_path"] == "/Library/LaunchAgents/com.persistence.plist"

