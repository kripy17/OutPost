"""Tests for macOS EndpointSecurity/OpenBSM collector normalization."""

import sys
from pathlib import Path

_MACOS = Path(__file__).resolve().parent.parent / "macos"
sys.path.insert(0, str(_MACOS))

try:
    from collectors.macos.collector_macos import parse_bsm_line
except ModuleNotFoundError:
    from collector_macos import parse_bsm_line


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
