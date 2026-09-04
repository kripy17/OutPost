"""Tests for Host Live Memory YARA Scan and Socket Intelligence."""

from starlette.testclient import TestClient

from app.main import app
from app.services.host_forensics import scan_live_memory_yara, get_enriched_live_sockets
from app.core.db import db_session


def test_scan_live_memory_yara():
    # Scan a small number of live processes
    res = scan_live_memory_yara(limit_pids=10)
    assert "total_scanned_processes" in res
    assert "threat_count" in res
    assert "threats" in res
    assert isinstance(res["clean"], bool)


def test_api_system_forensics_scan_and_sockets():
    client = TestClient(app)

    # 1. Test POST /system/forensics/scan/yara
    scan_resp = client.post("/system/forensics/scan/yara?limit=5")
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert "total_scanned_processes" in scan_data
    assert scan_data["total_scanned_processes"] >= 0

    # 2. Test GET /system/forensics/sockets
    sock_resp = client.get("/system/forensics/sockets")
    assert sock_resp.status_code == 200
    sock_data = sock_resp.json()
    assert "total" in sock_data
    assert "sockets" in sock_data
    assert isinstance(sock_data["sockets"], list)
