import os
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import host_forensics

client = TestClient(app)


def test_system_metrics():
    metrics = host_forensics.get_current_system_metrics()
    assert "cpu_percent" in metrics
    assert "memory_used_mb" in metrics
    assert "process_count" in metrics
    assert metrics["process_count"] >= 1


def test_live_processes():
    procs = host_forensics.get_live_processes()
    assert isinstance(procs, list)
    assert len(procs) > 0
    # Must find current process or init
    pids = [p["pid"] for p in procs]
    assert os.getpid() in pids or 1 in pids


def test_xray_snapshot_endpoint():
    res = client.get("/system/xray/snapshot")
    assert res.status_code == 200
    data = res.json()
    assert "metrics" in data
    assert "processes" in data
    assert "sockets" in data
    assert data["process_count"] > 0


def test_xray_process_detail():
    my_pid = os.getpid()
    res = client.get(f"/system/xray/process/{my_pid}")
    assert res.status_code == 200
    data = res.json()
    assert data["pid"] == my_pid
    assert "lineage" in data
    assert "correlated_events" in data


def test_xray_search():
    res = client.get("/system/xray/search?q=python")
    assert res.status_code == 200
    data = res.json()
    assert "matched_processes" in data
    assert "matched_sockets" in data


def test_live_simulation():
    res = client.post("/sandbox/simulate/live", json={"playbook_id": "recon_sweep"})
    assert res.status_code == 201
    data = res.json()
    assert "run_id" in data
    assert "terminal_output" in data
    assert len(data["stages"]) > 0
    assert data["events_count"] > 0
