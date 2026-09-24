"""Tests for Live Host Forensic Triage Pack Engine."""

from fastapi.testclient import TestClient

from app.main import app
from app.services import forensic_probes


def test_collect_host_triage_pack_service():
    """Verify triage pack compiles host metrics, probes, processes, and sockets."""
    pack = forensic_probes.collect_host_triage_pack(include_yara=False)
    assert "triage_id" in pack
    assert pack["triage_id"].startswith("triage_")
    assert "collected_at" in pack
    assert "summary" in pack
    assert pack["summary"]["total_probes_executed"] >= 5
    assert "probe_results" in pack
    assert "crontab_persistence" in pack["probe_results"]
    assert "deleted_binaries" in pack["probe_results"]
    assert "active_processes" in pack
    assert "active_sockets" in pack


def test_triage_pack_endpoint():
    """Verify POST /system/forensics/triage API endpoint."""
    client = TestClient(app)
    resp = client.post("/system/forensics/triage?include_yara=false")
    assert resp.status_code == 200
    data = resp.json()
    assert "triage_id" in data
    assert "summary" in data
    assert data["summary"]["total_probes_executed"] >= 5


def test_triage_pack_export_endpoint():
    """Verify GET /system/forensics/triage/export downloads JSON file."""
    client = TestClient(app)
    resp = client.get("/system/forensics/triage/export?include_yara=false")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert "attachment; filename=triage_" in resp.headers["content-disposition"]
    data = resp.json()
    assert "triage_id" in data
