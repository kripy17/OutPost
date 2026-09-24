"""Tests for Automated Incident Response Playbook Execution Engine."""

from fastapi.testclient import TestClient

from app.core.db import db_session
from app.main import app
from app.models import investigation as inv_model
from app.services.incident_playbooks import execute_playbook_automated


def test_execute_playbook_automated_service():
    """Verify automated playbook execution runs probes, instantiates tasks, and logs notes."""
    with db_session() as conn:
        inv = inv_model.create(conn, "Active Ransomware Outbreak Test", "analyst")
        inv_id = inv["id"]

        res = execute_playbook_automated(
            conn,
            investigation_id=inv_id,
            playbook_id="ransomware_containment",
            auto_contain=True,
            run_probes=True,
            target_host="test-workstation-01",
        )

        assert res["status"] == "completed"
        assert res["contained"] is True
        assert res["tasks_instantiated"] >= 8
        assert res["probes_executed_count"] >= 3
        assert "deleted_binaries" in res["probes"]

        # Check investigation status was updated to contained
        updated_inv = inv_model.get(conn, inv_id)
        assert updated_inv["status"] == "contained"

        # Check host containment entry was created
        row = conn.execute(
            "SELECT isolated, reason FROM host_containment WHERE host_id = ?",
            ("test-workstation-01",),
        ).fetchone()
        assert row is not None
        assert row["isolated"] == 1


def test_execute_playbook_endpoint():
    """Verify POST /investigations/{id}/playbooks/{playbook_id}/execute API route."""
    client = TestClient(app)

    # Create an investigation
    with db_session() as conn:
        inv = inv_model.create(conn, "Credential Dumping Triage", "analyst")
        inv_id = inv["id"]

    resp = client.post(
        f"/investigations/{inv_id}/playbooks/credential_dumping/execute",
        json={"auto_contain": False, "run_probes": True, "target_host": "local"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert data["contained"] is False
    assert data["tasks_instantiated"] >= 5
    assert data["probes_executed_count"] >= 3
