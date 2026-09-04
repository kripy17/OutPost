"""Tests for Continuous Detection Validation Scorecard & Matrix."""

import pytest
from fastapi.testclient import TestClient

from app.core.db import db_session
from app.main import app
from app.services.technique_catalog import get_technique_validation_matrix


@pytest.fixture
def client():
    return TestClient(app)


def test_get_technique_validation_matrix_initial():
    with db_session() as conn:
        matrix = get_technique_validation_matrix(conn)
        assert "summary" in matrix
        assert "techniques" in matrix
        assert matrix["summary"]["total_techniques"] >= 10
        assert len(matrix["techniques"]) == matrix["summary"]["total_techniques"]
        # All or most initially untested if fresh table
        assert any(t["detection_status"] in ("untested", "detected", "telemetry_only") for t in matrix["techniques"])


@pytest.mark.asyncio
async def test_execute_technique_updates_validation_ledger(client):
    # Run a fast safe canary: T1059.004-bash-pipe
    res = client.post("/sandbox/techniques/run", json={"test_id": "T1059.004-bash-pipe"})
    assert res.status_code == 200
    data = res.json()
    assert data["test_id"] == "T1059.004-bash-pipe"
    assert data["status"] == "success"
    assert data["detection_status"] in ("detected", "telemetry_only")
    assert "mttd_ms" in data
    assert "matched_rules" in data

    # Verify that the matrix API now reflects the tested canary
    mat_res = client.get("/sandbox/techniques/matrix")
    assert mat_res.status_code == 200
    mat_data = mat_res.json()
    summary = mat_data["summary"]
    assert summary["tested_count"] >= 1

    # Find the specific technique in the matrix
    tested_t = next((t for t in mat_data["techniques"] if t["id"] == "T1059.004-bash-pipe"), None)
    assert tested_t is not None
    assert tested_t["detection_status"] in ("detected", "telemetry_only")
    assert tested_t["last_validated_at"] is not None
    assert tested_t["mttd_ms"] is not None


def test_validate_matrix_batch_endpoint(client):
    # Run a sweep on tactic Discovery or Execution
    res = client.post("/sandbox/techniques/validate-matrix", json={"tactic": "Execution"})
    assert res.status_code == 200
    data = res.json()
    assert "sweep_count" in data
    assert "results" in data
    assert "scorecard" in data
    assert data["sweep_count"] >= 1
    assert data["scorecard"]["tested_count"] >= 1
