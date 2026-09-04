"""Tests for Incident Response Playbooks catalog and investigation integration."""

import pytest
from fastapi.testclient import TestClient

from app.core.db import db_session
from app.main import app
from app.models import investigation as inv_model
from app.services.incident_playbooks import (
    apply_playbook_to_investigation,
    get_playbook,
    list_playbooks,
)


@pytest.fixture
def client():
    return TestClient(app)


def test_list_and_get_playbooks():
    pbs = list_playbooks()
    assert len(pbs) >= 4
    pb_ids = {p["id"] for p in pbs}
    assert "ransomware_containment" in pb_ids
    assert "credential_dumping" in pb_ids
    assert "c2_intrusion" in pb_ids
    assert "data_exfiltration" in pb_ids

    # Detail check
    pb = get_playbook("ransomware_containment")
    assert pb is not None
    assert pb["name"] == "Ransomware & Destructive Locker Protocol"
    assert pb["severity"] == "critical"
    assert len(pb["tasks"]) >= 5
    assert len(pb["recommended_probes"]) >= 1


def test_apply_playbook_to_investigation():
    with db_session() as conn:
        inv = inv_model.create(
            conn, title="Active Ransomware Incident", created_by="analyst", tags=["ransomware", "critical"]
        )
        inv_id = inv["id"]

        res = apply_playbook_to_investigation(
            conn, inv_id, "ransomware_containment", assignee="lead_analyst"
        )
        assert res["investigation_id"] == inv_id
        assert res["playbook_id"] == "ransomware_containment"
        assert res["tasks_created_count"] >= 5

        # Verify tasks in database
        tasks = inv_model.list_tasks(conn, inv_id)
        assert len(tasks) == res["tasks_created_count"]
        # Confirm containment priority critical task
        crit_tasks = [t for t in tasks if t["priority"] == "critical"]
        assert len(crit_tasks) >= 2
        assert all(t["assignee"] == "lead_analyst" for t in tasks)

        # Verify audit note was added
        notes = inv_model.list_notes(conn, inv_id)
        assert any("Applied Incident Response Playbook" in n["note"] for n in notes)


def test_api_playbooks_endpoints(client):
    # 1. List
    res = client.get("/investigations/playbooks")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 4

    # 2. Get
    res = client.get("/investigations/playbooks/c2_intrusion")
    assert res.status_code == 200
    detail = res.json()
    assert detail["id"] == "c2_intrusion"
    assert len(detail["tasks"]) >= 4

    # 3. Apply via POST
    inv_res = client.post(
        "/investigations",
        json={"title": "Playbook Test Case", "tags": ["test"]},
        headers={"X-User-Role": "admin"},
    )
    assert inv_res.status_code == 201
    inv_id = inv_res.json()["id"]

    apply_res = client.post(
        f"/investigations/{inv_id}/apply-playbook",
        json={"playbook_id": "credential_dumping", "assignee": "secops"},
        headers={"X-User-Role": "admin"},
    )
    assert apply_res.status_code == 200
    apply_data = apply_res.json()
    assert apply_data["tasks_created_count"] >= 4

    # Verify tasks endpoint shows the newly created playbook tasks
    tasks_res = client.get(f"/investigations/{inv_id}/tasks")
    assert tasks_res.status_code == 200
    assert len(tasks_res.json()) == apply_data["tasks_created_count"]
