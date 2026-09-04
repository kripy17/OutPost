"""Tests for Incident Response Tasks, Causality Timeline, and Remediation Scripts."""

import pytest
from starlette.testclient import TestClient

from app.main import app
from app.core.db import db_session
from app.models import investigation as inv_store
from app.models import run as run_store


def test_investigation_tasks_lifecycle():
    client = TestClient(app)

    # 1. Create an investigation
    resp = client.post("/investigations", json={"title": "IR Case 2026-Alpha", "tags": ["apt", "c2"]})
    assert resp.status_code == 201
    inv = resp.json()
    inv_id = inv["id"]

    # 2. Create a task
    t_resp = client.post(
        f"/investigations/{inv_id}/tasks",
        json={
            "title": "Isolate secondary domain controller",
            "category": "containment",
            "priority": "critical",
            "assignee": "analyst-1",
            "due_at": "2026-09-05T00:00:00Z",
        },
    )
    assert t_resp.status_code == 201
    task = t_resp.json()
    assert task["title"] == "Isolate secondary domain controller"
    assert task["category"] == "containment"
    assert task["status"] == "todo"
    assert task["priority"] == "critical"
    task_id = task["id"]

    # 3. List tasks
    list_resp = client.get(f"/investigations/{inv_id}/tasks")
    assert list_resp.status_code == 200
    tasks = list_resp.json()
    assert len(tasks) == 1
    assert tasks[0]["id"] == task_id

    # 4. Patch task to completed
    p_resp = client.patch(
        f"/investigations/{inv_id}/tasks/{task_id}",
        json={"status": "completed"},
    )
    assert p_resp.status_code == 200
    patched = p_resp.json()
    assert patched["status"] == "completed"
    assert patched["completed_at"] is not None

    # 5. Verify task appears in investigation detail
    det_resp = client.get(f"/investigations/{inv_id}")
    assert det_resp.status_code == 200
    assert len(det_resp.json()["tasks"]) == 1

    # 6. Delete task
    del_resp = client.delete(f"/investigations/{inv_id}/tasks/{task_id}")
    assert del_resp.status_code == 204

    # Verify list is empty
    empty_resp = client.get(f"/investigations/{inv_id}/tasks")
    assert len(empty_resp.json()) == 0


def test_generate_recommended_tasks():
    client = TestClient(app)
    # Create investigation
    inv = client.post("/investigations", json={"title": "Host Intrusion Triage"}).json()
    inv_id = inv["id"]

    # Attach a host ref and run with alert
    run_id = "run-ir-test-01"
    with db_session() as conn:
        run_store.create_run(conn, run_id, "ransom_canary", "linux")
        conn.execute(
            "INSERT INTO events (run_id, platform, event_type, timestamp, host_id) VALUES (?, 'linux', 'process_create', '2026-09-04T12:00:00Z', 'endpoint-prod-42')",
            (run_id,),
        )
        conn.execute(
            "INSERT INTO alerts (run_id, rule_id, rule_name, severity, triggered_at, details, investigation_id) "
            "VALUES (?, 'shadow-access', 'Shadow File Access', 'malicious', '2026-09-04T12:00:00Z', 'Test alert', ?)",
            (run_id, inv_id),
        )

    # Attach host ref
    ref_res = client.post(f"/investigations/{inv_id}/refs", json={"ref_type": "host", "ref_id": "endpoint-prod-42"})
    assert ref_res.status_code == 201

    # Trigger generation
    gen_resp = client.post(f"/investigations/{inv_id}/tasks/generate-recommended")
    assert gen_resp.status_code == 200
    tasks = gen_resp.json()
    assert len(tasks) >= 2
    titles = [t["title"] for t in tasks]
    assert any("Isolate endpoint" in t for t in titles)
    assert any("credential" in t.lower() for t in titles)


def test_investigation_timeline_and_remediation_script():
    client = TestClient(app)
    # 1. Create investigation
    inv = client.post("/investigations", json={"title": "C2 Infiltration Incident"}).json()
    inv_id = inv["id"]

    # 2. Add note
    client.post(f"/investigations/{inv_id}/notes", json={"note": "Observed lateral SMB traffic to staging server."})

    # 3. Add task
    client.post(
        f"/investigations/{inv_id}/tasks",
        json={"title": "Check firewall logs for outbound port 4444", "category": "triage"},
    )

    # 4. Fetch timeline
    t_resp = client.get(f"/investigations/{inv_id}/timeline")
    assert t_resp.status_code == 200
    timeline = t_resp.json()
    assert timeline["total"] >= 3
    event_types = {e["event_type"] for e in timeline["events"]}
    assert "lifecycle" in event_types
    assert "note" in event_types
    assert "task" in event_types

    # 5. Fetch remediation script (Bash)
    bash_resp = client.get(f"/investigations/{inv_id}/remediation-script?shell=bash")
    assert bash_resp.status_code == 200
    assert "#!/usr/bin/env bash" in bash_resp.text
    assert "OutPost SOC Automated Remediation Script" in bash_resp.text

    # 6. Fetch remediation script (PowerShell)
    ps_resp = client.get(f"/investigations/{inv_id}/remediation-script?shell=powershell")
    assert ps_resp.status_code == 200
    assert "OutPost SOC Automated Remediation Script (PowerShell)" in ps_resp.text
    assert "Write-Host" in ps_resp.text
