"""Tests for investigation case brief export (Markdown & JSON)."""

from .conftest import make_run


def test_investigation_export_markdown(client):
    # 1. Create an investigation
    resp = client.post("/investigations", json={"title": "Ransomware Intrusion Alpha", "tags": ["ransomware", "apt"]})
    assert resp.status_code == 201
    inv_id = resp.json()["id"]

    # 2. Add an analyst note
    note_resp = client.post(f"/investigations/{inv_id}/notes", json={"note": "Observed lateral staging via SMB"})
    assert note_resp.status_code == 201

    # 3. Export as Markdown
    exp_resp = client.get(f"/investigations/{inv_id}/export?format=markdown")
    assert exp_resp.status_code == 200
    assert "text/markdown" in exp_resp.headers.get("content-type", "")
    assert f"outpost-incident-brief-{inv_id}.md" in exp_resp.headers.get("content-disposition", "")
    
    text = exp_resp.text
    assert "# OUTPOST INCIDENT RESPONSE CASE BRIEF" in text
    assert inv_id in text
    assert "Ransomware Intrusion Alpha" in text
    assert "Observed lateral staging via SMB" in text
    assert "5. Containment & Remediation Checklist" in text
    assert "TLP" in text


def test_investigation_export_json(client):
    resp = client.post("/investigations", json={"title": "Cobalt Strike Beacon Outpost", "tags": ["c2", "beacon"]})
    assert resp.status_code == 201
    inv_id = resp.json()["id"]

    exp_resp = client.get(f"/investigations/{inv_id}/export?format=json")
    assert exp_resp.status_code == 200
    data = exp_resp.json()
    assert data["case"]["id"] == inv_id
    assert data["case"]["title"] == "Cobalt Strike Beacon Outpost"
    assert "narrative" in data
    assert "compromised_assets" in data["narrative"]
    assert "remediation_checklist" in data["narrative"]
    assert "exported_at" in data
