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


def test_investigation_export_stix(client):
    # 1. Create an investigation
    resp = client.post("/investigations", json={"title": "BlackCat Infrastructure Takedown", "tags": ["ransomware", "c2"]})
    assert resp.status_code == 201
    inv_id = resp.json()["id"]

    # 2. Add an IOC ref and run ref
    run_id = make_run(client, sample_name="blackcat_dropper.bin")
    run_ref = client.post(f"/investigations/{inv_id}/refs", json={"ref_type": "run", "ref_id": run_id})
    assert run_ref.status_code == 201

    ioc_resp = client.post("/iocs", json={"value": "198.51.100.99", "type": "ip", "label": "C2 IP"})
    assert ioc_resp.status_code == 201
    ioc_id = ioc_resp.json()["ioc_id"]

    ioc_ref = client.post(f"/investigations/{inv_id}/refs", json={"ref_type": "ioc", "ref_id": ioc_id})
    assert ioc_ref.status_code == 201

    # 3. Export STIX 2.1 bundle
    exp_resp = client.get(f"/investigations/{inv_id}/export?format=stix")
    assert exp_resp.status_code == 200
    bundle = exp_resp.json()

    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert "objects" in bundle

    obj_types = {o["type"] for o in bundle["objects"]}
    assert {"incident", "x-outpost-investigation", "relationship", "indicator", "x-outpost-run"} <= obj_types

    incident = next(o for o in bundle["objects"] if o["type"] == "incident")
    assert incident["name"] == "BlackCat Infrastructure Takedown"
    assert incident["id"].startswith("incident--")

    inv_obj = next(o for o in bundle["objects"] if o["type"] == "x-outpost-investigation")
    assert inv_obj["investigation_id"] == inv_id
    assert inv_obj["refs_count"] == 2

    # Verify relationships point to the incident
    relationships = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert any(r["target_ref"] == incident["id"] and r["relationship_type"] == "indicates" for r in relationships)
    assert any(r["target_ref"] == incident["id"] and r["relationship_type"] == "related-to" for r in relationships)

