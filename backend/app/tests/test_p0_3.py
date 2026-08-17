"""P0.3 investigation + finding integration — focused tests.

Covers the investigation lifecycle (create → triage → active → … → close →
reopen), tags, refs (idempotent, validated, removable), notes, derived
severity/counts, finding attach/detach through PATCH /alerts/{id}, audit
actions, and auth (analyst reads / admin writes / agent 403).

The session DB is shared across the whole suite — every assertion is scoped
to this test's unique values, never global totals.
"""

import importlib

import pytest
from fastapi.testclient import TestClient

from .conftest import make_run


def _conn(run_id: str, ip: str = "203.0.113.77") -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "network_connection",
        "timestamp": "2026-08-17T00:00:00Z", "pid": 1, "dest_ip": ip, "dest_port": 4444, "protocol": "tcp",
    }


def _detection_findings(client, sample: str, ip: str = "203.0.113.77") -> list[int]:
    """A run with a detection finding; returns [alert_id]."""
    run_id = make_run(client, sample_name=sample)
    client.post("/ingest/batch", json=[_conn(run_id, ip)])
    alerts = client.get(f"/runs/{run_id}/alerts").json()
    assert alerts, "unusual-port should have fired"
    return [a["id"] for a in alerts]


def _create_inv(client, title: str, tags: list[str] | None = None) -> dict:
    resp = client.post("/investigations", json={"title": title, "tags": tags or []})
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Create / list / detail
# ---------------------------------------------------------------------------


def test_create_investigation(client):
    inv = _create_inv(client, "p03-create — phishing campaign")
    assert inv["status"] == "created"
    assert inv["severity"] is None  # no findings yet
    assert inv["finding_count"] == 0 and inv["ref_count"] == 0
    assert inv["tags"] == [] and inv["created_at"] and inv["updated_at"]
    assert inv["closed_at"] is None
    # Round-trips through the detail payload.
    det = client.get(f"/investigations/{inv['id']}").json()
    assert det["id"] == inv["id"] and det["title"] == "p03-create — phishing campaign"
    assert det["findings"] == [] and det["refs"] == [] and det["notes"] == []


def test_reject_blank_title(client):
    assert client.post("/investigations", json={"title": "   "}).status_code == 422
    assert client.post("/investigations", json={"title": ""}).status_code == 422
    assert client.post("/investigations", json={}).status_code == 422


def test_create_with_tags_normalized_and_deduped(client):
    inv = _create_inv(client, "p03-tags case", tags=["Phishing", "phishing", "  c2  ", "", "Phishing"])
    assert sorted(inv["tags"]) == ["c2", "phishing"]
    det = client.get(f"/investigations/{inv['id']}").json()
    assert sorted(det["tags"]) == ["c2", "phishing"]


def test_list_investigations_and_filters(client):
    _create_inv(client, "p03-list-one — credential harvest")
    closed = _create_inv(client, "p03-list-two — beacon", tags=["cnc"])
    client.post(f"/investigations/{closed['id']}/close", json={"conclusion": "confirmed FP"})
    data = client.get("/investigations").json()
    assert set(data) == {"total", "limit", "offset", "investigations"}
    assert any(i["title"].startswith("p03-list-") for i in data["investigations"])
    # Status filter.
    closed_only = client.get("/investigations", params={"status": "closed"}).json()
    assert all(i["status"] == "closed" for i in closed_only["investigations"])
    assert any(i["id"] == closed["id"] for i in closed_only["investigations"])
    # q searches title + tags.
    by_title = client.get("/investigations", params={"q": "credential harvest"}).json()
    assert any(i["title"] == "p03-list-one — credential harvest" for i in by_title["investigations"])
    by_tag = client.get("/investigations", params={"q": "cnc"}).json()
    assert any(i["id"] == closed["id"] for i in by_tag["investigations"])
    assert client.get("/investigations", params={"status": "banana"}).status_code == 422


# ---------------------------------------------------------------------------
# PATCH / lifecycle
# ---------------------------------------------------------------------------


def test_patch_title_and_forward_status(client):
    inv = _create_inv(client, "p03-patch original")
    resp = client.patch(f"/investigations/{inv['id']}", json={"title": "p03-patch renamed"})
    assert resp.status_code == 200
    assert resp.json()["title"] == "p03-patch renamed"
    # Forward transition: created → active is legal.
    moved = client.patch(f"/investigations/{inv['id']}", json={"status": "active"}).json()
    assert moved["status"] == "active"
    # Backward is rejected.
    assert client.patch(f"/investigations/{inv['id']}", json={"status": "created"}).status_code == 422
    assert client.patch(f"/investigations/{inv['id']}", json={"status": "banana"}).status_code == 422
    # Blank title rejected.
    assert client.patch(f"/investigations/{inv['id']}", json={"title": " "}).status_code == 422
    # Unknown investigation 404.
    assert client.patch("/investigations/nope", json={"title": "x"}).status_code == 404


def test_patch_replaces_tags(client):
    inv = _create_inv(client, "p03-tag-replace", tags=["a", "b"])
    resp = client.patch(f"/investigations/{inv['id']}", json={"tags": ["b", "c"]}).json()
    assert sorted(resp["tags"]) == ["b", "c"]


def test_close_requires_conclusion_and_reopen(client):
    inv = _create_inv(client, "p03-close-reopen")
    assert client.post(f"/investigations/{inv['id']}/close", json={"conclusion": "  "}).status_code == 422
    assert client.post(f"/investigations/{inv['id']}/close", json={}).status_code == 422
    closed = client.post(f"/investigations/{inv['id']}/close", json={"conclusion": "confirmed malicious"}).json()
    assert closed["status"] == "closed" and closed["closed_at"]
    assert closed["conclusion"] == "confirmed malicious"
    # Reopen.
    reopened = client.post(f"/investigations/{inv['id']}/reopen").json()
    assert reopened["status"] == "active" and reopened["closed_at"] is None
    # Re-close; close twice → 422 (already closed); reopen from closed works.
    client.post(f"/investigations/{inv['id']}/close", json={"conclusion": "again"})
    assert client.post(f"/investigations/{inv['id']}/close", json={"conclusion": "again"}).status_code == 422
    assert client.post(f"/investigations/{inv['id']}/reopen").status_code == 200
    # Reopen a non-closed (now active) → 422.
    assert client.post(f"/investigations/{inv['id']}/reopen").status_code == 422
    assert client.post("/investigations/nope/close", json={"conclusion": "x"}).status_code == 404
    assert client.post("/investigations/nope/reopen").status_code == 404


# ---------------------------------------------------------------------------
# Refs
# ---------------------------------------------------------------------------


def test_add_valid_refs_run_host_ioc_artifact(client):
    run_id = make_run(client, sample_name="p03-refs.bin", platform="linux")
    client.post("/ingest/batch", json=[{**_conn(run_id), "host_id": "p03-ref-host"}])
    ioc = client.post("/iocs", json={"value": "203.0.113.199", "type": "ip"}).json()
    sample = client.post("/samples", params={"name": "p03-ref-art.exe"}, content=b"MZ\x90\x00ref-artifact").json()
    inv = _create_inv(client, "p03-refs case")
    for ref_type, ref_id in (
        ("run", run_id),
        ("host", "p03-ref-host"),
        ("ioc", ioc["ioc_id"]),
        ("artifact", sample["sample_id"]),
    ):
        resp = client.post(f"/investigations/{inv['id']}/refs", json={"ref_type": ref_type, "ref_id": ref_id})
        assert resp.status_code == 201, resp.text
        assert resp.json()["ref_type"] == ref_type and resp.json()["ref_id"] == ref_id
    det = client.get(f"/investigations/{inv['id']}").json()
    assert len(det["refs"]) == 4
    assert det["ref_count"] == 4
    assert {r["ref_type"] for r in det["refs"]} == {"run", "host", "ioc", "artifact"}


def test_add_duplicate_ref_is_idempotent(client):
    run_id = make_run(client, sample_name="p03-dup-ref.bin")
    inv = _create_inv(client, "p03-dup-ref case")
    r1 = client.post(f"/investigations/{inv['id']}/refs", json={"ref_type": "run", "ref_id": run_id}).json()
    r2 = client.post(f"/investigations/{inv['id']}/refs", json={"ref_type": "run", "ref_id": run_id}).json()
    assert r1["ref_id"] == r2["ref_id"]
    assert client.get(f"/investigations/{inv['id']}").json()["ref_count"] == 1


def test_invalid_refs_rejected(client):
    inv = _create_inv(client, "p03-bad-refs case")
    assert client.post(f"/investigations/{inv['id']}/refs", json={"ref_type": "run", "ref_id": "no-such-run"}).status_code == 422
    assert client.post(f"/investigations/{inv['id']}/refs", json={"ref_type": "ioc", "ref_id": "no-such-ioc"}).status_code == 422
    assert client.post(f"/investigations/{inv['id']}/refs", json={"ref_type": "artifact", "ref_id": "no-such-art"}).status_code == 422
    assert client.post(f"/investigations/{inv['id']}/refs", json={"ref_type": "host", "ref_id": "no-such-host"}).status_code == 422
    assert client.post(f"/investigations/{inv['id']}/refs", json={"ref_type": "banana", "ref_id": "x"}).status_code == 422
    assert client.post("/investigations/nope/refs", json={"ref_type": "run", "ref_id": "x"}).status_code == 404


def test_campaign_ref_validates_against_derived_keys(client):
    # Two runs sharing an IP form a campaign (key = the signature IP).
    a = make_run(client, sample_name="p03-camp-a.bin")
    b = make_run(client, sample_name="p03-camp-b.bin")
    client.post("/ingest/batch", json=[_conn(a, "203.0.113.188")])
    client.post("/ingest/batch", json=[_conn(b, "203.0.113.188")])
    inv = _create_inv(client, "p03-campaign case")
    resp = client.post(f"/investigations/{inv['id']}/refs", json={"ref_type": "campaign", "ref_id": "203.0.113.188"})
    assert resp.status_code == 201, resp.text
    # A non-campaign IP is rejected.
    assert client.post(f"/investigations/{inv['id']}/refs", json={"ref_type": "campaign", "ref_id": "10.99.99.99"}).status_code == 422


def test_remove_ref(client):
    run_id = make_run(client, sample_name="p03-remove-ref.bin")
    inv = _create_inv(client, "p03-remove-ref case")
    client.post(f"/investigations/{inv['id']}/refs", json={"ref_type": "run", "ref_id": run_id})
    assert client.delete(f"/investigations/{inv['id']}/refs/{run_id}").status_code == 204
    assert client.get(f"/investigations/{inv['id']}").json()["ref_count"] == 0
    # Removing again → 404.
    assert client.delete(f"/investigations/{inv['id']}/refs/{run_id}").status_code == 404
    assert client.delete("/investigations/nope/refs/x").status_code == 404


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


def test_add_note_and_reject_blank(client):
    inv = _create_inv(client, "p03-notes case")
    note = client.post(f"/investigations/{inv['id']}/notes", json={"note": "first observation"}).json()
    assert note["note"] == "first observation" and note["actor"] and note["created_at"]
    assert client.post(f"/investigations/{inv['id']}/notes", json={"note": "   "}).status_code == 422
    assert client.post(f"/investigations/{inv['id']}/notes", json={"note": ""}).status_code == 422
    assert client.post("/investigations/nope/notes", json={"note": "x"}).status_code == 404
    det = client.get(f"/investigations/{inv['id']}").json()
    assert [n["note"] for n in det["notes"]] == ["first observation"]
    # Notes are searchable through q.
    found = client.get("/investigations", params={"q": "first observation"}).json()
    assert any(i["id"] == inv["id"] for i in found["investigations"])


# ---------------------------------------------------------------------------
# Finding ↔ investigation
# ---------------------------------------------------------------------------


def test_attach_detach_finding_and_derived_severity(client):
    inv = _create_inv(client, "p03-sev case")
    # Attach a suspicious finding (the unusual-port rule) → severity suspicious.
    aid1 = _detection_findings(client, "p03-sev-a.bin", ip="203.0.113.101")[0]
    resp = client.patch(f"/alerts/{aid1}", json={"status": "open", "investigation_id": inv["id"]})
    assert resp.status_code == 200
    assert resp.json()["investigation_id"] == inv["id"]
    assert client.get(f"/investigations/{inv['id']}").json()["severity"] == "suspicious"
    assert client.get(f"/investigations/{inv['id']}").json()["finding_count"] == 1
    # Attach an analyst-authored MALICIOUS finding → severity escalates.
    run_id = make_run(client, sample_name="p03-sev-mal.bin")
    created = client.post("/findings", json={"run_id": run_id, "severity": "malicious", "details": "malware confirmed"}).json()
    aid2 = created["id"]
    client.patch(f"/alerts/{aid2}", json={"status": "open", "investigation_id": inv["id"]})
    assert client.get(f"/investigations/{inv['id']}").json()["severity"] == "malicious"
    assert client.get(f"/investigations/{inv['id']}").json()["finding_count"] == 2
    # Detach the malicious one → back to suspicious.
    client.patch(f"/alerts/{aid2}", json={"status": "open", "investigation_id": None})
    assert client.get(f"/investigations/{inv['id']}").json()["severity"] == "suspicious"
    # Detach the last one → severity NULL.
    client.patch(f"/alerts/{aid1}", json={"status": "open", "investigation_id": None})
    body = client.get(f"/investigations/{inv['id']}").json()
    assert body["severity"] is None and body["finding_count"] == 0


def test_attach_nonexistent_investigation_rejected(client):
    aid = _detection_findings(client, "p03-noinv.bin", ip="203.0.113.103")[0]
    assert client.patch(f"/alerts/{aid}", json={"status": "open", "investigation_id": "no-such-case"}).status_code == 422
    # The finding is untouched.
    assert client.get(f"/findings/{aid}").json()["investigation_id"] is None


def test_omitted_investigation_id_leaves_link_unchanged(client):
    inv = _create_inv(client, "p03-omit case")
    aid = _detection_findings(client, "p03-omit.bin", ip="203.0.113.104")[0]
    client.patch(f"/alerts/{aid}", json={"status": "open", "investigation_id": inv["id"]})
    # Status-only PATCH (no investigation_id key) → link untouched.
    resp = client.patch(f"/alerts/{aid}", json={"status": "acknowledged", "comment": "seen"}).json()
    assert resp["investigation_id"] == inv["id"]
    assert resp["status"] == "acknowledged"


def test_findings_ride_along_in_detail(client):
    inv = _create_inv(client, "p03-detail findings")
    aid = _detection_findings(client, "p03-detail.bin", ip="203.0.113.105")[0]
    client.patch(f"/alerts/{aid}", json={"status": "open", "investigation_id": inv["id"]})
    det = client.get(f"/investigations/{inv['id']}").json()
    assert any(f["id"] == aid for f in det["findings"])
    assert det["findings"][0]["source"] == "detection"


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def test_audit_actions(client):
    inv = _create_inv(client, "p03-audit case")
    run_id = make_run(client, sample_name="p03-audit-run.bin")
    client.patch(f"/investigations/{inv['id']}", json={"status": "triage"})
    client.post(f"/investigations/{inv['id']}/refs", json={"ref_type": "run", "ref_id": run_id})
    client.post(f"/investigations/{inv['id']}/notes", json={"note": "audit me"})
    client.post(f"/investigations/{inv['id']}/close", json={"conclusion": "done"})
    client.post(f"/investigations/{inv['id']}/reopen")
    aid = _detection_findings(client, "p03-audit-f.bin", ip="203.0.113.106")[0]
    client.patch(f"/alerts/{aid}", json={"status": "open", "investigation_id": inv["id"]})
    client.patch(f"/alerts/{aid}", json={"status": "open", "investigation_id": None})

    data = client.get("/audit").json()
    by_target = [e for e in data["events"] if e["target_id"] == inv["id"] or (e["target_type"] == "finding" and e["target_id"] == str(aid))]
    actions = {e["action"] for e in by_target}
    assert {
        "investigation.create", "investigation.status", "investigation.ref.add",
        "investigation.note", "investigation.close", "investigation.reopen",
        "investigation.finding.attach", "investigation.finding.detach",
    } <= actions


def test_ref_remove_audited(client):
    run_id = make_run(client, sample_name="p03-audit-remove.bin")
    inv = _create_inv(client, "p03-audit-remove case")
    client.post(f"/investigations/{inv['id']}/refs", json={"ref_type": "run", "ref_id": run_id})
    client.delete(f"/investigations/{inv['id']}/refs/{run_id}")
    data = client.get("/audit").json()
    assert any(e["action"] == "investigation.ref.remove" and e["target_id"] == inv["id"] for e in data["events"])


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@pytest.fixture()
def auth_env(monkeypatch):
    monkeypatch.setenv("OUTPOST_ADMIN_PASSWORD", "admin-secret")
    monkeypatch.setenv("OUTPOST_ANALYST_PASSWORD", "analyst-secret")
    from ..core import auth as auth_mod

    importlib.reload(auth_mod)
    yield
    monkeypatch.delenv("OUTPOST_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("OUTPOST_ANALYST_PASSWORD", raising=False)


def _client():
    from ..main import app

    return TestClient(app)


def test_p03_roles_admin_writes_analyst_reads_agent_denied(auth_env, monkeypatch):
    monkeypatch.setenv("OUTPOST_AGENT_TOKEN", "agent-secret")
    from ..core import auth as auth_mod

    importlib.reload(auth_mod)
    try:
        c = _client()
        admin = c.post("/auth/login", json={"password": "admin-secret"}).json()["token"]
        analyst = c.post("/auth/login", json={"password": "analyst-secret"}).json()["token"]
        ah, yh, gh = {"Authorization": f"Bearer {admin}"}, {"Authorization": f"Bearer {analyst}"}, {"Authorization": "Bearer agent-secret"}
        run_id = c.post(
            "/runs", json={"sample_name": "p03-auth.bin", "platform": "windows", "session_type": "analysis", "source": "cli"}, headers=ah
        ).json()["run_id"]

        # Admin: full CRUD + lifecycle.
        inv = c.post("/investigations", json={"title": "p03-auth case"}, headers=ah).json()
        assert c.get("/investigations", headers=ah).status_code == 200
        assert c.get(f"/investigations/{inv['id']}", headers=ah).status_code == 200
        assert c.patch(f"/investigations/{inv['id']}", json={"title": "renamed"}, headers=ah).status_code == 200
        assert c.post(f"/investigations/{inv['id']}/refs", json={"ref_type": "run", "ref_id": run_id}, headers=ah).status_code == 201
        assert c.post(f"/investigations/{inv['id']}/notes", json={"note": "x"}, headers=ah).status_code == 201
        assert c.post(f"/investigations/{inv['id']}/close", json={"conclusion": "done"}, headers=ah).status_code == 200
        assert c.post(f"/investigations/{inv['id']}/reopen", headers=ah).status_code == 200

        # Analyst: reads OK, mutations 403 (the gate's read-only analyst role).
        assert c.get("/investigations", headers=yh).status_code == 200
        assert c.get(f"/investigations/{inv['id']}", headers=yh).status_code == 200
        assert c.post("/investigations", json={"title": "x"}, headers=yh).status_code == 403
        assert c.patch(f"/investigations/{inv['id']}", json={"title": "x"}, headers=yh).status_code == 403
        assert c.post(f"/investigations/{inv['id']}/notes", json={"note": "x"}, headers=yh).status_code == 403
        assert c.post(f"/investigations/{inv['id']}/close", json={"conclusion": "x"}, headers=yh).status_code == 403
        assert c.post(f"/investigations/{inv['id']}/reopen", headers=yh).status_code == 403
        assert c.delete(f"/investigations/{inv['id']}/refs/{run_id}", headers=yh).status_code == 403

        # Agent: 403 on all investigation resources (deny-by-default gate).
        assert c.get("/investigations", headers=gh).status_code == 403
        assert c.get(f"/investigations/{inv['id']}", headers=gh).status_code == 403
        assert c.post("/investigations", json={"title": "x"}, headers=gh).status_code == 403
        assert c.post(f"/investigations/{inv['id']}/notes", json={"note": "x"}, headers=gh).status_code == 403
        # Investigation-related finding mutation also denied.
        assert c.patch("/alerts/1", json={"status": "open", "investigation_id": inv["id"]}, headers=gh).status_code == 403
        # Unauthenticated → 401.
        assert c.get("/investigations").status_code == 401
    finally:
        monkeypatch.delenv("OUTPOST_AGENT_TOKEN", raising=False)
        importlib.reload(auth_mod)


# ---------------------------------------------------------------------------
# Regressions
# ---------------------------------------------------------------------------


def test_alerts_patch_regression_status_only(client):
    """Status + comment PATCH without investigation_id keeps working and the
    verdict fields stay untouched (P0.2 guarantee)."""
    aid = _detection_findings(client, "p03-qreg.bin", ip="203.0.113.107")[0]
    resp = client.patch(f"/alerts/{aid}", json={"status": "acknowledged", "comment": "seen"}).json()
    assert resp["status"] == "acknowledged" and resp["status_comment"] == "seen"
    assert resp["disposition"] is None and resp["confidence"] is None
    assert resp["investigation_id"] is None
    # Verdicts still ride along.
    resp = client.patch(f"/alerts/{aid}", json={"status": "acknowledged", "disposition": "false-positive", "confidence": "low"}).json()
    assert resp["disposition"] == "false-positive" and resp["confidence"] == "low"


def test_alerts_queue_regression_unchanged(client):
    run_id = make_run(client, sample_name="p03-queue.bin", platform="linux")
    client.post("/ingest/batch", json=[{**_conn(run_id), "host_id": "p03-qhost"}])
    data = client.get("/alerts/queue", params={"status": "all", "q": "p03-queue"}).json()
    assert set(data) == {"total", "open", "acknowledged", "resolved", "sort", "limit", "offset", "alerts"}
    assert "marked_seen" not in data


def test_full_round_trip(client):
    """The whole analyst journey: create → attach findings → refs → notes →
    close → reopen → re-attach → final state."""
    inv = _create_inv(client, "p03-round-trip — full case", tags=["urgent"])
    run_id = make_run(client, sample_name="p03-rt.bin")
    client.post("/ingest/batch", json=[{**_conn(run_id), "host_id": "p03-rt-host"}])
    aids = _detection_findings(client, "p03-rt-det.bin", ip="203.0.113.108")
    aid = aids[0]
    client.patch(f"/alerts/{aid}", json={"status": "open", "investigation_id": inv["id"]})
    client.post(f"/investigations/{inv['id']}/refs", json={"ref_type": "run", "ref_id": run_id})
    client.post(f"/investigations/{inv['id']}/notes", json={"note": "opened case"})
    assert client.get(f"/investigations/{inv['id']}").json()["severity"] == "suspicious"
    client.post(f"/investigations/{inv['id']}/close", json={"conclusion": "contained — IOC watchlisted"})
    closed = client.get(f"/investigations/{inv['id']}").json()
    assert closed["status"] == "closed" and closed["closed_at"]
    client.post(f"/investigations/{inv['id']}/reopen")
    reopened = client.get(f"/investigations/{inv['id']}").json()
    assert reopened["status"] == "active" and reopened["closed_at"] is None
    assert reopened["finding_count"] == 1 and reopened["ref_count"] == 1
    assert [n["note"] for n in reopened["notes"]] == ["opened case"]
