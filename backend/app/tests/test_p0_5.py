"""P0.5 — global search (GET /search).

Covers: grouped results across findings / iocs / artifacts / hosts /
sessions / investigations / campaigns, qualifier parsing (type: status:
severity: disposition: host: rule: case:), free text + qualifier composition,
type: group restriction, empty results, validation, per-group limits, and
auth (analyst read OK, agent 403 — deny-by-default). `/ioc/search` regression
is covered by the existing test suite; the legacy endpoint is untouched here.

The test DB is session-scoped and shared with the rest of the suite, so every
assertion uses unique marker values (a dedicated search-tag prefix) and never
hard-codes global counts.
"""

import importlib

import pytest
from fastapi.testclient import TestClient

from .conftest import make_run
from .test_samples import _upload

_TAG = "p05search"
_IP = "203.0.113.251"  # unique to this file (outside .55/.66/.77 used elsewhere)
_IP2 = "203.0.113.252"  # dedicated to the campaign test — scoped so prior
# _seed() calls (which also touch _IP) can't pre-form a campaign for it.
_DOMAIN = "p05-search-domain.example"


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient as TC

    from ..main import app

    with TC(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Fixtures: a run with events + a detection + an IOC + an investigation, all
# tagged with _TAG so queries stay collision-resistant in the shared DB.
# ---------------------------------------------------------------------------


def _seed(client, conn) -> dict:
    """Create the search fixture set: run → event → finding, an IOC, a
    detection alert, an investigation with a finding attached, and a sample
    artifact. Returns the ids to assert on."""
    run_id = make_run(client, sample_name=f"{_TAG}-sample.bin", source="cli")
    # Event touching _IP on the tagged host (drives campaign derivation + the
    # host filter). Ingested via /ingest/batch — the collector shipping path.
    r = client.post(
        "/ingest/batch",
        json=[
            {
                "run_id": run_id,
                "platform": "windows",
                "event_type": "network_connection",
                "timestamp": "2026-08-17T10:00:00Z",
                "pid": 1,
                "dest_ip": _IP,
                "dest_port": 4444,
                "protocol": "tcp",
                "host_id": f"{_TAG}-host",
            }
        ],
    )
    assert r.status_code in (200, 202), r.text
    # A detection finding on the same run.
    r = client.post(
        "/findings",
        json={
            "run_id": run_id,
            "rule_id": f"{_TAG}-rule",
            "rule_name": f"{_TAG} beacon detection",
            "severity": "malicious",
            "details": f"beaconing to {_IP}",
            "related_ip": _IP,
        },
    )
    finding_id = r.json()["id"]
    # An IOC.
    r = client.post("/iocs", json={"value": _IP, "type": "ip", "label": f"{_TAG} c2"})
    ioc_id = r.json()["ioc_id"]
    # An investigation with the finding attached (status included — the PATCH
    # contract requires the triage transition field).
    r = client.post("/investigations", json={"title": f"{_TAG} case", "tags": [_TAG, "c2"]})
    inv_id = r.json()["id"]
    client.patch(f"/alerts/{finding_id}", json={"status": "open", "investigation_id": inv_id})
    # An artifact (sample upload).
    sample_id = _upload(client, _MZ, name=f"{_TAG}-artifact.bin").json()["sample_id"]
    return {
        "run_id": run_id,
        "finding_id": finding_id,
        "ioc_id": ioc_id,
        "inv_id": inv_id,
        "sample_id": sample_id,
    }


_MZ = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00http://p05-search.example/beacon "


# ---------------------------------------------------------------------------
# Core grouped search
# ---------------------------------------------------------------------------


def test_free_text_finds_finding_and_campaign(client, conn):
    ids = _seed(client, conn)
    r = client.get("/search", params={"q": _TAG})
    assert r.status_code == 200
    d = r.json()
    assert d["q"] == _TAG
    assert d["qualifiers"] == {}
    # The finding group must surface the seeded detection.
    findings = d["groups"]["findings"]
    assert findings["total"] >= 1
    titles = [h["title"] for h in findings["hits"]]
    assert f"{_TAG} beacon detection" in titles
    hit = next(h for h in findings["hits"] if h["title"] == f"{_TAG} beacon detection")
    assert hit["id"] == str(ids["finding_id"])
    assert hit["kind"] == "malicious"
    assert hit["payload"]["related_ip"] == _IP


def test_all_seven_groups_present(client, conn):
    _seed(client, conn)
    r = client.get("/search", params={"q": _TAG})
    d = r.json()
    assert set(d["groups"].keys()) == {
        "findings", "iocs", "artifacts", "hosts", "sessions", "investigations", "campaigns",
    }
    # Every seeded entity is discoverable in its own group.
    assert any(h["title"] == _IP for h in d["groups"]["iocs"]["hits"])
    assert any(_TAG in h["title"] for h in d["groups"]["sessions"]["hits"])
    assert any(_TAG in h["title"] for h in d["groups"]["artifacts"]["hits"])
    assert any(h["title"] == f"{_TAG}-host" for h in d["groups"]["hosts"]["hits"])
    assert any(h["title"] == f"{_TAG} case" for h in d["groups"]["investigations"]["hits"])


def test_campaign_group_derives_from_events(client, conn):
    """Campaigns have no table — the group must surface an IP as a campaign
    only when the derivation (IP shared by >= 2 runs) holds. One run is not
    enough; add a second run touching _IP2 and it should appear. Scoped to
    _IP2 so prior _seed() calls (which touch _IP) can't pre-form it."""
    run1 = make_run(client, sample_name=f"{_TAG}-camp1.bin", source="cli")
    client.post(
        "/ingest/batch",
        json=[
            {
                "run_id": run1,
                "platform": "windows",
                "event_type": "network_connection",
                "timestamp": "2026-08-17T10:00:00Z",
                "pid": 1,
                "dest_ip": _IP2,
                "dest_port": 4444,
                "protocol": "tcp",
                "host_id": f"{_TAG}-host",
            }
        ],
    )
    r = client.get("/search", params={"q": _IP2})
    d = r.json()
    assert d["groups"]["campaigns"]["total"] == 0
    # Second run touching the same IP → campaign forms.
    run2 = make_run(client, sample_name=f"{_TAG}-camp2.bin", source="cli")
    client.post(
        "/ingest/batch",
        json=[
            {
                "run_id": run2,
                "platform": "windows",
                "event_type": "network_connection",
                "timestamp": "2026-08-17T10:05:00Z",
                "pid": 1,
                "dest_ip": _IP2,
                "dest_port": 4444,
                "protocol": "tcp",
                "host_id": f"{_TAG}-host",
            }
        ],
    )
    r = client.get("/search", params={"q": _IP2})
    d = r.json()
    assert d["groups"]["campaigns"]["total"] == 1
    assert d["groups"]["campaigns"]["hits"][0]["id"] == _IP2


# ---------------------------------------------------------------------------
# Qualifiers
# ---------------------------------------------------------------------------


def test_type_qualifier_restricts_groups(client, conn):
    _seed(client, conn)
    r = client.get("/search", params={"q": f"type:ioc {_IP}"})
    d = r.json()
    for group, res in d["groups"].items():
        if group == "iocs":
            assert res["total"] == 1
        else:
            assert res["total"] == 0
    r = client.get("/search", params={"q": f"type:finding {_TAG}"})
    d = r.json()
    assert d["groups"]["findings"]["total"] >= 1
    assert d["groups"]["iocs"]["total"] == 0
    assert d["groups"]["campaigns"]["total"] == 0


def test_status_qualifier_on_findings(client, conn):
    ids = _seed(client, conn)
    # Open first, then acknowledge; the status qualifier must follow it.
    r = client.get("/search", params={"q": f"type:finding status:open {_TAG}"})
    assert any(h["id"] == str(ids["finding_id"]) for h in r.json()["groups"]["findings"]["hits"])
    client.patch(f"/alerts/{ids['finding_id']}", json={"status": "acknowledged"})
    r = client.get("/search", params={"q": f"type:finding status:acknowledged {_TAG}"})
    assert any(h["id"] == str(ids["finding_id"]) for h in r.json()["groups"]["findings"]["hits"])
    r = client.get("/search", params={"q": f"type:finding status:open {_TAG}"})
    assert not any(h["id"] == str(ids["finding_id"]) for h in r.json()["groups"]["findings"]["hits"])


def test_disposition_and_severity_qualifiers(client, conn):
    ids = _seed(client, conn)
    client.patch(f"/alerts/{ids['finding_id']}", json={"status": "open", "disposition": "confirmed-malicious"})
    r = client.get("/search", params={"q": f"type:finding disposition:confirmed-malicious {_TAG}"})
    assert any(h["id"] == str(ids["finding_id"]) for h in r.json()["groups"]["findings"]["hits"])
    r = client.get("/search", params={"q": f"type:finding disposition:benign {_TAG}"})
    assert not any(h["id"] == str(ids["finding_id"]) for h in r.json()["groups"]["findings"]["hits"])
    # severity
    r = client.get("/search", params={"q": f"type:finding severity:malicious {_TAG}"})
    assert any(h["id"] == str(ids["finding_id"]) for h in r.json()["groups"]["findings"]["hits"])
    r = client.get("/search", params={"q": f"type:finding severity:suspicious {_TAG}"})
    assert not any(h["id"] == str(ids["finding_id"]) for h in r.json()["groups"]["findings"]["hits"])


def test_host_qualifier(client, conn):
    _seed(client, conn)
    r = client.get("/search", params={"q": f"host:{_TAG}-host {_TAG}"})
    d = r.json()
    # The finding ran on the tagged host via its event.
    assert d["groups"]["hosts"]["total"] == 1
    assert d["groups"]["hosts"]["hits"][0]["id"] == f"{_TAG}-host"
    assert d["groups"]["findings"]["total"] >= 1


def test_rule_qualifier(client, conn):
    ids = _seed(client, conn)
    r = client.get("/search", params={"q": f"type:finding rule:{_TAG}-rule"})
    assert any(h["id"] == str(ids["finding_id"]) for h in r.json()["groups"]["findings"]["hits"])


def test_case_qualifier(client, conn):
    ids = _seed(client, conn)
    r = client.get("/search", params={"q": f"type:finding case:{ids['inv_id']}"})
    assert any(h["id"] == str(ids["finding_id"]) for h in r.json()["groups"]["findings"]["hits"])


def test_ioc_disposition_qualifier(client, conn):
    ids = _seed(client, conn)
    client.patch(f"/iocs/{ids['ioc_id']}/disposition", json={"disposition": "confirmed-malicious"})
    r = client.get("/search", params={"q": f"type:ioc disposition:confirmed-malicious {_IP}"})
    assert r.json()["groups"]["iocs"]["total"] == 1
    r = client.get("/search", params={"q": f"type:ioc disposition:benign {_IP}"})
    assert r.json()["groups"]["iocs"]["total"] == 0


def test_investigation_status_qualifier(client, conn):
    ids = _seed(client, conn)
    r = client.get("/search", params={"q": f"type:investigation status:created {_TAG}"})
    assert any(h["id"] == ids["inv_id"] for h in r.json()["groups"]["investigations"]["hits"])
    r = client.get("/search", params={"q": f"type:investigation status:closed {_TAG}"})
    assert not any(h["id"] == ids["inv_id"] for h in r.json()["groups"]["investigations"]["hits"])


# ---------------------------------------------------------------------------
# Envelope / validation
# ---------------------------------------------------------------------------


def test_empty_results_honest(client, conn):
    r = client.get("/search", params={"q": "zzz-no-such-p05-thing-987654321"})
    assert r.status_code == 200
    for res in r.json()["groups"].values():
        assert res["total"] == 0
        assert res["hits"] == []


def test_investigation_hit_carries_counts(client, conn):
    ids = _seed(client, conn)
    r = client.get("/search", params={"q": f"type:investigation {_TAG} case"})
    hit = next(h for h in r.json()["groups"]["investigations"]["hits"] if h["id"] == ids["inv_id"])
    assert hit["payload"]["finding_count"] >= 1
    assert hit["payload"]["status"] == "created"


def test_limit_per_group(client, conn):
    # Seed enough artifacts to overflow a limit of 1 (the DB may already have
    # samples; we just assert the page is capped and total is honest).
    for i in range(3):
        _upload(client, _MZ + bytes([i]), name=f"{_TAG}-many-{i}.bin")
    r = client.get("/search", params={"q": _TAG, "limit": 1})
    d = r.json()
    for res in d["groups"].values():
        assert len(res["hits"]) <= 1
        assert res["total"] >= len(res["hits"])
    r = client.get("/search", params={"q": _TAG, "limit": 100})
    assert r.status_code == 422  # capped at 50


def test_blank_q_rejected(client):
    assert client.get("/search", params={"q": "   "}).status_code == 422
    assert client.get("/search").status_code == 422


def test_unknown_type_qualifier_stays_free_text(client, conn):
    _seed(client, conn)
    # An unknown type: value is not a qualifier — it stays free text, which
    # won't match anything (honest empty rather than a spurious group filter).
    r = client.get("/search", params={"q": "type:not-a-group"})
    assert r.status_code == 200
    for res in r.json()["groups"].values():
        assert res["total"] == 0


# ---------------------------------------------------------------------------
# Auth — the search surface is analyst-facing: analyst reads OK, agent 403
# (deny-by-default in the gate), admin reads OK.
# ---------------------------------------------------------------------------


@pytest.fixture()
def auth_env(monkeypatch):
    monkeypatch.setenv("OUTPOST_ADMIN_PASSWORD", "admin-secret")
    monkeypatch.setenv("OUTPOST_ANALYST_PASSWORD", "analyst-secret")
    monkeypatch.setenv("OUTPOST_AGENT_TOKEN", "agent-secret")
    from ..core import auth as auth_mod

    importlib.reload(auth_mod)
    yield
    monkeypatch.delenv("OUTPOST_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("OUTPOST_ANALYST_PASSWORD", raising=False)
    monkeypatch.delenv("OUTPOST_AGENT_TOKEN", raising=False)


def _auth_client(auth_env):
    from ..main import app

    with TestClient(app) as c:
        admin = c.post("/auth/login", json={"password": "admin-secret"}).json()["token"]
        analyst = c.post("/auth/login", json={"password": "analyst-secret"}).json()["token"]
        ah = {"Authorization": f"Bearer {admin}"}
        yh = {"Authorization": f"Bearer {analyst}"}
        gh = {"Authorization": "Bearer agent-secret"}
        return c, ah, yh, gh


def test_analyst_can_search(auth_env):
    c, ah, yh, _gh = _auth_client(auth_env)
    assert c.get("/search", params={"q": "anything"}, headers=yh).status_code == 200
    assert c.get("/search", params={"q": "anything"}, headers=ah).status_code == 200


def test_unauthenticated_401(auth_env):
    c, _ah, _yh, _gh = _auth_client(auth_env)
    assert c.get("/search", params={"q": "anything"}).status_code == 401


def test_agent_denied(auth_env):
    # The agent credential is limited to telemetry endpoints; /search is
    # deny-by-default for the agent role.
    c, _ah, _yh, gh = _auth_client(auth_env)
    assert c.get("/search", params={"q": "anything"}, headers=gh).status_code == 403
