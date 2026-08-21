"""P0.6 — host aggregate timeline (GET /hosts/{host_id}/timeline).

A pure read model: no host-timeline table exists (asserted), hosts are
derived from events.host_id / agent_heartbeats / host_snapshots, and the
timeline merges events, findings, sessions, IOCs (via provenance refs), and
investigations into one chronological feed.

Covers: cross-resource aggregation, chronological ordering (newest first),
kind / event_type / q filters, pagination with honest totals, empty feeds
for a known-but-quiet host, 404 for unknown hosts, and auth (analyst/admin
read OK, agent 403 — deny-by-default). The session DB is shared across the
suite, so every assertion is scoped to this file's unique host id.
"""

import importlib

import pytest
from fastapi.testclient import TestClient

from .conftest import make_run

_HOST = "p06-host"
_IP = "203.0.113.253"  # unique to this file


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient as TC

    from ..main import app

    with TC(app) as c:
        yield c


def _ingest_event(client, run_id: str, ts: str, ip: str = _IP, host: str = _HOST, event_type: str = "network_connection", pid: int = 1) -> None:
    r = client.post(
        "/ingest/batch",
        json=[
            {
                "run_id": run_id,
                "platform": "linux",
                "event_type": event_type,
                "timestamp": ts,
                "pid": pid,
                "dest_ip": ip,
                "dest_port": 4444,
                "protocol": "tcp",
                "host_id": host,
            }
        ],
    )
    assert r.status_code in (200, 202), r.text


def _seed(client, conn) -> dict:
    """A host with: 3 events across 2 runs, a detection finding, an IOC
    (provenance via the finding), and an investigation with the finding
    attached. Timestamps are ordered so the merged feed is deterministic."""
    run1 = make_run(client, sample_name="p06-run1.bin", source="cli")
    _ingest_event(client, run1, "2026-08-17T10:00:00Z", pid=100)
    _ingest_event(client, run1, "2026-08-17T10:01:00Z", pid=200, event_type="process_create")
    run2 = make_run(client, sample_name="p06-run2.bin", source="cli")
    _ingest_event(client, run2, "2026-08-17T10:02:00Z", pid=300)
    # Detection finding on run1 (earliest alert).
    r = client.post(
        "/findings",
        json={
            "run_id": run1,
            "rule_id": "p06-rule",
            "rule_name": "p06 beacon detection",
            "severity": "malicious",
            "details": f"beaconing to {_IP}",
            "related_ip": _IP,
        },
    )
    finding_id = r.json()["id"]
    # IOC with provenance to an event ON THE HOST (so it derives to the
    # host timeline). Provenance is wired directly — P0.2 defers IOC
    # backfill, exactly like the P0.2 IOC-detail tests do.
    r = client.post("/iocs", json={"value": _IP, "type": "ip", "label": "p06 c2"})
    ioc_id = r.json()["ioc_id"]
    conn.execute(
        "INSERT OR IGNORE INTO ioc_provenance (ioc_id, ref_type, ref_id, first_seen) "
        "VALUES (?, 'event', (SELECT id FROM events WHERE host_id = ? ORDER BY timestamp ASC LIMIT 1), '2026-08-17T10:00:00Z')",
        (ioc_id, _HOST),
    )
    conn.commit()
    # Investigation with the finding attached.
    r = client.post("/investigations", json={"title": "p06 case", "tags": ["p06"]})
    inv_id = r.json()["id"]
    client.patch(f"/alerts/{finding_id}", json={"status": "open", "investigation_id": inv_id})
    return {"run1": run1, "run2": run2, "finding_id": finding_id, "ioc_id": ioc_id, "inv_id": inv_id}


def _kinds(d: dict) -> list[str]:
    return [e["kind"] for e in d["timeline"]]


# ---------------------------------------------------------------------------
# Core aggregation + ordering
# ---------------------------------------------------------------------------


def test_no_host_timeline_table_exists(conn):
    """The P0.6 read model must NOT create a host-timeline table."""
    tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "host_timeline" not in tables
    assert "host_timelines" not in tables


def test_cross_resource_aggregation(client, conn):
    ids = _seed(client, conn)
    r = client.get(f"/hosts/{_HOST}/timeline")
    assert r.status_code == 200
    d = r.json()
    assert d["host_id"] == _HOST
    kinds = set(_kinds(d))
    assert kinds == {"event", "finding", "session", "ioc", "investigation"}
    # Every seeded resource is present.
    assert any(e["id"] == str(ids["finding_id"]) and e["kind"] == "finding" for e in d["timeline"])
    assert any(e["id"] == ids["ioc_id"] and e["kind"] == "ioc" for e in d["timeline"])
    assert any(e["id"] == ids["inv_id"] and e["kind"] == "investigation" for e in d["timeline"])
    assert any(e["id"] == ids["run1"] and e["kind"] == "session" for e in d["timeline"])


def test_chronological_ordering_newest_first(client, conn):
    _seed(client, conn)
    r = client.get(f"/hosts/{_HOST}/timeline")
    d = r.json()
    stamps = [e["timestamp"] for e in d["timeline"]]
    assert stamps == sorted(stamps, reverse=True), "timeline must be newest-first"


def test_finding_payload_carries_links(client, conn):
    ids = _seed(client, conn)
    r = client.get(f"/hosts/{_HOST}/timeline", params={"kind": "finding"})
    hit = next(e for e in r.json()["timeline"] if e["id"] == str(ids["finding_id"]))
    assert hit["payload"]["run_id"] == ids["run1"]
    assert hit["payload"]["investigation_id"] == ids["inv_id"]
    assert hit["payload"]["severity"] == "malicious"


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


def test_kind_filter(client, conn):
    _seed(client, conn)
    for kind in ("event", "finding", "session", "ioc", "investigation"):
        r = client.get(f"/hosts/{_HOST}/timeline", params={"kind": kind})
        assert r.status_code == 200
        assert set(_kinds(r.json())) == {kind}
    r = client.get(f"/hosts/{_HOST}/timeline", params={"kind": "bogus"})
    assert r.status_code == 422


def test_event_type_filter(client, conn):
    ids = _seed(client, conn)
    # Scope to the seeded run so the counts are deterministic (the session
    # DB is shared — other runs may touch _HOST later in the suite).
    q_run = ids["run1"]
    r = client.get(f"/hosts/{_HOST}/timeline", params={"kind": "event", "event_type": "process_create", "q": q_run})
    d = r.json()
    assert d["total"] == 1
    assert all(e["payload"]["event_type"] == "process_create" for e in d["timeline"])
    r = client.get(f"/hosts/{_HOST}/timeline", params={"kind": "event", "event_type": "network_connection", "q": q_run})
    assert r.json()["total"] == 1
    # The events themselves carry the run id for deep-linking.
    hit = d["timeline"][0]
    assert hit["payload"]["run_id"] == ids["run1"]


def test_q_filter_matches_all_kinds(client, conn):
    _seed(client, conn)
    # IOC value matches.
    r = client.get(f"/hosts/{_HOST}/timeline", params={"q": _IP})
    d = r.json()
    assert d["total"] >= 1
    assert any(e["kind"] == "ioc" and e["title"] == _IP for e in d["timeline"])
    # Finding rule name matches.
    r = client.get(f"/hosts/{_HOST}/timeline", params={"q": "p06 beacon"})
    assert any(e["kind"] == "finding" for e in r.json()["timeline"])
    # Session sample matches (title carries the sample name; id is run_id).
    r = client.get(f"/hosts/{_HOST}/timeline", params={"q": "p06-run2"})
    assert any(e["kind"] == "session" and e["title"] == "p06-run2.bin" for e in r.json()["timeline"])
    # No match → honest empty.
    r = client.get(f"/hosts/{_HOST}/timeline", params={"q": "zzz-no-match-9876"})
    d = r.json()
    assert d["total"] == 0
    assert d["timeline"] == []


def test_total_honest_across_kinds_with_q(client, conn):
    """total must be the count across ALL kinds after q, not the page size."""
    _seed(client, conn)
    r = client.get(f"/hosts/{_HOST}/timeline", params={"q": _IP, "limit": 1})
    d = r.json()
    assert len(d["timeline"]) == 1
    # q matches the finding (details/related_ip), the ioc (value), and the
    # events (dest_ip) — so total must reflect all of those, not 1.
    assert d["total"] >= 3


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


def test_pagination_with_honest_total(client, conn):
    _seed(client, conn)
    r_all = client.get(f"/hosts/{_HOST}/timeline", params={"limit": 200})
    total = r_all.json()["total"]
    page1 = client.get(f"/hosts/{_HOST}/timeline", params={"limit": 2, "offset": 0}).json()
    page2 = client.get(f"/hosts/{_HOST}/timeline", params={"limit": 2, "offset": 2}).json()
    assert page1["total"] == page2["total"] == total
    assert len(page1["timeline"]) == 2
    assert len(page2["timeline"]) == 2
    ids1 = [e["id"] for e in page1["timeline"]]
    ids2 = [e["id"] for e in page2["timeline"]]
    assert not set(ids1) & set(ids2), "pages must not overlap"
    # Reassembled ids equal the full feed's first four (newest-first order).
    full_ids = [e["id"] for e in r_all.json()["timeline"]]
    assert ids1 + ids2 == full_ids[:4]


def test_empty_feed_for_known_quiet_host(client, conn):
    """A host known to the fleet (heartbeat only, no events) is not 404 —
    it returns an honest empty timeline."""
    r = client.post(f"/agents/{_HOST}-quiet/heartbeat", json={"platform": "linux"})
    assert r.status_code == 200
    r = client.get(f"/hosts/{_HOST}-quiet/timeline")
    assert r.status_code == 200
    d = r.json()
    assert d["total"] == 0
    assert d["timeline"] == []
    assert d["platform"] == "linux"
    assert d["last_heartbeat"] is not None


def test_unknown_host_404(client):
    assert client.get("/hosts/never-seen-host-zzz/timeline").status_code == 404


# ---------------------------------------------------------------------------
# Auth — analyst-facing read resource: analyst/admin read OK, agent 403
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


def test_roles_read_timeline_agent_denied(auth_env):
    c, ah, yh, gh = _auth_client(auth_env)
    # Create a run with an event first (auth is on — need a valid token).
    run_id = c.post(
        "/runs",
        json={"sample_name": "p06-auth.bin", "platform": "linux", "session_type": "analysis", "source": "cli"},
        headers=ah,
    ).json()["run_id"]
    c.post(
        "/ingest/batch",
        json=[{"run_id": run_id, "platform": "linux", "event_type": "network_connection", "timestamp": "2026-08-17T11:00:00Z", "pid": 1, "dest_ip": _IP, "host_id": _HOST}],
        headers=ah,
    )
    assert c.get(f"/hosts/{_HOST}/timeline", headers=ah).status_code == 200
    assert c.get(f"/hosts/{_HOST}/timeline", headers=yh).status_code == 200
    assert c.get(f"/hosts/{_HOST}/timeline", headers=gh).status_code == 403
    assert c.get(f"/hosts/{_HOST}/timeline").status_code == 401
