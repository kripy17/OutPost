"""P0.2 resource/API foundations — focused tests.

- Finding API: the shared queue with source/disposition/confidence filters,
  unread_only + opt-in mark_seen (bounded, idempotent, page-scoped), detail,
  analyst-authored findings, and the extended PATCH /alerts/{id} verdicts —
  with the /alerts/queue compatibility surface pinned.
- IOC API: create with normalization + dedupe, list filters, the workspace
  detail payload (provenance/findings/derived runs+hosts), audited
  disposition mutation, invalid enums.
- Analysis job API: persisted static jobs (real static analysis with stored
  bytes), cancel transitions over store-created queued rows, unexecuted
  backends (watched-host / isolated-outpost) 501 at the API — capability
  honesty; external-provider executes via the sandbox providers instead of
  501-ing (provider wiring covered in test_analysis_provider_jobs) —
  observations (NO observations table), findings.
- Auth: analyst reads / writes 403, admin reads+writes, agent 403 on all
  three analyst-facing resources.
"""

import importlib

import pytest
from fastapi.testclient import TestClient

from ..models import analysis_jobs as jobs_store
from .conftest import make_run
from .test_samples import _upload

_MZ = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00http://evil.example/beacon 203.0.113.99 "


def _queued_job(client, conn, backend: str, sample: str) -> dict:
    """A queued dynamic job created at the store layer — POST /analysis
    refuses unexecuted backends (501), but the store keeps supporting the
    queued state for when executors land (and legacy rows still render)."""
    run_id = make_run(client, sample_name=sample)
    job = jobs_store.create_job(conn, run_id, backend)
    conn.commit()  # the API reads through its own connection
    return job


def _conn(run_id: str, ip: str = "203.0.113.77") -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "network_connection",
        "timestamp": "2026-08-17T00:00:00Z", "pid": 1, "dest_ip": ip, "dest_port": 4444, "protocol": "tcp",
    }


def _lolbin(run_id: str) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "process_create",
        "timestamp": "2026-08-17T00:00:00Z", "pid": 2, "ppid": 1, "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA",
    }


def _detection_findings(client, sample: str, ip: str = "203.0.113.77") -> list[int]:
    """A run with a detection finding; returns [alert_id]."""
    run_id = make_run(client, sample_name=sample)
    client.post("/ingest/batch", json=[_conn(run_id, ip)])
    alerts = client.get(f"/runs/{run_id}/alerts").json()
    assert alerts, "unusual-port should have fired"
    return [a["id"] for a in alerts]


# ---------------------------------------------------------------------------
# Finding API — queue semantics
# ---------------------------------------------------------------------------


def test_findings_queue_envelope_and_defaults(client):
    aid = _detection_findings(client, "p02-env.bin")[0]
    # Scope by sample name: the shared session DB has many open alerts, so the
    # default 50-row page (aging) would not reach this newest finding.
    data = client.get("/findings", params={"q": "p02-env"}).json()
    mine = [a for a in data["alerts"] if a["id"] == aid]
    assert len(mine) == 1
    row = mine[0]
    assert row["source"] == "detection"
    assert row["confidence"] is None
    assert row["disposition"] is None
    assert row["seen_at"] is None
    assert row["investigation_id"] is None
    # Same envelope as /alerts/queue (compat) — and NO unseen mutation.
    q = client.get("/alerts/queue").json()
    assert set(q) == {"total", "open", "acknowledged", "resolved", "sort", "limit", "offset", "alerts"}
    assert client.get(f"/findings/{aid}").json()["seen_at"] is None


def test_findings_source_filter(client):
    run_id = make_run(client, sample_name="p02-src.bin")
    _detection_findings(client, "p02-src-det.bin")
    created = client.post("/findings", json={"run_id": run_id, "severity": "suspicious", "details": "x"}).json()
    det = client.get("/findings", params={"source": "detection", "q": "p02-src"}).json()
    ana = client.get("/findings", params={"source": "analyst", "q": "p02-src"}).json()
    assert all(a["source"] == "detection" for a in det["alerts"])
    assert all(a["source"] == "analyst" for a in ana["alerts"])
    assert created["id"] in {a["id"] for a in ana["alerts"]}
    assert client.get("/findings", params={"source": "bogus"}).status_code == 422


def test_findings_confidence_and_disposition_filters(client):
    run_id = make_run(client, sample_name="p02-verdict.bin")
    created = client.post("/findings", json={"run_id": run_id, "severity": "malicious", "details": "v"}).json()
    client.patch(f"/alerts/{created['id']}", json={"status": "open", "confidence": "high", "disposition": "confirmed-malicious"})
    by_conf = client.get("/findings", params={"confidence": "high", "q": "p02-verdict"}).json()
    by_disp = client.get("/findings", params={"disposition": "confirmed-malicious", "q": "p02-verdict"}).json()
    assert {a["id"] for a in by_conf["alerts"]} == {created["id"]}
    assert {a["id"] for a in by_disp["alerts"]} == {created["id"]}
    # A detection finding (confidence NULL) is excluded by the confidence filter.
    _detection_findings(client, "p02-verdict-det.bin")
    none_high = client.get("/findings", params={"confidence": "high", "q": "p02-verdict"}).json()
    assert all(a["confidence"] == "high" for a in none_high["alerts"])
    assert client.get("/findings", params={"confidence": "banana"}).status_code == 422
    assert client.get("/findings", params={"disposition": "banana"}).status_code == 422


def test_unread_only_semantics(client):
    aid = _detection_findings(client, "p02-unread.bin")[0]
    # Ack the alert — acknowledged is NOT unread even before seen_at is set.
    client.patch(f"/alerts/{aid}", json={"status": "acknowledged"})
    unread = client.get("/findings", params={"unread_only": "true", "q": "p02-unread"}).json()
    assert all(a["id"] != aid for a in unread["alerts"])
    # Default (no unread_only, status=all): the acknowledged alert IS visible.
    allv = client.get("/findings", params={"status": "all", "q": "p02-unread"}).json()
    assert any(a["id"] == aid for a in allv["alerts"])
    # An open unseen alert is unread.
    aid2 = _detection_findings(client, "p02-unread-2.bin")[0]
    unread2 = client.get("/findings", params={"unread_only": "true", "q": "p02-unread-2"}).json()
    assert any(a["id"] == aid2 for a in unread2["alerts"])


def test_mark_seen_is_opt_in_bounded_and_idempotent(client):
    # Two open findings in two runs; query page size 1.
    _detection_findings(client, "p02-seen-a.bin", ip="203.0.113.101")
    _detection_findings(client, "p02-seen-b.bin", ip="203.0.113.102")
    page1 = client.get("/findings", params={"q": "p02-seen-", "limit": 1, "sort": "newest"}).json()
    assert len(page1["alerts"]) == 1
    first_id = page1["alerts"][0]["id"]
    # mark_seen=false (the default read): nothing mutates.
    assert page1["marked_seen"] == 0

    marked = client.get("/findings", params={"q": "p02-seen-", "limit": 1, "sort": "newest", "mark_seen": "true"}).json()
    assert marked["marked_seen"] == 1
    assert client.get(f"/findings/{first_id}").json()["seen_at"] is not None

    # Only the returned page was marked — the OTHER alert is still unseen.
    page2 = client.get("/findings", params={"q": "p02-seen-", "limit": 1, "sort": "newest", "offset": 1}).json()
    other = page2["alerts"][0]["id"]
    assert client.get(f"/findings/{other}").json()["seen_at"] is None

    # Idempotent: re-marking the same page marks 0 (already stamped).
    again = client.get("/findings", params={"q": "p02-seen-", "limit": 1, "sort": "newest", "mark_seen": "true"}).json()
    assert again["marked_seen"] == 0


def test_get_finding_detail_and_post_analyst_finding(client):
    run_id = make_run(client, sample_name="p02-detail.bin")
    created = client.post(
        "/findings",
        json={"run_id": run_id, "severity": "malicious", "details": "hand-made", "related_ip": "203.0.113.55"},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["source"] == "analyst"
    assert body["rule_id"] == "analyst-finding"
    assert body["status"] == "open"
    assert body["related_ip"] == "203.0.113.55"

    det = client.get(f"/findings/{body['id']}").json()
    assert det["source"] == "analyst" and det["details"] == "hand-made"
    assert client.get("/findings/999999").status_code == 404
    # Analyst findings need a real run.
    assert client.post("/findings", json={"run_id": "nope", "severity": "suspicious", "details": "x"}).status_code == 404


def test_patch_alerts_sets_verdicts_without_breaking_triage(client):
    aid = _detection_findings(client, "p02-patch.bin")[0]
    # Status-only PATCH still works (regression).
    resp = client.patch(f"/alerts/{aid}", json={"status": "acknowledged", "comment": "seen"}).json()
    assert resp["status"] == "acknowledged" and resp["status_comment"] == "seen"
    assert resp["disposition"] is None
    # Verdicts now ride along.
    resp = client.patch(f"/alerts/{aid}", json={"status": "acknowledged", "disposition": "false-positive", "confidence": "low"}).json()
    assert resp["disposition"] == "false-positive" and resp["confidence"] == "low"
    # Unknown investigation 422 (the investigation API arrives in P0.3).
    assert client.patch(f"/alerts/{aid}", json={"status": "open", "investigation_id": "no-such-case"}).status_code == 422
    # Bad enums still 422 (pydantic).
    assert client.patch(f"/alerts/{aid}", json={"status": "open", "disposition": "banana"}).status_code == 422
    assert client.patch(f"/alerts/{aid}", json={"status": "open", "confidence": "banana"}).status_code == 422


def test_alerts_queue_regression_unchanged(client):
    """The compatibility surface: /alerts/queue has no P0 params, no
    marked_seen key, and behaves exactly as before."""
    run_id = make_run(client, sample_name="p02-qreg.bin", platform="linux")
    client.post(
        "/ingest/batch",
        json=[{**_conn(run_id), "host_id": "qreg-host"}, _lolbin(run_id)],
    )
    data = client.get("/alerts/queue", params={"status": "all", "q": "p02-qreg"}).json()
    assert set(data) == {"total", "open", "acknowledged", "resolved", "sort", "limit", "offset", "alerts"}
    assert len(data["alerts"]) == 2
    unusual = next(a for a in data["alerts"] if a["rule_id"] == "unusual-port")
    assert "qreg-host" in unusual["host_ids"]
    # The P0 finding fields are present on the rows (superset) but the queue
    # itself gained no new parameters or keys.
    assert all(a["source"] == "detection" for a in data["alerts"])


# ---------------------------------------------------------------------------
# IOC API
# ---------------------------------------------------------------------------


def test_ioc_create_normalizes_and_dedupes(client):
    a = client.post("/iocs", json={"value": "  EVIL.Example.COM ", "type": "domain", "label": "c2"}).json()
    assert a["value"] == "evil.example.com"
    assert a["disposition"] == "candidate"
    assert a["label"] == "c2"
    assert a["first_seen"]
    # Dedupe: same normalized value+type → the SAME row (idempotent).
    b = client.post("/iocs", json={"value": "evil.example.com", "type": "domain"}).json()
    assert b["ioc_id"] == a["ioc_id"]
    assert b["label"] == "c2"  # untouched by the repeat
    # Different type → a different IOC (UNIQUE is value+type).
    c = client.post("/iocs", json={"value": "evil.example.com", "type": "url"}).json()
    assert c["ioc_id"] != a["ioc_id"]
    # IPs are lowercased? No — IPs have no case, but normalization strips.
    ip = client.post("/iocs", json={"value": " 203.0.113.99 ", "type": "ip"}).json()
    assert ip["value"] == "203.0.113.99"
    # filepath is NOT case-folded (the type set excludes it).
    fp = client.post("/iocs", json={"value": "C:\\Temp\\X.EXE", "type": "filepath"}).json()
    assert fp["value"] == "C:\\Temp\\X.EXE"
    # Invalid type 422 (pydantic literal).
    assert client.post("/iocs", json={"value": "x", "type": "ipaddr"}).status_code == 422


def test_ioc_list_filters(client):
    # Self-contained values: the session DB is shared, so every assertion is
    # scoped to this test's unique tokens rather than global totals.
    client.post("/iocs", json={"value": "10.0.0.1", "type": "ip"})
    client.post("/iocs", json={"value": "unique-filter.example", "type": "domain", "label": "unique filter label"})
    client.post("/iocs", json={"value": "198.51.100.7", "type": "ip"})
    allv = client.get("/iocs").json()
    assert allv["total"] >= 3
    # type filter: every returned row is a domain, and ours is present.
    by_type = client.get("/iocs", params={"type": "domain"}).json()
    assert all(i["type"] == "domain" for i in by_type["iocs"])
    assert any(i["value"] == "unique-filter.example" for i in by_type["iocs"])
    # q matches value — scoped to this test's unique value.
    by_q = client.get("/iocs", params={"q": "unique-filter"}).json()
    assert by_q["total"] >= 1 and all("unique-filter" in i["value"] for i in by_q["iocs"])
    # q matches label too.
    by_label = client.get("/iocs", params={"q": "unique filter label"}).json()
    assert by_label["total"] >= 1 and any(i["value"] == "unique-filter.example" for i in by_label["iocs"])
    empty = client.get("/iocs", params={"q": "zzz-no-match-zzz"}).json()
    assert empty["total"] == 0
    # Pagination envelope.
    p = client.get("/iocs", params={"limit": 2, "offset": 0}).json()
    assert p["limit"] == 2 and len(p["iocs"]) == 2


def test_ioc_detail_payload_derives_runs_and_hosts(client):
    # 203.0.113.166 is unique to this test — test_standout pins exact counts
    # on other 203.0.113.x values in the shared session DB.
    run_id = make_run(client, sample_name="p02-ioc-detail.bin", platform="linux")
    client.post("/ingest/batch", json=[{**_conn(run_id, "203.0.113.166"), "host_id": "ioc-host-a"}])
    aid = client.get(f"/runs/{run_id}/alerts").json()[0]["id"]
    # P3.1: detection itself populated the entity — create/reuse returns the
    # SAME canonical row, no manual wiring needed.
    ioc = client.post("/iocs", json={"value": "203.0.113.166", "type": "ip"}).json()
    assert ioc["source"] == "detection"

    det = client.get(f"/iocs/{ioc['ioc_id']}").json()
    assert det["value"] == "203.0.113.166"
    ref_types = {p["ref_type"] for p in det["provenance"]}
    assert "finding" in ref_types and "event" in ref_types
    # Finding rides along with the full alert row.
    assert any(f["id"] == aid for f in det["findings"])
    # Runs + hosts DERIVED from the provenance — not fabricated.
    assert [r["run_id"] for r in det["runs"]] == [run_id]
    assert "ioc-host-a" in det["hosts"]
    assert det["abuse_score"] is None  # no enrichment backfill in P0.2
    # An IOC with no provenance reports empty runs/hosts (honest).
    bare = client.post("/iocs", json={"value": "10.1.2.3", "type": "ip"}).json()
    bare_det = client.get(f"/iocs/{bare['ioc_id']}").json()
    assert bare_det["runs"] == [] and bare_det["hosts"] == [] and bare_det["provenance"] == []
    assert client.get("/iocs/no-such").status_code == 404


def test_ioc_disposition_mutation_is_audited(client, conn):
    ioc = client.post("/iocs", json={"value": "203.0.113.44", "type": "ip"}).json()
    resp = client.patch(f"/iocs/{ioc['ioc_id']}/disposition", json={"disposition": "confirmed-malicious", "label": "confirmed c2"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["disposition"] == "confirmed-malicious"
    assert body["label"] == "confirmed c2"
    # Audited.
    data = client.get("/audit").json()
    assert any(e["action"] == "ioc.disposition" and e["target_id"] == ioc["ioc_id"] for e in data["events"])
    # Filter reflects the verdict.
    by_disp = client.get("/iocs", params={"disposition": "confirmed-malicious"}).json()
    assert any(i["ioc_id"] == ioc["ioc_id"] for i in by_disp["iocs"])
    # Invalid disposition 422; unknown ioc 404.
    assert client.patch(f"/iocs/{ioc['ioc_id']}/disposition", json={"disposition": "banana"}).status_code == 422
    assert client.patch("/iocs/nope/disposition", json={"disposition": "benign"}).status_code == 404


def test_ioc_search_regression(client):
    """/ioc/search (event-corpus search) is untouched by the new entity API."""
    # 203.0.113.155 is unique to this test — test_standout pins exact counts
    # on other 203.0.113.x values in the shared session DB.
    run_id = make_run(client, sample_name="p02-iocsearch.bin")
    client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.155")])
    data = client.get("/ioc/search", params={"value": "203.0.113.155"}).json()
    assert data["count"] == 1
    assert data["matches"][0]["run_id"] == run_id
    assert data["reputation"] is None
    assert "samples" in data


# ---------------------------------------------------------------------------
# Analysis job API
# ---------------------------------------------------------------------------


def test_static_analysis_job_with_stored_bytes(client):
    meta = _upload(client, _MZ, "p02-static.exe").json()
    resp = client.post("/analysis", json={"backend": "static", "sample_id": meta["sample_id"]})
    assert resp.status_code == 201
    job = resp.json()
    assert job["backend"] == "static"
    assert job["status"] == "completed"
    assert job["progress"] == 100
    assert job["sample_name"] == "p02-static.exe"
    assert job["finished_at"] and job["started_at"]
    # The static payload is persisted as the job's result.
    obs = client.get(f"/analysis/{job['run_id']}/observations").json()
    kinds = {o["kind"] for o in obs["observations"]}
    assert kinds >= {"strings", "iocs", "pe", "elf"}
    assert job["result"]["iocs"]["ips"] == ["203.0.113.99"]


def test_static_job_without_bytes_is_honest(client):
    job = client.post("/analysis", json={"backend": "static", "sample_name": "p02-nobytes.exe", "platform": "windows"}).json()
    assert job["status"] == "completed"
    obs = client.get(f"/analysis/{job['run_id']}/observations").json()
    assert any(o["kind"] == "note" for o in obs["observations"])


def test_job_state_is_persisted(client, conn):
    """The P0.2 point of the analysis_jobs table: state survives in the DB,
    not in memory (the pre-P0 sandbox tasks were in-memory only)."""
    job = _queued_job(client, conn, "watched-host", "p02-persist.bin")
    row = conn.execute("SELECT * FROM analysis_jobs WHERE run_id = ?", (job["run_id"],)).fetchone()
    assert row is not None
    assert row["backend"] == "watched-host" and row["status"] == "queued"
    # The run was created too (the job id doubles as the run id).
    assert conn.execute("SELECT 1 FROM runs WHERE run_id = ?", (job["run_id"],)).fetchone()


def test_list_and_filter_jobs(client, conn):
    s = client.post("/analysis", json={"backend": "static", "sample_name": "p02-list-a.bin"}).json()
    w = _queued_job(client, conn, "watched-host", "p02-list-b.bin")
    e = _queued_job(client, conn, "external-provider", "p02-list-c.bin")
    # The shared session DB holds jobs from earlier tests — assert the set
    # CONTAINS ours and every row matches the filter, not exact equality.
    by_backend = client.get("/analysis", params={"backend": "watched-host"}).json()
    assert w["run_id"] in {j["run_id"] for j in by_backend["jobs"]}
    assert all(j["backend"] == "watched-host" for j in by_backend["jobs"])
    by_status = client.get("/analysis", params={"status": "queued"}).json()
    queued_ids = {j["run_id"] for j in by_status["jobs"]}
    assert {w["run_id"], e["run_id"]} <= queued_ids
    assert all(j["status"] == "queued" for j in by_status["jobs"])
    by_artifact = client.get("/analysis", params={"artifact_id": "nope"}).json()
    assert by_artifact["total"] == 0
    # artifact_id maps to the vault sample model. Use DISTINCT bytes so the
    # sha256 differs from the earlier static-job test's _MZ upload (samples
    # dedupe by hash — same bytes would alias to that test's sample_id).
    meta = _upload(client, _MZ + b"--unique-artifact-marker-42", "p02-list-art.exe").json()
    art_job = client.post("/analysis", json={"backend": "static", "sample_id": meta["sample_id"]}).json()
    by_artifact = client.get("/analysis", params={"artifact_id": meta["sample_id"]}).json()
    assert art_job["run_id"] in {j["run_id"] for j in by_artifact["jobs"]}
    assert all(j["run_id"] == art_job["run_id"] for j in by_artifact["jobs"])
    assert client.get("/analysis", params={"backend": "bogus"}).status_code == 422
    assert client.get("/analysis", params={"status": "bogus"}).status_code == 422
    assert client.get(f"/analysis/{s['run_id']}").json()["run_id"] == s["run_id"]
    assert client.get("/analysis/no-such-run").status_code == 404


def test_cancel_transitions(client, conn):
    q = _queued_job(client, conn, "watched-host", "p02-cancel.bin")
    got = client.post(f"/analysis/{q['run_id']}/cancel").json()
    assert got["status"] == "canceled"
    assert got["finished_at"]
    # Terminal states are not cancellable.
    assert client.post(f"/analysis/{q['run_id']}/cancel").status_code == 422
    s = client.post("/analysis", json={"backend": "static", "sample_name": "p02-cancel2.bin"}).json()
    assert s["status"] == "completed"
    assert client.post(f"/analysis/{s['run_id']}/cancel").status_code == 422
    assert client.post("/analysis/no-such/cancel").status_code == 404


def test_unexecuted_backends_return_501(client):
    """Capability honesty at the contract layer: backends with no executor
    are refused by the API — never a queued row that would sit forever.
    (external-provider has an executor now — the sandbox providers — so it
    is exercised in test_analysis_provider_jobs, not here.)"""
    before = client.get("/analysis").json()["total"]
    for backend, fragment in (
        ("watched-host", "no executor"),
        ("isolated-outpost", "no isolated execution"),
    ):
        resp = client.post("/analysis", json={"backend": backend, "sample_name": "x.bin"})
        assert resp.status_code == 501, backend
        assert fragment in resp.json()["detail"], backend
    # No run/job was created.
    assert client.get("/analysis").json()["total"] == before


def test_no_observations_table_created(client, conn):
    client.post("/analysis", json={"backend": "static", "sample_name": "p02-noobs.bin"})
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "observations" not in tables


def test_analysis_findings_uses_run_relationship(client, conn):
    job = client.post("/analysis", json={"backend": "static", "sample_name": "p02-aj-find.bin"}).json()
    # The job's run IS the analysis run — ingest into IT, not a separate run.
    client.post("/ingest/batch", json=[_conn(job["run_id"])])
    findings = client.get(f"/analysis/{job['run_id']}/findings").json()
    assert any(a["rule_id"] == "unusual-port" for a in findings)
    assert client.get(f"/analysis/{job['run_id']}/findings")  # run relationship
    # Events of the run are the observations-shaped payload for dynamic jobs
    # (store-created rows and provider-backed API jobs both land here).
    dyn = _queued_job(client, conn, "external-provider", "p02-aj-find-dyn.bin")
    client.post("/ingest/batch", json=[_conn(dyn["run_id"])])
    obs = client.get(f"/analysis/{dyn['run_id']}/observations").json()
    assert obs["backend"] == "external-provider"
    assert any(o["event_type"] == "network_connection" for o in obs["observations"])
    # Unknown run on findings → 404.
    assert client.get("/analysis/no-such/findings").status_code == 404


# ---------------------------------------------------------------------------
# Auth — analyst reads, admin writes, agent 403
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


def test_p02_roles_analyst_reads_admin_writes_agent_denied(auth_env, monkeypatch):
    monkeypatch.setenv("OUTPOST_AGENT_TOKEN", "agent-secret")
    from ..core import auth as auth_mod

    importlib.reload(auth_mod)
    try:
        c = _client()
        admin = c.post("/auth/login", json={"password": "admin-secret"}).json()["token"]
        analyst = c.post("/auth/login", json={"password": "analyst-secret"}).json()["token"]
        ah, yh, gh = {"Authorization": f"Bearer {admin}"}, {"Authorization": f"Bearer {analyst}"}, {"Authorization": "Bearer agent-secret"}
        # Auth is on — the run must be created with a valid token.
        run_id = c.post(
            "/runs", json={"sample_name": "p02-auth.bin", "platform": "windows", "session_type": "analysis", "source": "cli"}, headers=ah
        ).json()["run_id"]

        # Analyst: reads on all three P0.2 resources.
        assert c.get("/findings", headers=yh).status_code == 200
        assert c.get("/iocs", headers=yh).status_code == 200
        assert c.get("/analysis", headers=yh).status_code == 200
        # Analyst: writes 403 (read-only role).
        assert c.post("/findings", json={"run_id": run_id, "severity": "suspicious", "details": "x"}, headers=yh).status_code == 403
        assert c.post("/iocs", json={"value": "1.2.3.4", "type": "ip"}, headers=yh).status_code == 403
        assert c.post("/analysis", json={"backend": "static", "sample_name": "x.bin"}, headers=yh).status_code == 403
        # Admin: reads + writes.
        assert c.post("/findings", json={"run_id": run_id, "severity": "suspicious", "details": "x"}, headers=ah).status_code == 201
        assert c.post("/iocs", json={"value": "1.2.3.4", "type": "ip"}, headers=ah).status_code == 201
        assert c.post("/analysis", json={"backend": "static", "sample_name": "x.bin"}, headers=ah).status_code == 201
        # Agent: 403 on every analyst-facing resource (the existing gate — no
        # _agent_allowed change was needed).
        assert c.get("/findings", headers=gh).status_code == 403
        assert c.get("/iocs", headers=gh).status_code == 403
        assert c.get("/analysis", headers=gh).status_code == 403
        assert c.post("/iocs", json={"value": "1.2.3.4", "type": "ip"}, headers=gh).status_code == 403
        assert c.patch("/iocs/x/disposition", json={"disposition": "benign"}, headers=gh).status_code == 403
        # Unauthenticated → 401.
        assert c.get("/findings").status_code == 401
    finally:
        monkeypatch.delenv("OUTPOST_AGENT_TOKEN", raising=False)
        importlib.reload(auth_mod)
