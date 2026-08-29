"""Roadmap item — external-provider analysis backend wiring.

POST /analysis with backend='external-provider' executes through the sandbox
provider machinery instead of 501-ing: demo resolves inline, configured
providers detonate in a background task, and the persisted analysis_jobs row
carries every transition (queued → completed/failed) with a result payload.
watched-host and isolated-outpost stay honest 501s (test_p0_2 pins that).
"""

import pytest

from ..api import routes_analysis_jobs as routes
from ..core import config
from ..models import analysis_jobs as jobs_store
from ..services import sandbox as sandbox_service
from .conftest import make_run
from .test_samples import _upload

_MZ = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00http://evil.example/beacon 203.0.113.99 "


def _cleanup(conn, run_id: str | None, sample_id: str | None) -> None:
    """Session-scoped DB hygiene — remove this test's rows even on failure.

    Child-first ordering matters: ioc_findings → alerts and ioc_provenance →
    event/alert ids carry real FKs, so runs/alerts can only be deleted once
    every referencing row is gone (a partial cleanup here leaks rows into the
    shared session DB and breaks other tests' exact-set assertions).
    """
    if run_id:
        statements = (
            "DELETE FROM ioc_findings WHERE finding_id IN (SELECT id FROM alerts WHERE run_id = ?)",
            # provenance.ref_id is TEXT; events/alerts ids are INTEGER rowids.
            "DELETE FROM ioc_provenance WHERE (ref_type = 'event' AND ref_id IN "
            "(SELECT CAST(id AS TEXT) FROM events WHERE run_id = ?)) "
            "OR (ref_type = 'finding' AND ref_id IN "
            "(SELECT CAST(id AS TEXT) FROM alerts WHERE run_id = ?))",
            "DELETE FROM watchlist_hits WHERE run_id = ?",
            "DELETE FROM alerts WHERE run_id = ?",
            "DELETE FROM events WHERE run_id = ?",
            "DELETE FROM run_tuning_snapshot WHERE run_id = ?",
            "DELETE FROM run_process_maps WHERE run_id = ?",
            "DELETE FROM run_allowlist WHERE run_id = ?",
            "DELETE FROM run_notes WHERE run_id = ?",
            "DELETE FROM analysis_jobs WHERE run_id = ?",
            "DELETE FROM audit_log WHERE target_type = 'analysis' AND target_id = ?",
        )
        for sql in statements:
            try:
                conn.execute(sql, (run_id,) * sql.count("?"))
            except Exception:
                pass  # hygiene best-effort — never mask the test's own error
        # The run row LAST: every child must already be gone (FK enforced).
        try:
            conn.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
        except Exception:
            pass
    if sample_id:
        try:
            conn.execute("DELETE FROM samples WHERE sample_id = ?", (sample_id,))
        except Exception:
            pass
    conn.commit()


def _upload_unique(client, marker: str, name: str) -> dict:
    """A vault sample with distinct bytes (samples dedupe by sha256 across
    the shared session DB — same bytes would alias to another test's row)."""
    return _upload(client, _MZ + f"--{marker}--".encode(), name).json()


# ---------------------------------------------------------------------------
# Contract guards — what the endpoint refuses, honestly
# ---------------------------------------------------------------------------


def test_provider_backend_requires_sample_id(client, conn):
    try:
        resp = client.post("/analysis", json={"backend": "external-provider", "sample_name": "prov-nosid.bin"})
        assert resp.status_code == 422
        assert "sample_id" in resp.json()["detail"]
    finally:
        _cleanup(conn, None, None)


def test_provider_backend_unknown_sample_404(client, conn):
    try:
        resp = client.post("/analysis", json={"backend": "external-provider", "sample_id": "prov-no-such"})
        assert resp.status_code == 404
        assert "Unknown sample_id" in resp.json()["detail"]
    finally:
        _cleanup(conn, None, None)


def test_provider_backend_missing_bytes_is_honest(client, conn):
    meta = _upload_unique(client, "prov-bytes", "prov-nobytes.bin")
    (config.SAMPLES_DIR / f"{meta['sample_id']}.bin").unlink()
    try:
        resp = client.post(
            "/analysis", json={"backend": "external-provider", "sample_id": meta["sample_id"], "provider": "demo"}
        )
        assert resp.status_code == 404
        assert "not stored" in resp.json()["detail"]
        # No run/job was created for the refused request.
        assert jobs_store.get_job(conn, meta["sample_id"]) is None
    finally:
        _cleanup(conn, None, meta["sample_id"])


def test_provider_backend_unknown_provider_422(client, conn):
    meta = _upload_unique(client, "prov-badp", "prov-badp.bin")
    try:
        resp = client.post(
            "/analysis", json={"backend": "external-provider", "sample_id": meta["sample_id"], "provider": "nope"}
        )
        assert resp.status_code == 422
        assert "Unknown sandbox provider" in resp.json()["detail"]
    finally:
        _cleanup(conn, None, meta["sample_id"])


def test_provider_backend_unconfigured_named_provider_422(client, conn, monkeypatch):
    monkeypatch.setattr(sandbox_service, "is_configured", lambda p: False)
    meta = _upload_unique(client, "prov-nokey", "prov-nokey.bin")
    try:
        resp = client.post(
            "/analysis", json={"backend": "external-provider", "sample_id": meta["sample_id"], "provider": "anyrun"}
        )
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert "anyrun" in detail and "ANYRUN_API_KEY" in detail
    finally:
        _cleanup(conn, None, meta["sample_id"])


# ---------------------------------------------------------------------------
# The demo path — completes inline, persists everything
# ---------------------------------------------------------------------------


def test_demo_provider_completes_inline_with_persisted_result(client, conn):
    meta = _upload_unique(client, "prov-demo", "prov-demo.exe")
    run_id = None
    try:
        resp = client.post(
            "/analysis", json={"backend": "external-provider", "sample_id": meta["sample_id"], "provider": "demo"}
        )
        assert resp.status_code == 201
        job = resp.json()
        run_id = job["run_id"]
        assert job["status"] == "completed"
        assert job["progress"] == 100
        assert job["finished_at"] and job["started_at"]
        assert job["result"]["provider"] == "demo"
        assert job["result"]["task_id"]
        # Real detonation output: events landed through the pipeline.
        assert job["events"] > 0
        # Persisted (not just shaped for the response): raw store reread.
        row = jobs_store.get_job(conn, run_id)
        assert row["status"] == "completed" and row["progress"] == 100
        assert row["result"]["provider"] == "demo"
        # Observations use the dynamic branch — the run's events.
        obs = client.get(f"/analysis/{run_id}/observations").json()
        assert obs["backend"] == "external-provider"
        assert obs["observations"]
        # Audited with the provider named.
        data = client.get("/audit").json()
        assert any(
            e["action"] == "analysis.create" and e["target_id"] == run_id and "via demo" in (e["detail"] or "")
            for e in data["events"]
        )
    finally:
        _cleanup(conn, run_id, meta["sample_id"])


def test_auto_resolves_to_demo_without_configured_keys(client, conn, monkeypatch):
    monkeypatch.setattr(sandbox_service, "active_provider", lambda: "")
    meta = _upload_unique(client, "prov-auto", "prov-auto.exe")
    run_id = None
    try:
        resp = client.post("/analysis", json={"backend": "external-provider", "sample_id": meta["sample_id"]})
        assert resp.status_code == 201
        job = resp.json()
        run_id = job["run_id"]
        assert job["result"]["provider"] == "demo"
    finally:
        _cleanup(conn, run_id, meta["sample_id"])


# ---------------------------------------------------------------------------
# The background finalizer — terminal transitions land on the persisted row
# ---------------------------------------------------------------------------


async def _fake_run_success(task, sample_bytes):
    task.update(events=7, alerts=2, risk_score=42, highest_severity="malicious", status="completed")


async def _fake_run_failure(task, sample_bytes):
    task["status"] = "error"
    task["error"] = "provider outage: 503 from upstream"


@pytest.mark.asyncio
async def test_finalizer_success_persists_completed_state(client, conn, monkeypatch):
    monkeypatch.setattr(sandbox_service, "run_task", _fake_run_success)
    run_id = make_run(client, sample_name="prov-bg-ok.bin", source="sandbox:triage")
    jobs_store.create_job(conn, run_id, "external-provider", status=jobs_store.QUEUED)
    conn.commit()
    task = sandbox_service.create_task(run_id, None, "prov-bg-ok.bin", "triage", "windows")
    try:
        await routes._finish_external_job(run_id, task["task_id"], "triage", b"MZ")
        row = jobs_store.get_job(conn, run_id)
        assert row["status"] == "completed"
        assert row["progress"] == 100 and row["finished_at"]
        assert row["result"]["provider"] == "triage"
        assert row["result"]["risk_score"] == 42
        assert row["result"]["events"] == 7 and row["result"]["alerts"] == 2
    finally:
        _cleanup(conn, run_id, None)


@pytest.mark.asyncio
async def test_finalizer_failure_persists_failed_state_with_error(client, conn, monkeypatch):
    monkeypatch.setattr(sandbox_service, "run_task", _fake_run_failure)
    run_id = make_run(client, sample_name="prov-bg-fail.bin", source="sandbox:triage")
    jobs_store.create_job(conn, run_id, "external-provider", status=jobs_store.QUEUED)
    conn.commit()
    task = sandbox_service.create_task(run_id, None, "prov-bg-fail.bin", "triage", "windows")
    try:
        await routes._finish_external_job(run_id, task["task_id"], "triage", b"MZ")
        row = jobs_store.get_job(conn, run_id)
        assert row["status"] == "failed"
        assert row["finished_at"]
        assert "provider outage" in row["error"]
        assert row["result"]["error"].startswith("provider outage")
    finally:
        _cleanup(conn, run_id, None)


@pytest.mark.asyncio
async def test_finalizer_never_resurrects_a_canceled_job(client, conn, monkeypatch):
    monkeypatch.setattr(sandbox_service, "run_task", _fake_run_success)
    run_id = make_run(client, sample_name="prov-bg-cancel.bin", source="sandbox:demo")
    jobs_store.create_job(conn, run_id, "external-provider", status=jobs_store.QUEUED)
    jobs_store.set_status(conn, run_id, jobs_store.CANCELED)
    conn.commit()
    task = sandbox_service.create_task(run_id, None, "prov-bg-cancel.bin", "demo", "windows")
    try:
        await routes._finish_external_job(run_id, task["task_id"], "demo", b"MZ")
        assert jobs_store.get_job(conn, run_id)["status"] == "canceled"
    finally:
        _cleanup(conn, run_id, None)


@pytest.mark.asyncio
async def test_finalizer_fails_honestly_when_task_record_is_lost(client, conn):
    run_id = make_run(client, sample_name="prov-bg-lost.bin", source="sandbox:joe")
    jobs_store.create_job(conn, run_id, "external-provider", status=jobs_store.QUEUED)
    conn.commit()
    try:
        await routes._finish_external_job(run_id, "no-such-task", "joe", b"MZ")
        row = jobs_store.get_job(conn, run_id)
        assert row["status"] == "failed"
        assert "lost" in row["error"]
    finally:
        _cleanup(conn, run_id, None)
