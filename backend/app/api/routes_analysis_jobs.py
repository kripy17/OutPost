"""Analysis job API (P0.2) — persisted jobs over the `analysis_jobs` table.

- POST /analysis              — start a job: static (synchronous). watched-
                                host / external-provider / isolated-outpost
                                all 501: capability honesty at the contract
                                layer — no executor exists for them yet, so
                                the API refuses rather than persisting a
                                queued row that would sit forever.
- GET  /analysis              — list/filter jobs (backend / status / artifact)
- GET  /analysis/{run_id}     — one job + derived run stats (events/alerts/risk)
- POST /analysis/{run_id}/cancel — cancel a queued/running job
- GET  /analysis/{run_id}/observations — observations-shaped payload (NO
                                observations table — P0 defers it; static
                                returns the analysis payload, dynamic returns
                                the run's events)
- GET  /analysis/{run_id}/findings — the run's alerts (existing relationship)

Job state is PERSISTED (survives backend restarts) — the pre-P0 sandbox
tasks stayed in memory; these rows are the durable record.
"""

import asyncio
import uuid

from fastapi import APIRouter, HTTPException, Query, Request

from ..core import auth, config
from ..core.db import db_session
from ..core.schema import AnalysisJobCreateIn, AnalysisJobDTO
from ..models import analysis_jobs as jobs_store
from ..models import audit
from ..models import event as event_store
from ..models import run as run_store
from ..models import samples as samples_store
from ..services import events_stream, static_analysis, sandbox as sandbox_service

router = APIRouter(tags=["analysis"])

_BACKENDS = ("static", "watched-host", "external-provider", "isolated-outpost")
_UNEXECUTED = {
    "watched-host": "watched-host has no executor yet — OutPost cannot claim jobs on a designated analysis host (planned phase)",
    "isolated-outpost": "isolated-outpost is a reserved backend — OutPost has no isolated execution environment yet",
}
_JOB_STATUSES = ("queued", "running", "completed", "failed", "canceled")
_NONTERMINAL = ("queued", "running")


def _load_bytes(sample_id: str) -> bytes | None:
    if not sample_id or "/" in sample_id or "\\" in sample_id or ".." in sample_id:
        return None
    try:
        path = (config.SAMPLES_DIR / f"{sample_id}.bin").resolve()
        if not str(path).startswith(str(config.SAMPLES_DIR.resolve())):
            return None
        return path.read_bytes()
    except OSError:
        return None


async def _finish_external_job(run_id: str, task_id: str, provider: str, sample_bytes: bytes) -> None:
    """Finalizer for background sandbox executions — syncs terminal status to analysis_jobs."""
    task = sandbox_service.get_task(task_id)
    with db_session() as conn:
        job = jobs_store.get_job(conn, run_id)
        if not job:
            return
        if job["status"] == jobs_store.CANCELED:
            return
        if not task:
            jobs_store.set_status(conn, run_id, jobs_store.FAILED, error="Task record was lost in memory", result={"error": "Task record was lost in memory"})
            conn.commit()
            return

    try:
        await sandbox_service.run_task(task, sample_bytes)
    except Exception as err:
        with db_session() as conn:
            job = jobs_store.get_job(conn, run_id)
            if job and job["status"] != jobs_store.CANCELED:
                jobs_store.set_status(conn, run_id, jobs_store.FAILED, error=str(err), result={"error": str(err)})
                conn.commit()
        return

    with db_session() as conn:
        job = jobs_store.get_job(conn, run_id)
        if not job or job["status"] == jobs_store.CANCELED:
            return
        if task.get("status") == "error":
            err_msg = task.get("error") or "detonation failed"
            jobs_store.set_status(conn, run_id, jobs_store.FAILED, error=err_msg, result={"error": err_msg})
        else:
            jobs_store.set_status(
                conn,
                run_id,
                jobs_store.COMPLETED,
                progress=100,
                result={
                    "provider": provider,
                    "task_id": task_id,
                    "events": task.get("events", 0),
                    "alerts": task.get("alerts", 0),
                    "risk_score": task.get("risk_score", 0),
                },
            )
        conn.commit()


def _resolve_artifact(conn, body: AnalysisJobCreateIn) -> tuple[str, str]:
    """Resolve the artifact identity to (sample_name, platform). Prefers a
    vault sample_id; falls back to the caller-supplied sample_name. P0 defers
    the artifacts table, so `sample_id` is the samples-model mapping."""
    if body.sample_id:
        sample = samples_store.get_sample(conn, body.sample_id)
        if not sample:
            raise HTTPException(status_code=404, detail=f"Unknown sample_id: {body.sample_id}")
        return sample["original_name"], body.platform or sample["detected_platform"] or "windows"
    if body.sample_name and body.sample_name.strip():
        return body.sample_name.strip(), body.platform or "windows"
    raise HTTPException(status_code=422, detail="Provide sample_id or sample_name")


def _dto(conn, job: dict) -> dict:
    """Assemble the AnalysisJobDTO: the persisted row + run-derived stats via
    the existing run assembly (events/alerts/risk share the run machinery)."""
    out = dict(job)
    run = run_store.get_run(conn, job["run_id"])
    if run:
        summary = run_store.to_summary(conn, run)
        out["sample_name"] = summary.sample_name
        out["events"] = conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE run_id = ?", (job["run_id"],)
        ).fetchone()["n"]
        out["alerts"] = summary.alert_count
        out["risk_score"] = summary.risk_score
    return out


@router.post("/analysis", status_code=201, response_model=AnalysisJobDTO)
async def create_analysis_job(body: AnalysisJobCreateIn, request: Request) -> AnalysisJobDTO:
    """Start an analysis job. Backends without an executor are 501 — never
    silently substituted with a demo path or an eternally-queued row."""
    if body.backend in _UNEXECUTED:
        raise HTTPException(status_code=501, detail=_UNEXECUTED[body.backend])
    if body.backend not in _BACKENDS:
        raise HTTPException(status_code=422, detail=f"backend must be one of: {', '.join(_BACKENDS)}")

    if body.backend == "external-provider":
        if not body.sample_id:
            raise HTTPException(status_code=422, detail="sample_id is required for external-provider analysis")
        with db_session() as conn:
            sample = samples_store.get_sample(conn, body.sample_id)
            if not sample:
                raise HTTPException(status_code=404, detail=f"Unknown sample_id: {body.sample_id}")
            sample_bytes = _load_bytes(body.sample_id)
            if sample_bytes is None:
                raise HTTPException(status_code=404, detail=f"Sample bytes not stored on disk: {body.sample_id}")

            want_provider = (body.provider or "").strip()
            if want_provider:
                if want_provider not in ("demo", "triage", "anyrun", "joe", "hybrid-analysis", "cuckoo", "filescan"):
                    raise HTTPException(status_code=422, detail=f"Unknown sandbox provider: {want_provider}")
                if want_provider != "demo" and not sandbox_service.is_configured(want_provider):
                    key_name = f"{want_provider.upper().replace('-', '_')}_API_KEY"
                    raise HTTPException(status_code=422, detail=f"Provider '{want_provider}' requires {key_name} to be configured")
                chosen_provider = want_provider
            else:
                chosen_provider = sandbox_service.active_provider() or "demo"

            sample_name = sample["original_name"]
            platform = body.platform or sample["detected_platform"] or "windows"
            run_id = uuid.uuid4().hex[:12]
            run_store.create_run(
                conn,
                run_id=run_id,
                sample_name=sample_name,
                platform=platform,
                session_type="analysis",
                source=f"sandbox:{chosen_provider}",
            )
            conn.commit()

            now = jobs_store._now()
            if chosen_provider == "demo":
                task = sandbox_service.create_task(run_id, body.sample_id, sample_name, chosen_provider, platform)
                await sandbox_service.run_task(task, sample_bytes)
                job = jobs_store.create_job(
                    conn,
                    run_id,
                    "external-provider",
                    status=jobs_store.COMPLETED,
                    started_at=now,
                    finished_at=now,
                    progress=100,
                    result={
                        "provider": chosen_provider,
                        "task_id": task["task_id"],
                        "events": task.get("events", 0),
                        "alerts": task.get("alerts", 0),
                        "risk_score": task.get("risk_score", 0),
                    },
                )
                audit.log(
                    conn,
                    auth.role_from_request(request),
                    "analysis.create",
                    target_type="analysis",
                    target_id=run_id,
                    detail=f"backend {body.backend} · {sample_name} ({platform}) via {chosen_provider}",
                )
                conn.commit()
                events_stream.publish_run_update(
                    run_id,
                    0,
                    completed=True,
                    job_id=run_id,
                    job_status=job["status"],
                    progress=100,
                )
                return AnalysisJobDTO(**_dto(conn, job))
            else:
                task = sandbox_service.create_task(run_id, body.sample_id, sample_name, chosen_provider, platform)
                job = jobs_store.create_job(
                    conn,
                    run_id,
                    "external-provider",
                    status=jobs_store.QUEUED,
                    started_at=now,
                    progress=0,
                )
                audit.log(
                    conn,
                    auth.role_from_request(request),
                    "analysis.create",
                    target_type="analysis",
                    target_id=run_id,
                    detail=f"backend {body.backend} · {sample_name} ({platform}) via {chosen_provider}",
                )
                asyncio.create_task(_finish_external_job(run_id, task["task_id"], chosen_provider, sample_bytes))
                events_stream.publish_run_update(
                    run_id,
                    0,
                    completed=False,
                    job_id=run_id,
                    job_status=job["status"],
                    progress=0,
                )
                return AnalysisJobDTO(**_dto(conn, job))

    with db_session() as conn:
        sample_name, platform = _resolve_artifact(conn, body)
        run_id = uuid.uuid4().hex[:12]
        run_store.create_run(
            conn, run_id=run_id, sample_name=sample_name, platform=platform,
            session_type="analysis", source="analysis",
        )

        now = jobs_store._now()
        # Static is the only executable backend — it runs synchronously:
        # analyze the stored bytes and persist the payload as the job's
        # result (observations endpoint returns it). No events are ingested
        # — static observations ARE the output.
        sample_bytes = _load_bytes(body.sample_id) if body.sample_id else None
        result = None
        if sample_bytes is not None:
            result = static_analysis.analyze_sample(sample_bytes)
        job = jobs_store.create_job(
            conn, run_id, "static",
            status=jobs_store.COMPLETED,
            started_at=now, finished_at=now,
            progress=100,
            result=result or {"note": "no stored bytes — re-upload to run static analysis"},
        )
        audit.log(
            conn, auth.role_from_request(request), "analysis.create",
            target_type="analysis", target_id=run_id,
            detail=f"backend {body.backend} · {sample_name} ({platform})",
        )
        # P0.7 — extend the existing run_update frame (no new event type):
        # job create publishes the persisted state so live subscribers see
        # the job appear (queued) or finish (static completes synchronously).
        events_stream.publish_run_update(
            run_id, 0,
            completed=job["status"] in (jobs_store.COMPLETED, jobs_store.FAILED, jobs_store.CANCELED),
            job_id=run_id,
            job_status=job["status"],
            progress=job.get("progress") or 0,
        )
        return AnalysisJobDTO(**_dto(conn, job))


@router.get("/analysis", response_model=None)
def list_analysis_jobs(
    backend: str | None = Query(None, description="static | watched-host | external-provider | isolated-outpost"),
    status: str | None = Query(None, description="queued | running | completed | failed | canceled"),
    artifact_id: str | None = Query(None, description="Vault sample_id — the P0 mapping of the deferred artifacts table"),
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List persisted analysis jobs. `artifact_id` is the samples-model
    mapping (P0 defers the artifacts table): it filters to jobs whose run's
    sample matches that vault sample."""
    if backend is not None and backend not in _BACKENDS:
        raise HTTPException(status_code=422, detail=f"backend must be one of: {', '.join(_BACKENDS)}")
    if status is not None and status not in _JOB_STATUSES:
        raise HTTPException(status_code=422, detail="status must be queued, running, completed, failed, or canceled")
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    run_ids = None
    if artifact_id:
        with db_session() as conn:
            rows = conn.execute(
                "SELECT DISTINCT r.run_id FROM runs r JOIN samples s ON s.original_name = r.sample_name WHERE s.sample_id = ?",
                (artifact_id,),
            ).fetchall()
            run_ids = [r["run_id"] for r in rows]
            if not run_ids:
                return {"total": 0, "limit": limit, "offset": offset, "jobs": []}
    with db_session() as conn:
        total, rows = jobs_store.list_jobs(conn, backend=backend, status=status, run_ids=run_ids, limit=limit, offset=offset)
        jobs = [AnalysisJobDTO(**_dto(conn, j)).model_dump() for j in rows]
    return {"total": total, "limit": limit, "offset": offset, "jobs": jobs}


@router.get("/analysis/{run_id}", response_model=AnalysisJobDTO)
def get_analysis_job(run_id: str) -> AnalysisJobDTO:
    """One persisted job + the derived run stats (events/alerts/risk_score)."""
    with db_session() as conn:
        job = jobs_store.get_job(conn, run_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Unknown analysis job: {run_id}")
        return AnalysisJobDTO(**_dto(conn, job))


@router.post("/analysis/{run_id}/cancel", response_model=AnalysisJobDTO)
def cancel_analysis_job(run_id: str, request: Request) -> AnalysisJobDTO:
    """Cancel a queued/running job. Terminal states (completed/failed/
    canceled) are NOT cancellable — the persisted state wins."""
    with db_session() as conn:
        job = jobs_store.get_job(conn, run_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Unknown analysis job: {run_id}")
        if job["status"] not in _NONTERMINAL:
            raise HTTPException(
                status_code=422,
                detail=f"Cannot cancel a {job['status']} job — only queued or running jobs can be canceled",
            )
        updated = jobs_store.set_status(conn, run_id, jobs_store.CANCELED)
        audit.log(
            conn, auth.role_from_request(request), "analysis.cancel",
            target_type="analysis", target_id=run_id,
            detail=f"{job['status']} → canceled",
        )
        # P0.7 — the cancel transition emits the terminal frame exactly once
        # (from the mutation path; reconnect never re-emits — the DB row is
        # the source of truth).
        events_stream.publish_run_update(
            run_id, 0,
            completed=True,
            job_id=run_id,
            job_status=jobs_store.CANCELED,
            progress=updated.get("progress") or 0,
        )
        return AnalysisJobDTO(**_dto(conn, updated))


@router.get("/analysis/{run_id}/observations", response_model=None)
def get_analysis_observations(run_id: str) -> dict:
    """The observations-shaped payload. P0 DEFERS the observations table —
    nothing is persisted here: static jobs return the stored analysis
    payload; dynamic jobs return the run's events (the existing evidence)."""
    with db_session() as conn:
        job = jobs_store.get_job(conn, run_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Unknown analysis job: {run_id}")
        if job["backend"] == "static":
            result = job.get("result") or {}
            observations = [{"kind": k, "data": v} for k, v in result.items()]
        else:
            observations = event_store.list_events_for_run(conn, run_id)
    return {"backend": job["backend"], "observations": observations}


@router.get("/analysis/{run_id}/findings", response_model=None)
def get_analysis_findings(run_id: str) -> list[dict]:
    """Findings associated with the analysis run — the existing alerts/run
    relationship (same assembly as /runs/{id}/alerts). No cross-run
    aggregation in P0."""
    with db_session() as conn:
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        rows = event_store.list_alerts_for_run(conn, run_id)
    return rows
