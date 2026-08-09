"""Sandbox detonation endpoints (roadmap 3.3).

- GET  /sandbox/providers        — which providers are configured (live) vs
                                   the labeled demo fallback, for the UI badges
- POST /sandbox/detonate         — push a vault sample to a sandbox: creates a
                                   run, starts the task, returns task + run ids
- GET  /sandbox/tasks/{task_id}  — live status of one task (completed run id,
                                   event/alert counts, risk, or the error)

The demo path (no provider key configured, or provider=demo) resolves inline
and is already `completed` in the response; configured live providers run in a
background task the frontend polls.
"""

import asyncio

from fastapi import APIRouter, HTTPException

from ..core import config
from ..core.db import db_session
from ..core.schema import Platform, SandboxDetonateIn, SandboxTaskOut
from ..models import run as run_store
from ..models import samples as samples_store
from ..services import sandbox as sandbox_service

router = APIRouter(tags=["sandbox"])


def _load_bytes(sample_id: str) -> bytes | None:
    """Read a stored sample's bytes (mirrors routes_samples._load_bytes)."""
    try:
        return (config.SAMPLES_DIR / f"{sample_id}.bin").read_bytes()
    except OSError:
        return None


@router.get("/sandbox/providers", response_model=None)
def list_providers() -> dict:
    """Provider registry with configured flags + the active mode (live/demo).

    The webapp badges each provider chip: a configured provider detonates
    against the real API; the demo provider is the always-available labeled
    fallback.
    """
    active = sandbox_service.active_provider()
    return {
        "providers": sandbox_service.providers_status(),
        "active": active,
        "mode": "live" if active else "demo",
    }


@router.post("/sandbox/detonate", status_code=202, response_model=SandboxTaskOut)
async def detonate_sample(body: SandboxDetonateIn) -> SandboxTaskOut:
    """Detonate a vault sample in a sandbox.

    `provider` auto-resolves (configured provider, else demo); `platform`
    defaults to the sample's sniffed OS but can be overridden to pick the
    detonation VM OS.
    """
    with db_session() as conn:
        sample = samples_store.get_sample(conn, body.sample_id)
        if not sample:
            raise HTTPException(status_code=404, detail=f"Unknown sample_id: {body.sample_id}")

    sample_bytes = _load_bytes(body.sample_id)
    if sample_bytes is None:
        raise HTTPException(
            status_code=404,
            detail="Sample bytes are not stored — re-upload the file to enable sandbox detonation.",
        )

    try:
        provider = sandbox_service.resolve_provider(body.provider)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if provider != "demo" and not sandbox_service.is_configured(provider):
        raise HTTPException(
            status_code=422,
            detail=f"{provider} is not configured — set the {provider.upper()}_API_KEY env var (or use provider=demo)",
        )

    platform: Platform = body.platform or sample["detected_platform"] or "windows"
    run_id = sandbox_service.create_run_id()
    with db_session() as conn:
        run_store.create_run(
            conn,
            run_id=run_id,
            sample_name=sample["original_name"],
            platform=platform,
            session_type="analysis",
            source=f"sandbox:{provider}",
        )

    task = sandbox_service.create_task(run_id, body.sample_id, sample["original_name"], provider, platform)

    # Demo (and auto→demo) resolves inline so the response is already complete;
    # configured live providers detonate in the background (takes minutes).
    if provider == "demo":
        await sandbox_service.run_task(task, sample_bytes)
    else:
        asyncio.create_task(sandbox_service.run_task(task, sample_bytes))

    return SandboxTaskOut(**sandbox_service.task_out(task))


@router.get("/sandbox/tasks/{task_id}", response_model=SandboxTaskOut)
def get_task(task_id: str) -> SandboxTaskOut:
    """Live status of a detonation task — the frontend polls this while a live
    provider analysis runs (demo tasks are already complete on return)."""
    task = sandbox_service.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Unknown sandbox task: {task_id}")
    return SandboxTaskOut(**sandbox_service.task_out(task))
