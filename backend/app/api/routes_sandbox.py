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
import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..core import config
from ..core.db import db_session
from ..core.schema import Platform, SandboxDetonateIn, SandboxTaskOut
from ..models import event as event_store
from ..models import run as run_store
from ..models import samples as samples_store
from ..services import detection
from ..services import sandbox as sandbox_service
from ..services import screenshots as ss
from fastapi.responses import Response

router = APIRouter(tags=["sandbox"])


@router.get("/sandbox/detonate/{run_id}/screenshots", response_model=None)
def list_session_screenshots(run_id: str) -> dict:
    return ss.list_shots(run_id)


@router.get("/sandbox/detonate/{run_id}/screenshots/{name}")
def get_session_screenshot(run_id: str, name: str):
    data = ss.read_shot(run_id, name)
    if not data:
        raise HTTPException(status_code=404, detail="Screenshot not found")
    return Response(content=data, media_type="image/png")


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


@router.get("/sandbox/drivers", response_model=None)
def get_sandbox_drivers() -> list[dict]:
    """Inspect and list available sandbox isolation drivers (Bubblewrap, Wine, TempDir, Container)."""
    from ..services import dynamic_sandbox
    return dynamic_sandbox.get_available_isolation_drivers()


@router.post("/sandbox/detonate/dynamic", response_model=None)
async def detonate_dynamic(body: SandboxDetonateIn) -> dict:
    """Execute and trace a sample dynamically in an isolated subprocess environment."""
    from ..services import dynamic_sandbox

    try:
        result = await dynamic_sandbox.execute_and_trace(
            sample_id=body.sample_id,
            timeout_seconds=10,
            isolation_driver=body.isolation_driver or "auto",
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dynamic detonation failed: {e}")


@router.get("/sandbox/playbooks", response_model=None)
def get_playbooks() -> list[dict]:
    """List curated attack scenario playbooks for testing and demonstration."""
    from ..services.dynamic_sandbox import SIMULATION_SCENARIOS

    scenarios = []
    seen = set()
    for s in SIMULATION_SCENARIOS.values():
        if s["id"] in seen:
            continue
        seen.add(s["id"])
        scenarios.append({
            "id": s["id"],
            "name": s["name"],
            "severity": s["severity"],
            "platform": s["platform"],
            "description": s["description"],
            "techniques": s["techniques"],
            "stages_count": len(s["stages"]),
        })
    return scenarios


class PlaybookDetonateIn(BaseModel):
    playbook_id: str
    mode: str = "live"


@router.post("/sandbox/detonate/playbook", status_code=201, response_model=None)
async def detonate_playbook(body: PlaybookDetonateIn) -> dict:
    """Detonate a curated attack scenario playbook live with real subprocess execution and telemetry streaming."""
    from ..services.dynamic_sandbox import SIMULATION_SCENARIOS, execute_simulation_scenario_live

    if body.playbook_id not in SIMULATION_SCENARIOS:
        # Fallback if unknown
        valid_keys = list(SIMULATION_SCENARIOS.keys())
        playbook_key = valid_keys[0]
    else:
        playbook_key = body.playbook_id

    result = await execute_simulation_scenario_live(playbook_key)
    return result


@router.post("/sandbox/simulate/live", status_code=201, response_model=None)
async def simulate_live_scenario(body: PlaybookDetonateIn) -> dict:
    """Execute live simulation with terminal output and event generation."""
    from ..services.dynamic_sandbox import execute_simulation_scenario_live

    return await execute_simulation_scenario_live(body.playbook_id)
