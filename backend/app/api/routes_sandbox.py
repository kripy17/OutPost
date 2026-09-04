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
from fastapi.responses import FileResponse, Response

from ..core import config
from ..core.db import db_session
from ..core.schema import Platform, SandboxDetonateIn, SandboxTaskOut
from ..models import event as event_store
from ..models import run as run_store
from ..models import samples as samples_store
from ..services import detection
from ..services import sandbox as sandbox_service
from ..services import screenshots as ss

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
    if not sample_id or "/" in sample_id or "\\" in sample_id or ".." in sample_id:
        return None
    try:
        path = (config.SAMPLES_DIR / f"{sample_id}.bin").resolve()
        if not str(path).startswith(str(config.SAMPLES_DIR.resolve())):
            return None
        return path.read_bytes()
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
            "stages": [{"name": st["name"], "cmd": st["cmd"]} for st in s.get("stages", [])],
        })
    return scenarios


class PlaybookDetonateIn(BaseModel):
    playbook_id: str
    mode: str = "live"


class PlaybookStageIn(BaseModel):
    scenario_id: str
    stage_number: int
    run_id: str | None = None
    sandbox_dir: str | None = None
    facts: dict[str, str] | None = None


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


@router.post("/sandbox/simulate/stage", status_code=200, response_model=None)
async def simulate_scenario_stage(body: PlaybookStageIn) -> dict:
    """Execute a single stage of an adversary campaign interactively."""
    from ..services.dynamic_sandbox import execute_simulation_scenario_stage

    try:
        return await execute_simulation_scenario_stage(
            scenario_id=body.scenario_id,
            stage_number=body.stage_number,
            run_id=body.run_id,
            sandbox_dir_str=body.sandbox_dir,
            facts=body.facts,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stage execution failed: {e}")


class TechniqueRunIn(BaseModel):
    test_id: str
    run_id: str | None = None
    platform: str | None = None


@router.get("/sandbox/techniques", response_model=None)
def get_techniques(tactic: str | None = None, platform: str | None = None, q: str | None = None) -> list[dict]:
    """List and filter modular adversary technique emulation tests."""
    from ..services.technique_catalog import list_technique_tests
    return list_technique_tests(tactic=tactic, platform=platform, q=q)


@router.get("/sandbox/techniques/{test_id}", response_model=None)
def get_technique_detail(test_id: str) -> dict:
    """Retrieve details and commands for a specific technique test."""
    from ..services.technique_catalog import get_technique_test
    res = get_technique_test(test_id)
    if not res:
        raise HTTPException(status_code=404, detail="Technique test not found")
    return res


@router.post("/sandbox/techniques/run", status_code=200, response_model=None)
async def run_technique(body: TechniqueRunIn) -> dict:
    """Execute a single adversary technique test with pre-checks, telemetry capture, and automated cleanup."""
    from ..services.dynamic_sandbox import execute_technique_test
    try:
        return await execute_technique_test(body.test_id, run_id=body.run_id, platform_override=body.platform)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Technique simulation failed: {e}")


@router.get("/sandbox/artifacts/{run_id}", response_model=None)
def list_sandbox_artifacts(run_id: str) -> list[dict]:
    """List all persisted artifacts for a sandbox run."""
    if "/" in run_id or "\\" in run_id or ".." in run_id:
        raise HTTPException(status_code=400, detail="Invalid run_id")
    artifact_dir = (config.DATA_DIR / "sandbox_artifacts" / run_id).resolve()
    base_dir = (config.DATA_DIR / "sandbox_artifacts").resolve()
    if not str(artifact_dir).startswith(str(base_dir)) or not artifact_dir.is_dir():
        return []
    res = []
    for p in sorted(artifact_dir.iterdir()):
        if p.is_file():
            res.append({
                "filename": p.name,
                "size_bytes": p.stat().st_size,
                "download_url": f"/sandbox/artifacts/{run_id}/{p.name}",
            })
    return res


@router.get("/sandbox/artifacts/{run_id}/{filename}")
def get_sandbox_artifact(run_id: str, filename: str):
    """Download or view a dropped artifact from a dynamic sandbox or simulation run."""
    if "/" in run_id or "\\" in run_id or ".." in run_id:
        raise HTTPException(status_code=400, detail="Invalid run_id")
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    artifact_path = (config.DATA_DIR / "sandbox_artifacts" / run_id / filename).resolve()
    base_dir = (config.DATA_DIR / "sandbox_artifacts").resolve()
    if not str(artifact_path).startswith(str(base_dir)) or not artifact_path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")

    return FileResponse(
        path=str(artifact_path),
        filename=filename.split("_", 1)[-1] if "_" in filename else filename,
        media_type="application/octet-stream",
    )
