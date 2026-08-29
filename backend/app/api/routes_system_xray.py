"""System X-Ray Endpoints — Live Host System, Process, Socket Inspection & Control.

Provides API routes for:
- GET  /system/xray/snapshot        — Live processes + listening sockets + host pulse
- GET  /system/xray/process/{pid}   — Deep process inspection (lineage, sockets, files, env)
- POST /system/xray/process/{pid}/kill — Safe process termination (SIGTERM/SIGKILL) with audit
- GET  /system/xray/search          — Search live system processes, ports, files, users
"""

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from ..core import auth
from ..services import host_xray

router = APIRouter(tags=["system-xray"])


class ProcessKillIn(BaseModel):
    signal: str = "SIGTERM"


class ProcessActionIn(BaseModel):
    action: str = "terminate"
    expected_create_time: float | None = None


@router.get("/system/xray/snapshot", response_model=None)
def get_xray_snapshot() -> dict:
    """Full live host snapshot: metrics, all processes, and open sockets."""
    metrics = host_xray.get_current_system_metrics()
    processes = host_xray.get_live_processes()
    sockets = host_xray.get_live_sockets()

    return {
        "metrics": metrics,
        "processes": processes,
        "sockets": sockets,
        "process_count": len(processes),
        "socket_count": len(sockets),
    }


@router.get("/system/xray/process/{pid}", response_model=None)
def get_xray_process_detail(pid: int) -> dict:
    """Deep inspection of a single process PID."""
    detail = host_xray.get_process_xray_detail(pid)
    if not detail:
        raise HTTPException(
            status_code=404,
            detail=f"Process PID {pid} not found on live host or in telemetry history.",
        )
    return detail


@router.get("/system/xray/process/{pid}/capsule", response_model=None)
def export_xray_capsule(pid: int) -> dict:
    """Export complete forensic snapshot (.xray.json) for a process PID."""
    capsule = host_xray.generate_forensic_capsule(pid)
    if not capsule:
        raise HTTPException(
            status_code=404,
            detail=f"Process PID {pid} forensic snapshot could not be generated.",
        )
    return capsule


@router.post("/system/xray/process/{pid}/action", response_model=None)
def perform_xray_process_action(pid: int, body: ProcessActionIn, request: Request) -> dict:
    """Execute lifecycle controls on a process (freeze, resume, terminate, kill) with audit log."""
    user = auth.role_from_request(request) or "analyst"
    return host_xray.control_process(
        pid,
        action=body.action.lower(),
        expected_create_time=body.expected_create_time,
        request_user=user,
    )


@router.post("/system/xray/process/{pid}/kill", response_model=None)
def kill_xray_process(pid: int, body: ProcessKillIn, request: Request) -> dict:
    """Terminate or kill a process PID with audit log."""
    user = auth.role_from_request(request) or "analyst"
    sig = body.signal.upper()
    action = "terminate" if sig == "SIGTERM" else "kill"
    return host_xray.control_process(pid, action=action, request_user=user)


@router.get("/system/xray/search", response_model=None)
def search_xray_targets(q: str = Query(..., min_length=1)) -> dict:
    """Universal target resolver (Omarchy X-Ray style): :port, file:, service:, pid:, etc."""
    return host_xray.resolve_target_search(q)


@router.get("/system/xray/tree", response_model=None)
def get_xray_process_tree() -> list[dict]:
    """Hierarchical process causality tree for dynamic execution analysis."""
    return host_xray.get_process_tree()


@router.get("/system/xray/network", response_model=None)
def get_xray_network_matrix() -> dict:
    """Deep network socket & connection matrix categorized by threat domain."""
    return host_xray.get_categorized_network_matrix()


@router.get("/system/xray/explanations", response_model=None)
def get_xray_behavioral_explanations() -> list[dict]:
    """Automated behavioral heuristic explanations & findings cards."""
    return host_xray.generate_behavioral_explanations()
