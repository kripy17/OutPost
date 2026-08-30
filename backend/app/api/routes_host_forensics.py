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
from ..services import host_forensics

router = APIRouter(tags=["host-forensics"])


class ProcessKillIn(BaseModel):
    signal: str = "SIGTERM"


class ProcessActionIn(BaseModel):
    action: str = "terminate"
    expected_create_time: float | None = None


@router.get("/system/forensics/snapshot", response_model=None)
@router.get("/system/xray/snapshot", response_model=None)
def get_xray_snapshot() -> dict:
    """Full live host snapshot: metrics, all processes, and open sockets."""
    metrics = host_forensics.get_current_system_metrics()
    processes = host_forensics.get_live_processes()
    sockets = host_forensics.get_live_sockets()

    return {
        "metrics": metrics,
        "processes": processes,
        "sockets": sockets,
        "process_count": len(processes),
        "socket_count": len(sockets),
    }


@router.get("/system/forensics/process/{pid}", response_model=None)
@router.get("/system/xray/process/{pid}", response_model=None)
def get_xray_process_detail(pid: int) -> dict:
    """Deep inspection of a single process PID."""
    detail = host_forensics.get_process_xray_detail(pid)
    if not detail:
        raise HTTPException(
            status_code=404,
            detail=f"Process PID {pid} not found on live host or in telemetry history.",
        )
    return detail


@router.get("/system/forensics/process/{pid}/capsule", response_model=None)
@router.get("/system/xray/process/{pid}/capsule", response_model=None)
def export_xray_capsule(pid: int) -> dict:
    """Export complete forensic snapshot for a process PID."""
    capsule = host_forensics.generate_forensic_capsule(pid)
    if not capsule:
        raise HTTPException(
            status_code=404,
            detail=f"Process PID {pid} forensic snapshot could not be generated.",
        )
    return capsule


@router.post("/system/forensics/process/{pid}/action", response_model=None)
@router.post("/system/xray/process/{pid}/action", response_model=None)
def perform_xray_process_action(pid: int, body: ProcessActionIn, request: Request) -> dict:
    """Execute lifecycle controls on a process (freeze, resume, terminate, kill) with audit log."""
    user = auth.role_from_request(request) or "analyst"
    return host_forensics.control_process(
        pid,
        action=body.action.lower(),
        expected_create_time=body.expected_create_time,
        request_user=user,
    )


@router.post("/system/forensics/process/{pid}/kill", response_model=None)
@router.post("/system/xray/process/{pid}/kill", response_model=None)
def kill_xray_process(pid: int, body: ProcessKillIn, request: Request) -> dict:
    """Terminate or kill a process PID with audit log."""
    user = auth.role_from_request(request) or "analyst"
    sig = body.signal.upper()
    action = "terminate" if sig == "SIGTERM" else "kill"
    return host_forensics.control_process(pid, action=action, request_user=user)


@router.get("/system/forensics/search", response_model=None)
@router.get("/system/xray/search", response_model=None)
def search_xray_targets(q: str = Query(..., min_length=1)) -> dict:
    """Universal target resolver: :port, file:, service:, pid:, etc."""
    return host_forensics.resolve_target_search(q)


@router.get("/system/forensics/tree", response_model=None)
@router.get("/system/xray/tree", response_model=None)
def get_xray_process_tree() -> list[dict]:
    """Hierarchical process causality tree for dynamic execution analysis."""
    return host_forensics.get_process_tree()


@router.get("/system/forensics/network", response_model=None)
@router.get("/system/xray/network", response_model=None)
def get_xray_network_matrix() -> dict:
    """Deep network socket & connection matrix categorized by threat domain."""
    return host_forensics.get_categorized_network_matrix()


@router.get("/system/forensics/explanations", response_model=None)
@router.get("/system/xray/explanations", response_model=None)
def get_xray_behavioral_explanations() -> list[dict]:
    """Automated behavioral heuristic explanations & findings cards."""
    return host_forensics.generate_behavioral_explanations()


@router.post("/system/forensics/snapshot/baseline", response_model=None)
@router.post("/system/xray/snapshot/baseline", response_model=None)
def capture_xray_baseline_snapshot() -> dict:
    """Capture a new host system baseline for differential dynamic execution comparison."""
    return host_forensics.capture_baseline_snapshot()


@router.get("/system/forensics/snapshot/diff", response_model=None)
@router.get("/system/xray/snapshot/diff", response_model=None)
def get_xray_snapshot_differential() -> dict:
    """Compute differential delta (+/-) between captured baseline and current host state."""
    return host_forensics.compute_snapshot_diff()


class CapsuleCompareIn(BaseModel):
    capsule_a: dict
    capsule_b: dict


@router.post("/system/forensics/capsule/compare", response_model=None)
@router.post("/system/xray/capsule/compare", response_model=None)
def compare_xray_forensic_capsules(body: CapsuleCompareIn) -> dict:
    """Compare two forensic capsules side-by-side."""
    return host_forensics.compare_two_capsules(body.capsule_a, body.capsule_b)


@router.get("/system/forensics/catalog", response_model=None)
@router.get("/system/xray/catalog", response_model=None)
def get_xray_target_catalog() -> dict:
    """Target catalog for rapid inspection of Apps, Procs, Ports, and Devices."""
    return host_forensics.get_target_catalog()


@router.get("/system/forensics/process/{pid}/full", response_model=None)
@router.get("/system/xray/process/{pid}/full", response_model=None)
def get_xray_full_target_dossier(pid: int) -> dict:
    """Unified full target dossier for Deep Host Forensics."""
    dossier = host_forensics.get_full_target_dossier(pid)
    if not dossier:
        raise HTTPException(
            status_code=404,
            detail=f"Target process PID {pid} not found on live host or in telemetry history.",
        )
    return dossier


