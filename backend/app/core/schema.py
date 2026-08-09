"""Pydantic models — the single source of truth for API shapes.

Mirrors docs/02-BACKEND-SPEC.md exactly. Both collectors must produce JSON
matching `EventIn`; the frontend types in `frontend/src/types/index.ts` and the
CLI's `api_client.py` mirror these same shapes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

Platform = Literal["windows", "linux", "macos"]
EventType = Literal["process_create", "network_connection", "file_write", "registry_write"]
SessionType = Literal["live", "analysis"]
Severity = Literal["suspicious", "malicious"]
Reputation = Literal["clean", "suspicious", "malicious", "unknown"]
AlertStatus = Literal["open", "acknowledged", "resolved"]
AllowlistKind = Literal["ip", "file", "registry", "process", "hash"]


class EventIn(BaseModel):
    run_id: str
    platform: Platform
    event_type: EventType
    timestamp: datetime
    pid: Optional[int] = None
    ppid: Optional[int] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    file_path: Optional[str] = None
    registry_key: Optional[str] = None
    # Fleet identity — which agent/host the event came from. Omitted events
    # (webapp detonations, sandbox runs) default to 'local' at normalization.
    host_id: Optional[str] = None


class EventOut(EventIn):
    id: Optional[int] = None


class RunSummary(BaseModel):
    run_id: str
    sample_name: str
    platform: Platform
    session_type: SessionType = "analysis"
    # Provenance — where the run came from: monitor (webapp detonation), live
    # (host collector), sandbox:<provider> (external detonation), seed, cli.
    source: str = "monitor"
    # Fleet attribution — the distinct hosts whose events landed in this run
    # (webapp/sandbox runs are all 'local'). Lets the run card/detail show
    # which machines contributed, and the fleet link back to its runs.
    host_ids: list[str] = []
    started_at: datetime
    completed_at: Optional[datetime] = None
    process_count: int = 0
    unique_ips: int = 0
    alert_count: int = 0
    highest_severity: Optional[Severity] = None
    risk_score: int = 0


class Alert(BaseModel):
    id: Optional[int] = None
    run_id: str
    rule_id: str
    rule_name: str
    severity: Severity
    triggered_at: datetime
    related_pid: Optional[int] = None
    related_ip: Optional[str] = None
    # PIDs of the processes behind a composite rule (e.g. the enumerating
    # commands of enumeration-burst) — lets the live Monitor highlight the
    # actual actors in the process tree the moment the rule fires.
    related_pids: list[int] = []
    details: str
    # Triage (analyst workflow): open → acknowledged → resolved, with the
    # optional analyst comment recorded at the transition.
    status: AlertStatus = "open"
    status_comment: Optional[str] = None
    status_at: Optional[datetime] = None


class AlertStatusIn(BaseModel):
    status: AlertStatus
    comment: Optional[str] = None


class AllowlistIn(BaseModel):
    kind: AllowlistKind = "ip"
    value: str = Field(min_length=1, max_length=500)
    note: Optional[str] = None


class AllowlistEntry(BaseModel):
    id: int
    run_id: str
    kind: AllowlistKind
    value: str
    note: Optional[str] = None
    created_at: datetime
    # How many already-open matching alerts the POST auto-acknowledged (0 on
    # GET list — only the create response carries a meaningful value).
    acked: int = 0


class SuppressionIn(BaseModel):
    rule_id: str
    # None = global (every run); set = only that run. 422 on unknown rule_id.
    run_id: Optional[str] = None
    reason: Optional[str] = None


class Suppression(BaseModel):
    id: int
    rule_id: str
    run_id: Optional[str] = None
    reason: Optional[str] = None
    created_at: datetime


class ProcessNode(BaseModel):
    pid: int
    ppid: Optional[int] = None
    process_name: str
    command_line: Optional[str] = None
    # Network risk annotation (docs/07 signature visual): the worst reputation
    # of any destination this pid connected to, and the distinct IPs behind it.
    # Null / empty for processes with no outbound connections.
    flagged_reputation: Optional[Reputation] = None
    network_ips: list[str] = []
    children: list[ProcessNode] = []


class NetworkConnection(BaseModel):
    dest_ip: str
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    first_seen: datetime
    reputation: Optional[Reputation] = None
    abuse_score: Optional[int] = None
    vt_malicious_count: Optional[int] = None
    malware_family: Optional[str] = None
    # Personal watchlist match (Task 26) — independent of external feeds.
    watchlist: Optional[bool] = None
    watchlist_label: Optional[str] = None


class NoteIn(BaseModel):
    note: str = Field(min_length=1, max_length=2000)


class RunNote(BaseModel):
    run_id: str
    note: str
    created_at: datetime


class WatchlistEntry(BaseModel):
    value: str
    label: str
    added_at: datetime


class RunDetail(BaseModel):
    run: RunSummary
    process_tree: list[ProcessNode]
    network_connections: list[NetworkConnection]
    timeline: list[EventOut]
    alerts: list[Alert]
    # Roadmap 2.4 — correlated kill-chain sequence (stage→stage links).
    kill_chain: list[dict] = []
    # Roadmap 2.2 — uploaded-sample reputation evidence, when the run's
    # sample_name matches an uploaded binary (YARA + VirusTotal).
    sample_reputation: Optional[dict] = None


class RunCreate(BaseModel):
    sample_name: str
    platform: Platform
    session_type: SessionType = "analysis"
    # Provenance marker — the webapp sends "monitor" by default; the host
    # collector path is forced to "live" server-side when session_type=live.
    source: str = Field(default="monitor", max_length=32)


class SandboxDetonateIn(BaseModel):
    """Push a vault sample to an external sandbox for dynamic detonation.

    `provider` is one of anyrun/triage/joe/demo (or auto = the configured
    provider, falling back to the labeled demo when none is configured).
    `platform` overrides the sample's sniffed OS for the detonation VM;
    default is the sample's detected platform.
    """

    sample_id: str = Field(min_length=1, max_length=64)
    provider: str = Field(default="auto", max_length=16)
    platform: Optional[Platform] = None
    note: Optional[str] = Field(default=None, max_length=500)


class SandboxTaskOut(BaseModel):
    """One sandbox detonation task — the shape both the POST response and the
    status poll return, so the webapp can render the same card."""

    task_id: str
    run_id: str
    sample_id: str
    sample_name: str
    provider: str
    platform: Platform
    status: Literal["submitted", "running", "completed", "error"]
    events: int = 0
    alerts: int = 0
    risk_score: int = 0
    highest_severity: Optional[Severity] = None
    error: Optional[str] = None
    started_at: str
    finished_at: Optional[str] = None
