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


class EventOut(EventIn):
    id: Optional[int] = None


class RunSummary(BaseModel):
    run_id: str
    sample_name: str
    platform: Platform
    session_type: SessionType = "analysis"
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
    details: str


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
