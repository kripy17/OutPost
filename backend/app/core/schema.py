"""Pydantic models — the single source of truth for API shapes.

Mirrors docs/02-BACKEND-SPEC.md exactly. Both collectors must produce JSON
matching `EventIn`; the frontend types in `frontend/src/types/index.ts` and the
CLI's `api_client.py` mirror these same shapes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Platform = Literal["windows", "linux", "macos"]
EventType = Literal[
    "process_create",
    "network_connection",
    "file_write",
    "registry_write",
    "remote_thread",
    "process_access",
    "driver_load",
    "module_load",
    "file_delete",
]
SessionType = Literal["live", "analysis"]
Severity = Literal["suspicious", "malicious"]
Reputation = Literal["clean", "suspicious", "malicious", "unknown"]
AlertStatus = Literal["open", "acknowledged", "resolved"]
AllowlistKind = Literal["ip", "file", "registry", "process", "hash"]
# P0 finding layer — who produced the alert, the analyst verdict vocabulary,
# and the IOC / investigation types (P0.2 resource APIs).
FindingSource = Literal["detection", "analyst", "correlation"]
Confidence = Literal["high", "medium", "low"]
Disposition = Literal["false-positive", "confirmed-malicious", "benign", "watchlisted", "escalated"]
IocType = Literal["ip", "domain", "url", "hash", "email", "filepath", "registry", "mutex", "certificate", "other"]
IocDisposition = Literal["candidate", "enriched", "confirmed-malicious", "benign", "allowlisted", "watchlisted", "unresolved"]
AnalysisBackend = Literal["static", "watched-host", "external-provider", "isolated-outpost"]
AnalysisStatus = Literal["queued", "running", "completed", "failed", "canceled"]
# P0.3 investigation layer — the optional cross-workflow case anchor.
# Lifecycle: created → triage → active → contained → resolved → closed;
# reopen returns to `active`; close requires a conclusion.
InvestigationStatus = Literal["created", "triage", "active", "contained", "resolved", "closed"]
InvestigationRefType = Literal["artifact", "run", "host", "ioc", "campaign"]
# Canonical severity ordering for the derived investigation severity.
_SEVERITY_RANK = {"suspicious": 1, "malicious": 2}


class EventIn(BaseModel):
    run_id: str
    platform: Platform
    event_type: EventType
    timestamp: datetime
    pid: int | None = None
    ppid: int | None = None
    process_name: str | None = None
    command_line: str | None = None
    # Kernel-resolved executable path (auditd's `exe=`, symlinks followed) —
    # authoritative for masquerading and immune to argv[0] spoofing. NULL for
    # events that lack it (webapp/sandbox/seed, Sysmon without Image path).
    exe_path: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    protocol: str | None = None
    file_path: str | None = None
    registry_key: str | None = None
    # Fleet identity — which agent/host the event came from. Omitted events
    # (webapp detonations, sandbox runs) default to 'local' at normalization.
    host_id: str | None = None
    # The exact log channel (auditd / sysmon) a collector stamped on the
    # event — the Event Log's source tabs split collectors by this. NULL for
    # webapp/sandbox/seed events.
    log_source: str | None = None
    # DNS query string (resolved name) — populated by Sysmon DNS events and
    # DNS-capable collectors. Feeds the DNS-channel rules (tunneling,
    # high-entropy labels, covert DNS ports).
    query: str | None = None
    # TLS Server Name Indication from the handshake (Sysmon Event ID 3
    # DestinationHostname). Feeds the TLS-SNI / DNS-over-HTTPS rules.
    tls_sni: str | None = None
    # TLS client hello JA3 fingerprint hash (e.g. Cobalt Strike, Metasploit).
    ja3: str | None = None
    tls_ja3: str | None = None
    # The raw source record as shipped by a collector (the exact auditd
    # line / Sysmon event) — the Event Viewer's "raw record" pane pivots a
    # normalized row back to its source. NULL for webapp/sandbox/seed events.
    raw_record: str | None = None


class EventOut(EventIn):
    id: int | None = None
    # The raw record as shipped by the collector (JSON) — the Event Viewer's
    # "raw record" pane. Null for rows ingested before the column existed.
    raw_record: str | None = None


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
    completed_at: datetime | None = None
    process_count: int = 0
    unique_ips: int = 0
    alert_count: int = 0
    highest_severity: Severity | None = None
    risk_score: int = 0


class Alert(BaseModel):
    id: int | None = None
    run_id: str
    rule_id: str
    rule_name: str
    severity: Severity
    triggered_at: datetime
    related_pid: int | None = None
    related_ip: str | None = None
    # PIDs of the processes behind a composite rule (e.g. the enumerating
    # commands of enumeration-burst) — lets the live Monitor highlight the
    # actual actors in the process tree the moment the rule fires.
    related_pids: list[int] = []
    details: str
    # Triage (analyst workflow): open → acknowledged → resolved, with the
    # optional analyst comment recorded at the transition.
    status: AlertStatus = "open"
    status_comment: str | None = None
    status_at: datetime | None = None
    # P0 finding layer (additive — every existing consumer keeps working with
    # the defaults): who/what produced the alert, the analyst's verdicts, the
    # unread stamp, and the optional investigation the finding belongs to.
    source: FindingSource = "detection"
    confidence: Confidence | None = None
    disposition: Disposition | None = None
    seen_at: datetime | None = None
    investigation_id: str | None = None
    intel: list[dict] = []


class AlertStatusIn(BaseModel):
    status: AlertStatus
    comment: str | None = None


class AlertPatchIn(AlertStatusIn):
    """The extended PATCH contract: the triage transition plus the P0 finding
    verdicts (disposition / confidence) and the optional investigation link.
    All of them optional — a status-only PATCH behaves exactly as before."""

    disposition: Disposition | None = None
    confidence: Confidence | None = None
    investigation_id: str | None = None


class FindingDTO(Alert):
    """The semantic finding resource — a compatible superset of Alert (the
    physical table stays `alerts`; this is the API-level abstraction)."""


class FindingIn(BaseModel):
    """Create an analyst-authored finding. `source` is forced to 'analyst'
    server-side — the detection engine owns the 'detection' provenance."""

    run_id: str = Field(min_length=1, max_length=64)
    rule_id: str = Field(default="analyst-finding", min_length=1, max_length=128)
    rule_name: str = Field(default="Analyst finding", min_length=1, max_length=256)
    severity: Severity
    details: str = Field(min_length=1, max_length=4000)
    related_pid: int | None = None
    related_ip: str | None = None
    related_pids: list[int] = []
    comment: str | None = None


class IocDTO(BaseModel):
    ioc_id: str
    value: str
    type: IocType
    disposition: IocDisposition = "candidate"
    label: str | None = None
    abuse_score: int | None = None
    vt_malicious_count: int | None = None
    reputation: Reputation | None = None
    checked_at: datetime | None = None
    first_seen: datetime
    last_seen: datetime | None = None
    source: str | None = None


class IocCreateIn(BaseModel):
    value: str = Field(min_length=1, max_length=500)
    type: IocType
    label: str | None = Field(default=None, max_length=500)


class IocDispositionIn(BaseModel):
    disposition: IocDisposition
    label: str | None = Field(default=None, max_length=500)


class IocProvenanceDTO(BaseModel):
    ref_type: str
    ref_id: str
    first_seen: datetime


class IocDetailDTO(IocDTO):
    """The IOC workspace payload: the row plus everything OutPost knows about
    the indicator — where it was observed, the findings it links to, the runs
    and hosts it appeared in. Runs/hosts are DERIVED from provenance refs
    (event/finding → run → host); nothing is fabricated."""

    provenance: list[IocProvenanceDTO] = []
    findings: list[Alert] = []
    runs: list[dict] = []
    hosts: list[str] = []


class AnalysisJobDTO(BaseModel):
    """One persisted analysis job — `run_id` doubles as the job id (the run
    lifecycle/report/export machinery stays the single source of truth)."""

    run_id: str
    backend: AnalysisBackend
    status: AnalysisStatus = "queued"
    timeout_seconds: int | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    progress: int = 0
    result: dict | None = None
    # Derived live from the run (events/alerts/risk share the run assembly).
    sample_name: str | None = None
    events: int = 0
    alerts: int = 0
    risk_score: int = 0


class AnalysisJobCreateIn(BaseModel):
    """Start an analysis job. `backend` selects the execution backend;
    `sample_id` (vault sample) or `sample_name` identifies the artifact. For
    `static` the analysis runs synchronously; `watched-host` and
    `external-provider` persist queued state (their executors arrive in later
    phases); `isolated-outpost` is reserved and returns 501 — OutPost has no
    isolated execution backend yet."""

    backend: AnalysisBackend
    sample_id: str | None = Field(default=None, min_length=1, max_length=64)
    sample_name: str | None = Field(default=None, min_length=1, max_length=256)
    platform: Platform | None = None
    timeout_seconds: int | None = Field(default=None, ge=1, le=86400)
    label: str | None = Field(default=None, max_length=256)
    provider: str | None = Field(default=None, max_length=64)


class AllowlistIn(BaseModel):
    kind: AllowlistKind = "ip"
    value: str = Field(min_length=1, max_length=500)
    note: str | None = None


class AllowlistEntry(BaseModel):
    id: int
    run_id: str
    kind: AllowlistKind
    value: str
    note: str | None = None
    created_at: datetime
    # How many already-open matching alerts the POST auto-acknowledged (0 on
    # GET list — only the create response carries a meaningful value).
    acked: int = 0


class SuppressionIn(BaseModel):
    rule_id: str
    # None = global (every run); set = only that run. 422 on unknown rule_id.
    run_id: str | None = None
    # Optional value scope — a sample name, related IP, or detail substring.
    # Set = only alerts whose run/context matches are suppressed (e.g.
    # beaconing → "detonate-demo.sh" so future runs of that sample stay
    # quiet); None = the whole rule scope. Combined with run_id (set = a
    # specific run's matching alerts; None = every run's matching alerts).
    value: str | None = None
    reason: str | None = None


class Suppression(BaseModel):
    id: int
    rule_id: str
    run_id: str | None = None
    value: str | None = None
    reason: str | None = None
    created_at: datetime


class ProcessNode(BaseModel):
    pid: int
    ppid: int | None = None
    process_name: str
    command_line: str | None = None
    # Network risk annotation (docs/07 signature visual): the worst reputation
    # of any destination this pid connected to, and the distinct IPs behind it.
    # Null / empty for processes with no outbound connections.
    flagged_reputation: Reputation | None = None
    network_ips: list[str] = []
    children: list[ProcessNode] = []


class NetworkConnection(BaseModel):
    dest_ip: str
    dest_port: int | None = None
    protocol: str | None = None
    first_seen: datetime
    reputation: Reputation | None = None
    abuse_score: int | None = None
    vt_malicious_count: int | None = None
    malware_family: str | None = None
    # Personal watchlist match (Task 26) — independent of external feeds.
    watchlist: bool | None = None
    watchlist_label: str | None = None
    # When the reputation verdict was last fetched from an external feed
    # (cache age) — None when the IP was never checked.
    checked_at: str | None = None


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
    sample_reputation: dict | None = None
    # Explainability: the tuning knobs that deviated from stock while this
    # run was evaluated (captured once, immutable) — "scored under" context.
    effective_tuning: dict[str, object] = {}
    suppressed_alerts: dict[str, int] = {}


class RunCreate(BaseModel):
    sample_name: str
    platform: Platform
    session_type: SessionType = "analysis"
    # Provenance marker — webapp-synthetic detonations default to
    # "webapp-demo" (honest: generated, not host telemetry); the CLI sends
    # "cli"; the host collector path is forced to "live" server-side when
    # session_type=live.
    source: str = Field(default="webapp-demo", max_length=32)


class SandboxDetonateIn(BaseModel):
    """Push a vault sample to an external sandbox for dynamic detonation.

    `provider` is one of anyrun/triage/joe/demo (or auto = the configured
    provider, falling back to the labeled demo when none is configured).
    `platform` overrides the sample's sniffed OS for the detonation VM;
    default is the sample's detected platform.
    """

    sample_id: str = Field(min_length=1, max_length=64)
    provider: str = Field(default="auto", max_length=16)
    isolation_driver: str = Field(default="auto", max_length=32)
    platform: Platform | None = None
    note: str | None = Field(default=None, max_length=500)


class SandboxTaskOut(BaseModel):
    """One sandbox detonation task — the shape both the POST response and the
    status poll return, so the webapp can render the same card."""

    task_id: str
    run_id: str
    sample_name: str
    provider: str
    platform: Platform
    status: Literal["submitted", "running", "completed", "error"]
    events: int = 0
    alerts: int = 0
    risk_score: int = 0
    highest_severity: Severity | None = None
    error: str | None = None
    started_at: str
    finished_at: str | None = None


# ---------------------------------------------------------------------------
# P0.3 — Investigation
# ---------------------------------------------------------------------------


class InvestigationDTO(BaseModel):
    """One investigation — the case header with derived counts. `severity` is
    DERIVED from the attached findings (max of the canonical suspicious /
    malicious vocabulary), NULL when no findings are attached."""

    id: str
    title: str
    status: InvestigationStatus = "created"
    severity: Severity | None = None
    conclusion: str | None = None
    created_by: str | None = None
    created_at: datetime
    updated_at: datetime | None = None
    closed_at: datetime | None = None
    finding_count: int = 0
    ref_count: int = 0
    tags: list[str] = []


class InvestigationCreateIn(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    tags: list[str] = Field(default_factory=list, max_length=16)


class InvestigationPatchIn(BaseModel):
    """Fields justified by the P0 contract: title / tags / status / conclusion.
    Only fields actually present are written (Pydantic v2 model_fields_set)."""

    title: str | None = Field(default=None, min_length=1, max_length=256)
    tags: list[str] | None = None
    status: InvestigationStatus | None = None
    conclusion: str | None = Field(default=None, max_length=4000)


class InvestigationRefIn(BaseModel):
    ref_type: InvestigationRefType
    ref_id: str = Field(min_length=1, max_length=256)


class InvestigationRefDTO(BaseModel):
    investigation_id: str
    ref_type: InvestigationRefType
    ref_id: str
    added_at: datetime


class InvestigationNoteIn(BaseModel):
    note: str = Field(min_length=1, max_length=4000)


class InvestigationNoteDTO(BaseModel):
    id: int
    investigation_id: str
    note: str
    actor: str
    created_at: datetime


TaskCategory = Literal["containment", "eradication", "evidence_collection", "remediation", "triage"]
TaskStatus = Literal["todo", "in_progress", "completed", "cancelled"]
TaskPriority = Literal["low", "medium", "high", "critical"]


class InvestigationTaskIn(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    category: TaskCategory = "triage"
    priority: TaskPriority = "medium"
    assignee: str | None = None
    due_at: str | None = None


class InvestigationTaskPatchIn(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=256)
    category: TaskCategory | None = None
    status: TaskStatus | None = None
    priority: TaskPriority | None = None
    assignee: str | None = None
    due_at: str | None = None


class InvestigationTaskDTO(BaseModel):
    id: int
    investigation_id: str
    title: str
    category: TaskCategory
    status: TaskStatus
    priority: TaskPriority
    assignee: str | None = None
    due_at: str | None = None
    completed_at: str | None = None
    created_at: str
    updated_at: str | None = None


class InvestigationDetailDTO(InvestigationDTO):
    """The investigation workspace payload: the header, its tags, the attached
    findings (from the canonical alerts model — never duplicated), the
    evidence refs (pointers, not copies), and the analyst notes."""

    findings: list[Alert] = []
    refs: list[InvestigationRefDTO] = []
    notes: list[InvestigationNoteDTO] = []
    tasks: list[InvestigationTaskDTO] = []


class InvestigationCloseIn(BaseModel):
    conclusion: str = Field(min_length=1, max_length=4000)


class ApplyPlaybookIn(BaseModel):
    playbook_id: str
    assignee: str | None = None


# ---------------------------------------------------------------------------
# P0.5 — global search: the grouped GET /search envelope. One endpoint, every
# analyst-facing resource group; qualifiers parsed from the query string.
# ---------------------------------------------------------------------------
SearchGroup = Literal[
    "findings", "iocs", "artifacts", "hosts", "sessions", "investigations", "campaigns"
]

# P0.6 — the host-scoped aggregate timeline: a unified chronological feed of
# every resource kind tied to one host (events, findings, sessions/jobs,
# IOCs, investigations). A pure read model over the existing tables — no
# host-timeline storage.
TimelineKind = Literal["event", "finding", "session", "ioc", "investigation"]


class SearchHit(BaseModel):
    """One result row in a search group. `group` names the owning resource;
    `id` is the resource's own id; `kind` is a display hint; `title` is the
    primary match text; `subtitle` carries context (ip / run / severity / …);
    `payload` carries the fields each group needs to deep-link. Minimal and
    presentation-free: the webapp and CLI render from the same fields."""

    group: SearchGroup
    id: str
    kind: str | None = None
    title: str
    subtitle: str | None = None
    payload: dict = Field(default_factory=dict)


class SearchGroupResult(BaseModel):
    """A group's slice of the envelope: the page total (honest count across
    all matches in the group, not just this page) and the page hits."""

    total: int = 0
    hits: list[SearchHit] = []


class SearchResponseDTO(BaseModel):
    """The GET /search envelope — `q` echoes the normalized free text (after
    qualifiers were stripped), `qualifiers` echoes the parsed filters, and
    `groups` holds one SearchGroupResult per resource group searched."""

    q: str = ""
    qualifiers: dict = Field(default_factory=dict)
    groups: dict[str, SearchGroupResult] = Field(default_factory=dict)


class HostTimelineEntry(BaseModel):
    """One row of the host aggregate timeline. `kind` discriminates the
    resource; `timestamp` is the unified sort key (event time, alert trigger,
    session start, IOC first-seen, investigation created); `title`/`subtitle`
    carry the display text; `payload` carries the deep-link fields per kind."""

    kind: TimelineKind
    timestamp: datetime
    id: str
    title: str
    subtitle: str | None = None
    payload: dict = Field(default_factory=dict)


class HostTimelineDTO(BaseModel):
    """The host timeline envelope — host metadata plus the merged, filtered,
    paginated feed. `total` is the honest count across ALL kinds after the
    active filters (not just this page); `limit`/`offset` echo the request."""

    host_id: str
    platform: str | None = None
    last_heartbeat: datetime | None = None
    total: int = 0
    limit: int = 50
    offset: int = 0
    timeline: list[HostTimelineEntry] = []
