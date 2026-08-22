# Backend Specification (FastAPI)

## Unified Event Schema (Pydantic)

This is the single source of truth. Both collectors must produce JSON matching this shape.

```python
# app/core/schema.py
from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime

class EventIn(BaseModel):
    run_id: str
    platform: Literal["windows", "linux"]
    event_type: Literal["process_create", "network_connection", "file_write", "registry_write"]
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

class RunSummary(BaseModel):
    run_id: str
    sample_name: str                    # for live sessions, use a label like "Live monitor — 2026-07-30"
    platform: Literal["windows", "linux"]
    session_type: Literal["live", "analysis"] = "analysis"   # "live" = continuous monitoring, "analysis" = bounded session on one sample
    started_at: datetime
    completed_at: Optional[datetime]
    process_count: int
    unique_ips: int
    alert_count: int = 0
    highest_severity: Optional[str] = None   # "clean" | "suspicious" | "malicious", derived from Alert records

class Alert(BaseModel):
    id: Optional[int] = None
    run_id: str
    rule_id: str            # e.g. "T1055-process-injection", see docs/11-DETECTION-LOGIC.md
    rule_name: str           # human-readable, e.g. "Suspicious parent-child process relationship"
    severity: Literal["suspicious", "malicious"]
    triggered_at: datetime
    related_pid: Optional[int] = None
    related_ip: Optional[str] = None
    details: str             # short human-readable explanation of what specifically triggered it

class ProcessNode(BaseModel):
    pid: int
    ppid: Optional[int]
    process_name: str
    command_line: Optional[str]
    children: list["ProcessNode"] = []

class NetworkConnection(BaseModel):
    dest_ip: str
    dest_port: Optional[int]
    protocol: Optional[str]
    first_seen: datetime
    reputation: Optional[str] = None   # "clean" | "suspicious" | "malicious" | "unknown"
    abuse_score: Optional[int] = None
    vt_malicious_count: Optional[int] = None
    malware_family: Optional[str] = None   # populated via ThreatFox, see docs/08-INTEGRATIONS.md

class RunNote(BaseModel):
    run_id: str
    note: str
    created_at: datetime

class WatchlistEntry(BaseModel):
    value: str              # an IP, domain, or hash you're personally tracking
    label: str               # your own description, e.g. "C2 from sample X, June 2026"
    added_at: datetime
```

## API Endpoints — MVP

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/ingest/batch` | Collector ships a batch of events. Validates each against `EventIn`, stores, triggers detection heuristics, returns `202`. (Prefer batch over one-at-a-time — see `docs/03-COLLECTOR-SPEC.md`.) |
| `POST` | `/runs` | Start a new run — pass `session_type: "live"` for continuous monitoring or `"analysis"` for a bounded session on one sample. Returns generated `run_id`. |
| `POST` | `/runs/{run_id}/complete` | Marks run complete, triggers process-tree build + enrichment. (Live sessions may call this repeatedly to get periodic snapshots without actually ending.) |
| `GET` | `/runs` | List all runs (`RunSummary[]`), for run history (webapp) / `vantage list` (CLI). |
| `GET` | `/runs/{run_id}` | Full run detail: process tree + network connections + timeline + alerts. |
| `GET` | `/runs/{run_id}/alerts` | Just the `Alert[]` for this run — used for the live-alert stream in `vantage watch` and the webapp's alert banner. |
| `GET` | `/runs/{run_id}/export` | Returns exportable report (JSON, and PDF if implemented). |
| `GET` | `/health` | Basic liveness check. |

## API Endpoints — CLI & Standout Features (implement alongside the relevant feature, see `docs/10-STANDOUT-FEATURES.md`)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/samples/check-hash` | Pre-flight VirusTotal hash lookup before detonation (`docs/08-INTEGRATIONS.md` #1). |
| `GET` | `/ioc/search?value=` | Search across **all** past runs for a given IP/domain/hash — "have I seen this before?" |
| `GET` | `/runs/{run_id}/compare/{other_run_id}` | Diff two runs: processes/connections unique to each, shared ones. |
| `POST` | `/runs/{run_id}/notes` | Add an analyst note (`RunNote`) to a run. |
| `GET` | `/runs/{run_id}/notes` | Retrieve notes for a run. |
| `GET` | `/watchlist` | List personal watchlist entries. |
| `POST` | `/watchlist` | Add a `WatchlistEntry` — checked against every future run automatically. |

## Database Schema (SQLite)

```sql
CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    sample_name TEXT NOT NULL,
    platform TEXT NOT NULL CHECK(platform IN ('windows', 'linux')),
    session_type TEXT NOT NULL DEFAULT 'analysis' CHECK(session_type IN ('live', 'analysis')),
    started_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('suspicious', 'malicious')),
    triggered_at TEXT NOT NULL,
    related_pid INTEGER,
    related_ip TEXT,
    details TEXT NOT NULL
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    platform TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    pid INTEGER,
    ppid INTEGER,
    process_name TEXT,
    command_line TEXT,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT,
    file_path TEXT,
    registry_key TEXT
);

CREATE TABLE enrichment_cache (
    ip TEXT PRIMARY KEY,
    abuse_score INTEGER,
    vt_malicious_count INTEGER,
    reputation TEXT,
    checked_at TEXT NOT NULL
);

CREATE INDEX idx_events_run_id ON events(run_id);
CREATE INDEX idx_events_dest_ip ON events(dest_ip);
CREATE INDEX idx_alerts_run_id ON alerts(run_id);

-- Standout features (add when implementing docs/10-STANDOUT-FEATURES.md)
CREATE TABLE run_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    note TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE watchlist (
    value TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    added_at TEXT NOT NULL
);
```

## Process Tree Builder (logic outline)

1. Fetch all `process_create` events for a `run_id`
2. Build a `{pid: ProcessNode}` map
3. For each node, attach to its `ppid`'s `children` list (root nodes are processes whose `ppid` doesn't appear in this run — typically the sample's own launcher)
4. Return the root node(s) as the tree

## Detection Heuristics (logic outline — see `docs/11-DETECTION-LOGIC.md` for the full rule set)

Runs as part of `POST /ingest/batch` — each incoming event is checked against the rule set in `app/services/detection.py` immediately, not deferred to run completion, since this is what makes live monitoring actually "live." Any rule match creates an `Alert` record. Keep rules cheap (simple pattern/threshold checks against the event and recent history for the same `run_id`) — this runs on every ingested event, so it needs to stay fast.

## Enrichment Logic (logic outline)

1. Collect distinct `dest_ip` values for the run
2. For each IP: check `enrichment_cache` first
3. If not cached (or cache older than a set TTL, e.g. 7 days): query AbuseIPDB and VirusTotal, store result in cache
4. Derive `reputation` label from combined scores (e.g. `abuse_score > 50` or `vt_malicious_count > 3` → `"malicious"`; moderate scores → `"suspicious"`; else `"clean"`)
5. Attach reputation data to each `NetworkConnection` returned by `GET /runs/{run_id}`

## Environment Variables

```
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
DATABASE_PATH=./data/outpost.db
CORS_ORIGINS=http://localhost:5173
```
