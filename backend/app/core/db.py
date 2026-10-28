"""Database connection handling and schema initialization.

Default runtime is raw `sqlite3` (deliberate — dependency-light, schema fully
explicit). The schema below matches docs/02-BACKEND-SPEC.md exactly,
including the standout-feature tables created up front so migrations stay
simple.

When `OUTPOST_DATABASE_URL` is set (Tier 4, docs/16), `get_connection()` and
`init_db()` route through `core/db_pg` instead — a sqlite3-compatible shim
over psycopg3. Every caller keeps working unchanged: the shim translates
placeholders, LIKE/ILIKE, INSERT OR IGNORE, GROUP_CONCAT and lastrowid
semantics, and `db_session()` yields the same commit/rollback lifecycle.
"""

import logging
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    sample_name TEXT NOT NULL,
    platform TEXT NOT NULL CHECK(platform IN ('windows', 'linux')),
    session_type TEXT NOT NULL DEFAULT 'analysis' CHECK(session_type IN ('live', 'analysis')),
    -- Domain profile of the run (P0): 'monitoring_session' = host telemetry
    -- (live), 'analysis_job' = an artifact analysis (analysis). Kept in sync
    -- with session_type by the creation path and the _migrate_runs_kind
    -- backfill; session_type remains the compatibility field.
    kind TEXT NOT NULL DEFAULT 'monitoring_session'
        CHECK(kind IN ('monitoring_session', 'analysis_job')),
    source TEXT NOT NULL DEFAULT 'monitor',
    origin TEXT NOT NULL DEFAULT 'observed'
        CHECK(origin IN ('observed', 'replayed', 'imported', 'simulated', 'test')),
    started_at TEXT NOT NULL,
    completed_at TEXT,
    suppressed_alerts TEXT
);

-- P0 foundations (docs: OUTPOST — P0 BACKEND FOUNDATIONS SPECIFICATION).
-- The optional analyst-created investigation/case: the cross-workflow anchor
-- that binds findings, artifacts, hosts, sessions, IOCs and campaigns without
-- forcing any telemetry into a case. Lifecycle: created → triage → active →
-- contained → resolved → closed (reopen on new evidence; close requires a
-- conclusion).
--
-- Declared BEFORE `alerts` (not at the schema tail like the other P0 tables):
-- alerts carries an `investigation_id REFERENCES investigations(id)`, and the
CREATE TABLE IF NOT EXISTS technique_validations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    tactic TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    status TEXT NOT NULL CHECK(status IN ('success', 'failed')),
    detection_status TEXT NOT NULL CHECK(detection_status IN ('detected', 'telemetry_only', 'missed')),
    matched_rules TEXT NOT NULL DEFAULT '[]',
    events_count INTEGER NOT NULL DEFAULT 0,
    alerts_count INTEGER NOT NULL DEFAULT 0,
    mttd_ms INTEGER NOT NULL DEFAULT 0,
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_technique_validations_test ON technique_validations(test_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('suspicious', 'malicious')),
    triggered_at TEXT NOT NULL,
    related_pid INTEGER,
    related_ip TEXT,
    related_pids TEXT,
    details TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'acknowledged', 'resolved')),
    status_comment TEXT,
    status_at TEXT,
    assignee TEXT,
    origin TEXT NOT NULL DEFAULT 'observed'
        CHECK(origin IN ('observed', 'replayed', 'imported', 'simulated', 'test')),
    -- Finding-layer columns (P0, additive): who/what produced the alert
    -- ('detection' = rule engine, 'analyst' = hand-created, 'correlation' =
    -- derived), the analyst's confidence and disposition verdicts, when the
    -- analyst first saw it (NULL = unread), and the optional investigation
    -- the finding belongs to. Existing rows keep source='detection' and NULL
    -- verdicts — every pre-P0 alert is an unread detection with no
    -- investigation.
    source TEXT NOT NULL DEFAULT 'detection'
        CHECK(source IN ('detection', 'analyst', 'correlation')),
    confidence TEXT
        CHECK(confidence IS NULL OR confidence IN ('high', 'medium', 'low')),
    disposition TEXT
        CHECK(disposition IS NULL OR disposition IN
            ('false-positive', 'confirmed-malicious', 'benign', 'watchlisted', 'escalated')),
    seen_at TEXT,
    investigation_id TEXT,
    evidence_event_ids TEXT DEFAULT '[]',
    rule_condition TEXT,
    occurrence_count INTEGER DEFAULT 1,
    last_seen_at TEXT,
    entity_key TEXT,
    pid_fallback INTEGER DEFAULT 0,
    host_id TEXT DEFAULT 'local'
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    platform TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    origin TEXT NOT NULL DEFAULT 'observed'
        CHECK(origin IN ('observed', 'replayed', 'imported', 'simulated', 'test')),
    pid INTEGER,
    ppid INTEGER,
    process_name TEXT,
    command_line TEXT,
    -- The kernel-resolved executable path the collector got from auditd's
    -- `exe=` field (symlinks already followed). Authoritative for the
    -- masquerading rule: unlike argv[0]/cmdline it cannot be spoofed, and it
    -- survives processes that exit before /proc can be read. NULL for events
    -- that predate the column or lack the field.
    exe_path TEXT,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT,
    file_path TEXT,
    registry_key TEXT,
    host_id TEXT NOT NULL DEFAULT 'local',
    -- The raw record as shipped by the collector (JSON) — the Event Viewer's
    -- "raw record" view, for pivoting from a normalized row to the original
    -- auditd/Sysmon line. NULL for rows predating the column.
    raw_record TEXT,
    -- The exact log channel the event came from: 'auditd' (Linux collector)
    -- or 'sysmon' (Windows collector). NULL for webapp/sandbox/seed events.
    -- The Event Log's source tabs split collectors by this.
    log_source TEXT,
    -- DNS query string (resolved name) for DNS events — feeds the DNS-tunnel
    -- detection (high-entropy / oversized queries). NULL for non-DNS events.
    query TEXT,
    -- TLS Server Name Indication from the handshake (Sysmon Event ID 3
    -- DestinationHostname) — feeds TLS-SNI and DNS-over-HTTPS detection.
    tls_sni TEXT,
    -- Stable source identifier assigned at telemetry origin (auditd seq,
    -- Sysmon RecordNumber/EventRecordID, UUID). Prevents replay duplicates.
    source_event_id TEXT,
    -- Host boot session ID (e.g. /proc/sys/kernel/random/boot_id). Survives
    -- reboots and disambiguates PID reuse across boot cycles.
    boot_id TEXT,
    -- Process start timestamp for compound process identity:
    -- (host_id + boot_id + pid + process_start_time).
    process_start_time TEXT,
    user TEXT,
    parent_image TEXT,
    parent_command_line TEXT,
    hashes TEXT,
    integrity_level TEXT,
    session_id TEXT,
    connection_status TEXT,
    process_guid TEXT
);

CREATE TABLE IF NOT EXISTS finding_evidence_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    rule_condition TEXT,
    matched_at TEXT NOT NULL,
    UNIQUE (finding_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding ON finding_evidence_events(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_event ON finding_evidence_events(event_id);

CREATE TABLE IF NOT EXISTS enrichment_cache (
    ip TEXT PRIMARY KEY,
    abuse_score INTEGER,
    vt_malicious_count INTEGER,
    reputation TEXT,
    checked_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_run_id ON events(run_id);
CREATE INDEX IF NOT EXISTS idx_events_dest_ip ON events(dest_ip);
CREATE INDEX IF NOT EXISTS idx_events_run_type ON events(run_id, event_type);
CREATE INDEX IF NOT EXISTS idx_events_run_timestamp ON events(run_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_proc_identity ON events(host_id, pid);
CREATE INDEX IF NOT EXISTS idx_alerts_run_id ON alerts(run_id);

-- Write-through copy of the in-memory process map (persisted at completion)
-- so a restarted backend restores a long run's parent map warm instead of
-- re-scanning the whole run's process_create history on the next batch.
CREATE TABLE IF NOT EXISTS run_process_maps (
    run_id TEXT PRIMARY KEY,
    last_event_id INTEGER NOT NULL,
    pids_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    key TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    response_code INTEGER NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_idempotency_keys_created ON idempotency_keys(created_at);

-- Standout features (docs/10-STANDOUT-FEATURES.md)
CREATE TABLE IF NOT EXISTS run_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    note TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS watchlist (
    value TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    added_at TEXT NOT NULL
);

-- Analyst audit trail (who did what, when): triage transitions, logins,
-- rotation, allowlist/suppression edits, retention prunes, backups. Actor is
-- the role ('admin'/'analyst') when auth is on, 'local' for the zero-config
-- default, or the CLI/source label for non-web writers.
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    detail TEXT,
    outcome TEXT NOT NULL DEFAULT 'success',
    prev_hash TEXT,
    entry_hash TEXT,
    source_ip TEXT,
    before_state TEXT,
    after_state TEXT,
    reason TEXT,
    format_version INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checkpoint_seq INTEGER NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    last_audit_id INTEGER NOT NULL,
    last_entry_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    public_key TEXT NOT NULL
);

-- False-positive feedback loop: per-rule FP counters. Every "mark as false
-- positive" increments the rule's count; the run-detail UI reads these to
-- suggest threshold nudges / suppressions for noisy rules.
CREATE TABLE IF NOT EXISTS rule_fp (
    rule_id TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 1,
    last_fp_at TEXT NOT NULL
);

-- Agent liveness: the collector pings every ~60s (HEARTBEAT_INTERVAL) so the
-- fleet view can show last-seen/uptime per host and flag hosts that went
-- silent — independent of whether the host shipped events in that window.
CREATE TABLE IF NOT EXISTS agent_heartbeats (
    host_id TEXT PRIMARY KEY,
    last_heartbeat TEXT NOT NULL,
    platform TEXT,
    version TEXT,
    -- Last-auth context: how the host's traffic authenticated at its most
    -- recent heartbeat ('agent' = OUTPOST_AGENT_TOKEN, 'admin'/'analyst' =
    -- browser roles, 'local' = auth off / no credential) and when.
    last_auth_role TEXT,
    last_auth_at TEXT,
    metrics_json TEXT,
    agent_id TEXT,
    source_health_json TEXT
);

-- Cryptographic agent fleet enrollment (Phase 4.1): registered sensors with unique
-- identity, machine fingerprint, secret key for HMAC-SHA256 authenticated telemetry.
CREATE TABLE IF NOT EXISTS enrolled_agents (
    agent_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    platform TEXT,
    machine_id TEXT,
    enrolled_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    agent_secret TEXT NOT NULL,
    hardware_info TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    agent_version TEXT DEFAULT '1.0.0',
    privilege_level TEXT DEFAULT 'least_privilege',
    enforcement_capabilities TEXT DEFAULT '["telemetry"]'
);
CREATE INDEX IF NOT EXISTS idx_enrolled_agents_host_id ON enrolled_agents(host_id);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'fleet',
    max_uses INTEGER NOT NULL DEFAULT 1,
    uses_count INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0
);

-- Single-use agent nonces for replay attack prevention across server instances and restarts.
CREATE TABLE IF NOT EXISTS agent_nonces (
    nonce_key TEXT PRIMARY KEY,
    seen_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_nonces_seen_at ON agent_nonces(seen_at);

-- Watchlist live-alerting: first-seen-per-run dedup. A (run, ioc) row is
-- written the first time the IOC appears; ingestion only fires the webhook /
-- SSE toast when the INSERT actually inserted, so a live session that keeps
-- touching a watched C2 IP alerts once, not on every batch.
CREATE TABLE IF NOT EXISTS watchlist_hits (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (run_id, ioc_type, ioc_value)
);

-- Uploaded sample binaries (roadmap 1.4): magic-byte OS detection + hash.
-- 'unknown' platform: containers/scripts we accept with an honest "can't tell"
-- guess (untyped zip, unrecognized shebang interpreter). Reputation columns
-- (roadmap 2.2): VirusTotal detections + malware family + matched YARA rule
-- names (JSON array) attached at upload time.
CREATE TABLE IF NOT EXISTS samples (
    sample_id TEXT PRIMARY KEY,
    original_name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    detected_platform TEXT NOT NULL CHECK(detected_platform IN ('windows', 'linux', 'macos', 'unknown')),
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    origin TEXT NOT NULL DEFAULT 'imported'
        CHECK(origin IN ('observed', 'replayed', 'imported', 'simulated', 'test')),
    family TEXT,
    vt_detections INTEGER,
    malware_family TEXT,
    yara_rules TEXT
);
CREATE INDEX IF NOT EXISTS idx_samples_sha256 ON samples(sha256);

-- Roadmap 2.2 — hash reputation cache (VirusTotal file search by SHA-256).
-- Mirrors enrichment_cache for IPs; TTL reuse keeps free-tier quota sane.
CREATE TABLE IF NOT EXISTS hash_cache (
    sha256 TEXT PRIMARY KEY,
    vt_detections INTEGER,
    malware_family TEXT,
    checked_at TEXT NOT NULL
);

-- Roadmap 2.3 — rule tuning overrides (rule editor). detection.py falls back
-- to its module constants when a key is absent, so an empty table == defaults.
CREATE TABLE IF NOT EXISTS rule_tuning (
    rule_id TEXT PRIMARY KEY,
    param TEXT NOT NULL,
    value TEXT NOT NULL
);

-- Explainability (run-level rule context): which tuning knobs were in effect
-- while a run was evaluated, captured ONCE at first evaluation (immutable).
-- The run-detail page shows these so a tuned finding is explainable — the
-- exact thresholds it was scored under.
CREATE TABLE IF NOT EXISTS run_tuning_snapshot (
    run_id TEXT PRIMARY KEY,
    params TEXT NOT NULL  -- JSON: {"DNS_TUNNEL_MIN_DISTINCT": 3, ...}
);

-- Roadmap 3.1 — notification settings (webhook endpoint, toggle).
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Alert triage (analyst workflow): per-run IOC allowlists (matching alerts are
-- suppressed going forward and auto-acknowledged when added) and per-rule
-- suppressions (run_id NULL = global, set = that run only).
CREATE TABLE IF NOT EXISTS run_allowlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    kind TEXT NOT NULL CHECK(kind IN ('ip', 'file', 'registry', 'process', 'hash')),
    value TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_allowlist_run ON run_allowlist(run_id);

CREATE TABLE IF NOT EXISTS rule_suppressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    run_id TEXT,
    -- Optional value scope: a sample name, related IP, or detail substring.
    -- Set = only alerts whose run/context match it are suppressed (e.g.
    -- beaconing → 'detonate-demo.sh'); NULL = the whole rule scope.
    value TEXT,
    reason TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_suppressions_rule ON rule_suppressions(rule_id);

-- P0 foundations (docs: OUTPOST — P0 BACKEND FOUNDATIONS SPECIFICATION).
-- Additive: existing rows/tables are untouched; the API/queue layers that
-- consume these arrive in P0.2+. All tables are created up front so fresh
-- DBs start correct and old DBs only need the _migrate_* ALTERs below.
-- (The investigations group lives above the alerts table — see the comment
-- there for the Postgres declaration-order reason.)

-- Canonical IOC entity (P0): one row per normalized indicator value+type,
-- with a disposition lifecycle (candidate → enriched → verdict) and the
-- enrichment cache columns mirrored from enrichment_cache/hash_cache so an
-- IOC carries its reputation without joining per-lookup. UNIQUE(value, type)
-- is the identity — the same IP extracted from two runs is one IOC.
CREATE TABLE IF NOT EXISTS iocs (
    ioc_id TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    type TEXT NOT NULL
        CHECK(type IN ('ip', 'domain', 'url', 'hash', 'email', 'filepath',
                       'registry', 'mutex', 'certificate', 'other')),
    disposition TEXT NOT NULL DEFAULT 'candidate'
        CHECK(disposition IN ('candidate', 'enriched', 'confirmed-malicious',
                              'benign', 'allowlisted', 'watchlisted', 'unresolved')),
    label TEXT,
    abuse_score INTEGER,
    vt_malicious_count INTEGER,
    reputation TEXT,
    checked_at TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT,
    source TEXT,
    UNIQUE (value, type)
);

-- Where an IOC was observed: which event / finding / artifact first (and
-- every) carried it. UNIQUE(ioc_id, ref_type, ref_id) keeps provenance
-- idempotent; ioc_findings is the finding-side join for triage surfaces.
CREATE TABLE IF NOT EXISTS ioc_provenance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id TEXT NOT NULL REFERENCES iocs(ioc_id),
    ref_type TEXT NOT NULL
        CHECK(ref_type IN ('event', 'finding', 'artifact')),
    ref_id TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    UNIQUE (ioc_id, ref_type, ref_id)
);

CREATE TABLE IF NOT EXISTS ioc_findings (
    ioc_id TEXT NOT NULL REFERENCES iocs(ioc_id),
    finding_id INTEGER NOT NULL REFERENCES alerts(id),
    PRIMARY KEY (ioc_id, finding_id)
);

-- Persisted analysis-job state (P0): the execution record for artifact
-- analysis — static, watched-host, external-provider, and (future)
-- isolated-outpost. run_id doubles as the job id so the existing run
-- lifecycle/report/export machinery stays the single source of truth; job
-- status survives backend restarts (the pre-P0 sandbox tasks were
-- in-memory only). result is a JSON blob of backend-specific output.
CREATE TABLE IF NOT EXISTS analysis_jobs (
    run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
    backend TEXT NOT NULL
        CHECK(backend IN ('static', 'watched-host', 'external-provider', 'isolated-outpost')),
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK(status IN ('queued', 'running', 'completed', 'failed', 'canceled')),
    timeout_seconds INTEGER,
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    progress INTEGER DEFAULT 0,
    result TEXT
);

CREATE TABLE IF NOT EXISTS analysis_processes (
    process_pk TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    host_pid INTEGER NOT NULL,
    ns_pid INTEGER,
    host_ppid INTEGER,
    ns_ppid INTEGER,
    start_time_us INTEGER NOT NULL,
    end_time_us INTEGER,
    initial_ppid INTEGER NOT NULL,
    current_ppid INTEGER NOT NULL,
    exe_path TEXT NOT NULL,
    command_line TEXT NOT NULL,
    process_name TEXT NOT NULL,
    host_id TEXT DEFAULT 'local',
    uid INTEGER,
    gid INTEGER,
    exit_code INTEGER,
    status TEXT DEFAULT 'running'
);
CREATE INDEX IF NOT EXISTS idx_analysis_processes_run ON analysis_processes(run_id);
CREATE INDEX IF NOT EXISTS idx_analysis_processes_host_pid ON analysis_processes(run_id, host_pid);

CREATE TABLE IF NOT EXISTS analysis_events (
    event_pk TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    start_time_us INTEGER NOT NULL,
    mono_us INTEGER NOT NULL,
    process_pk TEXT REFERENCES analysis_processes(process_pk) ON DELETE SET NULL,
    category TEXT NOT NULL,
    event_type TEXT NOT NULL,
    action TEXT NOT NULL,
    source TEXT NOT NULL,
    origin TEXT NOT NULL,
    target_path TEXT,
    details TEXT,
    UNIQUE(run_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_analysis_events_run_seq ON analysis_events(run_id, seq);
CREATE INDEX IF NOT EXISTS idx_analysis_events_run_cat ON analysis_events(run_id, category);
CREATE INDEX IF NOT EXISTS idx_analysis_events_process ON analysis_events(process_pk);

CREATE TABLE IF NOT EXISTS run_analysis_stats (
    run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
    total_events INTEGER DEFAULT 0,
    process_count INTEGER DEFAULT 0,
    file_events_count INTEGER DEFAULT 0,
    network_events_count INTEGER DEFAULT 0,
    module_events_count INTEGER DEFAULT 0,
    dns_events_count INTEGER DEFAULT 0,
    suppressed_system_reads INTEGER DEFAULT 0,
    is_truncated INTEGER DEFAULT 0,
    truncation_reason TEXT
);
"""


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _migrate_runs_platform_macos(conn: sqlite3.Connection) -> None:
    """One-time rebuild of `runs` so its CHECK admits 'macos' (roadmap 3.2).

    SQLite cannot ALTER a CHECK constraint — same copy/drop/rename dance as
    the samples migration. Idempotent: skipped when 'macos' is already in the
    CHECK literal.
    """
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'runs'"
    ).fetchone()
    if row is None or "'macos'" in row["sql"]:
        return
    # events/alerts FK-reference runs — the copy/drop/rename must run with
    # foreign keys OFF (SQLite refuses to drop a parent table with FK ON).
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        conn.execute(
            """
            CREATE TABLE runs_new (
                run_id TEXT PRIMARY KEY,
                sample_name TEXT NOT NULL,
                platform TEXT NOT NULL CHECK(platform IN ('windows', 'linux', 'macos')),
                session_type TEXT NOT NULL DEFAULT 'analysis' CHECK(session_type IN ('live', 'analysis')),
                started_at TEXT NOT NULL,
                completed_at TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO runs_new SELECT run_id, sample_name, platform, session_type, started_at, completed_at FROM runs"
        )
        conn.execute("DROP TABLE runs")
        conn.execute("ALTER TABLE runs_new RENAME TO runs")
    finally:
        conn.execute("PRAGMA foreign_keys = ON")
    # Post-rebuild integrity: events/alerts reference runs(run_id) by name, so
    # the FK should resolve against the new table — prove it rather than
    # assuming it (a rebuild bug would otherwise corrupt the live DB silently).
    violations = conn.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise RuntimeError(f"runs migration left FK violations: {[dict(v) for v in violations[:3]]}")
    conn.commit()


def _migrate_alerts_triage(conn: sqlite3.Connection) -> None:
    """Idempotent: add the triage columns (status/comment/timestamp) to DBs
    created before the analyst-workflow pass. Fresh DBs get them from SCHEMA;
    older installs need the ALTER. Status defaults 'open' for every
    pre-existing alert."""
    cols = _column_names(conn, "alerts")
    if "status" not in cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'open'")
    if "status_comment" not in cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN status_comment TEXT")
    if "status_at" not in cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN status_at TEXT")
    conn.commit()


def _migrate_alerts_assignee(conn: sqlite3.Connection) -> None:
    """Idempotent: add the analyst assignee column (triage queue) to DBs
    created before the queue pass. Fresh DBs get it from SCHEMA."""
    cols = _column_names(conn, "alerts")
    if "assignee" not in cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN assignee TEXT")
    conn.commit()


def _migrate_alerts_findings(conn: sqlite3.Connection) -> None:
    """Idempotent: add the finding-layer columns (source / confidence /
    disposition / seen_at / investigation_id) to DBs created before the P0
    findings pass. Fresh DBs get them from SCHEMA; older installs need the
    ALTER. Existing rows keep the safe defaults — source='detection', NULL
    confidence/disposition/seen_at/investigation_id — so every pre-P0 alert
    stays a valid, unread, un-investigated detection. Also creates the unread
    partial index (status + seen_at IS NULL); it cannot live in SCHEMA because
    pre-triage DBs lack the `status` column when executescript runs, so it is
    created here after both columns are guaranteed to exist."""
    cols = _column_names(conn, "alerts")
    if "source" not in cols:
        conn.execute(
            "ALTER TABLE alerts ADD COLUMN source TEXT NOT NULL DEFAULT 'detection' "
            "CHECK(source IN ('detection', 'analyst', 'correlation'))"
        )
    if "confidence" not in cols:
        conn.execute(
            "ALTER TABLE alerts ADD COLUMN confidence TEXT "
            "CHECK(confidence IS NULL OR confidence IN ('high', 'medium', 'low'))"
        )
    if "disposition" not in cols:
        conn.execute(
            "ALTER TABLE alerts ADD COLUMN disposition TEXT "
            "CHECK(disposition IS NULL OR disposition IN "
            "('false-positive', 'confirmed-malicious', 'benign', 'watchlisted', 'escalated'))"
        )
    if "seen_at" not in cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN seen_at TEXT")
    if "investigation_id" not in cols:
        conn.execute(
            "ALTER TABLE alerts ADD COLUMN investigation_id TEXT REFERENCES investigations(id)"
        )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_unread ON alerts(status) WHERE seen_at IS NULL"
    )
    conn.commit()


def _migrate_runs_kind(conn: sqlite3.Connection) -> None:
    """Idempotent: add the `kind` domain-profile column (monitoring_session /
    analysis_job) to DBs created before the P0 pass, and backfill existing
    rows from session_type: live → monitoring_session, analysis →
    analysis_job. Must run AFTER _migrate_runs_platform_macos (whose rebuild
    drops newer columns and would otherwise wipe the ALTER). Fresh DBs get
    the column from SCHEMA; the backfill is a harmless no-op there because
    the creation path stamps kind directly."""
    if "kind" not in _column_names(conn, "runs"):
        conn.execute(
            "ALTER TABLE runs ADD COLUMN kind TEXT NOT NULL DEFAULT 'monitoring_session' "
            "CHECK(kind IN ('monitoring_session', 'analysis_job'))"
        )
    conn.execute(
        "UPDATE runs SET kind = CASE WHEN session_type = 'analysis' "
        "THEN 'analysis_job' ELSE 'monitoring_session' END"
    )
    conn.commit()


def _migrate_runs_source(conn: sqlite3.Connection) -> None:
    """Idempotent: add the `source` provenance column (where a run came from:
    monitor / live / sandbox:<provider> / seed / cli) to pre-existing DBs.
    Fresh DBs get it from SCHEMA; older installs need the ALTER. Existing
    runs are conservatively marked 'monitor' (the webapp detonation path)."""
    if "source" not in _column_names(conn, "runs"):
        conn.execute("ALTER TABLE runs ADD COLUMN source TEXT NOT NULL DEFAULT 'monitor'")
        conn.commit()


def _migrate_agent_heartbeats_auth(conn: sqlite3.Connection) -> None:
    """Idempotent: add the last-auth context columns (last_auth_role /
    last_auth_at) to DBs created before the fleet-auth pass. Fresh DBs get
    them from SCHEMA."""
    cols = _column_names(conn, "agent_heartbeats")
    if "last_auth_role" not in cols:
        conn.execute("ALTER TABLE agent_heartbeats ADD COLUMN last_auth_role TEXT")
    if "last_auth_at" not in cols:
        conn.execute("ALTER TABLE agent_heartbeats ADD COLUMN last_auth_at TEXT")
    conn.commit()


def _migrate_agent_heartbeats_metrics(conn: sqlite3.Connection) -> None:
    """Idempotent: add metrics_json and agent_id columns to agent_heartbeats."""
    cols = _column_names(conn, "agent_heartbeats")
    if "metrics_json" not in cols:
        conn.execute("ALTER TABLE agent_heartbeats ADD COLUMN metrics_json TEXT")
    if "agent_id" not in cols:
        conn.execute("ALTER TABLE agent_heartbeats ADD COLUMN agent_id TEXT")
    conn.commit()


def _migrate_enrolled_agents(conn: sqlite3.Connection) -> None:
    """Idempotent: ensure enrolled_agents and enrollment_tokens tables exist with inventory metadata."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS enrolled_agents (
            agent_id TEXT PRIMARY KEY,
            host_id TEXT NOT NULL,
            platform TEXT,
            machine_id TEXT,
            enrolled_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            agent_secret TEXT NOT NULL,
            hardware_info TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            agent_version TEXT DEFAULT '1.0.0',
            privilege_level TEXT DEFAULT 'least_privilege',
            enforcement_capabilities TEXT DEFAULT '["telemetry"]'
        )
        """
    )
    cols = {r[1] for r in conn.execute("PRAGMA table_info(enrolled_agents)").fetchall()}
    if "agent_version" not in cols:
        conn.execute("ALTER TABLE enrolled_agents ADD COLUMN agent_version TEXT DEFAULT '1.0.0'")
    if "privilege_level" not in cols:
        conn.execute("ALTER TABLE enrolled_agents ADD COLUMN privilege_level TEXT DEFAULT 'least_privilege'")
    if "enforcement_capabilities" not in cols:
        conn.execute("ALTER TABLE enrolled_agents ADD COLUMN enforcement_capabilities TEXT DEFAULT '[\"telemetry\"]'")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS enrollment_tokens (
            token TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            scope TEXT NOT NULL DEFAULT 'fleet',
            max_uses INTEGER NOT NULL DEFAULT 1,
            uses_count INTEGER NOT NULL DEFAULT 0,
            revoked INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS agent_nonces (
            nonce_key TEXT PRIMARY KEY,
            seen_at REAL NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_nonces_seen_at ON agent_nonces(seen_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_enrolled_agents_host_id ON enrolled_agents(host_id)")
    conn.commit()


def _migrate_events_host_id(conn: sqlite3.Connection) -> None:
    """Idempotent: add the `host_id` fleet column (which agent a host event
    came from) to pre-existing DBs. Fresh DBs get it from SCHEMA; older
    installs need the ALTER. Pre-existing events are marked 'local' — the
    zero-config webapp path where events originate on the same machine.

    Also creates the host aggregate index (P0): it cannot live in SCHEMA
    because pre-fleet DBs lack the column when executescript runs, so it is
    created here after the column is guaranteed to exist."""
    if "host_id" not in _column_names(conn, "events"):
        conn.execute("ALTER TABLE events ADD COLUMN host_id TEXT NOT NULL DEFAULT 'local'")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_host_id ON events(host_id)")
    conn.commit()


def _migrate_events_log_source(conn: sqlite3.Connection) -> None:
    """Idempotent: add the `log_source` channel column (auditd / sysmon) to
    DBs created before collectors tagged their events. Fresh DBs get it from
    SCHEMA; older installs need the ALTER."""
    cols = _column_names(conn, "events")
    if "log_source" not in cols:
        conn.execute("ALTER TABLE events ADD COLUMN log_source TEXT")
        conn.commit()


def _migrate_events_exe_path(conn: sqlite3.Connection) -> None:
    """Idempotent: add the `exe_path` column (kernel-resolved executable path
    from auditd's `exe=`) to DBs created before the collector fidelity pass.
    Fresh DBs get it from SCHEMA; older installs need the ALTER."""
    cols = _column_names(conn, "events")
    if "exe_path" not in cols:
        conn.execute("ALTER TABLE events ADD COLUMN exe_path TEXT")
        conn.commit()


def _backfill_events_log_source(conn: sqlite3.Connection) -> int:
    """Idempotent backfill: events shipped by a real collector BEFORE
    collectors started stamping `log_source` read NULL, leaving the
    Auditd/Sysmon channels empty despite the telemetry being there. The only
    remaining signal is the platform — the Linux collector streams auditd,
    the Windows collector Sysmon — so infer the channel for legacy live-run
    events that carry a real host (never the webapp-default 'local' stamp).

    Safe to run at every startup: after the first pass nothing matches, and
    new events are stamped explicitly by collectors so they are untouched.
    Returns the number of events newly tagged (0 when the channel data is
    already complete) — the on-demand endpoint surfaces this to operators."""
    cur = conn.execute(
        """
        UPDATE events
        SET log_source = CASE WHEN platform = 'linux' THEN 'auditd' ELSE 'sysmon' END
        WHERE log_source IS NULL
          AND platform IN ('linux', 'windows')
          AND host_id IS NOT NULL AND host_id != '' AND host_id != 'local'
          AND run_id IN (SELECT run_id FROM runs WHERE source = 'live')
        """
    )
    conn.commit()
    return cur.rowcount


def _migrate_events_query(conn: sqlite3.Connection) -> None:
    """Idempotent: add the DNS `query` string column (DNS-tunnel detection)."""
    cols = _column_names(conn, "events")
    if "query" not in cols:
        conn.execute("ALTER TABLE events ADD COLUMN query TEXT")


def _migrate_events_tls_sni(conn: sqlite3.Connection) -> None:
    """Idempotent: add the TLS SNI column (TLS-SNI / DoH detection)."""
    cols = _column_names(conn, "events")
    if "tls_sni" not in cols:
        conn.execute("ALTER TABLE events ADD COLUMN tls_sni TEXT")
        conn.commit()


def _migrate_events_source_event_id(conn: sqlite3.Connection) -> None:
    """Idempotent: add the `source_event_id` column to pre-existing DBs."""
    cols = _column_names(conn, "events")
    if "source_event_id" not in cols:
        conn.execute("ALTER TABLE events ADD COLUMN source_event_id TEXT")
        conn.commit()


def _migrate_events_boot_id(conn: sqlite3.Connection) -> None:
    """Idempotent: add the `boot_id` column to pre-existing DBs."""
    cols = _column_names(conn, "events")
    if "boot_id" not in cols:
        conn.execute("ALTER TABLE events ADD COLUMN boot_id TEXT")
        conn.commit()


def _migrate_events_process_start_time(conn: sqlite3.Connection) -> None:
    """Idempotent: add the `process_start_time` column to pre-existing DBs."""
    cols = _column_names(conn, "events")
    if "process_start_time" not in cols:
        conn.execute("ALTER TABLE events ADD COLUMN process_start_time TEXT")
        conn.commit()


def _migrate_events_identity_indexes(conn: sqlite3.Connection) -> None:
    """Idempotent: ensure source_event_id and proc_identity indexes exist."""
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source_id ON events(run_id, source_event_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_proc_identity ON events(host_id, pid)")
    conn.commit()


def _migrate_runs_suppressed_alerts(conn: sqlite3.Connection) -> None:
    """Idempotent: per-rule alert-cap suppressed counts on the run (storm
    guard — burst-prone rules like first-seen cap per run; the counts are
    recorded so the cap is visible, not silent)."""
    cols = _column_names(conn, "runs")
    if "suppressed_alerts" not in cols:
        conn.execute("ALTER TABLE runs ADD COLUMN suppressed_alerts TEXT")
        conn.commit()


def _migrate_rule_suppressions_value(conn: sqlite3.Connection) -> None:
    """Idempotent: add the `value` scope column (rule + sample/IP suppression)
    to pre-existing DBs. Fresh DBs get it from SCHEMA; older installs need
    the ALTER. Existing rows stay NULL = whole-rule scope (unchanged)."""
    if "value" not in _column_names(conn, "rule_suppressions"):
        conn.execute("ALTER TABLE rule_suppressions ADD COLUMN value TEXT")
        conn.commit()


def _migrate_events_raw_record(conn: sqlite3.Connection) -> None:
    """Idempotent: add the `raw_record` column (the collector's original JSON
    payload) to pre-existing DBs. Fresh DBs get it from SCHEMA; older installs
    need the ALTER. Existing rows stay NULL — only newly ingested events carry
    a raw record."""
    if "raw_record" not in _column_names(conn, "events"):
        conn.execute("ALTER TABLE events ADD COLUMN raw_record TEXT")
        conn.commit()


def _migrate_alerts_related_pids(conn: sqlite3.Connection) -> None:
    """Idempotent: add the JSON `related_pids` column to pre-existing DBs.

    Fresh DBs get it from SCHEMA; older installs (created before the recon
    highlight landed) need the ALTER. JSON array text — parsed on read.
    """
    if "related_pids" not in _column_names(conn, "alerts"):
        conn.execute("ALTER TABLE alerts ADD COLUMN related_pids TEXT")
        conn.commit()


def _migrate_alerts_evidence_and_dedup(conn: sqlite3.Connection) -> None:
    """Idempotent: add evidence_event_ids, rule_condition, occurrence_count,
    and last_seen_at columns to alerts table, and ensure finding_evidence_events
    table and indexes exist.
    """
    cols = _column_names(conn, "alerts")
    for name, decl in (
        ("evidence_event_ids", "TEXT DEFAULT '[]'"),
        ("rule_condition", "TEXT"),
        ("occurrence_count", "INTEGER DEFAULT 1"),
        ("last_seen_at", "TEXT"),
        ("entity_key", "TEXT"),
        ("pid_fallback", "INTEGER DEFAULT 0"),
        ("host_id", "TEXT DEFAULT 'local'"),
    ):
        if name not in cols:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {name} {decl}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_entity_key ON alerts(run_id, rule_id, entity_key)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_evidence_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
            event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            rule_condition TEXT,
            matched_at TEXT NOT NULL,
            UNIQUE (finding_id, event_id)
        );
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding ON finding_evidence_events(finding_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_finding_evidence_event ON finding_evidence_events(event_id)")
    conn.commit()


def _migrate_idempotency_keys(conn: sqlite3.Connection) -> None:
    """Idempotent: ensure idempotency_keys table and index exist."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS idempotency_keys (
            key TEXT PRIMARY KEY,
            endpoint TEXT NOT NULL,
            response_code INTEGER NOT NULL,
            response_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_idempotency_keys_created ON idempotency_keys(created_at)")
    conn.commit()


def _migrate_events_extended_telemetry(conn: sqlite3.Connection) -> None:
    """Idempotent: add user, parent_image, parent_command_line, hashes,
    integrity_level, session_id, connection_status, process_guid to events,
    and source_health_json to agent_heartbeats.
    """
    event_cols = _column_names(conn, "events")
    for col in (
        "user", "parent_image", "parent_command_line", "hashes",
        "integrity_level", "session_id", "connection_status", "process_guid"
    ):
        if col not in event_cols:
            conn.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")

    hb_cols = _column_names(conn, "agent_heartbeats")
    if "source_health_json" not in hb_cols:
        conn.execute("ALTER TABLE agent_heartbeats ADD COLUMN source_health_json TEXT")
    conn.commit()


def _migrate_samples_platform_unknown(conn: sqlite3.Connection) -> None:
    """One-time rebuild of `samples` so its CHECK admits 'unknown' + the
    roadmap-2.2 reputation columns.

    SQLite cannot ALTER a CHECK constraint, so DBs created before the
    script/archive sniffing landed must be rebuilt (copy → drop → rename).
    Idempotent: skipped when the constraint already contains 'unknown'.
    """
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'samples'"
    ).fetchone()
    if row is None or "'unknown'" in row["sql"]:
        # Even with the right CHECK, earlier v2 builds lack the 2.2 columns
        # (and the vault's family label, added with the sample library).
        cols = _column_names(conn, "samples")
        for name, decl in (
            ("family", "TEXT"),
            ("vt_detections", "INTEGER"),
            ("malware_family", "TEXT"),
            ("yara_rules", "TEXT"),
        ):
            if name not in cols:
                conn.execute(f"ALTER TABLE samples ADD COLUMN {name} {decl}")
        conn.commit()
        return
    conn.execute(
        """
        CREATE TABLE samples_new (
            sample_id TEXT PRIMARY KEY,
            original_name TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            detected_platform TEXT NOT NULL
                CHECK(detected_platform IN ('windows', 'linux', 'macos', 'unknown')),
            size INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            family TEXT,
            vt_detections INTEGER,
            malware_family TEXT,
            yara_rules TEXT
        )
        """
    )
    conn.execute(
        "INSERT INTO samples_new SELECT sample_id, original_name, sha256, "
        "detected_platform, size, created_at, NULL, NULL, NULL, NULL FROM samples"
    )
    conn.execute("DROP TABLE samples")
    conn.execute("ALTER TABLE samples_new RENAME TO samples")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_sha256 ON samples(sha256)")
    conn.commit()


def _migrate_events_run_timestamp(conn: sqlite3.Connection) -> None:
    """Idempotent: ensure composite index on events(run_id, timestamp) exists."""
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_run_timestamp ON events(run_id, timestamp)")
    conn.commit()


def _migrate_audit_log_hash_chain(conn: sqlite3.Connection) -> None:
    """Idempotent: ensure tamper-evident hash chain columns, checkpoints, and immutability triggers on audit_log."""
    cols = _column_names(conn, "audit_log")
    if "outcome" not in cols:
        conn.execute("ALTER TABLE audit_log ADD COLUMN outcome TEXT NOT NULL DEFAULT 'success'")
    if "prev_hash" not in cols:
        conn.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT")
    if "entry_hash" not in cols:
        conn.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT")
    if "source_ip" not in cols:
        conn.execute("ALTER TABLE audit_log ADD COLUMN source_ip TEXT")
    if "before_state" not in cols:
        conn.execute("ALTER TABLE audit_log ADD COLUMN before_state TEXT")
    if "after_state" not in cols:
        conn.execute("ALTER TABLE audit_log ADD COLUMN after_state TEXT")
    if "reason" not in cols:
        conn.execute("ALTER TABLE audit_log ADD COLUMN reason TEXT")
    if "format_version" not in cols:
        conn.execute("ALTER TABLE audit_log ADD COLUMN format_version INTEGER DEFAULT 1")
    conn.commit()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_checkpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            checkpoint_seq INTEGER NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            last_audit_id INTEGER NOT NULL,
            last_entry_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            public_key TEXT NOT NULL
        )
        """
    )
    conn.commit()

    # Backfill hashes for any legacy rows lacking entry_hash
    rows = conn.execute("SELECT id, ts, actor, action, target_type, target_id, detail, outcome, prev_hash, entry_hash FROM audit_log ORDER BY id ASC").fetchall()
    if rows and any(r["entry_hash"] is None for r in rows):
        import hashlib
        prev = "0" * 64
        for r in rows:
            if r["entry_hash"]:
                prev = r["entry_hash"]
                continue
            outcome = r["outcome"] or "success"
            canonical = f"{prev}:{r['ts']}:{r['actor']}:{r['action']}:{r['target_type'] or ''}:{r['target_id'] or ''}:{outcome}:{r['detail'] or ''}"
            h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            conn.execute("UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE id = ?", (prev, h, r["id"]))
            prev = h
        conn.commit()

    # Install database-level immutability triggers (strictly abort UPDATE and DELETE)
    try:
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'Audit log is immutable: updates prohibited');
            END;
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'Audit log is immutable: deletes prohibited');
            END;
            """
        )
        conn.commit()
    except Exception:
        pass


def _migrate_host_containment_lifecycle(conn: sqlite3.Connection) -> None:
    """Idempotent: add lifecycle state and verification columns to host_containment."""
    existing_tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if "host_containment" not in existing_tables:
        return
    cols = _column_names(conn, "host_containment")
    if "containment_state" not in cols:
        conn.execute("ALTER TABLE host_containment ADD COLUMN containment_state TEXT NOT NULL DEFAULT 'released'")
    if "enforcement_mode" not in cols:
        conn.execute("ALTER TABLE host_containment ADD COLUMN enforcement_mode TEXT NOT NULL DEFAULT 'none'")
    if "probe_details" not in cols:
        conn.execute("ALTER TABLE host_containment ADD COLUMN probe_details TEXT")
    if "deadman_expires_at" not in cols:
        conn.execute("ALTER TABLE host_containment ADD COLUMN deadman_expires_at TEXT")
    conn.commit()


def _migrate_host_actions(conn: sqlite3.Connection) -> None:
    """Idempotent: ensure host_actions table exists."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS host_actions (
            action_id TEXT PRIMARY KEY,
            host_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            target TEXT,
            payload TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'pending',
            timeout_seconds INTEGER NOT NULL DEFAULT 300,
            result TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_host_actions_host_status ON host_actions(host_id, status)")
    conn.commit()


def _migrate_scope_reset_remove_soc_tables(conn: sqlite3.Connection) -> None:
    """Step 1 Scope Reset: Drop parked SOC and fleet tables from active database.

    Drops orphaned tables: investigations, investigation_notes,
    investigation_tags, investigation_refs, investigation_tasks,
    technique_validations, host_containment, host_actions,
    host_snapshots, host_baselines.
    """
    tables_to_drop = [
        "investigation_tasks",
        "investigation_refs",
        "investigation_tags",
        "investigation_notes",
        "investigations",
        "host_containment",
        "host_actions",
        "host_snapshots",
        "host_baselines",
    ]
    for tbl in tables_to_drop:
        conn.execute(f"DROP TABLE IF EXISTS {tbl}")
    conn.commit()


def _migrate_runs_origin(conn: sqlite3.Connection) -> None:
    """Add origin column to runs table with domain validation CHECK constraint."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(runs)").fetchall()}
    if "origin" not in cols:
        conn.execute(
            "ALTER TABLE runs ADD COLUMN origin TEXT NOT NULL DEFAULT 'observed' "
            "CHECK(origin IN ('observed', 'replayed', 'imported', 'simulated', 'test'))"
        )
    # Backfill explicit seed/synthetic markers only (never match on sample name patterns)
    conn.execute(
        """
        UPDATE runs SET origin = 'simulated'
        WHERE source IN ('seed', 'webapp-demo', 'simulation', 'sandbox:demo')
        """
    )
    conn.commit()


def _migrate_tables_origin(conn: sqlite3.Connection) -> None:
    """Add origin column and domain validation CHECK constraint to samples, events, alerts."""
    # 1. runs backfill (ensure seed/demo/simulation rows are marked simulated by explicit source marker only)
    conn.execute(
        """
        UPDATE runs SET origin = 'simulated'
        WHERE source IN ('seed', 'webapp-demo', 'simulation', 'sandbox:demo')
        """
    )

    # 2. samples (default to imported; backfill strictly by explicit sample_id or sha256, never by original_name)
    cols_samples = {r["name"] for r in conn.execute("PRAGMA table_info(samples)").fetchall()}
    if "origin" not in cols_samples:
        conn.execute(
            "ALTER TABLE samples ADD COLUMN origin TEXT NOT NULL DEFAULT 'imported' "
            "CHECK(origin IN ('observed', 'replayed', 'imported', 'simulated', 'test'))"
        )

    # 3. events (propagate from simulated runs)
    cols_events = {r["name"] for r in conn.execute("PRAGMA table_info(events)").fetchall()}
    if "origin" not in cols_events:
        conn.execute(
            "ALTER TABLE events ADD COLUMN origin TEXT NOT NULL DEFAULT 'observed' "
            "CHECK(origin IN ('observed', 'replayed', 'imported', 'simulated', 'test'))"
        )
    conn.execute(
        """
        UPDATE events SET origin = 'simulated'
        WHERE run_id IN (SELECT run_id FROM runs WHERE origin = 'simulated')
        """
    )

    # 4. alerts (propagate from simulated runs)
    cols_alerts = {r["name"] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    if "origin" not in cols_alerts:
        conn.execute(
            "ALTER TABLE alerts ADD COLUMN origin TEXT NOT NULL DEFAULT 'observed' "
            "CHECK(origin IN ('observed', 'replayed', 'imported', 'simulated', 'test'))"
        )
    conn.execute(
        """
        UPDATE alerts SET origin = 'simulated'
        WHERE run_id IN (SELECT run_id FROM runs WHERE origin = 'simulated')
        """
    )
    conn.commit()


def _migrate_analysis_telemetry_schema(conn: sqlite3.Connection) -> None:
    """Create normalized analysis_processes, analysis_events, and run_analysis_stats tables."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS analysis_processes (
            process_pk TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            host_pid INTEGER NOT NULL,
            ns_pid INTEGER,
            host_ppid INTEGER,
            ns_ppid INTEGER,
            start_time_us INTEGER NOT NULL,
            end_time_us INTEGER,
            initial_ppid INTEGER NOT NULL,
            current_ppid INTEGER NOT NULL,
            exe_path TEXT NOT NULL,
            command_line TEXT NOT NULL,
            process_name TEXT NOT NULL,
            host_id TEXT DEFAULT 'local',
            uid INTEGER,
            gid INTEGER,
            exit_code INTEGER,
            status TEXT DEFAULT 'running'
        );
        CREATE INDEX IF NOT EXISTS idx_analysis_processes_run ON analysis_processes(run_id);
        CREATE INDEX IF NOT EXISTS idx_analysis_processes_host_pid ON analysis_processes(run_id, host_pid);

        CREATE TABLE IF NOT EXISTS analysis_events (
            event_pk TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            seq INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            start_time_us INTEGER NOT NULL,
            mono_us INTEGER NOT NULL,
            process_pk TEXT REFERENCES analysis_processes(process_pk) ON DELETE SET NULL,
            category TEXT NOT NULL,
            event_type TEXT NOT NULL,
            action TEXT NOT NULL,
            source TEXT NOT NULL,
            origin TEXT NOT NULL,
            target_path TEXT,
            details TEXT,
            UNIQUE(run_id, seq)
        );
        CREATE INDEX IF NOT EXISTS idx_analysis_events_run_seq ON analysis_events(run_id, seq);
        CREATE INDEX IF NOT EXISTS idx_analysis_events_run_cat ON analysis_events(run_id, category);
        CREATE INDEX IF NOT EXISTS idx_analysis_events_process ON analysis_events(process_pk);

        CREATE TABLE IF NOT EXISTS run_analysis_stats (
            run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
            total_events INTEGER DEFAULT 0,
            process_count INTEGER DEFAULT 0,
            file_events_count INTEGER DEFAULT 0,
            network_events_count INTEGER DEFAULT 0,
            module_events_count INTEGER DEFAULT 0,
            dns_events_count INTEGER DEFAULT 0,
            suppressed_system_reads INTEGER DEFAULT 0,
            is_truncated INTEGER DEFAULT 0,
            truncation_reason TEXT
        );
        """
    )
    conn.commit()


def get_connection():
    """Open a connection with a Row factory and foreign keys on.

    Postgres runtime when `config.DATABASE_URL` is set (psycopg shim, FKs
    always enforced); otherwise raw sqlite3. Reads config.DATABASE_PATH
    lazily so tests can point the app at a throwaway DB by reassigning
    config.DATABASE_PATH.
    """
    if config.DATABASE_URL:
        raise RuntimeError("Postgres runtime is parked. OutPost operates on SQLite.")
    Path(config.DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


SCHEMA_MIGRATIONS_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    downgrade_note TEXT NOT NULL
);
"""

ORDERED_MIGRATIONS = [
    (1, "alerts_related_pids", _migrate_alerts_related_pids, "Rebuild alerts table to remove related_pids column."),
    (2, "alerts_triage", _migrate_alerts_triage, "Rebuild alerts table to remove triage columns."),
    (3, "alerts_assignee", _migrate_alerts_assignee, "Rebuild alerts table to drop assignee column."),
    (4, "alerts_findings", _migrate_alerts_findings, "Rebuild alerts table to drop finding columns."),
    (5, "agent_heartbeats_auth", _migrate_agent_heartbeats_auth, "Rebuild agent_heartbeats to drop auth tokens."),
    (6, "agent_heartbeats_metrics", _migrate_agent_heartbeats_metrics, "Rebuild agent_heartbeats to drop metrics."),
    (7, "enrolled_agents", _migrate_enrolled_agents, "Drop enrolled_agents table."),
    (8, "samples_platform_unknown", _migrate_samples_platform_unknown, "Revert samples check constraint via table recreation."),
    (9, "runs_platform_macos", _migrate_runs_platform_macos, "Revert runs platform check constraint via table recreation."),
    (10, "runs_kind", _migrate_runs_kind, "Rebuild runs table to drop kind column."),
    (11, "runs_source", _migrate_runs_source, "Rebuild runs table to drop source column."),
    (12, "events_host_id", _migrate_events_host_id, "Rebuild events table to drop host_id."),
    (13, "events_raw_record", _migrate_events_raw_record, "Rebuild events table to drop raw_record."),
    (14, "events_log_source", _migrate_events_log_source, "Rebuild events table to drop log_source."),
    (15, "backfill_events_log_source", _backfill_events_log_source, "Idempotent backfill — safe no-op on downgrade."),
    (16, "events_exe_path", _migrate_events_exe_path, "Rebuild events table to drop exe_path."),
    (17, "events_query", _migrate_events_query, "Rebuild events table to drop query."),
    (18, "events_tls_sni", _migrate_events_tls_sni, "Rebuild events table to drop tls_sni."),
    (19, "events_source_event_id", _migrate_events_source_event_id, "Rebuild events table to drop source_event_id."),
    (20, "events_boot_id", _migrate_events_boot_id, "Rebuild events table to drop boot_id."),
    (21, "events_process_start_time", _migrate_events_process_start_time, "Rebuild events table to drop process_start_time."),
    (22, "events_identity_indexes", _migrate_events_identity_indexes, "Drop composite identity indexes on events."),
    (23, "events_run_timestamp", _migrate_events_run_timestamp, "Drop idx_events_run_timestamp index."),
    (24, "runs_suppressed_alerts", _migrate_runs_suppressed_alerts, "Rebuild runs table to drop suppressed_alerts."),
    (25, "rule_suppressions_value", _migrate_rule_suppressions_value, "Rebuild rule_suppressions table."),
    (26, "alerts_evidence_and_dedup", _migrate_alerts_evidence_and_dedup, "Drop finding_evidence_events table and alerts deduplication columns."),
    (27, "idempotency_keys", _migrate_idempotency_keys, "Drop idempotency_keys table."),
    (28, "events_extended_telemetry", _migrate_events_extended_telemetry, "Rebuild events table to drop extended telemetry fields."),
    (29, "audit_log_hash_chain", _migrate_audit_log_hash_chain, "Drop audit_log triggers and chain columns."),
    (30, "host_containment_lifecycle", _migrate_host_containment_lifecycle, "Rebuild host_containment table."),
    (31, "host_actions", _migrate_host_actions, "Drop host_actions table."),
    (32, "scope_reset_remove_soc_tables", _migrate_scope_reset_remove_soc_tables, "Recreate dropped SOC and fleet tables."),
    (33, "runs_origin", _migrate_runs_origin, "Rebuild runs table to drop origin column."),
    (34, "tables_origin", _migrate_tables_origin, "Rebuild samples, events, alerts to drop origin column."),
    (35, "analysis_telemetry_schema", _migrate_analysis_telemetry_schema, "Drop analysis_processes, analysis_events, and run_analysis_stats tables."),
]

DESTRUCTIVE_MIGRATIONS = {32, 35}


def _backup_database_before_migration(conn: sqlite3.Connection) -> str | None:
    """Create an automated timestamped backup of the database file before applying destructive migrations using SQLite online backup API."""
    try:
        rows = conn.execute("PRAGMA database_list").fetchall()
        db_path = None
        for row in rows:
            name = row[1] if isinstance(row, tuple) else row["name"]
            path = row[2] if isinstance(row, tuple) else row["file"]
            if name == "main" and path:
                db_path = path
                break
        if db_path and os.path.exists(db_path):
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup_path = f"{db_path}.backup-{timestamp}"
            backup_conn = sqlite3.connect(backup_path)
            try:
                conn.backup(backup_conn)
            finally:
                backup_conn.close()
            logging.getLogger("outpost.db").info("Created atomic online backup before destructive migration: %s", backup_path)
            print(f"Created timestamped backup before destructive migration: {backup_path}")
            return backup_path
    except Exception as exc:
        logging.getLogger("outpost.db").warning("Failed to create pre-migration database backup: %s", exc)
    return None


def apply_migrations(conn: sqlite3.Connection, dry_run: bool = False) -> list[dict]:
    """Execute ordered schema migrations against the database.

    If dry_run is True, returns planned actions without executing them.
    """
    conn.executescript(SCHEMA_MIGRATIONS_TABLE)
    applied_rows = conn.execute("SELECT version, name, applied_at, downgrade_note FROM schema_migrations ORDER BY version ASC").fetchall()
    applied_versions = {r["version"] for r in applied_rows}

    # If any pending migration is destructive, create automated timestamped backup prior to execution
    pending = [ver for ver, _, _, _ in ORDERED_MIGRATIONS if ver not in applied_versions]
    if not dry_run and any(ver in DESTRUCTIVE_MIGRATIONS for ver in pending):
        _backup_database_before_migration(conn)

    results = []
    for ver, name, fn, downgrade_note in ORDERED_MIGRATIONS:
        if ver in applied_versions:
            results.append({
                "version": ver,
                "name": name,
                "status": "applied",
                "downgrade_note": downgrade_note,
            })
            continue

        if dry_run:
            results.append({
                "version": ver,
                "name": name,
                "status": "pending",
                "downgrade_note": downgrade_note,
            })
        else:
            fn(conn)
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT OR REPLACE INTO schema_migrations (version, name, applied_at, downgrade_note) VALUES (?, ?, ?, ?)",
                (ver, name, now_iso, downgrade_note),
            )
            conn.commit()
            results.append({
                "version": ver,
                "name": name,
                "status": "applied",
                "applied_at": now_iso,
                "downgrade_note": downgrade_note,
            })
    return results


def get_schema_version(conn: sqlite3.Connection) -> dict:
    """Return the current recorded schema version and summary."""
    try:
        conn.executescript(SCHEMA_MIGRATIONS_TABLE)
        row = conn.execute("SELECT MAX(version) AS current_version, COUNT(*) as total_applied FROM schema_migrations").fetchone()
        current_version = row["current_version"] if row and row["current_version"] is not None else 0
        total_applied = row["total_applied"] if row else 0
        latest = conn.execute("SELECT * FROM schema_migrations ORDER BY version DESC LIMIT 1").fetchone()
        return {
            "current_version": current_version,
            "target_version": ORDERED_MIGRATIONS[-1][0],
            "total_applied": total_applied,
            "total_available": len(ORDERED_MIGRATIONS),
            "latest_migration": dict(latest) if latest else None,
        }
    except Exception as e:
        return {
            "current_version": 0,
            "target_version": ORDERED_MIGRATIONS[-1][0] if ORDERED_MIGRATIONS else 0,
            "error": str(e),
        }


def list_migrations(conn: sqlite3.Connection) -> list[dict]:
    """List all migrations, their status, applied date, and downgrade notes."""
    conn.executescript(SCHEMA_MIGRATIONS_TABLE)
    applied = {
        r["version"]: dict(r)
        for r in conn.execute("SELECT * FROM schema_migrations").fetchall()
    }
    output = []
    for ver, name, _, downgrade_note in ORDERED_MIGRATIONS:
        if ver in applied:
            item = dict(applied[ver])
            item["status"] = "applied"
        else:
            item = {
                "version": ver,
                "name": name,
                "applied_at": None,
                "downgrade_note": downgrade_note,
                "status": "pending",
            }
        output.append(item)
    return output


def dry_run_migrations(conn: sqlite3.Connection) -> list[dict]:
    """Return pending migrations in execution order without modifying the database."""
    return apply_migrations(conn, dry_run=True)


def init_db() -> None:
    """Create tables if they don't exist and run ordered versioned migrations. Idempotent — safe on every boot.

    On the Postgres runtime the translated DDL (the final runtime shape) is
    applied instead — fresh PG installs start correct and skip the SQLite
    ALTER migrations entirely.
    """
    if config.DATABASE_URL:
        raise RuntimeError("Postgres runtime is parked. OutPost operates on SQLite.")
    with get_connection() as conn:
        conn.executescript(SCHEMA)
        apply_migrations(conn)


@contextmanager
def db_session() -> Iterator[sqlite3.Connection]:
    """Transactional session: commits on success, rolls back on error."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
