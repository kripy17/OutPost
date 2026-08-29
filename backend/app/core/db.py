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

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from . import config, db_pg

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
-- Postgres runtime executes the translated DDL in declaration order — PG
-- requires a FK target to exist when the referencing table is created,
-- while SQLite resolves FKs lazily. Definition order here must therefore
-- satisfy both engines.
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'created'
        CHECK(status IN ('created', 'triage', 'active', 'contained', 'resolved', 'closed')),
    severity TEXT,
    conclusion TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    closed_at TEXT
);

CREATE TABLE IF NOT EXISTS investigation_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL REFERENCES investigations(id),
    note TEXT NOT NULL,
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS investigation_tags (
    investigation_id TEXT NOT NULL REFERENCES investigations(id),
    tag TEXT NOT NULL,
    PRIMARY KEY (investigation_id, tag)
);

-- Evidence references are pointers, not copies: an investigation links to
-- artifacts/runs/hosts/iocs/campaigns by id, never duplicates their data.
-- UNIQUE(investigation_id, ref_type, ref_id) keeps attach/detach idempotent.
CREATE TABLE IF NOT EXISTS investigation_refs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id TEXT NOT NULL REFERENCES investigations(id),
    ref_type TEXT NOT NULL
        CHECK(ref_type IN ('artifact', 'run', 'host', 'ioc', 'campaign')),
    ref_id TEXT NOT NULL,
    added_at TEXT NOT NULL,
    UNIQUE (investigation_id, ref_type, ref_id)
);

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
    investigation_id TEXT REFERENCES investigations(id)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    platform TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
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
    -- TLS client-hello MD5 fingerprint (JA3) — feeds the known-C2 rule.
    ja3 TEXT
);

CREATE TABLE IF NOT EXISTS enrichment_cache (
    ip TEXT PRIMARY KEY,
    abuse_score INTEGER,
    vt_malicious_count INTEGER,
    reputation TEXT,
    checked_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_run_id ON events(run_id);
-- Composite covering the hot paths: ingest dedup range scan + the run
-- timeline's ORDER BY timestamp (lets SQLite stop at the index, no sort).
CREATE INDEX IF NOT EXISTS idx_events_run_ts ON events(run_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_dest_ip ON events(dest_ip);
CREATE INDEX IF NOT EXISTS idx_events_run_type ON events(run_id, event_type);
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
    detail TEXT
);

-- False-positive feedback loop: per-rule FP counters. Every "mark as false
-- positive" increments the rule's count; the run-detail UI reads these to
-- suggest threshold nudges / suppressions for noisy rules.
CREATE TABLE IF NOT EXISTS rule_fp (
    rule_id TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 1,
    last_fp_at TEXT NOT NULL
);

-- Latest live-system snapshot per host (processes + listening ports), shipped
-- by the collectors on an interval while an agent is running. Payload is the
-- JSON snapshot; the webapp renders it as the "running now" view.
CREATE TABLE IF NOT EXISTS host_snapshots (
    host_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    collected_at TEXT NOT NULL
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
    last_auth_at TEXT
);

-- Active host containment & remediation: stores isolation status and queued actions.
CREATE TABLE IF NOT EXISTS host_containment (
    host_id TEXT PRIMARY KEY,
    isolated INTEGER NOT NULL DEFAULT 0,
    isolated_at TEXT,
    isolated_by TEXT,
    reason TEXT,
    pending_actions TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL
);

-- Per-host behavioral baseline (roadmap 4.x): what binaries execute and which
-- IPs a host talks to, learned from its own telemetry. The learner upserts
-- counts on every ingested batch; the deviation check flags first-time
-- process/IPs once the baseline is established.
CREATE TABLE IF NOT EXISTS host_baselines (
    host_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('process', 'net')),
    value TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (host_id, kind, value)
);

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

-- docs/08 MVP-tier — domain reputation cache (abuse.ch URLhaus host lookup +
-- ThreatFox IOC→malware-family), keyed by the observed hostname (DNS query /
-- TLS SNI). Mirrors enrichment_cache/hash_cache TTL discipline: never
-- re-query a cached domain within the window.
CREATE TABLE IF NOT EXISTS domain_cache (
    domain TEXT PRIMARY KEY,
    urlhaus_status TEXT,
    threatfox_malware TEXT,
    threatfox_confidence INTEGER,
    reputation TEXT,
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
    # Findings queue hot path: status filter + triggered_at sort in one index.
    # Created post-migration (status column may not exist in ancient DBs).
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_status_time ON alerts(status, triggered_at)"
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


def _migrate_events_ja3(conn: sqlite3.Connection) -> None:
    """Idempotent: add the JA3 fingerprint column (known-C2 detection)."""
    cols = _column_names(conn, "events")
    if "ja3" not in cols:
        conn.execute("ALTER TABLE events ADD COLUMN ja3 TEXT")
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


def get_connection():
    """Open a connection with a Row factory and foreign keys on.

    Postgres runtime when `config.DATABASE_URL` is set (psycopg shim, FKs
    always enforced); otherwise raw sqlite3. Reads config.DATABASE_PATH
    lazily so tests can point the app at a throwaway DB by reassigning
    config.DATABASE_PATH.
    """
    if config.DATABASE_URL:
        return db_pg.pg_connection()
    Path(config.DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Create tables if they don't exist. Idempotent — safe on every boot.

    On the Postgres runtime the translated DDL (the final runtime shape) is
    applied instead — fresh PG installs start correct and skip the SQLite
    ALTER migrations entirely.
    """
    if config.DATABASE_URL:
        db_pg.pg_init_db()
        return
    with get_connection() as conn:
        conn.executescript(SCHEMA)
        _migrate_alerts_related_pids(conn)
        _migrate_alerts_triage(conn)
        _migrate_alerts_assignee(conn)
        _migrate_alerts_findings(conn)
        _migrate_agent_heartbeats_auth(conn)
        _migrate_samples_platform_unknown(conn)
        _migrate_runs_platform_macos(conn)
        _migrate_runs_kind(conn)
        _migrate_runs_source(conn)
        _migrate_events_host_id(conn)
        _migrate_events_raw_record(conn)
        _migrate_events_log_source(conn)
        _backfill_events_log_source(conn)
        _migrate_events_exe_path(conn)
        _migrate_events_query(conn)
        _migrate_events_tls_sni(conn)
        _migrate_events_ja3(conn)
        _migrate_runs_suppressed_alerts(conn)
        _migrate_rule_suppressions_value(conn)


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
