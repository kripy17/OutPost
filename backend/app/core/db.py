"""SQLite connection handling and schema initialization.

Raw `sqlite3` is used deliberately (AGENTS.md permits SQLAlchemy or raw
sqlite3) to keep the backend dependency-light and the schema fully explicit.
The schema below matches docs/02-BACKEND-SPEC.md exactly, including the
standout-feature tables created up front so migrations stay simple.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    sample_name TEXT NOT NULL,
    platform TEXT NOT NULL CHECK(platform IN ('windows', 'linux')),
    session_type TEXT NOT NULL DEFAULT 'analysis' CHECK(session_type IN ('live', 'analysis')),
    source TEXT NOT NULL DEFAULT 'monitor',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    suppressed_alerts TEXT
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
    assignee TEXT
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
    tls_sni TEXT
);

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
    reason TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_suppressions_rule ON rule_suppressions(rule_id);
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
    zero-config webapp path where events originate on the same machine."""
    if "host_id" not in _column_names(conn, "events"):
        conn.execute("ALTER TABLE events ADD COLUMN host_id TEXT NOT NULL DEFAULT 'local'")
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


def _migrate_runs_suppressed_alerts(conn: sqlite3.Connection) -> None:
    """Idempotent: per-rule alert-cap suppressed counts on the run (storm
    guard — burst-prone rules like first-seen cap per run; the counts are
    recorded so the cap is visible, not silent)."""
    cols = _column_names(conn, "runs")
    if "suppressed_alerts" not in cols:
        conn.execute("ALTER TABLE runs ADD COLUMN suppressed_alerts TEXT")
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


def get_connection() -> sqlite3.Connection:
    """Open a connection with a Row factory and foreign keys on.

    Reads config.DATABASE_PATH lazily so tests can point the app at a
    throwaway DB by reassigning config.DATABASE_PATH.
    """
    Path(config.DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Create tables if they don't exist. Idempotent — safe on every boot."""
    with get_connection() as conn:
        conn.executescript(SCHEMA)
        _migrate_alerts_related_pids(conn)
        _migrate_alerts_triage(conn)
        _migrate_alerts_assignee(conn)
        _migrate_agent_heartbeats_auth(conn)
        _migrate_samples_platform_unknown(conn)
        _migrate_runs_platform_macos(conn)
        _migrate_runs_source(conn)
        _migrate_events_host_id(conn)
        _migrate_events_raw_record(conn)
        _migrate_events_log_source(conn)
        _backfill_events_log_source(conn)
        _migrate_events_exe_path(conn)
        _migrate_events_query(conn)
        _migrate_events_tls_sni(conn)
        _migrate_runs_suppressed_alerts(conn)


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
