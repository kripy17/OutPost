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
    started_at TEXT NOT NULL,
    completed_at TEXT
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
    details TEXT NOT NULL
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
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT,
    file_path TEXT,
    registry_key TEXT
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
CREATE INDEX IF NOT EXISTS idx_alerts_run_id ON alerts(run_id);

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

-- Roadmap 3.1 — notification settings (webhook endpoint, toggle).
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
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
        _migrate_samples_platform_unknown(conn)
        _migrate_runs_platform_macos(conn)


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
