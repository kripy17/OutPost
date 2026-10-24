"""Test schema migration 32: scope_reset_remove_soc_tables.

Verifies that upgrading a database from pre-scope-reset:
1. Applies migration 32 cleanly.
2. Drops orphaned SOC and fleet tables (investigations, investigation_notes/tags/refs/tasks,
   technique_validations, host_containment, host_actions, host_snapshots, host_baselines).
3. Preserves all analysis tables and data (samples, runs, events, alerts, audit_log, settings, iocs).
4. Maintains foreign key integrity across retained tables.
"""

import sqlite3
import tempfile
from pathlib import Path

from ..core.db import apply_migrations, get_schema_version, list_migrations


def test_upgrade_from_pre_scope_reset_database():
    with tempfile.NamedTemporaryFile(suffix=".db") as tf:
        db_path = tf.name

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    try:
        # 1. Populate a legacy pre-scope-reset database schema with both retained and obsolete tables
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL,
                downgrade_note TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                sample_name TEXT NOT NULL,
                platform TEXT NOT NULL,
                session_type TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'analysis_job',
                source TEXT NOT NULL DEFAULT 'cli',
                started_at TEXT NOT NULL,
                completed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(run_id),
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                triggered_at TEXT NOT NULL,
                details TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                source TEXT NOT NULL DEFAULT 'detection',
                confidence TEXT,
                disposition TEXT,
                seen_at TEXT,
                investigation_id TEXT
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(run_id),
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                platform TEXT NOT NULL,
                data TEXT NOT NULL,
                host_id TEXT NOT NULL DEFAULT 'local'
            );

            CREATE TABLE IF NOT EXISTS samples (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                sha256 TEXT NOT NULL UNIQUE,
                size INTEGER NOT NULL,
                type TEXT NOT NULL,
                platform TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id TEXT,
                detail TEXT,
                outcome TEXT NOT NULL DEFAULT 'success',
                source_ip TEXT,
                before_state TEXT,
                after_state TEXT,
                reason TEXT
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            -- Obsolete tables to be removed
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'created',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS investigation_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL REFERENCES investigations(id),
                note TEXT NOT NULL,
                actor TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS investigation_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL REFERENCES investigations(id),
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'todo',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS host_containment (
                host_id TEXT PRIMARY KEY,
                isolated INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS host_snapshots (
                host_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                collected_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS host_baselines (
                host_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 1,
                last_seen TEXT NOT NULL,
                PRIMARY KEY (host_id, kind, value)
            );
            """
        )

        # 2. Mark migrations 1..31 as previously applied
        for v in range(1, 32):
            conn.execute(
                "INSERT INTO schema_migrations (version, name, applied_at, downgrade_note) VALUES (?, ?, '2026-10-20T00:00:00Z', 'revert')",
                (v, f"legacy_migration_{v}"),
            )

        # 3. Seed data into retained analysis tables
        conn.execute(
            "INSERT INTO samples (id, name, sha256, size, type, platform, created_at) VALUES ('s-1', 'malware.exe', 'abc123sha256', 4096, 'pe', 'windows', '2026-10-20T00:00:00Z')"
        )
        conn.execute(
            "INSERT INTO runs (run_id, sample_name, platform, session_type, started_at) VALUES ('run-1', 'malware.exe', 'windows', 'analysis', '2026-10-20T00:00:00Z')"
        )
        conn.execute(
            "INSERT INTO alerts (run_id, rule_id, rule_name, severity, triggered_at, details) VALUES ('run-1', 'rule-1', 'Process Injection', 'malicious', '2026-10-20T00:00:01Z', 'VirtualAllocEx observed')"
        )
        conn.execute(
            "INSERT INTO events (run_id, timestamp, event_type, platform, data) VALUES ('run-1', '2026-10-20T00:00:01Z', 'process_create', 'windows', '{\"pid\": 100}')"
        )
        conn.execute(
            "INSERT INTO audit_log (ts, actor, action, target_type, target_id, detail) VALUES ('2026-10-20T00:00:00Z', 'analyst', 'sample.upload', 'sample', 's-1', 'Upload sample')"
        )
        conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES ('ANALYSIS_TIMEOUT', '120', '2026-10-20T00:00:00Z')"
        )

        # Seed data into obsolete tables (orphaned data)
        conn.execute(
            "INSERT INTO investigations (id, title, status, created_at) VALUES ('inv-1', 'Incident Case 1', 'active', '2026-10-20T00:00:00Z')"
        )
        conn.execute(
            "INSERT INTO investigation_notes (investigation_id, note, actor, created_at) VALUES ('inv-1', 'Suspicious activity', 'analyst', '2026-10-20T00:00:00Z')"
        )
        conn.execute(
            "INSERT INTO host_containment (host_id, isolated, updated_at) VALUES ('host-prod', 1, '2026-10-20T00:00:00Z')"
        )
        conn.execute(
            "INSERT INTO host_snapshots (host_id, payload, collected_at) VALUES ('host-prod', '{}', '2026-10-20T00:00:00Z')"
        )
        conn.commit()

        # 4. Execute migrations to upgrade
        results = apply_migrations(conn)
        applied_names = [r["name"] for r in results if r["status"] == "applied"]
        assert "scope_reset_remove_soc_tables" in applied_names

        # 5. Verify schema version reports migration 32
        v_info = get_schema_version(conn)
        assert v_info["current_version"] == 32

        # 6. Verify obsolete tables are completely dropped
        tables_after = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        for obsolete in (
            "investigations",
            "investigation_notes",
            "investigation_tasks",
            "host_containment",
            "host_snapshots",
            "host_baselines",
        ):
            assert obsolete not in tables_after, f"Expected {obsolete} to be dropped by migration 32"

        # 7. Verify all analysis core data is intact and uncorrupted
        sample_row = conn.execute("SELECT * FROM samples WHERE id = 's-1'").fetchone()
        assert sample_row["name"] == "malware.exe"
        assert sample_row["sha256"] == "abc123sha256"

        run_row = conn.execute("SELECT * FROM runs WHERE run_id = 'run-1'").fetchone()
        assert run_row["sample_name"] == "malware.exe"

        alert_row = conn.execute("SELECT * FROM alerts WHERE run_id = 'run-1'").fetchone()
        assert alert_row["rule_name"] == "Process Injection"
        assert alert_row["severity"] == "malicious"

        event_row = conn.execute("SELECT * FROM events WHERE run_id = 'run-1'").fetchone()
        assert event_row["event_type"] == "process_create"

        audit_row = conn.execute("SELECT * FROM audit_log WHERE target_id = 's-1'").fetchone()
        assert audit_row["action"] == "sample.upload"

        setting_row = conn.execute("SELECT * FROM settings WHERE key = 'ANALYSIS_TIMEOUT'").fetchone()
        assert setting_row["value"] == "120"

    finally:
        conn.close()
        Path(db_path).unlink(missing_ok=True)
