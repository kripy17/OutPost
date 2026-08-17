"""P0.1 schema foundations — focused tests for the additive P0 database layer.

Covers the five schema groups from the P0.1 specification:

1. investigations + notes/tags/refs
2. alerts finding columns (source/confidence/disposition/seen_at/investigation_id)
   + the unread partial index
3. iocs + ioc_provenance + ioc_findings
4. analysis_jobs persistence table
5. runs.kind profile column (with session_type backfill) + idx_events_host_id

Everything here is schema-level: no API, no DTOs, no business logic. The old-DB
tests simulate a pre-P0 database and prove init_db() migrates it without losing
data, because that is the entire P0.1 migration contract.
"""

import os
import sqlite3
import tempfile
from contextlib import contextmanager

import pytest

from ..core import config
from ..core.db import _column_names, get_connection, init_db
from ..models import run as run_store

NEW_TABLES = {
    "investigations",
    "investigation_notes",
    "investigation_tags",
    "investigation_refs",
    "iocs",
    "ioc_provenance",
    "ioc_findings",
    "analysis_jobs",
}

ALERT_COLUMNS = {"source", "confidence", "disposition", "seen_at", "investigation_id"}

RUNS_KIND = {"kind"}

INDEXES = {"idx_alerts_unread", "idx_events_host_id"}


@contextmanager
def _isolated_db():
    """Point the app at a throwaway DB, initialize it fresh, yield a conn.

    Restores config.DATABASE_PATH afterwards (get_connection reads it lazily,
    so tests can redirect the app at a temp file — see conftest)."""
    path = tempfile.mktemp(suffix=".db")
    old = config.DATABASE_PATH
    config.DATABASE_PATH = path
    try:
        init_db()
        with get_connection() as conn:
            yield conn
    finally:
        config.DATABASE_PATH = old
        if os.path.exists(path):
            os.remove(path)


def _tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {r[0] for r in rows}


def _indexes(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA index_list({table!r})").fetchall()
    return {r[1] for r in rows}


def _insert_alert(
    conn: sqlite3.Connection, run_id: str, *, severity: str = "malicious", **overrides
) -> int:
    """Insert a minimal valid alert row; returns its id."""
    values = {
        "run_id": run_id,
        "rule_id": "t-p0-rule",
        "rule_name": "P0 test rule",
        "severity": severity,
        "triggered_at": "2026-08-17T00:00:00+00:00",
        "details": "p0 test alert",
    }
    values.update(overrides)
    cols = ", ".join(values)
    marks = ", ".join("?" for _ in values)
    cur = conn.execute(
        f"INSERT INTO alerts ({cols}) VALUES ({marks})", list(values.values())
    )
    return cur.lastrowid


# ---------------------------------------------------------------------------
# A. Fresh database — tables, columns, indexes, constraints
# ---------------------------------------------------------------------------


def test_fresh_db_has_all_p0_tables():
    with _isolated_db() as conn:
        assert NEW_TABLES <= _tables(conn)


def test_fresh_db_alert_columns_and_defaults():
    with _isolated_db() as conn:
        cols = _column_names(conn, "alerts")
        assert ALERT_COLUMNS <= cols
        run_id = "fresh-alert-run"
        conn.execute(
            "INSERT INTO runs (run_id, sample_name, platform, session_type, kind, source, started_at) "
            "VALUES (?, 'x.bin', 'windows', 'analysis', 'analysis_job', 'cli', '2026-08-17T00:00:00+00:00')",
            (run_id,),
        )
        aid = _insert_alert(conn, run_id)
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (aid,)).fetchone()
        assert row["source"] == "detection"
        assert row["confidence"] is None
        assert row["disposition"] is None
        assert row["seen_at"] is None
        assert row["investigation_id"] is None


def test_fresh_db_runs_kind_default():
    with _isolated_db() as conn:
        assert "kind" in _column_names(conn, "runs")
        # Default is monitoring_session when kind is omitted (compat path).
        conn.execute(
            "INSERT INTO runs (run_id, sample_name, platform, session_type, source, started_at) "
            "VALUES ('no-kind', 'x.bin', 'linux', 'live', 'live', '2026-08-17T00:00:00+00:00')"
        )
        row = conn.execute("SELECT kind FROM runs WHERE run_id = 'no-kind'").fetchone()
        assert row["kind"] == "monitoring_session"


def test_fresh_db_required_indexes():
    with _isolated_db() as conn:
        assert "idx_alerts_unread" in _indexes(conn, "alerts")
        assert "idx_events_host_id" in _indexes(conn, "events")


# ---------------------------------------------------------------------------
# B. Existing database migration — data preserved, defaults + backfill applied
# ---------------------------------------------------------------------------

# The shape of a pre-P0 install: runs without kind/source/suppressed_alerts and
# without the macOS CHECK (so the copy/drop/rename rebuild runs), alerts
# without status/assignee or the finding columns.
_OLD_SCHEMA = """
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
    related_pids TEXT,
    details TEXT NOT NULL
);
"""


def _old_db() -> str:
    path = tempfile.mktemp(suffix=".db")
    conn = sqlite3.connect(path)
    conn.executescript(_OLD_SCHEMA)
    conn.execute(
        "INSERT INTO runs (run_id, sample_name, platform, session_type, started_at, completed_at) "
        "VALUES ('old-live', 'watch.bin', 'linux', 'live', '2026-08-01T00:00:00+00:00', NULL)"
    )
    conn.execute(
        "INSERT INTO runs (run_id, sample_name, platform, session_type, started_at, completed_at) "
        "VALUES ('old-analysis', 'sample.exe', 'windows', 'analysis', '2026-08-02T00:00:00+00:00', '2026-08-02T00:01:00+00:00')"
    )
    for run_id, sev, ip in (
        ("old-live", "malicious", "203.0.113.9"),
        ("old-analysis", "suspicious", "198.51.100.7"),
    ):
        conn.execute(
            "INSERT INTO alerts (run_id, rule_id, rule_name, severity, triggered_at, related_ip, details) "
            "VALUES (?, 'old-rule', 'Old Rule', ?, '2026-08-01T00:00:00+00:00', ?, 'pre-p0 alert')",
            (run_id, sev, ip),
        )
    conn.commit()
    conn.close()
    return path


@contextmanager
def _migrate_old_db():
    """Point the app at a pre-P0 DB and run the full init_db() migration chain."""
    path = _old_db()
    old = config.DATABASE_PATH
    config.DATABASE_PATH = path
    try:
        init_db()
        with get_connection() as conn:
            yield conn
    finally:
        config.DATABASE_PATH = old
        if os.path.exists(path):
            os.remove(path)


def test_old_db_migrates_with_data_and_new_tables():
    with _migrate_old_db() as conn:
        # Both old runs survive, with session_type intact and kind backfilled.
        runs = {r["run_id"]: r for r in conn.execute("SELECT * FROM runs").fetchall()}
        assert set(runs) == {"old-live", "old-analysis"}
        assert runs["old-live"]["session_type"] == "live"
        assert runs["old-live"]["kind"] == "monitoring_session"
        assert runs["old-analysis"]["session_type"] == "analysis"
        assert runs["old-analysis"]["kind"] == "analysis_job"

        # Both old alerts survive with the finding defaults.
        alerts = conn.execute(
            "SELECT * FROM alerts WHERE rule_id = 'old-rule' ORDER BY id"
        ).fetchall()
        assert len(alerts) == 2
        for a in alerts:
            assert a["source"] == "detection"
            assert a["confidence"] is None
            assert a["disposition"] is None
            assert a["seen_at"] is None
            assert a["investigation_id"] is None
            assert a["status"] == "open"
        assert {a["related_ip"] for a in alerts} == {"203.0.113.9", "198.51.100.7"}

        # Everything else landed too.
        assert NEW_TABLES <= _tables(conn)
        assert "idx_alerts_unread" in _indexes(conn, "alerts")
        assert "idx_events_host_id" in _indexes(conn, "events")


def test_mid_era_db_migrates_without_rebuild():
    """A DB created after the macOS rebuild + triage pass — only the P0 ALTERs
    apply (no copy/drop/rename of runs)."""
    path = tempfile.mktemp(suffix=".db")
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE runs (
            run_id TEXT PRIMARY KEY,
            sample_name TEXT NOT NULL,
            platform TEXT NOT NULL CHECK(platform IN ('windows', 'linux', 'macos')),
            session_type TEXT NOT NULL DEFAULT 'analysis' CHECK(session_type IN ('live', 'analysis')),
            source TEXT NOT NULL DEFAULT 'monitor',
            started_at TEXT NOT NULL,
            completed_at TEXT,
            suppressed_alerts TEXT
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
            related_pids TEXT,
            details TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'acknowledged', 'resolved')),
            status_comment TEXT,
            status_at TEXT,
            assignee TEXT
        );
        """
    )
    conn.execute(
        "INSERT INTO runs (run_id, sample_name, platform, session_type, source, started_at) "
        "VALUES ('mid-analysis', 'mid.exe', 'windows', 'analysis', 'cli', '2026-08-03T00:00:00+00:00')"
    )
    conn.commit()
    conn.close()
    old = config.DATABASE_PATH
    config.DATABASE_PATH = path
    try:
        init_db()
        with get_connection() as c:
            row = c.execute("SELECT kind FROM runs WHERE run_id = 'mid-analysis'").fetchone()
            assert row["kind"] == "analysis_job"
            assert "idx_alerts_unread" in _indexes(c, "alerts")
            assert "idx_events_host_id" in _indexes(c, "events")
    finally:
        config.DATABASE_PATH = old
        if os.path.exists(path):
            os.remove(path)


# ---------------------------------------------------------------------------
# C. Idempotency
# ---------------------------------------------------------------------------


def test_init_db_is_idempotent_on_migrated_db():
    path = _old_db()
    old = config.DATABASE_PATH
    config.DATABASE_PATH = path
    try:
        init_db()  # first migration
        with get_connection() as conn:
            before = {
                "runs": conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()["n"],
                "alerts": conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"],
            }
        init_db()  # second run against the same (already migrated) DB
        with get_connection() as conn:
            after = {
                "runs": conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()["n"],
                "alerts": conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"],
            }
            assert after == before
            assert NEW_TABLES <= _tables(conn)
            # The unread index exists exactly once (idempotent re-creation).
            assert "idx_alerts_unread" in _indexes(conn, "alerts")
    finally:
        config.DATABASE_PATH = old
        if os.path.exists(path):
            os.remove(path)


def test_init_db_is_idempotent_on_fresh_db():
    with _isolated_db() as conn:
        tables_before = _tables(conn)
    init_db()
    with get_connection() as conn:
        assert _tables(conn) == tables_before


# ---------------------------------------------------------------------------
# D. CHECK constraints — invalid enum values rejected
# ---------------------------------------------------------------------------


def test_invalid_investigation_status_rejected():
    with _isolated_db() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO investigations (id, title, status, created_at) "
                "VALUES ('inv-1', 'x', 'bogus', '2026-08-17T00:00:00+00:00')"
            )
        conn.execute(
            "INSERT INTO investigations (id, title, status, created_at) "
            "VALUES ('inv-1', 'x', 'active', '2026-08-17T00:00:00+00:00')"
        )


def test_invalid_ioc_type_and_disposition_rejected():
    with _isolated_db() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO iocs (ioc_id, value, type, disposition, first_seen) "
                "VALUES ('ioc-1', '1.2.3.4', 'ipaddr', 'candidate', '2026-08-17T00:00:00+00:00')"
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO iocs (ioc_id, value, type, disposition, first_seen) "
                "VALUES ('ioc-1', '1.2.3.4', 'ip', 'unknown', '2026-08-17T00:00:00+00:00')"
            )
        # Valid row inserts once disposition/type are in range.
        conn.execute(
            "INSERT INTO iocs (ioc_id, value, type, disposition, first_seen) "
            "VALUES ('ioc-1', '1.2.3.4', 'ip', 'enriched', '2026-08-17T00:00:00+00:00')"
        )


def test_invalid_alert_source_confidence_disposition_rejected():
    with _isolated_db() as conn:
        conn.execute(
            "INSERT INTO runs (run_id, sample_name, platform, session_type, kind, source, started_at) "
            "VALUES ('cstr-run', 'c.bin', 'windows', 'analysis', 'analysis_job', 'cli', '2026-08-17T00:00:00+00:00')"
        )
        for kwargs in (
            {"source": "machine"},
            {"confidence": "certain"},
            {"disposition": "guilty"},
        ):
            with pytest.raises(sqlite3.IntegrityError):
                _insert_alert(conn, "cstr-run", **kwargs)
        # Valid verdict vocabulary inserts fine.
        _insert_alert(
            conn,
            "cstr-run",
            source="analyst",
            confidence="high",
            disposition="confirmed-malicious",
        )


def test_invalid_analysis_job_backend_and_status_rejected():
    with _isolated_db() as conn:
        conn.execute(
            "INSERT INTO runs (run_id, sample_name, platform, session_type, kind, source, started_at) "
            "VALUES ('job-run', 'j.bin', 'windows', 'analysis', 'analysis_job', 'cli', '2026-08-17T00:00:00+00:00')"
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO analysis_jobs (run_id, backend, status) VALUES ('job-run', 'vm', 'queued')"
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO analysis_jobs (run_id, backend, status) VALUES ('job-run', 'static', 'done')"
            )
        conn.execute(
            "INSERT INTO analysis_jobs (run_id, backend, status, progress) "
            "VALUES ('job-run', 'static', 'running', 42)"
        )


def test_invalid_run_kind_rejected():
    with _isolated_db() as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO runs (run_id, sample_name, platform, session_type, kind, source, started_at) "
            "VALUES ('bad-kind', 'b.bin', 'windows', 'analysis', 'session', 'cli', '2026-08-17T00:00:00+00:00')"
        )


def test_iocs_unique_value_type():
    with _isolated_db() as conn:
        conn.execute(
            "INSERT INTO iocs (ioc_id, value, type, first_seen) "
            "VALUES ('ioc-1', '203.0.113.5', 'ip', '2026-08-17T00:00:00+00:00')"
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO iocs (ioc_id, value, type, first_seen) "
                "VALUES ('ioc-2', '203.0.113.5', 'ip', '2026-08-17T00:00:00+00:00')"
            )
        # Same value under a different type is a different IOC.
        conn.execute(
            "INSERT INTO iocs (ioc_id, value, type, first_seen) "
            "VALUES ('ioc-3', '203.0.113.5', 'domain', '2026-08-17T00:00:00+00:00')"
        )


# ---------------------------------------------------------------------------
# E. Foreign keys
# ---------------------------------------------------------------------------


def test_investigation_references_work():
    with _isolated_db() as conn:
        conn.execute(
            "INSERT INTO investigations (id, title, status, created_at) "
            "VALUES ('inv-fk', 'Case', 'active', '2026-08-17T00:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO investigation_notes (investigation_id, note, actor, created_at) "
            "VALUES ('inv-fk', 'note', 'analyst', '2026-08-17T00:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO investigation_tags (investigation_id, tag) VALUES ('inv-fk', 'tag1')"
        )
        conn.execute(
            "INSERT INTO investigation_refs (investigation_id, ref_type, ref_id, added_at) "
            "VALUES ('inv-fk', 'run', 'some-run', '2026-08-17T00:00:00+00:00')"
        )
        # Attach/detach stays idempotent — duplicate ref is rejected.
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO investigation_refs (investigation_id, ref_type, ref_id, added_at) "
                "VALUES ('inv-fk', 'run', 'some-run', '2026-08-17T00:00:00+00:00')"
            )
        # Orphaned children are rejected.
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO investigation_refs (investigation_id, ref_type, ref_id, added_at) "
                "VALUES ('missing', 'run', 'r', '2026-08-17T00:00:00+00:00')"
            )


def test_alert_investigation_fk():
    with _isolated_db() as conn:
        conn.execute(
            "INSERT INTO runs (run_id, sample_name, platform, session_type, kind, source, started_at) "
            "VALUES ('fk-run', 'f.bin', 'windows', 'analysis', 'analysis_job', 'cli', '2026-08-17T00:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO investigations (id, title, status, created_at) "
            "VALUES ('inv-a', 'Case A', 'triage', '2026-08-17T00:00:00+00:00')"
        )
        aid = _insert_alert(conn, "fk-run", investigation_id="inv-a")
        row = conn.execute("SELECT investigation_id FROM alerts WHERE id = ?", (aid,)).fetchone()
        assert row["investigation_id"] == "inv-a"
        with pytest.raises(sqlite3.IntegrityError):
            _insert_alert(conn, "fk-run", investigation_id="inv-nope")


def test_ioc_provenance_and_findings_fk():
    with _isolated_db() as conn:
        conn.execute(
            "INSERT INTO iocs (ioc_id, value, type, first_seen) "
            "VALUES ('ioc-fk', '203.0.113.99', 'ip', '2026-08-17T00:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO ioc_provenance (ioc_id, ref_type, ref_id, first_seen) "
            "VALUES ('ioc-fk', 'event', 'evt-1', '2026-08-17T00:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO runs (run_id, sample_name, platform, session_type, kind, source, started_at) "
            "VALUES ('ioc-run', 'i.bin', 'windows', 'analysis', 'analysis_job', 'cli', '2026-08-17T00:00:00+00:00')"
        )
        aid = _insert_alert(conn, "ioc-run")
        conn.execute(
            "INSERT INTO ioc_findings (ioc_id, finding_id) VALUES ('ioc-fk', ?)", (aid,)
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO ioc_provenance (ioc_id, ref_type, ref_id, first_seen) "
                "VALUES ('ioc-missing', 'event', 'evt-2', '2026-08-17T00:00:00+00:00')"
            )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO ioc_findings (ioc_id, finding_id) VALUES ('ioc-fk', 999999)"
            )


def test_analysis_job_run_fk():
    with _isolated_db() as conn:
        conn.execute(
            "INSERT INTO runs (run_id, sample_name, platform, session_type, kind, source, started_at) "
            "VALUES ('aj-run', 'a.bin', 'linux', 'analysis', 'analysis_job', 'cli', '2026-08-17T00:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO analysis_jobs (run_id, backend, status) VALUES ('aj-run', 'watched-host', 'completed')"
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO analysis_jobs (run_id, backend, status) VALUES ('aj-missing', 'static', 'queued')"
            )


# ---------------------------------------------------------------------------
# Run creation path — kind is stamped, never left to drift
# ---------------------------------------------------------------------------


def test_create_run_stamps_kind_from_session_type():
    with _isolated_db() as conn:
        run_store.create_run(conn, "rk-analysis", "a.exe", "windows", session_type="analysis", source="cli")
        run_store.create_run(conn, "rk-live", "w.bin", "linux", session_type="live", source="live")
        rows = {r["run_id"]: r["kind"] for r in conn.execute("SELECT run_id, kind FROM runs").fetchall()}
        assert rows == {"rk-analysis": "analysis_job", "rk-live": "monitoring_session"}
