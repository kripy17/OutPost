"""Test audit logging model invariants.

Verifies:
1. audit.log persists structured audit records.
2. audit.log rejects unrecognized arguments with TypeError (no *args/**kwargs silent swallowing).
3. audit.log raises database exceptions instead of silently swallowing them.
"""

import sqlite3

import pytest

from ..models import audit


def test_audit_log_success():
    conn = sqlite3.connect(":memory:")
    conn.execute(
        """
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            detail TEXT,
            outcome TEXT NOT NULL,
            source_ip TEXT,
            before_state TEXT,
            after_state TEXT,
            reason TEXT
        )
        """
    )
    audit.log(
        conn,
        actor="analyst",
        action="sample.upload",
        target_type="sample",
        target_id="s-123",
        detail="uploaded benign.sh",
        outcome="success",
        before_state={"status": "none"},
        after_state={"status": "ready"},
        reason="initial analysis",
    )
    row = conn.execute("SELECT * FROM audit_log").fetchone()
    assert row is not None
    assert row[2] == "analyst"
    assert row[3] == "sample.upload"
    assert row[4] == "sample"
    assert row[5] == "s-123"
    assert row[6] == "uploaded benign.sh"
    assert row[7] == "success"
    assert '{"status": "none"}' in row[9]
    assert '{"status": "ready"}' in row[10]
    assert row[11] == "initial analysis"


def test_audit_log_rejects_unknown_arguments():
    conn = sqlite3.connect(":memory:")
    with pytest.raises(TypeError):
        # invalid keyword argument
        audit.log(conn, actor="analyst", action="sample.upload", unknown_param="bad")

    with pytest.raises(TypeError):
        # extra positional argument
        audit.log(conn, "analyst", "sample.upload", "sample", "s-123", "detail", "success", "127.0.0.1", None, None, None, "extra_pos_arg")


def test_audit_log_propagates_db_exceptions():
    conn = sqlite3.connect(":memory:")
    # audit_log table does not exist
    with pytest.raises(sqlite3.OperationalError):
        audit.log(conn, actor="analyst", action="test")
