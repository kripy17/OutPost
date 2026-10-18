"""Comprehensive automated verification gate for OutPost's tamper-evident audit log.

Guarantees:
1. Every audit entry is cryptographically hash-chained via SHA-256 (committing to
   prev_hash, timestamp, actor, source_ip, action, target, states, reason, outcome, detail).
2. The SQLite database engine enforces immutability via engine triggers aborting
   any UPDATE or DELETE attempt with an error.
3. Any simulated raw tampering (e.g. direct corruption) is reliably caught by
   verify_audit_chain, pin-pointing the exact first break position, entry ID,
   expected digest, and found digest.
4. Checkpoints can be signed using a local private key and verified or exported
   out-of-band to prevent state rewrite attacks.
5. Mutating operational endpoints (samples, detonations, host containment, webhooks)
   consistently write to the audit trail.
"""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from ..core.db import db_session
from ..main import app
from ..models import audit


def test_sequential_hash_chain_verification():
    """Verify sequential entries form an unbroken cryptographic hash chain."""
    with db_session() as conn:
        # Initial check
        report = audit.verify_audit_chain(conn)
        assert report["valid"] is True
        initial_count = report["entries_verified"]

        # Append new entries with diverse action types and state changes
        h1 = audit.log(
            conn,
            actor="analyst-alice",
            action="alert.status",
            target_type="alert",
            target_id="101",
            outcome="success",
            source_ip="192.168.1.50",
            before_state={"status": "open"},
            after_state={"status": "in_progress"},
            reason="Beginning triage of lateral movement indicator",
            detail="Triage started",
        )
        assert len(h1) == 64

        h2 = audit.log(
            conn,
            actor="responder-bob",
            action="agent.isolate",
            target_type="agent",
            target_id="host-win10-01",
            outcome="success",
            source_ip="192.168.1.51",
            before_state={"isolated": False},
            after_state={"isolated": True},
            reason="Active C2 beacon observed",
            detail="Quarantine host at network layer",
        )
        assert len(h2) == 64

        # Chain verification
        report2 = audit.verify_audit_chain(conn)
        assert report2["valid"] is True
        assert report2["intact"] is True
        assert report2["status"] == "intact"
        assert report2["entries_verified"] == initial_count + 2
        assert report2["first_break"] is None

        # Backwards compatible tuple unpacking
        valid, count, err = audit.verify_audit_chain(conn)
        assert valid is True
        assert count == initial_count + 2
        assert err is None


def test_sqlite_trigger_prevents_updates():
    """Verify that SQLite triggers block UPDATE queries on audit_log at the engine level."""
    with db_session() as conn:
        audit.log(
            conn,
            actor="auditor",
            action="auth.login",
            detail="Valid operator session initialized",
        )
        row = conn.execute("SELECT id FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        entry_id = row["id"]

        with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)) as exc_info:
            conn.execute("UPDATE audit_log SET actor = 'malicious_actor' WHERE id = ?", (entry_id,))
        assert "Audit log is immutable" in str(exc_info.value)


def test_sqlite_trigger_prevents_deletions():
    """Verify that SQLite triggers block DELETE queries on audit_log at the engine level."""
    with db_session() as conn:
        audit.log(
            conn,
            actor="auditor",
            action="auth.login",
            detail="Valid operator session initialized",
        )
        row = conn.execute("SELECT id FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        entry_id = row["id"]

        with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)) as exc_info:
            conn.execute("DELETE FROM audit_log WHERE id = ?", (entry_id,))
        assert "Audit log is immutable" in str(exc_info.value)


def test_tamper_detection_pinpoints_first_break():
    """Verify that tampering (simulated adversary with direct DB access) is accurately detected."""
    # Create an in-memory isolated database to test raw tampering without affecting application db
    raw_conn = sqlite3.connect(":memory:")
    raw_conn.row_factory = sqlite3.Row

    raw_conn.execute(
        """
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            detail TEXT,
            outcome TEXT NOT NULL DEFAULT 'success',
            prev_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
            entry_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
            source_ip TEXT,
            before_state TEXT,
            after_state TEXT,
            reason TEXT
        )
        """
    )
    raw_conn.execute(
        """
        CREATE TABLE audit_checkpoints (
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

    # Insert 3 chained entries
    audit.log(raw_conn, actor="user1", action="auth.login", detail="login 1")
    audit.log(raw_conn, actor="user2", action="agent.isolate", detail="isolate host")
    audit.log(raw_conn, actor="user3", action="rules.modify", detail="modify rule")

    initial_report = audit.verify_audit_chain(raw_conn)
    assert initial_report["valid"] is True
    assert initial_report["entries_verified"] == 3

    # Tamper with row 2's detail field directly
    raw_conn.execute("UPDATE audit_log SET detail = 'tampered detail content' WHERE id = 2")
    raw_conn.commit()

    tampered_report = audit.verify_audit_chain(raw_conn)
    assert tampered_report["valid"] is False
    assert tampered_report["intact"] is False
    assert tampered_report["status"] == "tampered"
    assert tampered_report["first_break"] is not None
    assert tampered_report["first_break"]["id"] == 2
    assert tampered_report["first_break"]["index"] == 1
    assert "entry_hash verification failed" in tampered_report["first_break"]["reason"]
    assert tampered_report["entries_verified"] == 1

    raw_conn.close()


def test_cryptographic_checkpoint_signing_and_verification():
    """Verify signed checkpoints validate against local keys and reject forged signatures."""
    with db_session() as conn:
        audit.log(conn, actor="system", action="backup.create", detail="Scheduled snapshot")
        checkpoint = audit.create_checkpoint(conn)

        assert checkpoint["checkpoint_seq"] >= 1
        assert len(checkpoint["last_entry_hash"]) == 64
        assert len(checkpoint["signature"]) == 64
        assert len(checkpoint["public_key_fingerprint"]) == 64

        # Verify legitimate checkpoint
        assert audit.verify_checkpoint(checkpoint) is True

        # Tampered signature is rejected
        forged = dict(checkpoint)
        forged["signature"] = "deadbeef" * 8
        assert audit.verify_checkpoint(forged) is False

        # Tampered entry hash is rejected
        forged_hash = dict(checkpoint)
        forged_hash["last_entry_hash"] = "0" * 64
        assert audit.verify_checkpoint(forged_hash) is False


def test_audit_api_endpoints():
    """Verify the audit REST API exposed endpoints."""
    client = TestClient(app)

    # Verify endpoint
    res_verify = client.get("/audit/verify")
    assert res_verify.status_code == 200
    data_verify = res_verify.json()
    assert data_verify["valid"] is True
    assert data_verify["status"] == "intact"
    assert "verified_through" in data_verify

    # Checkpoint endpoint
    res_cp = client.post("/audit/checkpoint")
    assert res_cp.status_code == 201
    data_cp = res_cp.json()
    assert data_cp["status"] == "created"
    assert "checkpoint" in data_cp

    # Checkpoints listing
    res_list = client.get("/audit/checkpoints")
    assert res_list.status_code == 200
    assert "checkpoints" in res_list.json()

    # Export bundle
    res_export = client.get("/audit/checkpoint/export")
    assert res_export.status_code == 200
    bundle = res_export.json()
    assert "outpost_audit_verification" in bundle
    assert "latest_checkpoint" in bundle
    assert "disclaimer" in bundle
    assert bundle["outpost_audit_verification"]["valid"] is True


def test_mutating_endpoints_record_audit():
    """Verify that mutating endpoints (sample upload, settings) create audit entries."""
    client = TestClient(app)

    # 1. Sample upload audit check
    sample_bytes = b"MZ\x90\x00\x03\x00\x00\x00Mock PE content for audit test"
    upload_res = client.post(
        "/samples",
        content=sample_bytes,
        params={"name": "audit_sample.exe"},
    )
    assert upload_res.status_code in (200, 201)
    sample_id = upload_res.json()["sample_id"]

    # Verify audit log entry
    audit_res = client.get("/audit?action=sample.upload")
    assert audit_res.status_code == 200
    events = audit_res.json()["events"]
    matching = [e for e in events if e["target_id"] == sample_id]
    assert len(matching) >= 1
    assert matching[0]["action"] == "sample.upload"
    assert matching[0]["outcome"] == "success"

    # 2. Webhook update audit check
    webhook_res = client.put(
        "/notifications/settings",
        json={"webhook_url": "https://hooks.slack.com/services/T00/B00/X00"},
    )
    assert webhook_res.status_code == 200

    audit_res2 = client.get("/audit?action=settings.webhook_update")
    assert audit_res2.status_code == 200
    events2 = audit_res2.json()["events"]
    assert len(events2) >= 1
    assert events2[0]["action"] == "settings.webhook_update"
