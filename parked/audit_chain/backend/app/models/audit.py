"""Analyst audit trail — verifiable, tamper-evident record of all operational actions.

Every analyst-relevant mutation (containment isolation/release, process kill/freeze,
triage transitions, FP marks, logins, rotation, allowlist/suppression edits,
rule modifications, detonation start/abort, sample upload/delete, webhook updates,
retention archives, backups) writes one row via `log()`.

Tamper-evident guarantees:
1. Cryptographic hash-chaining: each entry commits to the preceding entry's SHA-256
   digest (`entry_hash = SHA256(prev_hash:ts:actor:source_ip:action:target_type:target_id:before:after:reason:outcome:detail)`).
2. Data-layer immutability: database-level triggers strictly prohibit UPDATE and DELETE.
3. Out-of-band periodic checkpoints: periodic head state is signed with a local key,
   allowing analysts to export checkpoints for out-of-band validation (print/cold storage)
   to protect against raw database file rewrites.
4. Comprehensive verification routine: `verify_audit_chain()` recomputes the entire chain
   and reports the first break (position, expected, found).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Path for out-of-band audit checkpoint signing keys and key fingerprints
_DATA_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data"
_KEY_FILE = _DATA_DIR / "audit_signing.key"
_FINGERPRINT_FILE = _DATA_DIR / "audit_signing_key.fingerprint"
_PUB_FILE = _DATA_DIR / "audit_signing.pub"  # Backward compatibility alias

# Comprehensive operational action vocabulary
ACTIONS = (
    # Host containment & process execution controls
    "agent.isolate",
    "agent.unisolate",
    "agent.process.kill",
    "agent.process.freeze",
    "agent.process.resume",
    "agent.process.kill_queued",
    "agent.register",
    "agent.action.ack",
    "agent.action.completed",
    # Detection rules, tuning & suppressions
    "rules.create",
    "rules.modify",
    "rules.enable",
    "rules.disable",
    "rules.delete",
    "rules.fp-threshold",
    "allowlist.add",
    "allowlist.remove",
    "suppression.add",
    "suppression.remove",
    # Samples & dynamic detonations
    "sample.upload",
    "sample.delete",
    "detonation.start",
    "detonation.abort",
    # Alerts, triage & investigations
    "alert.status",
    "alert.false-positive",
    "finding.create",
    "finding.update",
    "investigation.create",
    "investigation.update",
    "investigation.close",
    "investigation.import",
    "investigation.export",
    # Authentication & credential lifecycle
    "auth.login",
    "auth.login.failed",
    "auth.logout",
    "auth.password",
    "auth.agent_token",
    "auth.token_revoke",
    # Integrations & intelligence configuration
    "settings.webhook_update",
    "settings.enrichment_update",
    "intel.import",
    "watchlist.add",
    "watchlist.remove",
    # Retention, backup & export operations
    "retention.prune",
    "retention.archive",
    "backup.create",
    "restore.apply",
    "report.export",
    "snapshot.ingest",
    "support_bundle.export",
)


class AuditVerificationReport(dict):
    """Structured report returned by audit chain verification.

    Implements tuple unpacking `(valid, count, error)` for full backward compatibility
    with existing callers while providing structured dictionary fields.
    """

    def __iter__(self):
        return iter((self["valid"], self["entries_verified"], self["error"]))

    @property
    def valid(self) -> bool:
        return bool(self.get("valid"))

    @property
    def intact(self) -> bool:
        return bool(self.get("intact"))


def _serialize_state(val: Any) -> str:
    """Deterministic sorted compact JSON serialization with sorted keys and no whitespace."""
    if val is None:
        return ""
    if isinstance(val, (dict, list)):
        try:
            return json.dumps(val, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        except Exception:
            return str(val)
    return str(val)


def get_or_create_signing_key() -> tuple[bytes, str]:
    """Retrieve or generate the local 256-bit symmetric checkpoint signing key (HMAC-SHA256) and key fingerprint.
    Checkpoints use symmetric HMAC-SHA256 with this local secret key; the fingerprint file records the key ID,
    not an asymmetric public key.
    """
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    if _KEY_FILE.exists():
        try:
            key = _KEY_FILE.read_bytes()
        except OSError:
            key = secrets.token_bytes(32)
    else:
        key = secrets.token_bytes(32)
        try:
            _KEY_FILE.write_bytes(key)
            os.chmod(_KEY_FILE, 0o600)
        except OSError:
            pass

    fingerprint = hashlib.sha256(key).hexdigest()
    try:
        if not _FINGERPRINT_FILE.exists() or _FINGERPRINT_FILE.read_text().strip() != fingerprint:
            _FINGERPRINT_FILE.write_text(fingerprint)
            os.chmod(_FINGERPRINT_FILE, 0o644)
        if not _PUB_FILE.exists() or _PUB_FILE.read_text().strip() != fingerprint:
            _PUB_FILE.write_text(fingerprint)
            os.chmod(_PUB_FILE, 0o644)
    except OSError:
        pass

    return key, fingerprint


def compute_entry_hash(
    prev_hash: str,
    ts: str,
    actor: str,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    outcome: str = "success",
    detail: str | None = None,
    source_ip: str | None = None,
    before_state: Any = None,
    after_state: Any = None,
    reason: str | None = None,
    format_version: int | None = None,
) -> str:
    """Compute the authoritative SHA-256 digest committing to audit fields.
    format_version 1: Legacy 8-field canonical format.
    format_version 2: Extended 12-field canonical format (with source_ip, state snapshots, reason).
    """
    before_str = _serialize_state(before_state)
    after_str = _serialize_state(after_state)
    target_type_str = target_type or ""
    target_id_str = target_id or ""
    detail_str = detail or ""
    source_ip_str = source_ip or ""
    reason_str = reason or ""

    if format_version == 1:
        canonical = f"{prev_hash}:{ts}:{actor}:{action}:{target_type_str}:{target_id_str}:{outcome}:{detail_str}"
    elif format_version == 2:
        canonical = (
            f"{prev_hash}:{ts}:{actor}:{source_ip_str}:{action}:{target_type_str}:"
            f"{target_id_str}:{before_str}:{after_str}:{reason_str}:{outcome}:{detail_str}"
        )
    else:
        # Backward-compatible determination when format_version is omitted
        if source_ip_str or before_str or after_str or reason_str:
            canonical = (
                f"{prev_hash}:{ts}:{actor}:{source_ip_str}:{action}:{target_type_str}:"
                f"{target_id_str}:{before_str}:{after_str}:{reason_str}:{outcome}:{detail_str}"
            )
        else:
            canonical = f"{prev_hash}:{ts}:{actor}:{action}:{target_type_str}:{target_id_str}:{outcome}:{detail_str}"

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def log(
    conn: sqlite3.Connection,
    actor: str,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: str | None = None,
    outcome: str = "success",
    source_ip: str | None = None,
    before_state: Any = None,
    after_state: Any = None,
    reason: str | None = None,
) -> str:
    """Append one entry chained into the tamper-evident audit log."""
    ts = datetime.now(timezone.utc).isoformat()
    try:
        count_row = conn.execute("SELECT COUNT(*) as cnt FROM audit_log").fetchone()
        row_count = count_row["cnt"] if count_row else 0
        if row_count == 0:
            prev_hash = "0" * 64
        else:
            cur = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            if cur is None or not cur["entry_hash"]:
                raise RuntimeError("Fatal audit chain integrity violation: audit_log contains rows but previous entry_hash could not be retrieved")
            prev_hash = cur["entry_hash"]
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            prev_hash = "0" * 64
        else:
            raise RuntimeError(f"Fatal audit log error: failed to read previous entry hash from database: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"Fatal audit log error: failed to read previous entry hash from database: {exc}") from exc

    format_version = 2 if (source_ip or before_state is not None or after_state is not None or reason) else 1
    entry_hash = compute_entry_hash(
        prev_hash=prev_hash,
        ts=ts,
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        outcome=outcome,
        detail=detail,
        source_ip=source_ip,
        before_state=before_state,
        after_state=after_state,
        reason=reason,
        format_version=format_version,
    )

    before_str = _serialize_state(before_state) if before_state is not None else None
    after_str = _serialize_state(after_state) if after_state is not None else None

    # Check whether extended columns exist in the active connection
    try:
        cur_cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    except Exception:
        cur_cols = set()

    if "format_version" in cur_cols:
        conn.execute(
            """
            INSERT INTO audit_log (
                ts, actor, action, target_type, target_id, detail, outcome,
                prev_hash, entry_hash, source_ip, before_state, after_state, reason, format_version
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts, actor, action, target_type, target_id, detail, outcome,
                prev_hash, entry_hash, source_ip, before_str, after_str, reason, format_version
            ),
        )
    elif "source_ip" in cur_cols:
        conn.execute(
            """
            INSERT INTO audit_log (
                ts, actor, action, target_type, target_id, detail, outcome,
                prev_hash, entry_hash, source_ip, before_state, after_state, reason
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts, actor, action, target_type, target_id, detail, outcome,
                prev_hash, entry_hash, source_ip, before_str, after_str, reason
            ),
        )
    else:
        conn.execute(
            """
            INSERT INTO audit_log (ts, actor, action, target_type, target_id, detail, outcome, prev_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ts, actor, action, target_type, target_id, detail, outcome, prev_hash, entry_hash),
        )

    return entry_hash

    return entry_hash


def verify_audit_chain(conn: sqlite3.Connection) -> AuditVerificationReport:
    """Verify cryptographic integrity of the entire audit trail hash chain.

    Recomputes the SHA-256 chain across every record in ascending sequence:
    1. Each entry's prev_hash must match the preceding entry's entry_hash.
    2. Each entry's entry_hash must match the recomputed canonical SHA-256 digest.

    Returns an AuditVerificationReport detailing intact status and first break if any.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        rows = conn.execute(
            """
            SELECT id, ts, actor, action, target_type, target_id, detail, outcome,
                   prev_hash, entry_hash, source_ip, before_state, after_state, reason, format_version
            FROM audit_log ORDER BY id ASC
            """
        ).fetchall()
    except sqlite3.OperationalError:
        # Fallback if extended columns are not yet present
        rows = conn.execute(
            """
            SELECT id, ts, actor, action, target_type, target_id, detail, outcome,
                   prev_hash, entry_hash, NULL as source_ip, NULL as before_state, NULL as after_state, NULL as reason, 1 as format_version
            FROM audit_log ORDER BY id ASC
            """
        ).fetchall()

    if not rows:
        return AuditVerificationReport({
            "valid": True,
            "intact": True,
            "entries_verified": 0,
            "verified_through": 0,
            "total_entries": 0,
            "status": "intact",
            "first_break": None,
            "error": None,
            "verified_at": now_iso,
        })

    expected_prev = "0" * 64
    for idx, r in enumerate(rows):
        entry_id = r["id"]
        actual_prev = r["prev_hash"] or ("0" * 64)

        if idx > 0 and actual_prev != expected_prev:
            err = f"Broken chain link at audit ID {entry_id} (row {idx}): expected prev_hash {expected_prev}, got {actual_prev}"
            return AuditVerificationReport({
                "valid": False,
                "intact": False,
                "entries_verified": idx,
                "verified_through": rows[idx - 1]["id"] if idx > 0 else 0,
                "total_entries": len(rows),
                "status": "tampered",
                "first_break": {
                    "index": idx,
                    "id": entry_id,
                    "expected_hash": expected_prev,
                    "found_hash": actual_prev,
                    "reason": "prev_hash mismatch",
                },
                "error": err,
                "verified_at": now_iso,
            })

        outcome = r["outcome"] or "success"

        version = int(r["format_version"]) if "format_version" in r.keys() and r["format_version"] is not None else None

        expected_hash = compute_entry_hash(
            prev_hash=actual_prev,
            ts=r["ts"],
            actor=r["actor"],
            action=r["action"],
            target_type=r["target_type"],
            target_id=r["target_id"],
            outcome=outcome,
            detail=r["detail"],
            source_ip=r["source_ip"],
            before_state=r["before_state"],
            after_state=r["after_state"],
            reason=r["reason"],
            format_version=version,
        )

        # Strictly reject missing or empty entry_hash
        if not r["entry_hash"]:
            err = f"Tampered entry detected at audit ID {entry_id} (row {idx}): entry_hash is missing or NULL"
            return AuditVerificationReport({
                "valid": False,
                "intact": False,
                "entries_verified": idx,
                "verified_through": rows[idx - 1]["id"] if idx > 0 else 0,
                "total_entries": len(rows),
                "status": "tampered",
                "first_break": {
                    "index": idx,
                    "id": entry_id,
                    "expected_hash": expected_hash,
                    "found_hash": None,
                    "reason": "missing entry_hash",
                },
                "error": err,
                "verified_at": now_iso,
            })

        if r["entry_hash"] != expected_hash:
            # Fallback check format_version=1 for rows created prior to v2 format migration
            legacy_expected = compute_entry_hash(
                prev_hash=actual_prev,
                ts=r["ts"],
                actor=r["actor"],
                action=r["action"],
                target_type=r["target_type"],
                target_id=r["target_id"],
                outcome=outcome,
                detail=r["detail"],
                format_version=1,
            )
            if r["entry_hash"] == legacy_expected:
                expected_hash = legacy_expected
            else:
                err = f"Tampered entry detected at audit ID {entry_id} (row {idx}): hash mismatch"
                return AuditVerificationReport({
                    "valid": False,
                    "intact": False,
                    "entries_verified": idx,
                    "verified_through": rows[idx - 1]["id"] if idx > 0 else 0,
                    "total_entries": len(rows),
                    "status": "tampered",
                    "first_break": {
                        "index": idx,
                        "id": entry_id,
                        "expected_hash": expected_hash,
                        "found_hash": r["entry_hash"],
                        "reason": "entry_hash verification failed",
                    },
                    "error": err,
                    "verified_at": now_iso,
                })

        expected_prev = r["entry_hash"]

    total = len(rows)

    # Check for tail truncation against latest signed checkpoint
    try:
        latest_cp = conn.execute(
            "SELECT checkpoint_seq, created_at, last_audit_id, last_entry_hash, signature, public_key FROM audit_checkpoints ORDER BY checkpoint_seq DESC LIMIT 1"
        ).fetchone()
    except Exception:
        latest_cp = None

    if latest_cp:
        cp_audit_id = int(latest_cp["last_audit_id"])
        cp_entry_hash = str(latest_cp["last_entry_hash"])
        cp_seq = int(latest_cp["checkpoint_seq"])

        current_max_id = rows[-1]["id"] if rows else 0
        if current_max_id < cp_audit_id:
            err = f"Tail truncation detected: signed checkpoint seq {cp_seq} committed through audit ID {cp_audit_id} ({cp_entry_hash[:16]}...), but audit log terminates early at ID {current_max_id}"
            return AuditVerificationReport({
                "valid": False,
                "intact": False,
                "entries_verified": total,
                "verified_through": current_max_id,
                "total_entries": total,
                "status": "truncated",
                "first_break": {
                    "index": total,
                    "id": cp_audit_id,
                    "expected_hash": cp_entry_hash,
                    "found_hash": rows[-1]["entry_hash"] if rows else None,
                    "reason": f"tail truncation: missing committed entries up to ID {cp_audit_id}",
                },
                "error": err,
                "verified_at": now_iso,
            })

    return AuditVerificationReport({
        "valid": True,
        "intact": True,
        "entries_verified": total,
        "verified_through": rows[-1]["id"] if rows else 0,
        "total_entries": total,
        "status": "intact",
        "first_break": None,
        "error": None,
        "verified_at": now_iso,
    })


def create_checkpoint(conn: sqlite3.Connection) -> dict[str, Any]:
    """Create a cryptographically signed checkpoint over the current audit log head.

    Signs the latest entry hash, entry ID, and timestamp with the local signing key.
    The public key fingerprint and signature can be exported out-of-band to prevent
    database rewrite attacks.
    """
    key, pub = get_or_create_signing_key()
    now_iso = datetime.now(timezone.utc).isoformat()

    last_row = conn.execute("SELECT id, entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    last_audit_id = int(last_row["id"]) if last_row else 0
    last_entry_hash = str(last_row["entry_hash"]) if last_row and last_row["entry_hash"] else ("0" * 64)

    try:
        seq_row = conn.execute("SELECT COALESCE(MAX(checkpoint_seq), 0) + 1 AS next_seq FROM audit_checkpoints").fetchone()
        seq = int(seq_row["next_seq"]) if seq_row else 1
    except sqlite3.OperationalError:
        seq = 1

    payload = f"{seq}:{now_iso}:{last_audit_id}:{last_entry_hash}:{pub}"
    sig = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    try:
        conn.execute(
            """
            INSERT INTO audit_checkpoints (checkpoint_seq, created_at, last_audit_id, last_entry_hash, signature, public_key)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (seq, now_iso, last_audit_id, last_entry_hash, sig, pub),
        )
    except Exception:
        pass

    return {
        "checkpoint_seq": seq,
        "created_at": now_iso,
        "last_audit_id": last_audit_id,
        "last_entry_hash": last_entry_hash,
        "public_key_fingerprint": pub,
        "signature": sig,
    }


def verify_checkpoint(checkpoint: dict[str, Any], key: bytes | None = None) -> bool:
    """Verify an exported checkpoint's cryptographic signature and keypair fingerprint."""
    if key is None:
        key, pub = get_or_create_signing_key()
    else:
        pub = hashlib.sha256(key).hexdigest()

    cp_pub = checkpoint.get("public_key_fingerprint") or checkpoint.get("public_key")
    if cp_pub and cp_pub != pub:
        return False

    seq = checkpoint.get("checkpoint_seq")
    created_at = checkpoint.get("created_at")
    last_audit_id = checkpoint.get("last_audit_id")
    last_entry_hash = checkpoint.get("last_entry_hash")
    stored_sig = checkpoint.get("signature")

    payload = f"{seq}:{created_at}:{last_audit_id}:{last_entry_hash}:{pub}"
    expected_sig = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(stored_sig or "", expected_sig)


def list_checkpoints(conn: sqlite3.Connection, limit: int = 50) -> list[dict[str, Any]]:
    """List recent signed audit checkpoints."""
    try:
        rows = conn.execute(
            "SELECT * FROM audit_checkpoints ORDER BY checkpoint_seq DESC LIMIT ?",
            (max(1, min(limit, 200)),),
        ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []


def list_events(conn: sqlite3.Connection, limit: int = 200, action: str | None = None) -> list[dict]:
    """Newest audit entries first; `action` optionally filters to one action."""
    limit = max(1, min(limit, 1000))
    if action:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT ?",
            (action, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]
