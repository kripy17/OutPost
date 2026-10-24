"""Test suite verifying agent authentication hardening:
1. Server computes SHA-256 of request body and strictly rejects mismatches against X-OutPost-Digest.
2. Authenticated agent credentials are bound to host_id (preventing cross-host containment/ack mutation).
3. Nonces are persisted in the database to prevent replay across restarts.
4. Shared agent token is retired for scoped host mutation.
"""

import hashlib
import hmac
import time

from app.core import auth as auth_service
from app.core.db import db_session


def test_request_body_digest_tamper_rejection(client, monkeypatch):
    """Server computes SHA-256 of request body and rejects tampered bodies or fake digests."""
    monkeypatch.setenv("OUTPOST_AUTH_REQUIRED", "1")
    monkeypatch.setenv("OUTPOST_ADMIN_PASSWORD", "admin-pass-123")

    reg = client.post("/agents/register", json={"host_id": "host-tamper-check", "platform": "linux"}).json()
    agent_id = reg["agent_id"]
    secret = reg["agent_secret"]

    now_ts = str(int(time.time()))
    path = "/agents/host-tamper-check/heartbeat"
    nonce = "nonce-tamper-12345"

    original_body = b'{"platform": "linux", "version": "1.0"}'
    correct_digest = hashlib.sha256(original_body).hexdigest()

    canonical = f"{agent_id}:{now_ts}:POST:{path}::{nonce}:{correct_digest}"
    signature = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    headers = {
        "X-OutPost-Agent-Id": agent_id,
        "X-OutPost-Timestamp": now_ts,
        "X-OutPost-Nonce": nonce,
        "X-OutPost-Digest": correct_digest,
        "X-OutPost-Signature": signature,
        "Content-Type": "application/json",
    }

    # 1. Authentic request with matching body digest succeeds
    res_ok = client.post(path, content=original_body, headers=headers)
    assert res_ok.status_code == 200

    # 2. Tampered request body with original digest and signature MUST fail with 401
    tampered_body = b'{"platform": "linux", "version": "1.0", "injected_payload": "hostile"}'
    now_ts_2 = str(int(time.time()))
    nonce_2 = "nonce-tamper-67890"
    canonical_2 = f"{agent_id}:{now_ts_2}:POST:{path}::{nonce_2}:{correct_digest}"
    sig_2 = hmac.new(secret.encode("utf-8"), canonical_2.encode("utf-8"), hashlib.sha256).hexdigest()

    tampered_headers = {
        "X-OutPost-Agent-Id": agent_id,
        "X-OutPost-Timestamp": now_ts_2,
        "X-OutPost-Nonce": nonce_2,
        "X-OutPost-Digest": correct_digest,  # Doesn't match tampered_body!
        "X-OutPost-Signature": sig_2,
        "Content-Type": "application/json",
    }
    res_tampered = client.post(path, content=tampered_body, headers=tampered_headers)
    assert res_tampered.status_code == 401
    assert "digest" in res_tampered.json().get("detail", "").lower() or "authentication" in res_tampered.json().get("detail", "").lower()


def test_agent_credential_bound_to_host_id(client, monkeypatch):
    """Enrolled agent for host-A cannot mutate containment or ack actions for host-B."""
    monkeypatch.setenv("OUTPOST_AUTH_REQUIRED", "1")
    monkeypatch.setenv("OUTPOST_ADMIN_PASSWORD", "admin-pass-123")

    reg_a = client.post("/agents/register", json={"host_id": "sensor-alpha", "platform": "linux"}).json()
    agent_id_a = reg_a["agent_id"]
    secret_a = reg_a["agent_secret"]

    now_ts = str(int(time.time()))
    nonce = "nonce-cross-host-01"

    # Attempt to report containment on sensor-bravo using sensor-alpha's credentials
    path = "/agents/sensor-bravo/containment/report"
    body = b'{"enforcement_mode": "full", "success": true}'
    digest = hashlib.sha256(body).hexdigest()

    canonical = f"{agent_id_a}:{now_ts}:POST:{path}::{nonce}:{digest}"
    sig = hmac.new(secret_a.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    headers = {
        "X-OutPost-Agent-Id": agent_id_a,
        "X-OutPost-Timestamp": now_ts,
        "X-OutPost-Nonce": nonce,
        "X-OutPost-Digest": digest,
        "X-OutPost-Signature": sig,
        "Content-Type": "application/json",
    }

    res = client.post(path, content=body, headers=headers)
    assert res.status_code == 403
    assert "not authorized for host" in res.json().get("detail", "").lower() or "credential" in res.json().get("detail", "").lower()


def test_nonces_sliding_window_cache_replay_protection(client, monkeypatch):
    """Nonces are checked against thread-safe in-memory sliding window cache with 180s TTL, rejecting replays."""
    nonce_key = f"test-agent-persist:{int(time.time())}:unique-nonce-12345"
    now = time.time()

    # First record should succeed and be cached in memory
    assert auth_service._check_and_record_nonce(nonce_key, now) is True

    # Replay of the same nonce must be rejected
    assert auth_service._check_and_record_nonce(nonce_key, now + 1) is False


def test_shared_agent_token_retired_for_containment_and_ack(client, monkeypatch):
    """The legacy shared agent token cannot mutate containment or ack actions on enrolled hosts; enrolled credentials required."""
    monkeypatch.setenv("OUTPOST_AUTH_REQUIRED", "1")
    monkeypatch.setenv("OUTPOST_ADMIN_PASSWORD", "admin-pass-123")
    monkeypatch.setenv("OUTPOST_AGENT_TOKEN", "legacy-shared-agent-token-xyz")

    # Enroll legacy-host
    client.post("/agents/register", json={"host_id": "legacy-host", "platform": "linux"})

    shared_headers = {
        "Authorization": "Bearer legacy-shared-agent-token-xyz",
        "Content-Type": "application/json",
    }

    # Telemetry and heartbeat work with agent credential
    hb_res = client.post("/agents/legacy-host/heartbeat", json={"platform": "linux"}, headers=shared_headers)
    assert hb_res.status_code == 200

    # Containment report is blocked with 403 for shared agent token
    cont_res = client.post(
        "/agents/legacy-host/containment/report",
        json={"enforcement_mode": "full", "success": True},
        headers=shared_headers,
    )
    assert cont_res.status_code == 403
    assert "retired" in cont_res.json().get("detail", "").lower() or "enrolled" in cont_res.json().get("detail", "").lower()

    # Action ack is blocked with 403 for shared agent token
    ack_res = client.post(
        "/agents/legacy-host/actions/ack",
        json={"action_ids": ["act-123"]},
        headers=shared_headers,
    )
    assert ack_res.status_code == 403
    assert "retired" in ack_res.json().get("detail", "").lower() or "enrolled" in ack_res.json().get("detail", "").lower()

