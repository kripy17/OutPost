"""Optional auth gate — env-gated, so these tests flip the env vars on/off
around each case. With no passwords configured the API is fully open (the
zero-config default the rest of the suite relies on). With a password set,
every non-public request needs a token, and the read-only `analyst` role is
blocked from mutations."""

import importlib
import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _reset_login_limiter():
    """Every test starts with a clean rate limiter — TestClient presents a
    single IP, so failed-login counts would otherwise leak across cases."""
    from ..core import auth as auth_mod

    auth_mod.login_limiter.reset()
    yield


@pytest.fixture()
def auth_env(monkeypatch):
    """Enable admin + analyst passwords for the duration of the test."""
    monkeypatch.setenv("OUTPOST_ADMIN_PASSWORD", "admin-secret")
    monkeypatch.setenv("OUTPOST_ANALYST_PASSWORD", "analyst-secret")
    # The middleware reads env at request time via auth_service.auth_enabled(),
    # so no app reload is needed — but force a fresh import of the auth module
    # anyway so module-level nothing is cached.
    from ..core import auth as auth_mod

    importlib.reload(auth_mod)
    yield
    monkeypatch.delenv("OUTPOST_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("OUTPOST_ANALYST_PASSWORD", raising=False)


def _client():
    from ..main import app

    return TestClient(app)


def test_auth_me_reports_disabled_by_default(client):
    body = _client().get("/auth/me").json()
    assert body["enabled"] is False
    assert body["authenticated"] is False


def test_login_404_when_disabled(client):
    assert _client().post("/auth/login", json={"password": "x"}).status_code == 404


def test_login_and_me_roundtrip(auth_env):
    c = _client()
    resp = c.post("/auth/login", json={"password": "admin-secret"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["role"] == "admin"
    assert body["read_only"] is False
    token = body["token"]

    me = c.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert me["authenticated"] is True and me["role"] == "admin"

    # Wrong password 401, unknown role 401 (same response shape).
    assert c.post("/auth/login", json={"password": "nope"}).status_code == 401


def test_analyst_login_is_read_only(auth_env):
    c = _client()
    token = c.post("/auth/login", json={"password": "analyst-secret"}).json()["token"]
    me = c.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert me["read_only"] is True and me["role"] == "analyst"


def test_gate_blocks_unauthenticated_writes_and_reads(auth_env):
    c = _client()
    # Public: health + auth/me need no token.
    assert c.get("/health").status_code == 200
    # Non-public GET without token → 401.
    assert c.get("/runs").status_code == 401
    # Non-public POST without token → 401.
    assert c.post("/runs", json={"sample_name": "x", "platform": "windows", "session_type": "analysis"}).status_code == 401


# -- OUTPOST_AGENT_TOKEN (host collector credential) ---------------------------


def test_agent_token_ships_telemetry_but_stays_scoped(auth_env, monkeypatch):
    """The shared agent credential authenticates the collector surface
    (heartbeat, ingest, session lifecycle, run reads) but is refused
    everywhere else — a stolen agent token can't triage alerts or touch
    settings/campaigns/watchlist."""
    from ..core import auth as auth_mod

    monkeypatch.setenv("OUTPOST_AGENT_TOKEN", "agent-secret")
    importlib.reload(auth_mod)
    try:
        c = _client()
        h = {"Authorization": "Bearer agent-secret"}

        # Telemetry: heartbeat, snapshot, ingest.
        assert c.post("/agents/prod-host/heartbeat", json={"platform": "linux"}, headers=h).status_code == 200
        assert c.post("/ingest/snapshot", json={"host_id": "prod-host"}, headers=h).status_code == 200
        # Full ingest loop: create a run as the agent, then ship a batch into it.
        run = c.post(
            "/runs",
            json={"sample_name": "agent-prod-host-2026-08-11", "platform": "linux", "session_type": "live", "source": "agent"},
            headers=h,
        )
        assert run.status_code == 201
        run_id = run.json()["run_id"]
        batch = c.post(
            "/ingest/batch",
            json=[
                {
                    "run_id": run_id,
                    "platform": "linux",
                    "event_type": "process_create",
                    "timestamp": "2026-08-11T12:00:00Z",
                    "pid": 1,
                    "process_name": "bash",
                }
            ],
            headers=h,
        )
        assert batch.status_code == 202

        # Session lifecycle: list + active-live + complete are agent-ok.
        assert c.get("/runs", headers=h).status_code == 200
        assert c.get("/runs/active-live", headers=h).status_code in (200, 404)
        assert c.post(f"/runs/{run_id}/complete", headers=h).status_code == 200

        # Scoped OUT: non-telemetry surfaces refuse the agent credential.
        assert c.get("/campaigns", headers=h).status_code == 403
        assert c.get("/alerts/queue", headers=h).status_code == 403
        assert c.post("/watchlist", json={"value": "1.2.3.4"}, headers=h).status_code == 403

        # Without ANY credential the same telemetry is still 401.
        assert c.post("/agents/prod-host/heartbeat", json={"platform": "linux"}).status_code == 401

        # Admin credential is unaffected by the agent token's presence.
        admin = c.post("/auth/login", json={"password": "admin-secret"}).json()["token"]
        assert c.get("/campaigns", headers={"Authorization": f"Bearer {admin}"}).status_code == 200
    finally:
        monkeypatch.delenv("OUTPOST_AGENT_TOKEN", raising=False)
        importlib.reload(auth_mod)


def test_agent_token_without_admin_still_scoped(monkeypatch):
    """Agent token configured but NO role passwords: auth is enabled (agent
    token implies enforcement) and only the telemetry surface opens."""
    from ..core import auth as auth_mod

    monkeypatch.delenv("OUTPOST_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("OUTPOST_ANALYST_PASSWORD", raising=False)
    monkeypatch.setenv("OUTPOST_AGENT_TOKEN", "agent-secret")
    importlib.reload(auth_mod)
    try:
        assert auth_mod.auth_enabled() is True
        c = _client()
        h = {"Authorization": "Bearer agent-secret"}
        assert c.post("/agents/h1/heartbeat", json={}, headers=h).status_code == 200
        assert c.get("/runs", headers=h).status_code == 200
        assert c.get("/campaigns", headers=h).status_code == 403
        assert c.get("/campaigns").status_code == 401
    finally:
        monkeypatch.delenv("OUTPOST_AGENT_TOKEN", raising=False)
        importlib.reload(auth_mod)


def test_agent_token_rotation_via_api(auth_env, monkeypatch):
    """POST /auth/agent-token (admin) stores a DB token that immediately wins
    over the env bootstrap value; the old token stops working, the new one
    works, and only the admin role can rotate."""
    from ..core import auth as auth_mod

    monkeypatch.setenv("OUTPOST_AGENT_TOKEN", "old-env-token-0001")
    importlib.reload(auth_mod)
    try:
        c = _client()
        admin = c.post("/auth/login", json={"password": "admin-secret"}).json()["token"]
        ah = {"Authorization": f"Bearer {admin}"}

        # Pre-rotation: the env token works on telemetry.
        assert c.post("/agents/h1/heartbeat", json={}, headers={"Authorization": "Bearer old-env-token-0001"}).status_code == 200

        # Rotate (admin) → the endpoint stores the new token.
        resp = c.post("/auth/agent-token", json={"token": "new-rotated-token-0002"}, headers=ah)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

        # DB-stored value now wins: the OLD env token is rejected, the new
        # one authenticates — no restart needed.
        assert c.post("/agents/h1/heartbeat", json={}, headers={"Authorization": "Bearer old-env-token-0001"}).status_code == 401
        assert c.post("/agents/h1/heartbeat", json={}, headers={"Authorization": "Bearer new-rotated-token-0002"}).status_code == 200
        assert auth_mod.agent_token() == "new-rotated-token-0002"

        # Scoping holds for the rotated token too.
        assert c.get("/campaigns", headers={"Authorization": "Bearer new-rotated-token-0002"}).status_code == 403

        # Only admin rotates: analyst + anonymous are refused. (/auth/* is
        # public by design — the endpoint enforces its own admin check, so
        # both come back 403, exactly like /auth/password.)
        analyst = c.post("/auth/login", json={"password": "analyst-secret"}).json()["token"]
        assert c.post("/auth/agent-token", json={"token": "x" * 20}, headers={"Authorization": f"Bearer {analyst}"}).status_code == 403
        assert c.post("/auth/agent-token", json={"token": "x" * 20}).status_code == 403
    finally:
        # The settings row would leak into later tests (DB-stored wins over
        # their env tokens) — remove it and restore the pure-env state.
        from ..core.db import db_session

        with db_session() as conn:
            conn.execute("DELETE FROM settings WHERE key = 'AGENT_TOKEN'")
        monkeypatch.delenv("OUTPOST_AGENT_TOKEN", raising=False)
        importlib.reload(auth_mod)


def test_agent_token_rotation_bootstrap_when_auth_disabled(monkeypatch):
    """With no role credentials, setting an agent token is the one-time
    bootstrap: it enables enforcement and the telemetry surface opens to it."""
    from ..core import auth as auth_mod

    monkeypatch.delenv("OUTPOST_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("OUTPOST_ANALYST_PASSWORD", raising=False)
    importlib.reload(auth_mod)
    try:
        assert auth_mod.auth_enabled() is False
        c = _client()
        # No auth on → the bootstrap call is accepted without a token.
        assert c.post("/auth/agent-token", json={"token": "bootstrap-token-0003"}).status_code == 200
        assert auth_mod.auth_enabled() is True
        assert c.post("/agents/h1/heartbeat", json={}, headers={"Authorization": "Bearer bootstrap-token-0003"}).status_code == 200
        assert c.get("/campaigns", headers={"Authorization": "Bearer bootstrap-token-0003"}).status_code == 403
    finally:
        from ..core.db import db_session

        with db_session() as conn:
            conn.execute("DELETE FROM settings WHERE key = 'AGENT_TOKEN'")
        importlib.reload(auth_mod)


# -- OUTPOST_AUTH_REQUIRED (production fail-closed flag) -----------------------


def test_auth_required_flag_forces_enforcement_without_credentials(monkeypatch):
    """Flag set + no credential: auth is ENFORCED (enabled) and startup
    REFUSES to run — the fail-closed gate, so a prod deploy can't end up with
    an empty (forgeable) token-signing key."""
    from ..core import auth as auth_mod

    monkeypatch.setenv("OUTPOST_AUTH_REQUIRED", "1")
    monkeypatch.delenv("OUTPOST_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("OUTPOST_ANALYST_PASSWORD", raising=False)
    monkeypatch.delenv("OUTPOST_ADMIN_PASSWORD_HASH", raising=False)
    importlib.reload(auth_mod)
    try:
        assert auth_mod.auth_enabled() is True
        with pytest.raises(RuntimeError, match="OUTPOST_AUTH_REQUIRED"):
            auth_mod.validate_config()
    finally:
        monkeypatch.delenv("OUTPOST_AUTH_REQUIRED", raising=False)
        importlib.reload(auth_mod)


def test_auth_required_flag_with_admin_credential_starts(monkeypatch):
    """Flag + a configured admin password: auth enforced AND startup passes."""
    from ..core import auth as auth_mod

    monkeypatch.setenv("OUTPOST_AUTH_REQUIRED", "1")
    monkeypatch.setenv("OUTPOST_ADMIN_PASSWORD", "admin-secret")
    monkeypatch.delenv("OUTPOST_ANALYST_PASSWORD", raising=False)
    importlib.reload(auth_mod)
    try:
        assert auth_mod.auth_enabled() is True
        auth_mod.validate_config()  # no raise
        # And the live app enforces it.
        c = _client()
        assert c.get("/runs").status_code == 401
        token = c.post("/auth/login", json={"password": "admin-secret"}).json()["token"]
        assert c.get("/runs", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    finally:
        monkeypatch.delenv("OUTPOST_AUTH_REQUIRED", raising=False)
        monkeypatch.delenv("OUTPOST_ADMIN_PASSWORD", raising=False)
        importlib.reload(auth_mod)


def test_auth_required_flag_zero_preserves_zero_config_default(monkeypatch):
    """OUTPOST_AUTH_REQUIRED=0 (or absent) + no credentials → open default."""
    from ..core import auth as auth_mod

    monkeypatch.setenv("OUTPOST_AUTH_REQUIRED", "0")
    monkeypatch.delenv("OUTPOST_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("OUTPOST_ANALYST_PASSWORD", raising=False)
    importlib.reload(auth_mod)
    try:
        assert auth_mod.auth_enabled() is False
        auth_mod.validate_config()  # no raise
    finally:
        monkeypatch.delenv("OUTPOST_AUTH_REQUIRED", raising=False)
        importlib.reload(auth_mod)


def test_admin_token_can_read_and_write(auth_env):
    c = _client()
    token = c.post("/auth/login", json={"password": "admin-secret"}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    assert c.get("/runs", headers=h).status_code == 200
    resp = c.post("/runs", json={"sample_name": "auth-run.bin", "platform": "windows", "session_type": "analysis"}, headers=h)
    assert resp.status_code == 201
    assert c.post(f"/runs/{resp.json()['run_id']}/complete", headers=h).status_code == 200


def test_analyst_token_read_ok_write_403(auth_env):
    c = _client()
    token = c.post("/auth/login", json={"password": "analyst-secret"}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    assert c.get("/runs", headers=h).status_code == 200
    resp = c.post("/runs", json={"sample_name": "x", "platform": "windows", "session_type": "analysis"}, headers=h)
    assert resp.status_code == 403


def test_token_query_param_works_for_sse(auth_env):
    c = _client()
    token = c.post("/auth/login", json={"password": "analyst-secret"}).json()["token"]
    # The ?token= fallback must be accepted on a gated route: simulate by
    # checking /auth/me via query param.
    me = c.get(f"/auth/me?token={token}").json()
    assert me["authenticated"] is True


def test_gated_401_carries_cors_headers(auth_env):
    """Regression: the auth gate must sit INSIDE the CORS middleware, so a
    401/403 (or any gate short-circuit) still returns Access-Control-Allow-
    Origin. Otherwise the browser blocks the response and the login screen
    can never see an error — CORS errors on every gated fetch."""
    c = _client()
    resp = c.get(
        "/runs",
        headers={"Origin": "http://localhost:5173"},  # the config default
    )
    assert resp.status_code == 401
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_sse_stream_requires_token_when_auth_on(auth_env):
    """The live alert stream is gated too — EventSource can't set headers, so
    the frontend appends ?token=; both the absent and bad-token cases 401.
    (The valid-token path is covered by the middleware's shared pass-through;
    the stream's generator blocks until the first event, so it isn't
    exercised through the test client.)"""
    c = _client()
    assert c.get("/events/stream").status_code == 401
    assert c.get("/events/stream?token=garbage").status_code == 401


def test_tampered_token_rejected(auth_env):
    c = _client()
    token = c.post("/auth/login", json={"password": "admin-secret"}).json()["token"]
    parts = token.split(".")
    parts[1] = ("0" * 64) if len(parts[1]) >= 64 else "0" * len(parts[1])
    bad = ".".join(parts)
    assert c.get("/runs", headers={"Authorization": f"Bearer {bad}"}).status_code == 401


# -- PBKDF2 salted-hash credentials (rotation + env-hash bootstrap) -------------
#
# The DB is session-scoped: any test that writes a password hash into the
# `settings` table MUST delete it again (finally), or auth stays enabled for
# every later test in the run.

_DB_KEYS = ("ADMIN_PASSWORD_HASH", "ANALYST_PASSWORD_HASH")


def _clear_db_hashes(conn):
    conn.execute(f"DELETE FROM settings WHERE key IN ({','.join('?' * len(_DB_KEYS))})", _DB_KEYS)
    conn.commit()


def test_hash_password_roundtrip_and_format():
    from ..core import auth as auth_mod

    h = auth_mod.hash_password("correct horse battery staple")
    assert h.startswith("pbkdf2_sha256$")
    assert len(h.split("$")) == 4  # algo$iterations$salt$dk
    assert auth_mod.verify_password("correct horse battery staple", h) is True
    assert auth_mod.verify_password("wrong", h) is False
    assert auth_mod.verify_password("x", "pbkdf2_sha256$garbage") is False  # malformed fails closed


def test_env_hash_login_and_credential_mode(monkeypatch):
    """OUTPOST_ADMIN_PASSWORD_HASH (precomputed) authenticates without any
    plaintext anywhere; /auth/me reports credential_mode=hash."""
    from ..core import auth as auth_mod

    monkeypatch.setenv("OUTPOST_ADMIN_PASSWORD_HASH", auth_mod.hash_password("hashed-secret"))
    c = _client()
    resp = c.post("/auth/login", json={"password": "hashed-secret"})
    assert resp.status_code == 200
    token = resp.json()["token"]
    me = c.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert me["credential_mode"] == "hash"
    # The plaintext env var is NOT set — nothing compares plaintext.
    assert os.getenv("OUTPOST_ADMIN_PASSWORD") is None
    assert c.post("/auth/login", json={"password": "hashed-secret-wrong"}).status_code == 401


def test_legacy_plaintext_env_still_reports_plaintext_mode(auth_env):
    c = _client()
    token = c.post("/auth/login", json={"password": "admin-secret"}).json()["token"]
    me = c.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert me["credential_mode"] == "plaintext"


def test_bootstrap_via_auth_password_sets_admin_hash(client, conn):
    """With auth fully off, POST /auth/password bootstraps: stores a salted
    hash in the DB and turns the gate on — no env vars needed."""
    _clear_db_hashes(conn)
    try:
        c = _client()
        assert c.get("/auth/me").json()["enabled"] is False

        resp = c.post("/auth/password", json={"role": "admin", "new_password": "bootstrap-pass-1"})
        assert resp.status_code == 200
        assert resp.json()["credential_mode"] == "hash"

        # Auth is now on; the new admin hash is the only credential.
        assert c.get("/auth/me").json()["enabled"] is True
        assert c.get("/runs").status_code == 401
        login = c.post("/auth/login", json={"password": "bootstrap-pass-1"})
        assert login.status_code == 200
        assert login.json()["role"] == "admin"
    finally:
        _clear_db_hashes(conn)


def test_rotation_requires_admin_token(client, conn):
    """Bootstrap admin, then: analyst token can't rotate; admin token can, and
    the old password stops working while the new one logs in."""
    _clear_db_hashes(conn)
    try:
        c = _client()
        # Bootstrap: while auth is off, the first call sets the admin hash and
        # turns the gate on; analyst is then set with the admin token.
        c.post("/auth/password", json={"role": "admin", "new_password": "rot-admin-1"})
        admin_tok = c.post("/auth/login", json={"password": "rot-admin-1"}).json()["token"]
        c.post(
            "/auth/password",
            json={"role": "analyst", "new_password": "rot-analyst-1"},
            headers={"Authorization": f"Bearer {admin_tok}"},
        )

        analyst_tok = c.post("/auth/login", json={"password": "rot-analyst-1"}).json()["token"]
        # Read-only analyst is blocked from rotation.
        assert c.post(
            "/auth/password",
            json={"role": "admin", "new_password": "blocked-rot-9"},
            headers={"Authorization": f"Bearer {analyst_tok}"},
        ).status_code == 403
        # No token at all → 403 (auth is on; only admin may rotate).
        assert c.post("/auth/password", json={"role": "admin", "new_password": "blocked-rot-9"}).status_code == 403

        resp = c.post(
            "/auth/password",
            json={"role": "admin", "new_password": "rot-admin-2"},
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        assert resp.status_code == 200
        # Old password dead, new one lives.
        assert c.post("/auth/login", json={"password": "rot-admin-1"}).status_code == 401
        assert c.post("/auth/login", json={"password": "rot-admin-2"}).status_code == 200
        # The new hash was persisted, not compared as plaintext.
        row = conn.execute("SELECT value FROM settings WHERE key = 'ADMIN_PASSWORD_HASH'").fetchone()
        assert row and row["value"].startswith("pbkdf2_sha256$")
    finally:
        _clear_db_hashes(conn)


# -- Brute-force rate limiting -------------------------------------------------
#
# The login endpoint counts failed attempts per IP (sliding window) and locks
# the IP out with a 429 once the threshold is crossed — even a correct
# password is refused during the cooldown. Success forgives the counter.


def _tight_limiter(monkeypatch, max_attempts=3, window=60, lockout=60):
    """Replace the module singleton with a small-limit instance for the test."""
    from ..core import auth as auth_mod

    limiter = auth_mod.LoginRateLimiter(max_attempts=max_attempts, window=window, lockout=lockout)
    monkeypatch.setattr(auth_mod, "login_limiter", limiter)
    return limiter


def test_login_locks_out_after_too_many_failures(auth_env, monkeypatch):
    limiter = _tight_limiter(monkeypatch)
    c = _client()

    # 3 wrong passwords: 401, 401, 401 — the 3rd crosses the threshold.
    for _ in range(2):
        assert c.post("/auth/login", json={"password": "wrong-pass"}).status_code == 401
    blocked = c.post("/auth/login", json={"password": "wrong-pass"})
    assert blocked.status_code == 429
    assert "locked out" in blocked.json()["detail"]
    assert int(blocked.headers["retry-after"]) > 0

    # Lockout refuses even the CORRECT password until the cooldown expires.
    denied = c.post("/auth/login", json={"password": "admin-secret"})
    assert denied.status_code == 429

    # Expiring the lockout lets the correct password through again.
    limiter._blocked_until.clear()
    assert c.post("/auth/login", json={"password": "admin-secret"}).status_code == 200


def test_successful_login_forgives_failed_attempts(auth_env, monkeypatch):
    _tight_limiter(monkeypatch)
    c = _client()

    assert c.post("/auth/login", json={"password": "wrong"}).status_code == 401
    assert c.post("/auth/login", json={"password": "wrong"}).status_code == 401
    # A success resets the counter…
    assert c.post("/auth/login", json={"password": "admin-secret"}).status_code == 200
    # …so two more failures don't trip the 3-attempt lockout.
    assert c.post("/auth/login", json={"password": "wrong"}).status_code == 401
    assert c.post("/auth/login", json={"password": "wrong"}).status_code == 401
    assert c.post("/auth/login", json={"password": "admin-secret"}).status_code == 200


def test_ratelimit_status_reports_knobs_and_live_state(auth_env, monkeypatch):
    """GET /auth/ratelimit exposes the tuned knobs read-only plus the live
    guard state (tracked + locked IPs) — what the Settings panel renders."""
    limiter = _tight_limiter(monkeypatch, max_attempts=3, window=60, lockout=60)
    c = _client()

    # Clean state first: knobs reported, nothing tracked.
    status = c.get("/auth/ratelimit").json()
    assert status["max_attempts"] == 3
    assert status["window_seconds"] == 60
    assert status["lockout_seconds"] == 60
    assert status["tracked_ips"] == 0 and status["locked_ips"] == 0

    # Two failed logins → one tracked IP, still not locked.
    c.post("/auth/login", json={"password": "wrong"})
    c.post("/auth/login", json={"password": "wrong"})
    status = c.get("/auth/ratelimit").json()
    assert status["tracked_ips"] == 1 and status["locked_ips"] == 0

    # Third failure crosses the threshold → the IP shows up locked with a
    # positive cooldown.
    c.post("/auth/login", json={"password": "wrong"})
    status = c.get("/auth/ratelimit").json()
    assert status["locked_ips"] == 1
    assert status["locked"][0]["ip"] == "testclient"
    assert status["locked"][0]["remaining_seconds"] > 0


def test_ratelimit_status_reports_disabled_when_auth_off(client):
    """With the zero-config default (auth off) the panel still renders —
    enabled: false tells the UI to show the guard as inactive."""
    status = _client().get("/auth/ratelimit").json()
    assert status["enabled"] is False
    assert status["max_attempts"] == 5


def test_limiter_env_tuning(monkeypatch):
    """AUTH_MAX_ATTEMPTS / AUTH_WINDOW_SECONDS / AUTH_LOCKOUT_SECONDS drive
    the defaults when no explicit values are passed."""
    from ..core import auth as auth_mod

    monkeypatch.setenv("AUTH_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("AUTH_WINDOW_SECONDS", "120")
    monkeypatch.setenv("AUTH_LOCKOUT_SECONDS", "30")
    limiter = auth_mod.LoginRateLimiter()
    assert limiter.max_attempts == 2 and limiter.window == 120 and limiter.lockout == 30


def test_password_rotation_invalidates_old_tokens(client, conn):
    """Signing key is the role's verifier — a new hash (rotation) changes the
    key, so tokens issued before the rotation no longer verify."""
    _clear_db_hashes(conn)
    try:
            c = _client()
            c.post("/auth/password", json={"role": "admin", "new_password": "rot-pass-1"})
            old_tok = c.post("/auth/login", json={"password": "rot-pass-1"}).json()["token"]
            assert c.get("/runs", headers={"Authorization": f"Bearer {old_tok}"}).status_code == 200

            admin_tok = old_tok  # rotate while the old token is still valid
            c.post(
                "/auth/password",
                json={"role": "admin", "new_password": "rot-pass-2"},
                headers={"Authorization": f"Bearer {admin_tok}"},
            )
            # Old token now fails (signing key changed with the hash).
            assert c.get("/runs", headers={"Authorization": f"Bearer {old_tok}"}).status_code == 401
            # Fresh token from the new password works.
            new_tok = c.post("/auth/login", json={"password": "rot-pass-2"}).json()["token"]
            assert c.get("/runs", headers={"Authorization": f"Bearer {new_tok}"}).status_code == 200
    finally:
        _clear_db_hashes(conn)
