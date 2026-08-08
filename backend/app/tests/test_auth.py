"""Optional auth gate — env-gated, so these tests flip the env vars on/off
around each case. With no passwords configured the API is fully open (the
zero-config default the rest of the suite relies on). With a password set,
every non-public request needs a token, and the read-only `analyst` role is
blocked from mutations."""

import importlib
import os

import pytest
from fastapi.testclient import TestClient


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
