"""Authentication endpoints (optional — enabled only when a role credential is
configured via env or the settings table).

- POST /auth/login     — exchange a role password for a signed token
- GET  /auth/me        — who am I? (webapp boot gate: authenticated + role)
- POST /auth/password  — rotate a role's password (admin token required);
                         also the bootstrap: when auth is entirely disabled,
                         the first call sets the admin hash and turns auth on.

Passwords are stored as salted PBKDF2 hashes (never plaintext); see
core/auth.py. When auth is disabled, login always 404s and /auth/me reports
`enabled: false` — the webapp skips the login screen entirely, keeping
zero-config local runs frictionless.
"""

import time

from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ..core import auth
from ..core.db import db_session
from ..models import audit

router = APIRouter(tags=["auth"])


class LoginIn(BaseModel):
    password: str


class PasswordIn(BaseModel):
    role: str = Field(default="admin", pattern="^(admin|analyst)$")
    new_password: str = Field(min_length=8, max_length=200)


@router.post("/auth/login", response_model=None)
def login(body: LoginIn, request: Request) -> dict:
    if not auth.auth_enabled():
        raise HTTPException(status_code=404, detail="Authentication is not configured on this server")
    ip = request.client.host if request.client else "unknown"
    # Brute-force guard: locked-out IPs are refused even with the right
    # password until the cooldown expires (Retry-After tells the client how
    # long). Only *failed* attempts count; success forgives recent failures.
    remaining = auth.login_limiter.lockout_remaining(ip)
    if remaining > 0:
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed login attempts — try again in {int(remaining)}s",
            headers={"Retry-After": str(int(remaining))},
        )
    role = auth.check_credentials(body.password)
    if role is None:
        with db_session() as conn:
            audit.log(conn, ip, "auth.login.failed", target_type="auth", target_id=ip)
        lockout = auth.login_limiter.record_failure(ip)
        if lockout:
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed login attempts — locked out for {int(lockout)}s",
                headers={"Retry-After": str(int(lockout))},
            )
        raise HTTPException(status_code=401, detail="Invalid password")
    auth.login_limiter.record_success(ip)
    with db_session() as conn:
        audit.log(conn, role, "auth.login", target_type="auth", target_id=ip)
    token = auth.issue_token(role)
    return {
        "token": token,
        "role": role,
        "expires_in": auth.TOKEN_TTL_SECONDS,
        "read_only": role == "analyst",
    }


@router.get("/auth/ratelimit", response_model=None)
def rate_limit_status() -> dict:
    """Read-only view of the login brute-force guard for the Settings page:
    the env-tunable knobs (AUTH_MAX_ATTEMPTS / AUTH_WINDOW_SECONDS /
    AUTH_LOCKOUT_SECONDS) plus live state — how many IPs are tracked and
    currently locked out. Returns counters and config, never credentials."""
    return {"enabled": auth.auth_enabled(), **auth.login_limiter.status()}


@router.get("/auth/me", response_model=None)
def me(
    authorization: str = Header("", alias="Authorization"),
    token: str = Query(""),
) -> dict:
    """Report the current session. Always 200 — the webapp boot gate reads
    `enabled` to decide whether to show a login screen at all."""
    tok = auth.token_from_request({"authorization": authorization}, {"token": token})
    role = auth.verify_token(tok) if tok else None
    return {
        "enabled": auth.auth_enabled(),
        "authenticated": role is not None,
        "role": role,
        "read_only": role == "analyst",
        "credential_mode": auth.credential_mode(role) if role else None,
        "expires_at": int(time.time()) + auth.TOKEN_TTL_SECONDS if role else None,
    }


@router.post("/auth/password", response_model=None)
def set_password(body: PasswordIn, request: Request) -> dict:
    """Rotate a role's password (admin only). Also the one-time bootstrap:
    when auth is disabled, the first call sets the admin hash and enables it —
    so a fresh server can be locked down without env vars."""
    if auth.auth_enabled():
        # Already configured → only an admin token may rotate passwords.
        tok = auth.token_from_request(dict(request.headers), dict(request.query_params))
        role = auth.verify_token(tok) if tok else None
        if role != "admin":
            raise HTTPException(status_code=403, detail="Only the admin role can change passwords")
    actor = auth.role_from_request(request)
    with db_session() as conn:
        auth.set_password_hash(conn, body.role, body.new_password)
        audit.log(conn, actor, "auth.password", target_type="role", target_id=body.role)
    return {
        "role": body.role,
        "credential_mode": "hash",
        "message": f"{body.role} password stored as a salted PBKDF2 hash",
    }
