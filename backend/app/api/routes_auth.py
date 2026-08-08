"""Authentication endpoints (optional — enabled only when a role password is
configured via env).

- POST /auth/login  — exchange a role password for a signed token
- GET  /auth/me     — who am I? (webapp boot gate: authenticated + role)

When auth is disabled (no OUTPOST_ADMIN_PASSWORD / OUTPOST_ANALYST_PASSWORD),
login always 404s and /auth/me reports `enabled: false` — the webapp skips
the login screen entirely, keeping zero-config local runs frictionless.
"""

import time

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel

from ..core import auth

router = APIRouter(tags=["auth"])


class LoginIn(BaseModel):
    password: str


@router.post("/auth/login", response_model=None)
def login(body: LoginIn) -> dict:
    if not auth.auth_enabled():
        raise HTTPException(status_code=404, detail="Authentication is not configured on this server")
    role = auth.check_credentials(body.password)
    if role is None:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = auth.issue_token(role)
    return {
        "token": token,
        "role": role,
        "expires_in": auth.TOKEN_TTL_SECONDS,
        "read_only": role == "analyst",
    }


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
        "expires_at": int(time.time()) + auth.TOKEN_TTL_SECONDS if role else None,
    }
