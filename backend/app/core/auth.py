"""Optional API authentication — HMAC-signed tokens, stdlib only.

Deliberately dependency-light (no PyJWT): tokens are a base64url JSON payload
(`role`, `exp`) plus an HMAC-SHA256 signature keyed by the role's password.
Two roles:

- `admin`   (OUTPOST_ADMIN_PASSWORD)   — full access, including mutations
- `analyst` (OUTPOST_ANALYST_PASSWORD) — read-only (GET/HEAD/OPTIONS only)

Auth is DISABLED when neither password env var is set (the repo's default —
zero-config local runs and the full test suite never touch auth). Each role's
tokens are signed with that role's own secret, so an analyst password can
never forge an admin token.
"""

import base64
import hashlib
import hmac
import json
import os
import time

TOKEN_TTL_SECONDS = 60 * 60 * 24  # 24h


def _admin_password() -> str:
    return os.getenv("OUTPOST_ADMIN_PASSWORD", "").strip()


def _analyst_password() -> str:
    return os.getenv("OUTPOST_ANALYST_PASSWORD", "").strip()


def auth_enabled() -> bool:
    """True when at least one role password is configured."""
    return bool(_admin_password() or _analyst_password())


def _secret_for_role(role: str) -> str:
    return _admin_password() if role == "admin" else _analyst_password() if role == "analyst" else ""


def check_credentials(password: str) -> str | None:
    """Return the role whose password matches, else None (wrong / unknown).

    Constant-ish effort: compares against both configured passwords regardless
    of which (if any) matches, so a timing probe can't distinguish a valid
    role name from a typo."""
    candidates = [("admin", _admin_password()), ("analyst", _analyst_password())]
    matched: str | None = None
    for role, secret in candidates:
        if secret and hmac.compare_digest(password.encode(), secret.encode()):
            matched = role
    return matched


def _sign(secret: str, payload_b64: str) -> str:
    return hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()


def issue_token(role: str) -> str | None:
    """Issue a signed token for a role; None when that role isn't configured."""
    secret = _secret_for_role(role)
    if not secret:
        return None
    payload = json.dumps({"role": role, "exp": int(time.time()) + TOKEN_TTL_SECONDS}).encode()
    payload_b64 = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    return f"{payload_b64}.{_sign(secret, payload_b64)}"


def verify_token(token: str) -> str | None:
    """Validate a token; return its role or None (expired / tampered / unknown)."""
    if not token:
        return None
    try:
        payload_b64, sig = token.split(".", 1)
        # Restore padding stripped at issue time.
        pad = "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
        role = payload.get("role")
        secret = _secret_for_role(role)
        if not secret or int(payload.get("exp", 0)) < time.time():
            return None
        if not hmac.compare_digest(sig, _sign(secret, payload_b64)):
            return None
        return role
    except Exception:
        return None


def token_from_request(headers: dict, query: dict) -> str:
    """Pull the token from `Authorization: Bearer <t>` or `?token=<t>`.

    The query-param fallback exists for the SSE stream endpoint
    (`/events/stream`): `EventSource` can't set Authorization headers, so the
    frontend appends `?token=…` for it. Everywhere else uses the header.
    """
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return (query.get("token") or "").strip()
