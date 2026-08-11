"""Optional API authentication — PBKDF2-salted credentials, stdlib only.

Credentials are never compared as plaintext: each role's password is verified
against a salted PBKDF2-SHA256 hash (format `pbkdf2_sha256$<iters>$<salt>$<dk>`).
Sources, in precedence order per role:

1. **DB-stored hash** — `settings` rows `ADMIN_PASSWORD_HASH` /
   `ANALYST_PASSWORD_HASH`, written by `POST /auth/password` (rotation) and
   read on every request. Survives restarts, no secrets in env.
2. **Env hash** — `OUTPOST_ADMIN_PASSWORD_HASH` / `OUTPOST_ANALYST_PASSWORD_HASH`
   (precomputed with `outpost auth hash`). Bootstrap before any DB row exists.
3. **Env plaintext** — `OUTPOST_ADMIN_PASSWORD` / `OUTPOST_ANALYST_PASSWORD`
   (legacy; still accepted, verified with `compare_digest`).

Auth is DISABLED when no role has any configured credential — the repo's
zero-config default, so local runs and the full test suite never touch auth.

Tokens: base64url JSON payload (`role`, `exp`) + HMAC-SHA256 signature keyed
by the role's *verifier* (the hash string, or the legacy plaintext). Because
the verifier is stable across restarts, tokens survive process restarts;
rotating a role's password (new hash) invalidates that role's existing
tokens, which is the desired rotation semantics.

Each role's tokens are signed with that role's own verifier, so an analyst
credential can never forge an admin token. `check_credentials` always
evaluates both roles (constant-ish effort; PBKDF2 dominates the timing).
"""

import base64
import hashlib
import hmac
import json
import os
import time

TOKEN_TTL_SECONDS = 60 * 60 * 24  # 24h
PBKDF2_ITERATIONS = 210_000  # OWASP-flavored for PBKDF2-HMAC-SHA256
_HASH_ALGO = "pbkdf2_sha256"

_ROLES = ("admin", "analyst")


def _stored_agent_token() -> str:
    """DB-stored agent token (settings `AGENT_TOKEN`, written by
    POST /auth/agent-token rotation). Lazy import keeps this module free of
    db.py at import time (no circular dependency) — same pattern as
    `_stored_hash`."""
    from ..core.db import db_session

    with db_session() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = 'AGENT_TOKEN'").fetchone()
        return (row["value"] if row else "").strip()


def set_agent_token(conn, token: str) -> None:
    """Persist a fresh agent token (rotation); the DB-stored value then wins
    over the env bootstrap token until rotated again."""
    conn.execute(
        """
        INSERT INTO settings (key, value) VALUES ('AGENT_TOKEN', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (token,),
    )


def agent_token() -> str:
    """The shared agent credential, resolved per request.

    DB-stored (rotation via POST /auth/agent-token) wins over the env
    bootstrap `OUTPOST_AGENT_TOKEN` — so a rotated token applies immediately
    and survives restarts, and a stale env value becomes inert. Empty when
    neither is set — the zero-config default.
    """
    return _stored_agent_token() or os.getenv("OUTPOST_AGENT_TOKEN", "").strip()


def verify_agent_token(token: str) -> bool:
    """Constant-time check against the configured agent token. Fails closed:
    no token configured or an empty presented token never matches."""
    configured = agent_token()
    if not configured or not token:
        return False
    return hmac.compare_digest(token.encode(), configured.encode())


def _env_hash(role: str) -> str:
    return os.getenv(f"OUTPOST_{role.upper()}_PASSWORD_HASH", "").strip()


def _env_plain(role: str) -> str:
    return os.getenv(f"OUTPOST_{role.upper()}_PASSWORD", "").strip()


def _stored_hash(role: str) -> str:
    """The role's DB-stored hash (settings table), or \"\" — lazy import keeps
    this module free of db.py at import time (no circular dependency)."""
    from ..core.db import db_session

    key = f"{role.upper()}_PASSWORD_HASH"
    with db_session() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return (row["value"] if row else "").strip()


def _verifier_for_role(role: str) -> tuple[str, bool]:
    """(verifier, is_hash) for a role: stored DB hash → env hash → env plaintext."""
    h = _stored_hash(role) or _env_hash(role)
    if h:
        return h, True
    p = _env_plain(role)
    return p, False


# -- Hashing -------------------------------------------------------------------


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Salt + PBKDF2-SHA256 a password; returns the self-describing hash string."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{_HASH_ALGO}${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verify against a hash from `hash_password`. Any malformed
    hash (wrong algo, bad fields) fails closed."""
    try:
        algo, iters, salt_hex, dk_hex = stored.split("$", 3)
        if algo != _HASH_ALGO:
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, TypeError):
        return False


def set_password_hash(conn, role: str, new_password: str) -> str:
    """Persist a fresh salted hash for a role; returns the stored hash string."""
    key = f"{role.upper()}_PASSWORD_HASH"
    h = hash_password(new_password)
    conn.execute(
        """
        INSERT INTO settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (key, h),
    )
    return h


# -- Enabling + credential check ------------------------------------------------


def _auth_required_flag() -> bool:
    """`OUTPOST_AUTH_REQUIRED=1` — the production switch: this instance must
    ALWAYS enforce auth, even before any credential exists. Fail-closed at
    startup (see validate_config) so a prod deploy can never run open."""
    return os.getenv("OUTPOST_AUTH_REQUIRED", "").strip().lower() in ("1", "true", "yes", "on")


def auth_enabled() -> bool:
    """True when auth must be enforced: the OUTPOST_AUTH_REQUIRED flag, OR a
    role has a credential configured (env or DB), OR an agent token is set
    (a deploy that configured agents means the surface is protected).

    Env check first — the zero-config default has neither, so the DB read
    below only happens once auth is genuinely in play.
    """
    if _auth_required_flag():
        return True
    if agent_token():
        return True
    if any(_env_hash(r) or _env_plain(r) for r in _ROLES):
        return True
    return bool(_stored_hash("admin") or _stored_hash("analyst"))


def validate_config() -> None:
    """Fail-closed startup gate for OUTPOST_AUTH_REQUIRED.

    With the flag set but no admin credential, tokens would be signed with an
    empty verifier (trivially forgeable) — far worse than running open. Refuse
    to boot with a clear message instead. Called from the app lifespan after
    init_db so the DB-backed credential check can read the settings table.
    """
    if not _auth_required_flag():
        return
    verifier, _ = _verifier_for_role("admin")
    if not verifier:
        raise RuntimeError(
            "OUTPOST_AUTH_REQUIRED=1 but no admin credential is configured — refusing to "
            "start with auth that could be forged. Set OUTPOST_ADMIN_PASSWORD "
            "(or a precomputed OUTPOST_ADMIN_PASSWORD_HASH from `outpost auth hash`) "
            "and restart. OUTPOST_ANALYST_PASSWORD is optional."
        )


def _secret_for_role(role: str) -> str:
    """Token-signing key: the role's verifier (stable across restarts)."""
    verifier, _ = _verifier_for_role(role)
    return verifier


def check_credentials(password: str) -> str | None:
    """Return the role whose credential matches, else None (wrong / unknown).

    Always evaluates both roles, so a timing probe can't distinguish a valid
    role name from a typo; PBKDF2 work dominates either way.
    """
    matched: str | None = None
    for role in _ROLES:
        verifier, is_hash = _verifier_for_role(role)
        if not verifier:
            continue
        if is_hash:
            if verify_password(password, verifier):
                matched = role
        elif hmac.compare_digest(password.encode(), verifier.encode()):
            matched = role
    return matched


def credential_mode(role: str) -> str:
    """How a role's credential is configured: 'hash' | 'plaintext' | 'none'."""
    verifier, is_hash = _verifier_for_role(role)
    if not verifier:
        return "none"
    return "hash" if is_hash else "plaintext"


# -- Login rate limiting -------------------------------------------------------
# In-memory per-IP failed-attempt tracking (sliding window + lockout). The
# login endpoint counts *failed* attempts; a success clears the counter, and
# once the limit is hit the IP is locked out for a cooldown. In-memory means
# this is correct for the default single-process uvicorn deployment — a
# multi-worker deployment should move the store to Redis. Env-tunable:
#   AUTH_MAX_ATTEMPTS      failed logins allowed per window  (default 5)
#   AUTH_WINDOW_SECONDS    sliding window length             (default 300)
#   AUTH_LOCKOUT_SECONDS   cooldown once the limit is hit    (default 900)


class LoginRateLimiter:
    def __init__(self, max_attempts: int | None = None, window: int | None = None, lockout: int | None = None):
        self.max_attempts = max_attempts if max_attempts is not None else int(os.getenv("AUTH_MAX_ATTEMPTS", "5"))
        self.window = window if window is not None else int(os.getenv("AUTH_WINDOW_SECONDS", "300"))
        self.lockout = lockout if lockout is not None else int(os.getenv("AUTH_LOCKOUT_SECONDS", "900"))
        self._fails: dict[str, list[float]] = {}   # ip -> failed-attempt timestamps
        self._blocked_until: dict[str, float] = {}  # ip -> monotonic unblock time

    def reset(self) -> None:
        """Clear all state — used by tests to keep cases independent."""
        self._fails.clear()
        self._blocked_until.clear()

    def lockout_remaining(self, ip: str) -> float:
        """Seconds still locked out for an IP (0 = not blocked). Expired
        lockouts are garbage-collected on read."""
        until = self._blocked_until.get(ip, 0.0)
        remaining = until - time.monotonic()
        if remaining <= 0 and until:
            self._blocked_until.pop(ip, None)
            self._fails.pop(ip, None)
        return max(0.0, remaining)

    def record_failure(self, ip: str) -> float:
        """Record a failed login; returns lockout seconds if the IP just
        crossed the threshold (0 otherwise)."""
        now = time.monotonic()
        recent = [t for t in self._fails.get(ip, []) if now - t < self.window]
        recent.append(now)
        self._fails[ip] = recent
        if len(recent) >= self.max_attempts:
            self._blocked_until[ip] = now + self.lockout
            self._fails.pop(ip, None)
            return float(self.lockout)
        return 0.0

    def record_success(self, ip: str) -> None:
        """A successful login forgives the IP's recent failures."""
        self._fails.pop(ip, None)
        self._blocked_until.pop(ip, None)

    def status(self) -> dict:
        """Read-only snapshot for the Settings page: the tuned knobs plus
        live state (how many IPs are tracked / currently locked out, with the
        longest lockouts first). No secrets — just counters and config."""
        now = time.monotonic()
        locked = []
        for ip, until in self._blocked_until.items():
            remaining = until - now
            if remaining > 0:
                locked.append({"ip": ip, "remaining_seconds": int(remaining)})
        locked.sort(key=lambda x: x["remaining_seconds"], reverse=True)
        return {
            "max_attempts": self.max_attempts,
            "window_seconds": self.window,
            "lockout_seconds": self.lockout,
            "tracked_ips": len(self._fails),
            "locked_ips": len(locked),
            "locked": locked[:20],
        }


login_limiter = LoginRateLimiter()


# -- Tokens --------------------------------------------------------------------


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


def role_from_request(request) -> str:
    """The acting identity for a request: the verified role when auth is on
    (falls back to 'local' if the token is missing/invalid so audit rows are
    never lost), or 'local' when auth is off. Collector traffic presents the
    shared agent credential and is attributed as 'agent'. Audit logging uses
    this."""
    if not auth_enabled():
        return "local"
    tok = token_from_request(dict(request.headers), dict(request.query_params))
    role = verify_token(tok) if tok else None
    if role is None and verify_agent_token(tok):
        return "agent"
    return role or "local"


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
