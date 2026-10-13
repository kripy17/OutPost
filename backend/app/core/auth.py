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
import secrets
import threading
import time

_REVOKED_TOKENS: set[str] = set()
_ACTIVE_SESSIONS: dict[str, dict] = {}  # session_id -> metadata
_SESSION_LOCK = threading.Lock()

TOKEN_TTL_SECONDS = 60 * 60 * 24  # 24h
PBKDF2_ITERATIONS = 210_000  # OWASP-flavored for PBKDF2-HMAC-SHA256
_HASH_ALGO = "pbkdf2_sha256"

_ROLES = ("admin", "responder", "analyst", "viewer")

_SEEN_SIGNATURES: dict[str, float] = {}
_SEEN_NONCES: dict[str, float] = {}
_SEEN_LOCK = threading.Lock()


def _check_and_record_signature(sig_key: str, now: float) -> bool:
    with _SEEN_LOCK:
        cutoff = now - 360.0
        expired = [k for k, v in _SEEN_SIGNATURES.items() if v < cutoff]
        for k in expired:
            _SEEN_SIGNATURES.pop(k, None)
        if sig_key in _SEEN_SIGNATURES:
            return False
        _SEEN_SIGNATURES[sig_key] = now
        return True


def _check_and_record_nonce(nonce_key: str, now: float) -> bool:
    with _SEEN_LOCK:
        cutoff = now - 180.0
        expired = [k for k, v in _SEEN_NONCES.items() if v < cutoff]
        for k in expired:
            _SEEN_NONCES.pop(k, None)
        if nonce_key in _SEEN_NONCES:
            return False
        _SEEN_NONCES[nonce_key] = now
        return True


def _server_secret() -> bytes:
    """Master key for server-side cryptographic envelopes (stdlib-only)."""
    env_secret = os.getenv("OUTPOST_SERVER_SECRET", "")
    if env_secret:
        return hashlib.sha256(env_secret.encode("utf-8")).digest()
    admin_v, _ = _verifier_for_role("admin")
    if admin_v:
        return hashlib.sha256(admin_v.encode("utf-8")).digest()
    return hashlib.sha256(b"outpost-master-agent-secret-envelope-key").digest()


def encrypt_agent_secret(secret_plaintext: str) -> str:
    """Encrypt agent secret before storing in the database (never stored in plaintext).
    Uses HMAC-SHA256 keystream stream cipher with random 16-byte salt (stdlib only).
    """
    if not secret_plaintext:
        return ""
    salt = os.urandom(16)
    key = hmac.new(_server_secret(), salt, hashlib.sha256).digest()
    pt = secret_plaintext.encode("utf-8")
    ct = bytearray()
    counter = 0
    while len(ct) < len(pt):
        block = hmac.new(key, counter.to_bytes(4, "big"), hashlib.sha256).digest()
        ct.extend(block)
        counter += 1
    ciphertext = bytes(a ^ b for a, b in zip(pt, ct[:len(pt)]))
    return f"enc${salt.hex()}${ciphertext.hex()}"


def decrypt_agent_secret(stored_secret: str) -> str:
    """Decrypt agent secret read from the database. Gracefully falls back to plaintext for legacy rows."""
    if not stored_secret:
        return ""
    if not stored_secret.startswith("enc$"):
        return stored_secret
    try:
        _, salt_hex, ct_hex = stored_secret.split("$", 2)
        salt = bytes.fromhex(salt_hex)
        ciphertext = bytes.fromhex(ct_hex)
        key = hmac.new(_server_secret(), salt, hashlib.sha256).digest()
        ct = bytearray()
        counter = 0
        while len(ct) < len(ciphertext):
            block = hmac.new(key, counter.to_bytes(4, "big"), hashlib.sha256).digest()
            ct.extend(block)
            counter += 1
        pt = bytes(a ^ b for a, b in zip(ciphertext, ct[:len(ciphertext)]))
        return pt.decode("utf-8")
    except Exception:
        return ""


def _stored_agent_token() -> str:
    """DB-stored agent token (settings `AGENT_TOKEN`), decrypted if stored encrypted."""
    from ..core.db import db_session

    with db_session() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = 'AGENT_TOKEN'").fetchone()
        if row and row["value"]:
            val = row["value"].strip()
            return decrypt_agent_secret(val)
        return ""


def set_agent_token(conn, token: str) -> None:
    """Persist a fresh agent token encrypted with server master secret (never stored in plaintext)."""
    enc = encrypt_agent_secret(token)
    conn.execute(
        """
        INSERT INTO settings (key, value) VALUES ('AGENT_TOKEN', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (enc,),
    )
    conn.execute("DELETE FROM settings WHERE key = 'AGENT_TOKEN_HASH'")


def agent_token() -> str:
    """The shared agent credential, resolved per request.

    DB-stored wins over env bootstrap `OUTPOST_AGENT_TOKEN`.
    Empty when neither is set — the zero-config default.
    """
    return _stored_agent_token() or os.getenv("OUTPOST_AGENT_TOKEN", "").strip()


def verify_agent_token(token: str) -> bool:
    """Constant-time check against configured agent token. Fails closed."""
    if not token:
        return False
    target = agent_token()
    if not target:
        return False
    return hmac.compare_digest(token.encode(), target.encode())


def verify_agent_hmac_headers(
    agent_id: str,
    timestamp_str: str,
    signature: str,
    method: str = "GET",
    path: str = "/",
    query_string: str = "",
    body_digest: str | None = None,
    nonce: str | None = None,
) -> bool:
    """Verify HMAC-SHA256 request signature for an enrolled agent.

    Signature covers agent_id, timestamp, method, path, query_string, nonce, and body_digest.
    Enforces a strict 120s replay window and server-side single-use nonce/signature tracking.
    """
    if not agent_id or not timestamp_str or not signature:
        return False
    try:
        try:
            ts = float(timestamp_str)
        except ValueError:
            from datetime import datetime
            ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).timestamp()
        # Short replay window: 120 seconds
        if abs(time.time() - ts) > 120:
            return False
    except Exception:
        return False

    # Server-side nonce tracking when nonce is supplied
    if nonce:
        if len(nonce) < 8:
            return False
        nonce_key = f"{agent_id}:{nonce}"
        if not _check_and_record_nonce(nonce_key, time.time()):
            return False

    secret = None
    if os.getenv("OUTPOST_AGENT_ID") == agent_id and os.getenv("OUTPOST_AGENT_SECRET"):
        secret = os.getenv("OUTPOST_AGENT_SECRET")
    else:
        try:
            from ..core.db import db_session
            with db_session() as conn:
                row = conn.execute(
                    "SELECT agent_secret, status FROM enrolled_agents WHERE agent_id = ?",
                    (agent_id,),
                ).fetchone()
                if row and row["status"] == "active":
                    secret = decrypt_agent_secret(row["agent_secret"])
                    from datetime import datetime, timezone
                    now_iso = datetime.now(timezone.utc).isoformat()
                    conn.execute("UPDATE enrolled_agents SET last_seen_at = ? WHERE agent_id = ?", (now_iso, agent_id))
        except Exception:
            pass

    if not secret:
        return False

    method_clean = (method or "GET").upper()
    path_clean = path or "/"
    query_clean = query_string or ""

    matched = False
    if nonce:
        canonical_v2 = f"{agent_id}:{timestamp_str}:{method_clean}:{path_clean}:{query_clean}:{nonce}:{body_digest or ''}"
        expected_v2 = hmac.new(secret.encode("utf-8"), canonical_v2.encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(signature.lower(), expected_v2.lower()):
            matched = True

    if not matched:
        canonical_v1 = f"{agent_id}:{timestamp_str}:{method_clean}:{path_clean}"
        expected_v1 = hmac.new(secret.encode("utf-8"), canonical_v1.encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(signature.lower(), expected_v1.lower()):
            matched = True

    if not matched:
        return False

    replay_key = f"{agent_id}:{signature.lower()}"
    if not _check_and_record_signature(replay_key, time.time()):
        return False

    return True


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
    """Fail-closed startup gate for auth and network binding.

    1. Fail-closed OUTPOST_AUTH_REQUIRED=1: refuses to start without an admin credential.
    2. Refuses to bind to any non-loopback address (0.0.0.0, ::, or external IP)
       with auth disabled — preventing accidental exposure of an unauthenticated instance.
    """
    auth_on = auth_enabled()
    if _auth_required_flag():
        verifier, _ = _verifier_for_role("admin")
        if not verifier:
            raise RuntimeError(
                "OUTPOST_AUTH_REQUIRED=1 but no admin credential is configured — refusing to "
                "start with auth that could be forged. Set OUTPOST_ADMIN_PASSWORD "
                "(or a precomputed OUTPOST_ADMIN_PASSWORD_HASH from `outpost auth hash`) "
                "and restart. OUTPOST_ANALYST_PASSWORD is optional."
            )

    # Check bind address from environment or sys.argv
    bind_host = (
        os.getenv("OUTPOST_BIND_HOST", "")
        or os.getenv("OUTPOST_HOST", "")
        or os.getenv("HOST", "")
        or os.getenv("UVICORN_HOST", "")
    ).strip().lower()

    if not bind_host:
        import sys
        for idx, arg in enumerate(sys.argv):
            if arg in ("--host", "-h") and idx + 1 < len(sys.argv):
                bind_host = sys.argv[idx + 1].strip().lower()
                break
            elif arg.startswith("--host="):
                bind_host = arg.split("=", 1)[1].strip().lower()
                break

    LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1", "testclient")
    if bind_host and bind_host not in LOOPBACK_HOSTS and not auth_on:
        raise RuntimeError(
            f"Refusing to bind to non-loopback address '{bind_host}' with authentication disabled. "
            "Configure admin credentials (OUTPOST_ADMIN_PASSWORD / OUTPOST_ADMIN_PASSWORD_HASH) "
            "or set OUTPOST_AUTH_REQUIRED=1 to bind beyond loopback."
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
    jti = secrets.token_hex(16)
    now = int(time.time())
    exp = now + TOKEN_TTL_SECONDS
    payload = json.dumps({"role": role, "jti": jti, "iat": now, "exp": exp}).encode()
    payload_b64 = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    token = f"{payload_b64}.{_sign(secret, payload_b64)}"
    tok_hash = hashlib.sha256(token.encode()).hexdigest()
    with _SESSION_LOCK:
        _ACTIVE_SESSIONS[jti] = {
            "session_id": jti,
            "role": role,
            "token_hash": tok_hash,
            "issued_at": now,
            "expires_at": exp,
        }
    return token


def revoke_token(token: str) -> bool:
    """Revoke a single token so it can never be used again."""
    if not token:
        return False
    tok_hash = hashlib.sha256(token.encode()).hexdigest()
    with _SESSION_LOCK:
        _REVOKED_TOKENS.add(tok_hash)
        for jti, sess in list(_ACTIVE_SESSIONS.items()):
            if sess.get("token_hash") == tok_hash:
                _ACTIVE_SESSIONS.pop(jti, None)
                break
    return True


def revoke_session_by_id(session_id: str) -> bool:
    """Revoke an active session by its session ID."""
    with _SESSION_LOCK:
        sess = _ACTIVE_SESSIONS.pop(session_id, None)
        if sess:
            _REVOKED_TOKENS.add(sess["token_hash"])
            return True
    return False


def list_active_sessions() -> list[dict]:
    """List all currently active non-expired sessions."""
    now = int(time.time())
    with _SESSION_LOCK:
        expired = [k for k, v in _ACTIVE_SESSIONS.items() if v.get("expires_at", 0) < now]
        for k in expired:
            _ACTIVE_SESSIONS.pop(k, None)
        return list(_ACTIVE_SESSIONS.values())


def verify_token(token: str) -> str | None:
    """Validate a token; return its role or None (expired / tampered / revoked)."""
    if not token:
        return None
    tok_hash = hashlib.sha256(token.encode()).hexdigest()
    with _SESSION_LOCK:
        if tok_hash in _REVOKED_TOKENS:
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
    shared agent credential or cryptographic HMAC signature and is attributed
    as 'agent'. Audit logging uses this."""
    headers = {k.lower(): v for k, v in request.headers.items()} if hasattr(request, "headers") else {}
    agent_id = headers.get("x-outpost-agent-id")
    ts = headers.get("x-outpost-timestamp")
    sig = headers.get("x-outpost-signature")
    nonce = headers.get("x-outpost-nonce")
    digest = headers.get("x-outpost-digest")
    if agent_id and ts and sig:
        method = getattr(request, "method", "GET")
        url = getattr(request, "url", None)
        path = url.path if url and hasattr(url, "path") else "/"
        if verify_agent_hmac_headers(agent_id, ts, sig, method, path, body_digest=digest, nonce=nonce):
            return "agent"

    if not auth_enabled():
        return "local"
    cookies = getattr(request, "cookies", {}) if hasattr(request, "cookies") else {}
    url = getattr(request, "url", None)
    path = url.path if url and hasattr(url, "path") else "/"
    tok = token_from_request(dict(request.headers), dict(request.query_params) if hasattr(request, "query_params") else {}, dict(cookies), path=path)
    role = verify_token(tok) if tok else None
    if role is None and verify_agent_token(tok):
        return "agent"
    return role or "local"


actor = role_from_request


def token_from_request(
    headers: dict,
    query: dict | None = None,
    cookies: dict | None = None,
    path: str | None = None,
) -> str:
    """Pull the token from `Authorization: Bearer <t>` or `Cookie: outpost_token=<t>`.

    The SSE token must not travel in the URL query string (prevents URL/proxy log leakage).
    Browser EventSource connections send the HttpOnly outpost_token cookie for SSE (/events/stream).
    Standard REST endpoints enforce Authorization: Bearer to avoid cross-request cookie leakage.
    """
    auth = headers.get("authorization", "") or headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    if path and (path.startswith("/events/stream") or path == "/auth/me"):
        if cookies and "outpost_token" in cookies:
            return (cookies.get("outpost_token") or "").strip()
        cookie_hdr = headers.get("cookie", "") or headers.get("Cookie", "")
        if "outpost_token=" in cookie_hdr:
            for part in cookie_hdr.split(";"):
                part = part.strip()
                if part.startswith("outpost_token="):
                    return part.split("=", 1)[1].strip()
    return ""
