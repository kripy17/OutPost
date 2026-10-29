"""OutPost backend — FastAPI application entrypoint.

Bootstraps the SQLite schema on startup, applies CORS for the frontend, mounts
an optional auth gate (env-gated — no passwords configured = no auth), and
mounts the API routers. Run with:

    cd backend && uvicorn app.main:app --reload
"""

import asyncio
import hashlib
import hmac
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.routes_admin import auto_prune_loop
from .api.routes_admin import router as admin_router
from .api.routes_analysis import router as analysis_router
from .api.routes_analysis_jobs import router as analysis_jobs_router
from .api.routes_auth import router as auth_router
from .api.routes_corpus import router as corpus_router
from .api.routes_diagnostics import router as diagnostics_router
from .api.routes_events import router as events_router
from .api.routes_health import router as health_router
from .api.routes_ingest import router as ingest_router
from .api.routes_intel import router as intel_router
from .api.routes_ioc import router as ioc_router
from .api.routes_iocs import router as iocs_router
from .api.routes_keys import router as keys_router
from .api.routes_metrics import router as metrics_router
from .api.routes_notifications import router as notifications_router
from .api.routes_parked import router as parked_router
from .api.routes_rules import router as rules_router
from .api.routes_runs import router as runs_router
from .api.routes_samples import router as samples_router
from .api.routes_sandbox import router as sandbox_router
from .api.routes_search import router as search_router
from .api.routes_setup import router as setup_router
from .api.routes_watchlist import router as watchlist_router
from .api.routes_yara import router as yara_router
from .core import auth as auth_service
from .core.config import CORS_ORIGINS
from .core.db import init_db

# Paths that never require a token, even with auth enabled: health/platform
# (the deck's pulse) and the auth endpoints themselves. The SSE stream is NOT
# public: EventSource can't set headers, so the frontend appends `?token=` to
# the URL instead — the gate below verifies it like any other request.
_PUBLIC_PREFIXES = ("/health", "/platform", "/auth/", "/agents/register")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Fail-closed auth: OUTPOST_AUTH_REQUIRED=1 refuses to start without an
    # admin credential (an empty signing key would be forgeable, worse than
    # running open). Only reached after init_db so DB credentials are visible.
    auth_service.validate_config()
    # Background auto-prune scheduler (off by default) — wakes every 60s and
    # runs the retention prune when a schedule is set. Canceled on shutdown.
    prune_task = asyncio.create_task(auto_prune_loop())
    try:
        yield
    finally:
        prune_task.cancel()


app = FastAPI(
    title="OutPost Backend",
    version="0.1.0",
    description="Cross-platform behavioral security monitor — API",
    lifespan=lifespan,
)


def _agent_allowed(method: str, path: str) -> bool:
    """Endpoints the agent credential may use: telemetry shipping and heartbeat only.

    Writes: event + snapshot ingestion, heartbeats, agent enrollment, session creation/completion,
    containment report, and action acknowledgment. Reads: run data (the agent lists/claims sessions).
    Containment actions (host isolation, process termination) and administrative
    endpoints are strictly forbidden for agent credentials.
    """
    if path.startswith("/ingest/"):
        return method in ("GET", "POST")
    if path == "/agents/register":
        return method == "POST"
    if path == "/agents/heartbeat":
        return method == "POST"
    if path.startswith("/agents/") and (
        path.endswith("/heartbeat")
        or path.endswith("/actions/ack")
        or path.endswith("/containment/report")
    ):
        return method == "POST"
    if path.startswith("/runs"):
        if method == "GET":
            return True
        return method == "POST" and (path == "/runs" or path.endswith("/complete"))
    return False


class DecompressionMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            import json as _json
            import zlib as _zlib

            headers = dict(scope.get("headers", []))
            encoding = headers.get(b"content-encoding", b"").decode("latin1").lower().strip()
            if encoding:
                new_headers = [(k, v) for k, v in scope["headers"] if k.lower() != b"content-encoding"]
                scope["headers"] = new_headers

                body_parts = []
                while True:
                    message = await receive()
                    body_parts.append(message.get("body", b""))
                    if not message.get("more_body", False):
                        break
                raw_body = b"".join(body_parts)

                _MAX_DECOMPRESS = 50 * 1024 * 1024  # 50 MB decompression limit
                if raw_body:
                    try:
                        if encoding == "gzip":
                            decompressor = _zlib.decompressobj(16 + _zlib.MAX_WBITS)
                            decompressed = decompressor.decompress(raw_body, _MAX_DECOMPRESS + 1)
                            if len(decompressed) > _MAX_DECOMPRESS or decompressor.unconsumed_tail:
                                raise ValueError("Decompressed payload exceeds 50MB ceiling")
                        elif encoding in ("deflate", "zlib"):
                            decompressor = _zlib.decompressobj()
                            decompressed = decompressor.decompress(raw_body, _MAX_DECOMPRESS + 1)
                            if len(decompressed) > _MAX_DECOMPRESS or decompressor.unconsumed_tail:
                                raise ValueError("Decompressed payload exceeds 50MB ceiling")
                        elif encoding == "zstd":
                            try:
                                import zstandard as _zstd
                                dctx = _zstd.ZstdDecompressor()
                                decompressed = dctx.decompress(raw_body, max_output_size=_MAX_DECOMPRESS)
                            except ImportError:
                                raise ValueError("zstd compression unsupported: zstandard package not installed")
                        else:
                            raise ValueError(f"Unsupported content-encoding: {encoding}")
                    except Exception as exc:
                        err_bytes = _json.dumps({"detail": f"Payload decompression error: {exc}"}).encode("utf-8")
                        await send({
                            "type": "http.response.start",
                            "status": 400,
                            "headers": [
                                (b"content-type", b"application/json"),
                                (b"content-length", str(len(err_bytes)).encode("latin1")),
                            ],
                        })
                        await send({
                            "type": "http.response.body",
                            "body": err_bytes,
                            "more_body": False,
                        })
                        return
                else:
                    decompressed = b""

                sent = False

                async def custom_receive():
                    nonlocal sent
                    if not sent:
                        sent = True
                        return {"type": "http.request", "body": decompressed, "more_body": False}
                    return {"type": "http.request", "body": b"", "more_body": False}

                return await self.app(scope, custom_receive, send)

        return await self.app(scope, receive, send)


app.add_middleware(DecompressionMiddleware)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Enforce strict Content-Security-Policy and browser defensive headers."""
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self' data:; connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.middleware("http")
async def auth_gate(request: Request, call_next):
    """Optional auth: with no role passwords configured this passes everything
    through (the zero-config default). With auth on, every non-public request
    needs a valid token; the read-only `analyst` role is limited to safe
    methods. Token arrives via `Authorization: Bearer` or `Cookie: outpost_token`."""
    if not auth_service.auth_enabled():
        return await call_next(request)

    path = request.url.path
    if any(path.startswith(p) for p in _PUBLIC_PREFIXES):
        return await call_next(request)

    headers = {k.lower(): v for k, v in request.headers.items()}
    agent_id = headers.get("x-outpost-agent-id")
    ts = headers.get("x-outpost-timestamp")
    sig = headers.get("x-outpost-signature")
    nonce = headers.get("x-outpost-nonce")
    digest = headers.get("x-outpost-digest")
    role = None
    agent_host_id = None

    if agent_id and ts and sig:
        body_bytes = await request.body()
        computed_digest = hashlib.sha256(body_bytes).hexdigest() if body_bytes else ""
        client_digest = (digest or "").strip()

        # Enforce strict body digest validation against X-OutPost-Digest header
        if client_digest:
            if not hmac.compare_digest(client_digest.lower(), computed_digest.lower()):
                return JSONResponse(status_code=401, content={"detail": "Request body digest mismatch (X-OutPost-Digest)"})

        effective_digest = client_digest or computed_digest

        if auth_service.verify_agent_hmac_headers(
            agent_id,
            ts,
            sig,
            request.method,
            path,
            query_string=request.url.query,
            body_digest=effective_digest,
            nonce=nonce,
        ):
            role = "agent"
            # Bind agent identity to enrolled host_id
            try:
                from .core.db import db_session
                with db_session() as conn:
                    row = conn.execute("SELECT host_id FROM enrolled_agents WHERE agent_id = ?", (agent_id,)).fetchone()
                    if row:
                        agent_host_id = row["host_id"]
            except Exception:
                pass
            request.state.agent_id = agent_id
            request.state.agent_host_id = agent_host_id

    if role is None:
        token = auth_service.token_from_request(
            dict(request.headers),
            dict(request.query_params),
            dict(request.cookies),
            path=path,
        )
        role = auth_service.verify_token(token) if token else None
        # The shared agent credential (OUTPOST_AGENT_TOKEN) is a *host* identity,
        # not a browser role: it may only touch telemetry (ship events, heartbeat,
        # claim/create/complete sessions, read run data). Everything else 403s, so
        # a stolen agent token can't triage alerts or touch settings.
        if role is None and auth_service.verify_agent_token(token):
            role = "agent"
            request.state.agent_id = "shared_agent_token"
            request.state.agent_host_id = None

    if role is None:
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})
    if role == "analyst" and request.method not in ("GET", "HEAD", "OPTIONS"):
        return JSONResponse(status_code=403, content={"detail": "Read-only analyst role cannot modify data"})
    if role == "agent":
        if not _agent_allowed(request.method, path):
            return JSONResponse(status_code=403, content={"detail": "Agent credential is limited to telemetry endpoints"})

        # Host-scoping gate: verify agent credential is authorized for the target host
        if path.startswith("/agents/"):
            parts = path.strip("/").split("/")
            if len(parts) >= 2:
                target_host_id = parts[1]
                if agent_host_id and agent_host_id != target_host_id:
                    return JSONResponse(
                        status_code=403,
                        content={"detail": f"Agent credential is not authorized for host '{target_host_id}'"},
                    )
                if not agent_host_id and (path.endswith("/actions/ack") or path.endswith("/containment/report")):
                    try:
                        from .core.db import db_session
                        with db_session() as conn:
                            enrolled_row = conn.execute(
                                "SELECT 1 FROM enrolled_agents WHERE host_id = ? AND status = 'active'",
                                (target_host_id,),
                            ).fetchone()
                            if enrolled_row:
                                return JSONResponse(
                                    status_code=403,
                                    content={"detail": "Shared agent token retired for enrolled hosts; host containment and action acknowledgments require enrolled cryptographic agent credentials."},
                                )
                    except Exception:
                        pass

    return await call_next(request)


# CORS must be the OUTERMOST middleware (registered last): Starlette wraps
# middlewares inside-out, so anything added after auth_gate runs before it.
# If the gate short-circuits a 401/403 (or auth is off), the response must
# still carry Access-Control-Allow-Origin or the browser blocks it — which
# previously broke the login screen (CORS errors on every gated fetch).
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(health_router)
app.include_router(metrics_router)
app.include_router(setup_router)
app.include_router(keys_router)
app.include_router(intel_router)
app.include_router(analysis_jobs_router)
app.include_router(events_router)
app.include_router(ingest_router)
app.include_router(runs_router)
app.include_router(ioc_router)
app.include_router(iocs_router)
app.include_router(search_router)
app.include_router(watchlist_router)
app.include_router(samples_router)
app.include_router(analysis_router)
app.include_router(rules_router)
app.include_router(yara_router)
app.include_router(sandbox_router)
app.include_router(admin_router)
app.include_router(notifications_router)
app.include_router(diagnostics_router)
app.include_router(corpus_router)
app.include_router(parked_router)
