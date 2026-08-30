"""OutPost backend — FastAPI application entrypoint.

Bootstraps the SQLite schema on startup, applies CORS for the frontend, mounts
an optional auth gate (env-gated — no passwords configured = no auth), and
mounts the API routers. Run with:

    cd backend && uvicorn app.main:app --reload
"""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.routes_admin import auto_prune_loop
from .api.routes_admin import router as admin_router
from .api.routes_agents import router as agents_router
from .api.routes_alerts import router as alerts_router
from .api.routes_analysis import router as analysis_router
from .api.routes_analysis_jobs import router as analysis_jobs_router
from .api.routes_audit import router as audit_router
from .api.routes_auth import router as auth_router
from .api.routes_campaigns import router as campaigns_router
from .api.routes_events import router as events_router
from .api.routes_findings import router as findings_router
from .api.routes_footprint import router as footprint_router
from .api.routes_health import router as health_router
from .api.routes_hosts import router as hosts_router
from .api.routes_ingest import router as ingest_router
from .api.routes_intel import router as intel_router
from .api.routes_investigations import router as investigations_router
from .api.routes_ioc import router as ioc_router
from .api.routes_iocs import router as iocs_router
from .api.routes_keys import router as keys_router
from .api.routes_metrics import router as metrics_router
from .api.routes_notifications import router as notifications_router
from .api.routes_rules import router as rules_router
from .api.routes_runs import router as runs_router
from .api.routes_samples import router as samples_router
from .api.routes_sandbox import router as sandbox_router
from .api.routes_search import router as search_router
from .api.routes_setup import router as setup_router
from .api.routes_host_forensics import router as host_forensics_router
from .api.routes_watchlist import router as watchlist_router
from .api.routes_yara import router as yara_router
from .core import auth as auth_service
from .core.config import CORS_ORIGINS
from .core.db import init_db

# Paths that never require a token, even with auth enabled: health/platform
# (the deck's pulse) and the auth endpoints themselves. The SSE stream is NOT
# public: EventSource can't set headers, so the frontend appends `?token=` to
# the URL instead — the gate below verifies it like any other request.
_PUBLIC_PREFIXES = ("/health", "/platform", "/auth/")


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
    # Fleet health watcher — pages when a heartbeat-enabled host goes silent
    # (one page per incident; recovery clears the flag).
    from .services import fleet_health

    fleet_task = asyncio.create_task(fleet_health.fleet_health_loop())
    try:
        yield
    finally:
        prune_task.cancel()
        fleet_task.cancel()


app = FastAPI(
    title="OutPost Backend",
    version="0.1.0",
    description="Cross-platform behavioral security monitor — API",
    lifespan=lifespan,
)


def _agent_allowed(method: str, path: str) -> bool:
    """Endpoints the agent credential may use: the collector/shipper surface.

    Writes: event + snapshot ingestion, heartbeats, session creation and
    completion. Reads: run data (the agent lists/claims sessions and the
    daily summary reads its own runs' alerts). Everything else is off-limits.
    """
    if path.startswith("/ingest/") or path.startswith("/agents/"):
        return method in ("GET", "POST")
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
            import gzip as _gzip
            import zlib as _zlib

            headers = dict(scope.get("headers", []))
            encoding = headers.get(b"content-encoding", b"").decode("latin1").lower().strip()
            if encoding in ("gzip", "deflate", "zlib", "zstd"):
                new_headers = [(k, v) for k, v in scope["headers"] if k.lower() != b"content-encoding"]
                scope["headers"] = new_headers

                body_parts = []
                while True:
                    message = await receive()
                    body_parts.append(message.get("body", b""))
                    if not message.get("more_body", False):
                        break
                raw_body = b"".join(body_parts)

                if raw_body:
                    try:
                        if encoding == "gzip":
                            decompressed = _gzip.decompress(raw_body)
                        elif encoding in ("deflate", "zlib"):
                            decompressed = _zlib.decompress(raw_body)
                        elif encoding == "zstd":
                            try:
                                import zstandard as _zstd
                                dctx = _zstd.ZstdDecompressor()
                                decompressed = dctx.decompress(raw_body)
                            except ImportError:
                                decompressed = raw_body
                        else:
                            decompressed = raw_body
                    except Exception:
                        decompressed = raw_body
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
async def auth_gate(request: Request, call_next):
    """Optional auth: with no role passwords configured this passes everything
    through (the zero-config default). With auth on, every non-public request
    needs a valid token; the read-only `analyst` role is limited to safe
    methods. Token arrives via `Authorization: Bearer` or `?token=` (SSE)."""
    if not auth_service.auth_enabled():
        return await call_next(request)

    path = request.url.path
    if any(path.startswith(p) for p in _PUBLIC_PREFIXES):
        return await call_next(request)

    token = auth_service.token_from_request(dict(request.headers), dict(request.query_params))
    role = auth_service.verify_token(token) if token else None
    # The shared agent credential (OUTPOST_AGENT_TOKEN) is a *host* identity,
    # not a browser role: it may only touch telemetry (ship events, heartbeat,
    # claim/create/complete sessions, read run data). Everything else 403s, so
    # a stolen agent token can't triage alerts or touch settings.
    if role is None and auth_service.verify_agent_token(token):
        role = "agent"
    if role is None:
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})
    if role == "analyst" and request.method not in ("GET", "HEAD", "OPTIONS"):
        return JSONResponse(status_code=403, content={"detail": "Read-only analyst role cannot modify data"})
    if role == "agent" and not _agent_allowed(request.method, path):
        return JSONResponse(status_code=403, content={"detail": "Agent credential is limited to telemetry endpoints"})
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
app.include_router(hosts_router)
app.include_router(metrics_router)
app.include_router(keys_router)
app.include_router(setup_router)
app.include_router(intel_router)
app.include_router(footprint_router)
app.include_router(ingest_router)
app.include_router(alerts_router)
app.include_router(findings_router)
app.include_router(analysis_jobs_router)
app.include_router(events_router)
app.include_router(investigations_router)
app.include_router(runs_router)
app.include_router(ioc_router)
app.include_router(iocs_router)
app.include_router(search_router)
app.include_router(watchlist_router)
app.include_router(samples_router)
app.include_router(campaigns_router)
app.include_router(analysis_router)
app.include_router(rules_router)
app.include_router(notifications_router)
app.include_router(yara_router)
app.include_router(sandbox_router)
app.include_router(agents_router)
app.include_router(host_forensics_router)
app.include_router(audit_router)
app.include_router(admin_router)
