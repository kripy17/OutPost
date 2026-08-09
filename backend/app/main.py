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

from .api.routes_alerts import router as alerts_router
from .api.routes_analysis import router as analysis_router
from .api.routes_auth import router as auth_router
from .api.routes_campaigns import router as campaigns_router
from .api.routes_events import router as events_router
from .api.routes_footprint import router as footprint_router
from .api.routes_health import router as health_router
from .api.routes_ioc import router as ioc_router
from .api.routes_ingest import router as ingest_router
from .api.routes_notifications import router as notifications_router
from .api.routes_rules import router as rules_router
from .api.routes_runs import router as runs_router
from .api.routes_samples import router as samples_router
from .api.routes_sandbox import router as sandbox_router
from .api.routes_watchlist import router as watchlist_router
from .api.routes_yara import router as yara_router
from .api.routes_agents import router as agents_router
from .api.routes_audit import router as audit_router
from .api.routes_admin import auto_prune_loop, router as admin_router
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
    if role is None:
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})
    if role == "analyst" and request.method not in ("GET", "HEAD", "OPTIONS"):
        return JSONResponse(status_code=403, content={"detail": "Read-only analyst role cannot modify data"})
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
app.include_router(footprint_router)
app.include_router(ingest_router)
app.include_router(alerts_router)
app.include_router(events_router)
app.include_router(runs_router)
app.include_router(ioc_router)
app.include_router(watchlist_router)
app.include_router(samples_router)
app.include_router(campaigns_router)
app.include_router(analysis_router)
app.include_router(rules_router)
app.include_router(notifications_router)
app.include_router(yara_router)
app.include_router(sandbox_router)
app.include_router(agents_router)
app.include_router(audit_router)
app.include_router(admin_router)
