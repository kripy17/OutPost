"""OutPost backend — FastAPI application entrypoint.

Bootstraps the SQLite schema on startup, applies CORS for the frontend, mounts
an optional auth gate (env-gated — no passwords configured = no auth), and
mounts the API routers. Run with:

    cd backend && uvicorn app.main:app --reload
"""

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
from .api.routes_watchlist import router as watchlist_router
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
    yield


app = FastAPI(
    title="OutPost Backend",
    version="0.1.0",
    description="Cross-platform behavioral security monitor — API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
