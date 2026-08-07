"""OutPost backend — FastAPI application entrypoint.

Bootstraps the SQLite schema on startup, applies CORS for the frontend, and
mounts the API routers. Run with:

    cd backend && uvicorn app.main:app --reload
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.routes_alerts import router as alerts_router
from .api.routes_analysis import router as analysis_router
from .api.routes_campaigns import router as campaigns_router
from .api.routes_events import router as events_router
from .api.routes_health import router as health_router
from .api.routes_ioc import router as ioc_router
from .api.routes_ingest import router as ingest_router
from .api.routes_notifications import router as notifications_router
from .api.routes_rules import router as rules_router
from .api.routes_runs import router as runs_router
from .api.routes_samples import router as samples_router
from .api.routes_watchlist import router as watchlist_router
from .core.config import CORS_ORIGINS
from .core.db import init_db


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

app.include_router(health_router)
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
