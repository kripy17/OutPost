"""Parked features compatibility routes.

Provides clean fallback responses for legacy / parked endpoints (investigations, campaigns, agents, alerts)
ensuring existing UI sub-decks and shell headers render cleanly without 404 console errors.
"""

from fastapi import APIRouter

router = APIRouter(tags=["parked"])


@router.get("/investigations", response_model=None)
def list_investigations_parked(limit: int = 50, offset: int = 0) -> dict:
    """Parked endpoint: returns empty investigation ledger."""
    return {"items": [], "total": 0, "limit": limit, "offset": offset}


@router.get("/campaigns", response_model=None)
def list_campaigns_parked() -> list:
    """Parked endpoint: returns empty campaign list."""
    return []


@router.get("/alerts", response_model=None)
def list_alerts_parked(limit: int = 50, offset: int = 0, provenance: str = None) -> list:
    """Parked endpoint: returns empty alert ledger."""
    return []


@router.get("/alerts/queue", response_model=None)
def list_alerts_queue_parked(status: str = "open", limit: int = 50) -> list:
    """Parked endpoint: returns empty alert queue."""
    return []


@router.get("/agents", response_model=None)
def list_agents_parked() -> list:
    """Parked endpoint: returns empty agent fleet list."""
    return []
