"""Parked features compatibility routes.

Provides clean fallback responses for legacy / parked endpoints (investigations, campaigns)
ensuring existing UI sub-decks render cleanly without 404 console errors.
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
