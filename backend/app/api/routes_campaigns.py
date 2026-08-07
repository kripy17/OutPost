"""Campaign clustering endpoint — GET /campaigns (webapp "Campaigns" view).

Auto-groups runs that share infrastructure into campaign cards: member runs,
shared-IOC evidence, and a combined run-attributed timeline. See
services/campaigns.py for the clustering rules.
"""

from fastapi import APIRouter

from ..core.db import db_session
from ..services import campaigns as campaigns_service

router = APIRouter(tags=["campaigns"])


@router.get("/campaigns", response_model=None)
def list_campaigns():
    """Every campaign found in run history, strongest first."""
    with db_session() as conn:
        return campaigns_service.build_campaigns(conn)
