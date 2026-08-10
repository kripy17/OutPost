"""Campaign clustering endpoints — webapp "Campaigns" view + STIX export.

- GET /campaigns          — auto-grouped runs sharing infrastructure (cards)
- GET /campaigns/{key}/export?format=stix — the cluster as a STIX 2.1 bundle

See services/campaigns.py for the clustering rules.
"""

from fastapi import APIRouter, HTTPException, Query

from ..core.db import db_session
from ..services import campaigns as campaigns_service
from ..services import stix as stix_service

router = APIRouter(tags=["campaigns"])


@router.get("/campaigns", response_model=None)
def list_campaigns(
    include_synthetic: bool = Query(
        False,
        description="Include campaigns built from synthetic-provenance runs (seeds / webapp detonations / the sandbox demo)",
    ),
):
    """Every campaign found in run history, strongest first. Synthetic-provenance
    member runs are excluded by default (archive parity); campaigns that fall
    below two real members are dropped. The CLI opts in with
    `include_synthetic=true` to keep terminal parity with the full story."""
    with db_session() as conn:
        return campaigns_service.build_campaigns(conn, include_synthetic=include_synthetic)


@router.get("/campaigns/{key}/export", response_model=None)
def export_campaign(key: str, format: str = "stix"):
    """A campaign as a shareable STIX 2.1 bundle (webapp per-card export).

    Carries the cluster metadata, every shared IOC as an indicator, each
    member run, and the relationships linking them — so a threat-intel team
    can hunt the whole cluster in MISP/OpenCTI, not one run at a time.
    """
    if format != "stix":
        raise HTTPException(status_code=422, detail="format must be stix")
    bundle = stix_service.build_campaign_stix_bundle(key)
    if "error" in bundle:
        raise HTTPException(status_code=404, detail=bundle["error"])
    return bundle
