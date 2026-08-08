"""Digital footprinting (roadmap) — GET /footprint/{sample_id}.

Passive domain/IP footprint for one uploaded sample. The seed (the sample's
observed infrastructure) is real; the passive expansion layer is a scaffold
waiting for a provider — see services/footprint.py. `?mock=1` renders
clearly-labeled synthetic data so the webapp can demo the UI shape.
"""

from fastapi import APIRouter, HTTPException, Query

from ..core.db import db_session
from ..services import footprint as footprint_service

router = APIRouter(tags=["footprint"])


@router.get("/footprint/{sample_id}", response_model=None)
def get_footprint(
    sample_id: str,
    mock: int = Query(0, ge=0, le=1, description="Fill the passive layer with clearly-labeled synthetic data"),
):
    with db_session() as conn:
        data = footprint_service.build_footprint(conn, sample_id, mock=bool(mock))
    if data is None:
        raise HTTPException(status_code=404, detail=f"Unknown sample_id: {sample_id}")
    return data
