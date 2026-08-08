"""Digital footprinting — GET /footprint/{sample_id}.

Passive domain/IP footprint for one uploaded sample. The seed (the sample's
observed infrastructure) is real; the passive expansion layer pulls real
reverse-DNS + crt.sh CT + RDAP data (services/footprint.py) with an honest
offline fallback. `?mock=1` forces clearly-labeled synthetic data instead.
"""

from fastapi import APIRouter, HTTPException, Query

from ..core.db import db_session
from ..services import footprint as footprint_service

router = APIRouter(tags=["footprint"])


@router.get("/footprint/{sample_id}", response_model=None)
async def get_footprint(
    sample_id: str,
    mock: int = Query(0, ge=0, le=1, description="Force clearly-labeled synthetic data instead of live lookups"),
):
    with db_session() as conn:
        data = await footprint_service.build_footprint(conn, sample_id, mock=bool(mock))
    if data is None:
        raise HTTPException(status_code=404, detail=f"Unknown sample_id: {sample_id}")
    return data
