"""Global search (P0.5) — one grouped endpoint over every analyst-facing
resource: findings, IOCs, artifacts (samples), hosts, sessions/jobs (runs),
investigations, and campaigns (derived). Free text plus qualifiers
(`type:` `status:` `severity:` `disposition:` `host:` `rule:` `case:`) are
parsed from the single `q` parameter; `type:` restricts the search to one
group. `/ioc/search` stays untouched (the legacy event-scoped search).
"""

from fastapi import APIRouter, HTTPException, Query

from ..core.db import db_session
from ..core.schema import SearchResponseDTO
from ..models import search as search_store

router = APIRouter(tags=["search"])

_SEARCH_LIMIT_MAX = 50


@router.get("/search", response_model=SearchResponseDTO)
def global_search(
    q: str = Query(..., min_length=1, max_length=500, description="Free text + qualifiers (type: status: severity: disposition: host: rule: case:)"),
    limit: int = Query(10, ge=1, le=_SEARCH_LIMIT_MAX, description="Max hits per group"),
) -> SearchResponseDTO:
    """Grouped search across every analyst-facing resource. Qualifiers narrow
    the match: `type:finding`, `status:open`, `severity:malicious`,
    `disposition:benign`, `host:<host_id>`, `rule:<rule_id>`,
    `case:<investigation_id>`. The `q` echo in the response is the free text
    with qualifiers stripped; `qualifiers` echoes the parsed filters."""
    q = q.strip()
    if not q:
        raise HTTPException(status_code=422, detail="q must not be empty")
    with db_session() as conn:
        out = search_store.search_all(conn, q, limit=limit)
    return SearchResponseDTO(**out)
