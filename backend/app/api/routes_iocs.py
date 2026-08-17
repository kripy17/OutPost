"""IOC resource API (P0.2) — the canonical IOC entity.

- GET  /iocs              — paged entity search (q / type / disposition)
- POST /iocs              — manual IOC creation (normalized, deduped)
- GET  /iocs/{id}         — the workspace payload: row + provenance + linked
                            findings + derived runs/hosts + enrichment attrs
- PATCH /iocs/{id}/disposition — analyst verdict (audited)

The existing `/ioc/search` (event-corpus search with reputation ride-along)
is untouched — that surface searches the RUN HISTORY; /iocs searches the new
IOC entity.
"""

from fastapi import APIRouter, HTTPException, Query, Request

from ..core import auth
from ..core.db import db_session
from ..core.schema import IocCreateIn, IocDetailDTO, IocDispositionIn, IocDTO
from ..models import audit
from ..models import iocs as ioc_store

router = APIRouter(tags=["iocs"])


@router.get("/iocs", response_model=None)
def list_iocs(
    q: str = Query("", max_length=500),
    type: str | None = Query(None, description="ip | domain | url | hash | email | filepath | registry | mutex | certificate | other"),
    disposition: str | None = Query(None, description="candidate | enriched | confirmed-malicious | benign | allowlisted | watchlisted | unresolved"),
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Paged IOC entity search. Envelope matches the repository's list
    conventions: total + limit/offset + the page under `iocs`."""
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    with db_session() as conn:
        total, rows = ioc_store.list_iocs(conn, q=q, ioc_type=type, disposition=disposition, limit=limit, offset=offset)
    return {"total": total, "limit": limit, "offset": offset, "iocs": rows}


@router.post("/iocs", status_code=201, response_model=IocDTO)
def create_ioc(body: IocCreateIn) -> IocDTO:
    """Manually create an IOC. Values are normalized (lowercase + strip for
    ip/domain/hash/email); identity is UNIQUE(value, type) — posting an
    existing indicator returns the existing row (idempotent, 201). Default
    disposition is `candidate`; `first_seen` is stamped now."""
    with db_session() as conn:
        row = ioc_store.create_ioc(conn, body.value, body.type, body.label)
    return IocDTO(**row)


@router.get("/iocs/{ioc_id}", response_model=IocDetailDTO)
def get_ioc_detail(ioc_id: str) -> IocDetailDTO:
    """The IOC workspace payload: the row, its provenance (where it was
    observed), linked findings, and the runs/hosts DERIVED from that
    provenance. Enrichment attributes (abuse_score / vt_malicious_count /
    reputation / checked_at) ride on the row — filled by the enrichment
    backfill in a later phase; runs/hosts are empty when nothing in the
    corpus references the indicator."""
    with db_session() as conn:
        row = ioc_store.get_ioc(conn, ioc_id)
        if not row:
            raise HTTPException(status_code=404, detail=f"Unknown IOC: {ioc_id}")
        provenance = ioc_store.provenance_rows(conn, ioc_id)
        findings = ioc_store.linked_findings(conn, ioc_id)
        runs = ioc_store.related_runs(conn, ioc_id)
        hosts = ioc_store.related_hosts(conn, ioc_id)
    return IocDetailDTO(
        **row,
        provenance=provenance,
        findings=findings,
        runs=runs,
        hosts=hosts,
    )


@router.patch("/iocs/{ioc_id}/disposition", response_model=IocDTO)
def update_ioc_disposition(ioc_id: str, body: IocDispositionIn, request: Request) -> IocDTO:
    """Apply an analyst verdict (and optional label) to an IOC. Audited —
    the disposition trail is part of the evidence record. The watchlist API
    is untouched; this verdict is the entity's own disposition."""
    with db_session() as conn:
        row = ioc_store.get_ioc(conn, ioc_id)
        if not row:
            raise HTTPException(status_code=404, detail=f"Unknown IOC: {ioc_id}")
        updated = ioc_store.set_disposition(conn, ioc_id, body.disposition, body.label)
        audit.log(
            conn, auth.role_from_request(request), "ioc.disposition",
            target_type="ioc", target_id=ioc_id,
            detail=f"{row['disposition']} → {body.disposition} · {row['value']} ({row['type']})"
            + (f" · label {body.label.strip()}" if body.label and body.label.strip() else ""),
        )
    return IocDTO(**updated)
