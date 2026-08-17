"""Finding API (P0.2) — the semantic finding resource over `alerts`.

The physical table remains `alerts` (P0.1); this router exposes it as
`findings` with the P0 layer: source / disposition / confidence filters,
the unread definition (`status='open' AND seen_at IS NULL`), opt-in
`mark_seen`, analyst-authored findings (`source='analyst'`), and the
extended verdict fields on the detail view.

The queue itself is the SAME implementation as /alerts/queue
(``models/findings.query_findings``) — /alerts/queue stays byte-compatible
and gains nothing; /findings adds the P0 filters. Reads never mutate:
`seen_at` is written only by an explicit `mark_seen=true` page.
"""

from fastapi import APIRouter, HTTPException, Query, Request

from ..core import auth
from ..core.db import db_session
from ..core.schema import FindingDTO, FindingIn
from ..models import audit
from ..models import findings as findings_store
from ..models import run as run_store

router = APIRouter(tags=["findings"])


@router.get("/findings", response_model=None)
def list_findings(
    status: str = Query("open"),
    source: str | None = Query(None, description="detection | analyst | correlation"),
    disposition: str | None = Query(None, description="false-positive | confirmed-malicious | benign | watchlisted | escalated"),
    confidence: str | None = Query(None, description="high | medium | low"),
    unread_only: bool = Query(False, description="Only status='open' AND seen_at IS NULL"),
    mark_seen: bool = Query(False, description="Opt-in: stamp seen_at on the rows of this page (only where still NULL)"),
    rule_id: str | None = None,
    severity: str | None = None,
    host_id: str | None = None,
    assignee: str | None = None,
    campaign: str | None = None,
    provenance: str | None = None,
    q: str | None = None,
    sort: str = Query("aging"),
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """The finding queue — same envelope as /alerts/queue, plus the P0
    filters. `unread_only` and `mark_seen` default OFF: automation must opt
    in to both, and a plain read never writes `seen_at`."""
    if status not in ("open", "acknowledged", "resolved", "all"):
        raise HTTPException(status_code=422, detail="status must be open, acknowledged, resolved, or all")
    if source not in ("detection", "analyst", "correlation", None):
        raise HTTPException(status_code=422, detail="source must be detection, analyst, or correlation")
    if disposition not in (
        "false-positive", "confirmed-malicious", "benign", "watchlisted", "escalated", None,
    ):
        raise HTTPException(status_code=422, detail="disposition must be false-positive, confirmed-malicious, benign, watchlisted, or escalated")
    if confidence not in ("high", "medium", "low", None):
        raise HTTPException(status_code=422, detail="confidence must be high, medium, or low")
    if severity not in ("suspicious", "malicious", None):
        raise HTTPException(status_code=422, detail="severity must be suspicious or malicious")
    if provenance not in ("real", "synthetic", None):
        raise HTTPException(status_code=422, detail="provenance must be real or synthetic")
    if sort not in ("aging", "newest"):
        raise HTTPException(status_code=422, detail="sort must be aging or newest")
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    with db_session() as conn:
        out = findings_store.query_findings(
            conn,
            status=status,
            source=source,
            disposition=disposition,
            confidence=confidence,
            unread_only=unread_only,
            rule_id=rule_id,
            severity=severity,
            host_id=host_id,
            assignee=assignee,
            campaign=campaign,
            provenance=provenance,
            q=q,
            sort=sort,
            limit=limit,
            offset=offset,
        )
        page_ids = out.pop("_page_ids")
        # mark_seen is the ONLY mutation, and it is bounded + idempotent:
        # exactly the rows of THIS page, only where seen_at is still NULL.
        marked = 0
        if mark_seen:
            marked = findings_store.mark_page_seen(conn, page_ids)
    out["marked_seen"] = marked
    return out


@router.get("/findings/{finding_id}", response_model=FindingDTO)
def get_finding(finding_id: int) -> FindingDTO:
    """One finding — the full alert row plus the P0 verdict fields. Evidence
    refs (event/artifact links) are deferred to a later phase; the existing
    related_pid / related_ip / related_pids / details stay the evidence and
    context fields."""
    with db_session() as conn:
        row = findings_store.get_finding(conn, finding_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Unknown finding id: {finding_id}")
    return FindingDTO(**row)


@router.post("/findings", status_code=201, response_model=FindingDTO)
def create_finding(body: FindingIn, request: Request) -> FindingDTO:
    """Create an analyst-authored finding on a run. `source` is forced to
    'analyst' — the detection engine is the only writer of 'detection'.
    Audited like every other analyst mutation."""
    with db_session() as conn:
        if not run_store.get_run(conn, body.run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {body.run_id}")
        row = findings_store.create_analyst_finding(conn, body)
        audit.log(
            conn, auth.role_from_request(request), "finding.create",
            target_type="finding", target_id=str(row["id"]),
            detail=f"{body.severity} · {body.rule_id} on run {body.run_id}",
        )
    return FindingDTO(**row)
