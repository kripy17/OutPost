"""Investigation API (P0.3) — the optional cross-workflow case anchor.

- POST   /investigations              — create (title + optional tags)
- GET    /investigations              — list (status / q filters, paged)
- GET    /investigations/{id}         — the workspace payload (header, tags,
                                        findings, refs, notes, counts)
- PATCH  /investigations/{id}         — title / tags / status / conclusion
                                        (forward-only status transitions)
- POST   /investigations/{id}/refs    — add an evidence ref (idempotent)
- DELETE /investigations/{id}/refs/{ref_id} — remove one ref
- POST   /investigations/{id}/notes   — append an analyst note
- POST   /investigations/{id}/close   — close (requires conclusion)
- POST   /investigations/{id}/reopen  — reopen closed → active

Finding attach/detach rides the existing PATCH /alerts/{id} (the nullable
alerts.investigation_id link) — see routes_alerts. Every mutation is audited.
"""

from fastapi import APIRouter, HTTPException, Query, Request

from ..core import auth
from ..core.db import db_session
from ..core.schema import (
    InvestigationCloseIn,
    InvestigationCreateIn,
    InvestigationDetailDTO,
    InvestigationDTO,
    InvestigationNoteDTO,
    InvestigationNoteIn,
    InvestigationPatchIn,
    InvestigationRefDTO,
    InvestigationRefIn,
    InvestigationTaskDTO,
    InvestigationTaskIn,
    InvestigationTaskPatchIn,
    ApplyPlaybookIn,
)
from ..models import audit
from ..models import investigation as inv_store
from ..models import iocs as ioc_store
from ..models import run as run_store
from ..models import samples as samples_store
from ..services import campaigns as campaigns_service

router = APIRouter(tags=["investigations"])

_STATUS_ORDER = ("created", "triage", "active", "contained", "resolved", "closed")


def _validate_ref(conn, ref_type: str, ref_id: str) -> None:
    """Validate a ref points at a real object of its type, using the existing
    storage. campaign refs validate against the DERIVED campaign keys (the
    signature IPs of two-run clusters) — the campaign itself has no table."""
    if ref_type == "run":
        if not run_store.get_run(conn, ref_id):
            raise HTTPException(status_code=422, detail=f"Unknown run: {ref_id}")
    elif ref_type == "host":
        exists = conn.execute(
            "SELECT 1 FROM events WHERE host_id = ? LIMIT 1", (ref_id,)
        ).fetchone()
        if not exists:
            raise HTTPException(status_code=422, detail=f"Unknown host: {ref_id}")
    elif ref_type == "ioc":
        if not ioc_store.get_ioc(conn, ref_id):
            raise HTTPException(status_code=422, detail=f"Unknown IOC: {ref_id}")
    elif ref_type == "artifact":
        if not samples_store.get_sample(conn, ref_id):
            raise HTTPException(status_code=422, detail=f"Unknown artifact: {ref_id}")
    elif ref_type == "campaign":
        keys = {c["key"] for c in campaigns_service.build_campaigns(conn, include_synthetic=True)}
        if ref_id not in keys:
            raise HTTPException(status_code=422, detail=f"Unknown campaign: {ref_id}")


def _require_investigation(conn, investigation_id: str) -> None:
    if not inv_store.get(conn, investigation_id):
        raise HTTPException(status_code=404, detail=f"Unknown investigation: {investigation_id}")


@router.post("/investigations", status_code=201, response_model=InvestigationDTO)
def create_investigation(body: InvestigationCreateIn, request: Request) -> InvestigationDTO:
    title = body.title.strip()
    if not title:
        raise HTTPException(status_code=422, detail="title must not be blank")
    actor = auth.role_from_request(request)
    with db_session() as conn:
        row = inv_store.create(conn, title, actor, body.tags)
        audit.log(
            conn, actor, "investigation.create",
            target_type="investigation", target_id=row["id"],
            detail=f"title {title!r} · tags {row['tags']}",
        )
        # P0.7 — investigation lifecycle is observable in realtime via the
        # extended run_update frame (no new event type).
        from ..services import events_stream

        events_stream.publish_run_update("", 0, investigation_id=row["id"])
    return InvestigationDTO(**row)


@router.get("/investigations", response_model=None)
def list_investigations(
    status: str | None = Query(None, description="created | triage | active | contained | resolved | closed"),
    q: str | None = Query(None, max_length=500, description="search title / tags / notes"),
    limit: int = 50,
    offset: int = 0,
) -> dict:
    if status is not None and status not in _STATUS_ORDER:
        raise HTTPException(status_code=422, detail=f"status must be one of: {', '.join(_STATUS_ORDER)}")
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    with db_session() as conn:
        total, rows = inv_store.list_investigations(conn, status=status, q=q, limit=limit, offset=offset)
    return {"total": total, "limit": limit, "offset": offset, "investigations": rows}


# -- Incident Response Playbooks ----------------------------------------------


@router.get("/investigations/playbooks", response_model=None)
def list_incident_playbooks() -> list[dict]:
    """List available standardized Incident Response Playbooks."""
    from ..services.incident_playbooks import list_playbooks
    return list_playbooks()


@router.get("/investigations/playbooks/{playbook_id}", response_model=None)
def get_incident_playbook(playbook_id: str) -> dict:
    """Retrieve details, phased checklist, and hunting queries for an IR Playbook."""
    from ..services.incident_playbooks import get_playbook
    pb = get_playbook(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found")
    return pb


@router.get("/investigations/{investigation_id}", response_model=InvestigationDetailDTO)
def get_investigation(investigation_id: str) -> InvestigationDetailDTO:
    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        row = inv_store.get(conn, investigation_id)
        findings = inv_store.findings_for_investigation(conn, investigation_id)
        refs = inv_store.list_refs(conn, investigation_id)
        notes = inv_store.list_notes(conn, investigation_id)
        tasks = inv_store.list_tasks(conn, investigation_id)
    return InvestigationDetailDTO(**row, findings=findings, refs=refs, notes=notes, tasks=tasks)


@router.patch("/investigations/{investigation_id}", response_model=InvestigationDTO)
def update_investigation(investigation_id: str, body: InvestigationPatchIn, request: Request) -> InvestigationDTO:
    actor = auth.role_from_request(request)
    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        current = inv_store.get(conn, investigation_id)

        # Lifecycle policy: forward-only (or same-state) transitions on PATCH.
        # Backward moves are close/reopen decisions, not silent patches; a
        # closed investigation may only change via the explicit reopen route.
        if body.status is not None and body.status != current["status"]:
            if body.status not in _STATUS_ORDER or current["status"] not in _STATUS_ORDER:
                raise HTTPException(status_code=422, detail=f"invalid status: {body.status}")
            if _STATUS_ORDER.index(body.status) < _STATUS_ORDER.index(current["status"]):
                raise HTTPException(
                    status_code=422,
                    detail=f"Cannot move backward {current['status']} → {body.status}; use close/reopen for lifecycle decisions",
                )
            if current["status"] == "closed":
                raise HTTPException(status_code=422, detail="closed investigations change via /reopen, not PATCH")

        if body.title is not None and not body.title.strip():
            raise HTTPException(status_code=422, detail="title must not be blank")

        row = inv_store.update(
            conn, investigation_id,
            title=body.title.strip() if body.title is not None else None,
            status=body.status,
            conclusion=body.conclusion.strip() if body.conclusion is not None else None,
            tags=body.tags,
        )
        detail_parts = []
        if body.title is not None:
            detail_parts.append(f"title → {body.title.strip()!r}")
        if body.status is not None:
            detail_parts.append(f"status → {body.status}")
        if body.conclusion is not None:
            detail_parts.append("conclusion set")
        if body.tags is not None:
            detail_parts.append(f"tags → {row['tags']}")
        audit.log(
            conn, actor, "investigation.status" if body.status is not None else "investigation.update",
            target_type="investigation", target_id=investigation_id,
            detail=" · ".join(detail_parts) or "no fields changed",
        )
    return InvestigationDTO(**row)


@router.post("/investigations/{investigation_id}/refs", status_code=201, response_model=InvestigationRefDTO)
def add_investigation_ref(investigation_id: str, body: InvestigationRefIn, request: Request) -> InvestigationRefDTO:
    actor = auth.role_from_request(request)
    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        _validate_ref(conn, body.ref_type, body.ref_id)
        ref = inv_store.add_ref(conn, investigation_id, body.ref_type, body.ref_id)
        audit.log(
            conn, actor, "investigation.ref.add",
            target_type="investigation", target_id=investigation_id,
            detail=f"{body.ref_type} {body.ref_id}",
        )
    return InvestigationRefDTO(**ref)


@router.delete("/investigations/{investigation_id}/refs/{ref_id}", status_code=204)
def remove_investigation_ref(investigation_id: str, ref_id: str, request: Request) -> None:
    actor = auth.role_from_request(request)
    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        removed = inv_store.remove_ref(conn, investigation_id, ref_id)
        if not removed:
            raise HTTPException(status_code=404, detail=f"No ref {ref_id} on investigation {investigation_id}")
        audit.log(
            conn, actor, "investigation.ref.remove",
            target_type="investigation", target_id=investigation_id,
            detail=f"ref_id {ref_id}",
        )


@router.post("/investigations/{investigation_id}/notes", status_code=201, response_model=InvestigationNoteDTO)
def add_investigation_note(investigation_id: str, body: InvestigationNoteIn, request: Request) -> InvestigationNoteDTO:
    note = body.note.strip()
    if not note:
        raise HTTPException(status_code=422, detail="note must not be blank")
    actor = auth.role_from_request(request)
    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        row = inv_store.add_note(conn, investigation_id, note, actor)
        audit.log(
            conn, actor, "investigation.note",
            target_type="investigation", target_id=investigation_id,
            detail=f"note #{row['id']}",
        )
    return InvestigationNoteDTO(**row)


@router.post("/investigations/{investigation_id}/close", response_model=InvestigationDTO)
def close_investigation(investigation_id: str, body: InvestigationCloseIn, request: Request) -> InvestigationDTO:
    conclusion = body.conclusion.strip()
    if not conclusion:
        raise HTTPException(status_code=422, detail="closing requires a conclusion")
    actor = auth.role_from_request(request)
    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        current = inv_store.get(conn, investigation_id)
        if current["status"] == "closed":
            raise HTTPException(status_code=422, detail=f"investigation {investigation_id} is already closed")
        row = inv_store.close(conn, investigation_id, conclusion)
        audit.log(
            conn, actor, "investigation.close",
            target_type="investigation", target_id=investigation_id,
            detail=f"closed · conclusion {conclusion!r}",
        )
        # P0.7 — close emits the status change; subscribers (investigation
        # workspace) refresh live, and the DB row is the reconnect source.
        from ..services import events_stream

        events_stream.publish_run_update("", 0, investigation_id=investigation_id)
    return InvestigationDTO(**row)


@router.post("/investigations/{investigation_id}/reopen", response_model=InvestigationDTO)
def reopen_investigation(investigation_id: str, request: Request) -> InvestigationDTO:
    actor = auth.role_from_request(request)
    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        current = inv_store.get(conn, investigation_id)
        if current["status"] != "closed":
            raise HTTPException(status_code=422, detail=f"investigation {investigation_id} is not closed ({current['status']})")
        row = inv_store.reopen(conn, investigation_id)
        audit.log(
            conn, actor, "investigation.reopen",
            target_type="investigation", target_id=investigation_id,
            detail="closed → active",
        )
        # P0.7 — reopen emits the status change (same additive frame).
        from ..services import events_stream

        events_stream.publish_run_update("", 0, investigation_id=investigation_id)
    return InvestigationDTO(**row)


@router.post("/investigations/{investigation_id}/synthesize", response_model=None)
def synthesize_case_narrative(investigation_id: str) -> dict:
    """Synthesize an executive incident narrative, kill-chain timeline, and remediation checklist from linked evidence."""
    from ..services.report import synthesize_investigation_narrative

    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        return synthesize_investigation_narrative(conn, investigation_id)


@router.get("/investigations/{investigation_id}/export")
def export_investigation(
    investigation_id: str,
    format: str = Query("markdown", description="markdown | json"),
):
    """Export an executive Incident Response Case Brief in Markdown or full JSON format."""
    from fastapi.responses import PlainTextResponse
    from ..services.report import (
        build_investigation_json_export,
        build_investigation_markdown_export,
    )

    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        if format.lower() == "json":
            return build_investigation_json_export(conn, investigation_id)
        else:
            md_text = build_investigation_markdown_export(conn, investigation_id)
            return PlainTextResponse(
                content=md_text,
                media_type="text/markdown",
                headers={
                    "Content-Disposition": f'attachment; filename="outpost-incident-brief-{investigation_id}.md"'
                },
            )


# -- Incident Response Tasks & Checklist -------------------------------------


@router.get("/investigations/{investigation_id}/tasks", response_model=list[InvestigationTaskDTO])
def list_investigation_tasks(
    investigation_id: str,
    status: str | None = Query(None, description="todo | in_progress | completed | cancelled"),
    category: str | None = Query(None, description="containment | eradication | evidence_collection | remediation | triage"),
) -> list[InvestigationTaskDTO]:
    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        rows = inv_store.list_tasks(conn, investigation_id, status=status, category=category)
    return [InvestigationTaskDTO(**r) for r in rows]


@router.post("/investigations/{investigation_id}/tasks", status_code=201, response_model=InvestigationTaskDTO)
def create_investigation_task(
    investigation_id: str,
    body: InvestigationTaskIn,
    request: Request,
) -> InvestigationTaskDTO:
    actor = auth.role_from_request(request)
    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        task = inv_store.create_task(
            conn,
            investigation_id,
            title=body.title.strip(),
            category=body.category,
            priority=body.priority,
            assignee=body.assignee,
            due_at=body.due_at,
        )
        audit.log(
            conn, actor, "investigation.task.create",
            target_type="investigation", target_id=investigation_id,
            detail=f"task #{task['id']} {task['title']!r} [{task['category']}]",
        )
    return InvestigationTaskDTO(**task)


@router.patch("/investigations/{investigation_id}/tasks/{task_id}", response_model=InvestigationTaskDTO)
def update_investigation_task(
    investigation_id: str,
    task_id: int,
    body: InvestigationTaskPatchIn,
    request: Request,
) -> InvestigationTaskDTO:
    actor = auth.role_from_request(request)
    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        task = inv_store.update_task(
            conn,
            task_id,
            title=body.title.strip() if body.title else None,
            category=body.category,
            status=body.status,
            priority=body.priority,
            assignee=body.assignee,
            due_at=body.due_at,
        )
        if not task:
            raise HTTPException(status_code=404, detail=f"Unknown task: {task_id}")
        audit.log(
            conn, actor, "investigation.task.update",
            target_type="investigation", target_id=investigation_id,
            detail=f"task #{task_id} status={task['status']} priority={task['priority']}",
        )
    return InvestigationTaskDTO(**task)


@router.delete("/investigations/{investigation_id}/tasks/{task_id}", status_code=204)
def delete_investigation_task(
    investigation_id: str,
    task_id: int,
    request: Request,
) -> None:
    actor = auth.role_from_request(request)
    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        deleted = inv_store.delete_task(conn, task_id)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"Unknown task: {task_id}")
        audit.log(
            conn, actor, "investigation.task.delete",
            target_type="investigation", target_id=investigation_id,
            detail=f"deleted task #{task_id}",
        )


@router.post("/investigations/{investigation_id}/tasks/generate-recommended", response_model=list[InvestigationTaskDTO])
def generate_recommended_investigation_tasks(
    investigation_id: str,
    request: Request,
) -> list[InvestigationTaskDTO]:
    actor = auth.role_from_request(request)
    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        created = inv_store.generate_recommended_tasks(conn, investigation_id)
        audit.log(
            conn, actor, "investigation.tasks.generate_recommended",
            target_type="investigation", target_id=investigation_id,
            detail=f"generated {len(created)} recommended response tasks",
        )
    return [InvestigationTaskDTO(**t) for t in created]


# -- Investigation Timeline & Causality ---------------------------------------


@router.get("/investigations/{investigation_id}/timeline", response_model=None)
def get_investigation_timeline(investigation_id: str) -> dict:
    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        events = inv_store.build_investigation_timeline(conn, investigation_id)
    return {"investigation_id": investigation_id, "total": len(events), "events": events}


# -- Automated Remediation Script Generator -----------------------------------


@router.get("/investigations/{investigation_id}/remediation-script")
def get_investigation_remediation_script(
    investigation_id: str,
    shell: str = Query("bash", description="bash | powershell"),
):
    from fastapi.responses import PlainTextResponse

    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        script = inv_store.generate_remediation_script(conn, investigation_id, shell=shell)
        ext = "ps1" if shell.lower() == "powershell" else "sh"
        media = "text/plain"
        return PlainTextResponse(
            content=script,
            media_type=media,
            headers={
                "Content-Disposition": f'attachment; filename="outpost-remediate-{investigation_id}.{ext}"'
            },
        )


# -- Incident Response Playbooks ----------------------------------------------


@router.post("/investigations/{investigation_id}/apply-playbook", response_model=None)
def apply_incident_playbook(
    investigation_id: str,
    body: ApplyPlaybookIn,
    request: Request,
) -> dict:
    """Instantiate a standardized Incident Response Playbook into the case."""
    actor = auth.role_from_request(request)
    from ..services.incident_playbooks import apply_playbook_to_investigation
    with db_session() as conn:
        _require_investigation(conn, investigation_id)
        try:
            res = apply_playbook_to_investigation(
                conn, investigation_id, body.playbook_id, assignee=body.assignee
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        audit.log(
            conn, actor, "investigation.playbook.apply",
            target_type="investigation", target_id=investigation_id,
            detail=f"applied playbook {body.playbook_id} ({res['tasks_created_count']} tasks)",
        )
    return res




