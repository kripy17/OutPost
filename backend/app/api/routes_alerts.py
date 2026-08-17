"""Alert surfaces.

- GET /runs/{run_id}/alerts — detection hits for one run (polled by the CLI's
  live stream and the webapp's alert banner).
- GET /alerts               — newest hits across ALL runs (dashboard feed).
- GET /alerts/export        — CSV of recent alerts across all runs.
- PATCH /alerts/{id}        — triage: open → acknowledged → resolved, with an
                              optional analyst comment (analyst workflow).
- POST /alerts/bulk         — same triage applied to many alerts at once
                              (bulk ack / bulk resolve from the run detail).
"""

import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from ..core import auth
from ..core.db import db_session
from ..core.schema import Alert, AlertPatchIn
from ..models import audit
from ..models import event as event_store
from ..models import findings as findings_store
from ..models import run as run_store
from ..models.event import _parse_related_pids

router = APIRouter(tags=["alerts"])


@router.get("/runs/{run_id}/alerts", response_model=list[Alert])
def get_alerts(run_id: str) -> list[Alert]:
    with db_session() as conn:
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        rows = event_store.list_alerts_for_run(conn, run_id)
    return [Alert(**row) for row in rows]


@router.patch("/alerts/{alert_id}", response_model=Alert)
def update_alert_status(alert_id: int, body: AlertPatchIn, request: Request) -> Alert:
    """Move one alert through the triage lifecycle and/or set its P0 finding
    verdicts. `comment` is optional and recorded at the transition; an empty
    comment is stored as NULL. The extended PATCH also accepts the optional
    disposition / confidence / investigation_id — each is written only when
    provided (None leaves the column untouched, so a status-only PATCH
    behaves exactly as before). Every change lands in the audit trail."""
    comment = (body.comment or "").strip() or None
    actor = auth.role_from_request(request)
    now = datetime.now(timezone.utc).isoformat()
    with db_session() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Unknown alert id: {alert_id}")
        if body.investigation_id is not None:
            inv = conn.execute(
                "SELECT 1 FROM investigations WHERE id = ?", (body.investigation_id,)
            ).fetchone()
            if not inv:
                raise HTTPException(status_code=422, detail=f"Unknown investigation: {body.investigation_id}")
        old = row["status"]
        # Only verdict fields that were actually sent are written (None =
        # untouched) — existing PATCH callers stay byte-compatible. The
        # status + comment are ALWAYS written, as before.
        sets = ["status = ?", "status_comment = ?", "status_at = ?"]
        values: list = [body.status, comment, now]
        for col, val in (
            ("disposition", body.disposition),
            ("confidence", body.confidence),
            ("investigation_id", body.investigation_id),
        ):
            if val is not None:
                sets.append(f"{col} = ?")
                values.append(val)
        conn.execute(
            f"UPDATE alerts SET {', '.join(sets)} WHERE id = ?",
            [*values, alert_id],
        )
        detail = f"{old} → {body.status}"
        if body.disposition:
            detail += f" · disposition {body.disposition}"
        if body.confidence:
            detail += f" · confidence {body.confidence}"
        if body.investigation_id:
            detail += f" · case {body.investigation_id}"
        audit.log(
            conn, actor, "alert.status",
            target_type="alert", target_id=str(alert_id),
            detail=detail + (f" — {comment}" if comment else ""),
        )
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    d = dict(row)
    _parse_related_pids(d)
    return Alert(**d)


class FalsePositiveIn(BaseModel):
    comment: str = ""


def _fp_suggestions(conn, rule_id: str, run_id: str, fp_count: int) -> list[dict]:
    """What should the analyst do about a rule that keeps false-positiving?

    - **threshold**: rules with an int-count tunable (beaconing/rename-burst/
      enumeration-burst) get a suggested bump — the knob, its current value,
      and a concrete nudge (+1 per FP, min 2). The existing
      PUT /rules/tuning/{param} applies it live, no restart.
    - **suppress**: suppress this rule for this run — one click, stops future
      batches of this run from re-firing it.
    """
    from ..services.detection import TUNABLE_DEFAULTS

    suggestions: list[dict] = []
    for name, (rid, type_name, default) in TUNABLE_DEFAULTS.items():
        if rid != rule_id or type_name != "int":
            continue
        current = conn.execute(
            "SELECT value FROM rule_tuning WHERE rule_id = ? AND param = ?",
            (rule_id, name),
        ).fetchone()
        current = int(current["value"]) if current else int(default)
        suggested = max(current + 1, fp_count + 1)
        if suggested > current:
            suggestions.append(
                {
                    "kind": "threshold",
                    "param": name,
                    "current": current,
                    "suggested": suggested,
                    "detail": f"Raise {name} from {current} to {suggested} — this rule has fired {fp_count} false positive(s)",
                }
            )
    suggestions.append(
        {
            "kind": "suppress",
            "run_id": run_id,
            "rule_id": rule_id,
            "detail": f"Suppress {rule_id} for this run so its future batches stop re-firing it",
        }
    )
    return suggestions


@router.post("/alerts/{alert_id}/false-positive", response_model=None)
def mark_false_positive(alert_id: int, body: FalsePositiveIn, request: Request) -> dict:
    """Mark an alert as a false positive (analyst feedback loop).

    Resolves the alert with an `FP` comment, increments the rule's FP
    counter, and returns actionable suggestions — a threshold nudge for rules
    with an int-count tunable and a per-run suppression — that the run-detail
    UI offers as one-click buttons wired to the existing tuning/suppression
    endpoints. The FP count also feeds the Rules page so noisy rules surface.
    """
    comment = (body.comment or "").strip()
    now = datetime.now(timezone.utc).isoformat()
    actor = auth.role_from_request(request)
    with db_session() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Unknown alert id: {alert_id}")
        rule_id = row["rule_id"]
        run_id = row["run_id"]
        conn.execute(
            "UPDATE alerts SET status = 'resolved', status_comment = ?, status_at = ? WHERE id = ?",
            (f"FP{': ' + comment if comment else ''}", now, alert_id),
        )
        conn.execute(
            "INSERT INTO rule_fp (rule_id, count, last_fp_at) VALUES (?, 1, ?) "
            "ON CONFLICT(rule_id) DO UPDATE SET count = count + 1, last_fp_at = excluded.last_fp_at",
            (rule_id, now),
        )
        fp_count = conn.execute(
            "SELECT count FROM rule_fp WHERE rule_id = ?", (rule_id,)
        ).fetchone()["count"]
        audit.log(
            conn, actor, "alert.false-positive",
            target_type="alert", target_id=str(alert_id),
            detail=f"rule {rule_id} · FP#{fp_count}" + (f" — {comment}" if comment else ""),
        )
        suggestions = _fp_suggestions(conn, rule_id, run_id, fp_count)
    return {"alert_id": alert_id, "rule_id": rule_id, "fp_count": fp_count, "suggestions": suggestions}


@router.get("/alerts/export", response_model=None)
def export_alerts(limit: int = 5000):
    """CSV of the newest alerts across every run (with the owning sample name)
    — for spreadsheets / sharing. `limit` defaults to the bulk export bound.
    """
    alerts = list_recent_alerts(limit=limit)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "timestamp", "run_id", "sample_name", "rule_id", "rule_name", "severity", "status", "related_pid", "related_ip", "details"])
    for a in alerts:
        writer.writerow([
            a["id"], a["triggered_at"], a["run_id"], a["sample_name"],
            a["rule_id"], a["rule_name"], a["severity"], a["status"],
            a["related_pid"], a["related_ip"], a["details"],
        ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="outpost-alerts.csv"'},
    )


class BulkStatusIn(BaseModel):
    ids: list[int]
    status: str
    comment: str = ""


@router.post("/alerts/bulk", response_model=None)
def bulk_update_alert_status(body: BulkStatusIn, request: Request) -> dict:
    """Apply one triage transition to many alerts (bulk ack / bulk resolve).

    Only alerts that actually exist are updated; the response reports the
    count. An invalid status (not open/acknowledged/resolved) is rejected
    up front — the same constraint PATCH enforces per row.
    """
    if body.status not in ("open", "acknowledged", "resolved"):
        raise HTTPException(status_code=422, detail="status must be open, acknowledged, or resolved")
    if not body.ids:
        return {"updated": 0}
    comment = (body.comment or "").strip() or None
    now = datetime.now(timezone.utc).isoformat()
    placeholders = ",".join("?" * len(body.ids))
    with db_session() as conn:
        conn.execute(
            f"UPDATE alerts SET status = ?, status_comment = ?, status_at = ? WHERE id IN ({placeholders})",
            [body.status, comment, now, *body.ids],
        )
        updated = conn.execute(
            f"SELECT COUNT(*) AS n FROM alerts WHERE id IN ({placeholders})",
            body.ids,
        ).fetchone()["n"]
        audit.log(
            conn, auth.role_from_request(request), "alert.status",
            target_type="alert", target_id=f"bulk:{len(body.ids)}",
            detail=f"{updated} of {len(body.ids)} → {body.status}" + (f" — {comment}" if comment else ""),
        )
    return {"updated": updated}


@router.get("/alerts")
def list_recent_alerts(limit: int = 20) -> list[dict]:
    """Newest alerts across every run, with the owning sample name.

    Powers the dashboard's live-findings feed. `limit` is clamped to keep the
    payload bounded.
    """
    limit = max(1, min(limit, 200))
    with db_session() as conn:
        rows = conn.execute(
            """
            SELECT a.*, r.sample_name
            FROM alerts a
            JOIN runs r ON r.run_id = a.run_id
            ORDER BY a.triggered_at DESC, a.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    out = [dict(r) for r in rows]
    for d in out:
        _parse_related_pids(d)
    return out


class AssigneeIn(BaseModel):
    assignee: str = ""


@router.post("/alerts/{alert_id}/assign", response_model=None)
def assign_alert(alert_id: int, body: AssigneeIn, request: Request) -> dict:
    """Claim an alert for an analyst (triage queue). Empty string unassigns.
    Every change lands in the audit trail."""
    assignee = (body.assignee or "").strip() or None
    now = datetime.now(timezone.utc).isoformat()
    with db_session() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Unknown alert id: {alert_id}")
        old = row["assignee"]
        conn.execute(
            "UPDATE alerts SET assignee = ?, status_at = ? WHERE id = ?",
            (assignee, now, alert_id),
        )
        audit.log(
            conn, auth.role_from_request(request), "alert.assign",
            target_type="alert", target_id=str(alert_id),
            detail=f"{old or '—'} → {assignee or '—'}",
        )
    return {"alert_id": alert_id, "assignee": assignee}


@router.get("/alerts/queue", response_model=None)
def list_alert_queue(
    status: str = "open",
    rule_id: str | None = None,
    severity: str | None = None,
    host_id: str | None = None,
    assignee: str | None = None,
    campaign: str | None = None,
    provenance: str | None = None,
    q: str | None = None,
    sort: str = "aging",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """The analyst triage queue — alerts across every run with run context.

    Filters: status (open/acknowledged/resolved/all), rule, severity, host,
    assignee, campaign (a shared IOC value), provenance (real = host/sandbox
    telemetry, synthetic = seed / webapp-demo / sandbox:demo runs — the same
    SYNTHETIC_SOURCES split the History archive uses), and free text across
    sample / rule / details. `sort=aging` surfaces open-oldest-first (SLA
    pressure); `sort=newest` flips it. Returns the envelope the queue page
    renders: totals per status plus the page of rows.

    This is the compatibility surface for the shared finding-queue query
    (``models/findings.query_findings``) — /findings exposes the same
    implementation with the P0 filters (source / disposition / confidence /
    unread_only / mark_seen) added. Behavior here is unchanged.
    """
    if status not in ("open", "acknowledged", "resolved", "all"):
        raise HTTPException(status_code=422, detail="status must be open, acknowledged, resolved, or all")
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
    out.pop("_page_ids", None)
    return out
