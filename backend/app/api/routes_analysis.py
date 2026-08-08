"""Analysis surfaces (roadmap 1.1 & 1.3).

- GET /events       — global event feed across all runs: filter by event type,
                      platform, run severity (has-alert), and free text; offset
                      pagination. The webapp's Event Viewer page.
- GET /events/export — same filters, CSV download (analysts hand the feed to
                      spreadsheets / threat-intel pipelines).
- GET /rules/meta   — MITRE ATT&CK technique/tactic + weight for every rule.
"""

import csv
import io
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Response

from ..core.db import db_session
from ..services.risk import RULE_META, rule_name

router = APIRouter(tags=["analysis"])

_EVENT_TYPES = {"process_create", "network_connection", "file_write", "registry_write"}
_PLATFORMS = {"windows", "linux"}
_SEVERITIES = {"suspicious", "malicious"}
_DEFAULT_LIMIT = 100
_MAX_LIMIT = 500


def _like(value: str) -> str:
    """Escape LIKE metacharacters so user input is matched literally."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


@router.get("/events", response_model=None)
def list_events(
    event_type: Optional[str] = None,
    platform: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    offset: int = Query(0, ge=0),
):
    """Filterable, paginated event feed (Event Viewer, roadmap 1.1).

    - `severity` filters to events whose *run* carries at least one alert of
      that severity — triage: "show me everything from findings-bearing runs".
    - `q` matches process name, file path, registry key, command line, dest IP.
    """
    if event_type is not None and event_type not in _EVENT_TYPES:
        raise HTTPException(status_code=422, detail=f"event_type must be one of {sorted(_EVENT_TYPES)}")
    if platform is not None and platform not in _PLATFORMS:
        raise HTTPException(status_code=422, detail=f"platform must be one of {sorted(_PLATFORMS)}")
    if severity is not None and severity not in _SEVERITIES:
        raise HTTPException(status_code=422, detail=f"severity must be one of {sorted(_SEVERITIES)}")

    where = ["1=1"]
    params: list = []

    if event_type:
        where.append("e.event_type = ?")
        params.append(event_type)
    if platform:
        where.append("e.platform = ?")
        params.append(platform)
    if severity:
        where.append("EXISTS (SELECT 1 FROM alerts a WHERE a.run_id = e.run_id AND a.severity = ?)")
        params.append(severity)
    if q:
        like = _like(q)
        where.append(
            "(e.process_name LIKE ? ESCAPE '\\' OR e.file_path LIKE ? ESCAPE '\\' "
            "OR e.registry_key LIKE ? ESCAPE '\\' OR e.command_line LIKE ? ESCAPE '\\' "
            "OR e.dest_ip = ? OR e.dest_ip LIKE ? ESCAPE '\\')"
        )
        params += [like, like, like, like, q, like]

    clause = " AND ".join(where)

    with db_session() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS n FROM events e WHERE {clause}", params).fetchone()["n"]
        rows = conn.execute(
            f"""
            SELECT e.*, r.sample_name, r.session_type,
                   (SELECT MAX(CASE a.severity WHEN 'malicious' THEN 2 WHEN 'suspicious' THEN 1 ELSE 0 END)
                    FROM alerts a WHERE a.run_id = e.run_id) AS run_sev
            FROM events e
            JOIN runs r ON r.run_id = e.run_id
            WHERE {clause}
            ORDER BY e.timestamp DESC, e.id DESC
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset],
        ).fetchall()
        events = [dict(r) for r in rows]

    sev_map = {2: "malicious", 1: "suspicious"}
    for ev in events:
        ev["run_severity"] = sev_map.get(ev.pop("run_sev"))

    return {
        "total": total,
        "returned": len(events),
        "limit": limit,
        "offset": offset,
        "events": events,
    }


@router.get("/events/export", response_model=None)
def export_events(
    event_type: Optional[str] = None,
    platform: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = Query(1000, ge=1, le=5000),
):
    """CSV export of the filtered event feed (same filters as GET /events).

    `limit` defaults much higher than the feed's (1000, up to 5000) — export
    is the bulk path; the webapp caps at 500 for interactive pagination.
    """
    feed = list_events(event_type=event_type, platform=platform, severity=severity, q=q, limit=limit, offset=0)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "run_id", "sample_name", "platform", "event_type", "pid", "ppid", "process_name", "command_line", "dest_ip", "dest_port", "protocol", "file_path", "registry_key", "run_severity"])
    for ev in feed["events"]:
        writer.writerow([
            ev["timestamp"], ev["run_id"], ev["sample_name"], ev["platform"],
            ev["event_type"], ev["pid"], ev["ppid"], ev["process_name"],
            ev["command_line"], ev["dest_ip"], ev["dest_port"], ev["protocol"],
            ev["file_path"], ev["registry_key"], ev["run_severity"],
        ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="outpost-events.csv"'},
    )


@router.get("/rules/meta", response_model=None)
def get_rules_meta():
    """ATT&CK technique/tactic + risk weight per rule (roadmap 1.3)."""
    return [
        {"rule_id": rid, "rule_name": rule_name(rid), **RULE_META[rid]}
        for rid in sorted(RULE_META)
    ]


@router.get("/coverage/navigator", response_model=None)
def get_coverage_navigator():
    """The coverage matrix as a MITRE ATT&CK Navigator layer (v4.3) — importable
    into https://mitre-attack.github.io/attack-navigator/ (Upload a layer)."""
    from ..services.navigator import build_navigator_layer

    return build_navigator_layer()
