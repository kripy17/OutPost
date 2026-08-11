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
from ..models.run import SYNTHETIC_SOURCES
from ..services.risk import RULE_META, RULE_REMEDIATION, rule_name

router = APIRouter(tags=["analysis"])

_EVENT_TYPES = {"process_create", "network_connection", "file_write", "registry_write"}
_PLATFORMS = {"windows", "linux"}
_SEVERITIES = {"suspicious", "malicious"}
# Provenance facets for the Event Log's source tabs: `live` = host collectors
# (auditd/Sysmon), `sandbox` = external-sandbox detonations, `webapp` =
# everything else (webapp synthetic detonations, CLI runs, seeds). The
# collectors stamp each shipped event with its exact channel (`log_source`:
# auditd / sysmon), so `auditd` and `sysmon` split the collector stream by
# log source — not by inference from the platform.
_SOURCES = {"live", "webapp", "sandbox", "auditd", "sysmon"}
_DEFAULT_LIMIT = 100
_MAX_LIMIT = 500


def _source_clause(source: str) -> tuple[str, list]:
    """WHERE fragment for a provenance facet, mirroring how runs record it:
    live sessions are forced to `source='live'` server-side; sandbox runs are
    `sandbox:<provider>`; webapp/CLI/seeds carry their own marker. The
    channel facets (`auditd` / `sysmon`) filter on the event's own
    log_source tag, so they work across any run type."""
    if source == "live":
        return "r.source = 'live'", []
    if source == "sandbox":
        return "r.source LIKE 'sandbox:%'", []
    if source == "auditd":
        return "e.log_source = 'auditd'", []
    if source == "sysmon":
        return "e.log_source = 'sysmon'", []
    return "r.source != 'live' AND r.source NOT LIKE 'sandbox:%'", []


def _like(value: str) -> str:
    """Escape LIKE metacharacters so user input is matched literally."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _parse_pids(raw: Optional[str]) -> list[int]:
    """Parse the `pid` filter — one integer or a comma-separated list (the
    recon-sweep jump: every enumerating PID of an enumeration-burst alert).
    422 on any token that isn't a positive integer."""
    if not raw:
        return []
    pids: list[int] = []
    for token in raw.split(","):
        t = token.strip()
        if not t:
            continue
        try:
            n = int(t)
        except ValueError:
            raise HTTPException(status_code=422, detail="pid must be a positive integer or comma-separated list")
        if n < 1:
            raise HTTPException(status_code=422, detail="pid must be a positive integer or comma-separated list")
        pids.append(n)
    return pids


def _validate_event_filters(
    event_type: Optional[str],
    platform: Optional[str],
    severity: Optional[str],
    source: Optional[str],
) -> None:
    """Shared dimension validation for the event feed and its count endpoints.
    `source` is None for /events/channel-counts (the dimension being split)."""
    if event_type is not None and event_type not in _EVENT_TYPES:
        raise HTTPException(status_code=422, detail=f"event_type must be one of {sorted(_EVENT_TYPES)}")
    if platform is not None and platform not in _PLATFORMS:
        raise HTTPException(status_code=422, detail=f"platform must be one of {sorted(_PLATFORMS)}")
    if severity is not None and severity not in _SEVERITIES:
        raise HTTPException(status_code=422, detail=f"severity must be one of {sorted(_SEVERITIES)}")
    if source is not None and source not in _SOURCES:
        raise HTTPException(status_code=422, detail=f"source must be one of {sorted(_SOURCES)}")


def _event_where(
    event_type: Optional[str],
    platform: Optional[str],
    severity: Optional[str],
    q: Optional[str],
    pids: list[int],
    source: Optional[str],
    include_synthetic: bool,
) -> tuple[list[str], list]:
    """Shared WHERE clause for the event feed and the channel-count split.
    Values must already be validated; pids must be parsed."""
    where = ["1=1"]
    params: list = []
    if pids:
        where.append(f"e.pid IN ({','.join('?' * len(pids))})")
        params += pids
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
            "OR e.dest_ip = ? OR e.dest_ip LIKE ? ESCAPE '\\' "
            "OR e.host_id LIKE ? ESCAPE '\\')"
        )
        params += [like, like, like, like, q, like, like]
    if source:
        frag, extra = _source_clause(source)
        where.append(frag)
        params += extra
    if not include_synthetic:
        marks = ",".join("?" for _ in SYNTHETIC_SOURCES)
        where.append(f"r.source NOT IN ({marks})")
        params += list(SYNTHETIC_SOURCES)
    return where, params


@router.get("/events", response_model=None)
def list_events(
    event_type: Optional[str] = None,
    platform: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
    pid: Optional[str] = None,
    source: Optional[str] = None,
    include_synthetic: bool = Query(
        False,
        description="Show events from synthetic-provenance runs (seeds / webapp detonations / the sandbox demo)",
    ),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    offset: int = Query(0, ge=0),
):
    """Filterable, paginated event feed (Event Viewer, roadmap 1.1).

    - `severity` filters to events whose *run* carries at least one alert of
      that severity — triage: "show me everything from findings-bearing runs".
    - `q` matches process name, file path, registry key, command line, dest IP.
    - `pid` filters to one process — the process-centric drill-down (everything
      that PID did: children, files, network, registry). Accepts a
      comma-separated list too, so a recon sweep jumps to every enumerating
      process at once.
    - `source` filters by provenance facet: `live` (host collectors),
      `sandbox` (external sandboxes), `webapp` (everything else).
    - `include_synthetic` — synthetic provenance (seed / webapp-demo / legacy
      monitor / sandbox:demo) is hidden by default, mirroring the runs
      archive: the Event Log reads as real telemetry first. Callers that
      deliberately opt into a provenance facet (the webapp source tabs) pass
      `true` alongside, since choosing a tab is itself an explicit ask.
    """
    _validate_event_filters(event_type, platform, severity, source)
    pids = _parse_pids(pid)
    where, params = _event_where(event_type, platform, severity, q, pids, source, include_synthetic)
    clause = " AND ".join(where)

    with db_session() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) AS n FROM events e JOIN runs r ON r.run_id = e.run_id WHERE {clause}",
            params,
        ).fetchone()["n"]
        rows = conn.execute(
            f"""
            SELECT e.*, r.sample_name, r.session_type, r.source,
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


@router.get("/events/channel-counts", response_model=None)
def event_channel_counts(
    event_type: Optional[str] = None,
    platform: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
    pid: Optional[str] = None,
    include_synthetic: bool = Query(
        False,
        description="Show events from synthetic-provenance runs (seeds / webapp detonations / the sandbox demo)",
    ),
) -> dict:
    """Per-channel totals for the Event Log's source-tab rail — one query
    instead of one request per tab. Mirrors list_events' filters minus
    `source` (the dimension being split), and buckets every filtered event
    into each channel it belongs to:

      live    — r.source = 'live'            (host collectors)
      sandbox — r.source LIKE 'sandbox:%'    (external sandboxes)
      webapp  — everything else              (webapp detonations, CLI, seeds)
      auditd / sysmon — the event's own log_source stamp (cross-cutting: a
                        live collector event counts in live AND its channel)

    `total` is the grand count across all buckets (the "All sources" tab).
    The buckets are facets, not a partition — auditd/sysmon deliberately
    overlap live, so the channel values need not sum to total."""
    _validate_event_filters(event_type, platform, severity, None)
    pids = _parse_pids(pid)
    where, params = _event_where(event_type, platform, severity, q, pids, None, include_synthetic)
    clause = " AND ".join(where)

    with db_session() as conn:
        row = conn.execute(
            f"""
            SELECT
              COUNT(*) AS total,
              SUM(CASE WHEN r.source = 'live' THEN 1 ELSE 0 END)                       AS live,
              SUM(CASE WHEN r.source LIKE 'sandbox:%' THEN 1 ELSE 0 END)               AS sandbox,
              SUM(CASE WHEN COALESCE(e.log_source, '') = 'auditd' THEN 1 ELSE 0 END)   AS auditd,
              SUM(CASE WHEN COALESCE(e.log_source, '') = 'sysmon' THEN 1 ELSE 0 END)   AS sysmon,
              SUM(CASE WHEN r.source != 'live' AND r.source NOT LIKE 'sandbox:%'
                       THEN 1 ELSE 0 END)                                              AS webapp
            FROM events e
            JOIN runs r ON r.run_id = e.run_id
            WHERE {clause}
            """,
            params,
        ).fetchone()

    channels = {k: int(row[k] or 0) for k in ("live", "auditd", "sysmon", "webapp", "sandbox")}
    return {"total": int(row["total"] or 0), "channels": channels}


@router.get("/events/process-summary", response_model=None)
def process_summary(pid: int) -> dict:
    """One process's identity + impact, for the hover preview on process-jump
    links: name + command line from its process-create record, the run it
    belongs to, its total event count, and how many alerts in those runs name
    this PID (related_pid or in related_pids). 404 when the pid has no events.
    """
    if pid < 1:
        raise HTTPException(status_code=422, detail="pid must be a positive integer")
    with db_session() as conn:
        row = conn.execute(
            """
            SELECT e.*, r.sample_name FROM events e
            JOIN runs r ON r.run_id = e.run_id
            WHERE e.pid = ?
            -- The identity is the process-CREATE record (name + command line);
            -- fall back to any event for pids with no create observed.
            ORDER BY (e.event_type = 'process_create') DESC, e.timestamp DESC
            LIMIT 1
            """,
            (pid,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"No events for pid {pid}")
        event_count = conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE pid = ?", (pid,)
        ).fetchone()["n"]
        run_ids = [
            r["run_id"]
            for r in conn.execute("SELECT DISTINCT run_id FROM events WHERE pid = ?", (pid,)).fetchall()
        ]
        alert_count = 0
        if run_ids:
            placeholders = ",".join("?" * len(run_ids))
            alert_count = conn.execute(
                f"""
                SELECT COUNT(*) AS n FROM alerts
                WHERE run_id IN ({placeholders}) AND (related_pid = ? OR related_pids LIKE ?)
                """,
                (*run_ids, pid, f"%{pid}%"),
            ).fetchone()["n"]
    return {
        "pid": pid,
        "process_name": row["process_name"],
        "command_line": row["command_line"],
        "platform": row["platform"],
        "host_id": row["host_id"],
        "run_id": row["run_id"],
        "sample_name": row["sample_name"],
        "event_count": event_count,
        "alert_count": alert_count,
    }


@router.get("/events/export", response_model=None)
def export_events(
    event_type: Optional[str] = None,
    platform: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
    pid: Optional[str] = None,
    source: Optional[str] = None,
    include_synthetic: bool = Query(
        False,
        description="Show events from synthetic-provenance runs (seeds / webapp detonations / the sandbox demo)",
    ),
    limit: int = Query(1000, ge=1, le=5000),
):
    """CSV export of the filtered event feed (same filters as GET /events,
    including the synthetic-hiding default — exports match what the feed
    shows).

    `limit` defaults much higher than the feed's (1000, up to 5000) — export
    is the bulk path; the webapp caps at 500 for interactive pagination.
    """
    feed = list_events(
        event_type=event_type, platform=platform, severity=severity, q=q, pid=pid,
        source=source, include_synthetic=include_synthetic, limit=limit, offset=0,
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "run_id", "sample_name", "platform", "source", "log_source", "event_type", "pid", "ppid", "process_name", "command_line", "dest_ip", "dest_port", "protocol", "file_path", "registry_key", "host_id", "run_severity"])
    for ev in feed["events"]:
        writer.writerow([
            ev["timestamp"], ev["run_id"], ev["sample_name"], ev["platform"], ev.get("source", ""),
            ev.get("log_source") or "",
            ev["event_type"], ev["pid"], ev["ppid"], ev["process_name"],
            ev["command_line"], ev["dest_ip"], ev["dest_port"], ev["protocol"],
            ev["file_path"], ev["registry_key"], ev.get("host_id", "local"), ev["run_severity"],
        ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="outpost-events.csv"'},
    )


@router.get("/rules/meta", response_model=None)
def get_rules_meta():
    """ATT&CK technique/tactic + risk weight + remediation per rule."""
    return [
        {
            "rule_id": rid,
            "rule_name": rule_name(rid),
            "remediation": RULE_REMEDIATION.get(rid, []),
            **RULE_META[rid],
        }
        for rid in sorted(RULE_META)
    ]


@router.get("/coverage/navigator", response_model=None)
def get_coverage_navigator():
    """The coverage matrix as a MITRE ATT&CK Navigator layer (v4.3) — importable
    into https://mitre-attack.github.io/attack-navigator/ (Upload a layer)."""
    from ..services.navigator import build_navigator_layer

    return build_navigator_layer()
