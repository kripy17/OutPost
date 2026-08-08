"""Run listing and detail endpoints.

- GET /runs          — RunSummary[] for run history (webapp) / `outpost list`
- GET /runs/{id}     — full detail: process tree + enriched connections +
                       timeline + alerts (webapp detail page / `outpost show`)
- GET /runs/{id}/export — JSON report or PDF (Task 21)
"""

from fastapi import APIRouter, HTTPException, Query, Response

from ..core.db import db_session
from ..core.schema import Alert, EventOut, NetworkConnection, NoteIn, RunDetail, RunNote, RunSummary
from ..models import event as event_store
from ..models import run as run_store
from ..models import run_notes as notes_store
from ..models import samples as samples_store
from ..services import enrichment, killchain, process_tree

router = APIRouter(tags=["runs"])


@router.get("/runs", response_model=list[RunSummary])
def list_runs(q: str = Query("", max_length=200)) -> list[RunSummary]:
    """Run history, newest first. `?q=<sample>` filters by sample-name
    substring — the sample vault's detonation-history links use it."""
    with db_session() as conn:
        rows = run_store.list_runs(conn, q=q.strip())
        return [run_store.to_summary(conn, r) for r in rows]


@router.get("/runs/active-live", response_model=RunSummary)
def get_active_live_run() -> RunSummary:
    """The newest open `live` session — what a host collector should stream
    into. The webapp's "Start live monitoring" creates one; the collector's
    `--auto` flag claims it, so real auditd/Sysmon events flow straight into
    the visible Monitor. 404 when nothing is open. Must be registered before
    `/runs/{run_id}` so "active-live" isn't captured as a run id."""
    with db_session() as conn:
        row = conn.execute(
            "SELECT * FROM runs WHERE session_type = 'live' AND completed_at IS NULL "
            "ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="No active live session — start one from the Monitor page")
        return run_store.to_summary(conn, row)


@router.get("/runs/{run_id}", response_model=RunDetail)
async def get_run_detail(run_id: str) -> RunDetail:
    from ..core.db import get_connection

    conn = get_connection()
    try:
        run_row = run_store.get_run(conn, run_id)
        if not run_row:
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")

        summary = run_store.to_summary(conn, run_row)

        # Process tree from process_create events.
        process_events = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM events WHERE run_id = ? AND event_type = 'process_create' ORDER BY timestamp ASC",
                (run_id,),
            ).fetchall()
        ]
        tree = process_tree.build_process_tree(process_events)

        # Timeline: all events chronologically.
        timeline_rows = event_store.list_events_for_run(conn, run_id)

        # Network connections: distinct destinations, enriched (cache-first).
        conn_rows = conn.execute(
            """
            SELECT dest_ip, dest_port, protocol, MIN(timestamp) AS first_seen
            FROM events
            WHERE run_id = ? AND event_type = 'network_connection' AND dest_ip IS NOT NULL
            GROUP BY dest_ip, dest_port, protocol
            ORDER BY first_seen ASC
            """,
            (run_id,),
        ).fetchall()

        alerts_rows = event_store.list_alerts_for_run(conn, run_id)

        # Enrichment does async HTTP calls; keep this connection for its
        # cache reads/writes (local SQLite — fine on the event loop thread).
        enriched = await enrichment.enrich_run(conn, run_id)

        # Risk halos on the process tree (docs/07 signature visual): map each
        # pid to the IPs it reached, then annotate nodes with the worst
        # reputation among them.
        net_rows = conn.execute(
            """
            SELECT DISTINCT pid, dest_ip FROM events
            WHERE run_id = ? AND event_type = 'network_connection'
              AND pid IS NOT NULL AND dest_ip IS NOT NULL
            """,
            (run_id,),
        ).fetchall()
        pid_ips: dict[int, list[str]] = {}
        for row in net_rows:
            pid_ips.setdefault(row["pid"], []).append(row["dest_ip"])
        ip_reputation = {ip: (data.get("reputation") or "unknown") for ip, data in enriched.items()}
        process_tree.annotate_process_tree(tree, pid_ips, ip_reputation)

        connections: list[NetworkConnection] = []
        for row in conn_rows:
            data = enriched.get(row["dest_ip"], {})
            connections.append(
                NetworkConnection(
                    dest_ip=row["dest_ip"],
                    dest_port=row["dest_port"],
                    protocol=row["protocol"],
                    first_seen=row["first_seen"],
                    reputation=data.get("reputation"),
                    abuse_score=data.get("abuse_score"),
                    vt_malicious_count=data.get("vt_malicious_count"),
                    watchlist=data.get("watchlist"),
                    watchlist_label=data.get("watchlist_label"),
                )
            )

        # Enrichment upserts into the cache — commit so the cache persists
        # (docs/02 rule 3: never re-query a cached IP).
        conn.commit()

        # Roadmap 2.4 — correlated kill-chain sequence over the fired alerts.
        chain = killchain.correlate_chain(alerts_rows)

        # Roadmap 2.2 — if an uploaded binary matches this run's sample name,
        # surface its YARA + VirusTotal reputation evidence.
        sample_reputation = None
        sample_row = conn.execute(
            "SELECT * FROM samples WHERE original_name = ? ORDER BY created_at DESC LIMIT 1",
            (run_row["sample_name"],),
        ).fetchone()
        if sample_row:
            import json as _json

            try:
                yara_rules = _json.loads(sample_row["yara_rules"] or "[]")
            except (ValueError, TypeError):
                yara_rules = []
            sample_reputation = {
                "sample_id": sample_row["sample_id"],
                "sha256": sample_row["sha256"],
                "yara_rules": yara_rules,
                "vt_detections": sample_row["vt_detections"],
                "malware_family": sample_row["malware_family"],
            }

        return RunDetail(
            run=summary,
            process_tree=tree,
            network_connections=connections,
            timeline=[EventOut(**dict(r)) for r in timeline_rows],
            alerts=[Alert(**a) for a in alerts_rows],
            kill_chain=chain,
            sample_reputation=sample_reputation,
        )
    finally:
        conn.close()


@router.get("/runs/{run_id}/export", response_model=None)
def export_run(run_id: str, format: str = "json") -> dict | Response:
    """Report export — JSON (default) or PDF (Task 21, docs/06).

    Same service backs the webapp export button and `outpost export`.
    `response_model=None` (not inferred from the `dict | Response` annotation)
    because FastAPI cannot build a Pydantic model from that union.
    """
    from ..services import report as report_service

    with db_session() as conn:
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")

    if format == "pdf":
        pdf = report_service.build_pdf_report(run_id)
        if pdf is None:
            raise HTTPException(status_code=501, detail="PDF export unavailable — reportlab not installed")
        return Response(
            content=pdf,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="outpost-report-{run_id[:12]}.pdf"'},
        )

    if format == "stix":
        # Roadmap 3.3 — STIX 2.1 bundle for analyst-team sharing.
        from ..services import stix as stix_service

        bundle = stix_service.build_stix_bundle(run_id)
        if "error" in bundle:
            raise HTTPException(status_code=404, detail=bundle["error"])
        return bundle

    return report_service.build_json_report(run_id)


# ---------------------------------------------------------------------------
# Phase 6 standout features (docs/10-STANDOUT-FEATURES.md)
# ---------------------------------------------------------------------------


@router.get("/runs/{run_id}/iocs", response_model=None)
def get_run_iocs(run_id: str, format: str = "json"):
    """Task 23 — IOC extraction. JSON by default, `?format=csv` for CSV.

    Pure aggregation over events; the reusable output of an analysis session.
    """
    if format not in ("json", "csv"):
        raise HTTPException(status_code=422, detail="format must be json or csv")

    from ..services import iocs as iocs_service

    with db_session() as conn:
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        data = iocs_service.extract_iocs(conn, run_id)

    if format == "csv":
        csv_text = iocs_service.iocs_to_csv(data)
        return Response(
            content=csv_text,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="outpost-iocs-{run_id[:12]}.csv"'
            },
        )
    return data


@router.get("/runs/{run_id}/compare/{other_id}", response_model=None)
def compare_runs(run_id: str, other_id: str):
    """Task 25 — diff two runs: processes/connections unique to each, shared."""
    with db_session() as conn:
        a = run_store.get_run(conn, run_id)
        b = run_store.get_run(conn, other_id)
        if not a:
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        if not b:
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {other_id}")

        def _sets(rid: str) -> tuple[set[str], set[str]]:
            procs = {
                r["process_name"]
                for r in conn.execute(
                    "SELECT DISTINCT process_name FROM events WHERE run_id = ? AND process_name IS NOT NULL",
                    (rid,),
                ).fetchall()
            }
            ips = {
                r["dest_ip"]
                for r in conn.execute(
                    "SELECT DISTINCT dest_ip FROM events WHERE run_id = ? AND dest_ip IS NOT NULL",
                    (rid,),
                ).fetchall()
            }
            return procs, ips

        pa, ia = _sets(run_id)
        pb, ib = _sets(other_id)

        return {
            "run_a": {"run_id": run_id, "sample_name": a["sample_name"]},
            "run_b": {"run_id": other_id, "sample_name": b["sample_name"]},
            "processes": {
                "only_a": sorted(pa - pb),
                "only_b": sorted(pb - pa),
                "shared": sorted(pa & pb),
            },
            "ips": {
                "only_a": sorted(ia - ib),
                "only_b": sorted(ib - ia),
                "shared": sorted(ia & ib),
            },
        }


@router.get("/runs/{run_id}/rules", response_model=None)
async def get_run_rules(run_id: str, format: str = "suricata"):
    """Task 27 — auto-generated detection rules from this run's findings.

    Suricata (default): one rule per malicious connection. Sigma: one rule per
    distinct alert rule_id. Plain-text response, ready to paste into a rules
    file. Connections are enriched on demand (cache-first) so rules work
    immediately after ingestion — no need to visit the detail page first.
    """
    if format not in ("suricata", "sigma"):
        raise HTTPException(status_code=422, detail="format must be suricata or sigma")

    from ..core.db import get_connection
    from ..services import rule_generator

    conn = get_connection()
    try:
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        conn_rows = conn.execute(
            """
            SELECT DISTINCT e.dest_ip, e.dest_port, e.protocol
            FROM events e
            WHERE e.run_id = ? AND e.event_type = 'network_connection' AND e.dest_ip IS NOT NULL
            """,
            (run_id,),
        ).fetchall()
        alerts = event_store.list_alerts_for_run(conn, run_id)
        enriched = await enrichment.enrich_run(conn, run_id)
        conn.commit()
    finally:
        conn.close()

    connections = [
        {
            "dest_ip": r["dest_ip"],
            "dest_port": r["dest_port"],
            "protocol": r["protocol"],
            "reputation": (enriched.get(r["dest_ip"]) or {}).get("reputation"),
        }
        for r in conn_rows
    ]

    if format == "sigma":
        text = "\n\n".join(rule_generator.generate_sigma_rules(run_id, alerts))
        if not text:
            text = "# No Sigma-generatable findings in this run."
    else:
        text = "\n".join(rule_generator.generate_suricata_rules(run_id, connections))
        if not text:
            text = "# No malicious connections observed in this run."

    return Response(
        content=text,
        media_type="text/plain",
        headers={"Content-Disposition": f'inline; filename="outpost-rules-{run_id[:12]}.txt"'},
    )


# ---------------------------------------------------------------------------
# Tier 2 #7 — per-run analyst notes (docs/10)
# ---------------------------------------------------------------------------


@router.get("/runs/{run_id}/notes", response_model=list[RunNote])
def list_run_notes(run_id: str) -> list[RunNote]:
    """Analyst notes attached to a run, oldest first."""
    with db_session() as conn:
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        return [RunNote(**r) for r in notes_store.list_notes(conn, run_id)]


@router.post("/runs/{run_id}/notes", status_code=201, response_model=RunNote)
def add_run_note(run_id: str, body: NoteIn) -> RunNote:
    """Attach a free-text note to a run (your own observations/hypotheses)."""
    note = body.note.strip()
    if not note:
        raise HTTPException(status_code=422, detail="note must not be empty")
    with db_session() as conn:
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        row = notes_store.add_note(conn, run_id, note)
    return RunNote(**row)
