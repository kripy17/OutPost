"""Run listing and detail endpoints.

- GET /runs          — RunSummary[] for run history (webapp) / `outpost list`
- GET /runs/{id}     — full detail: process tree + enriched connections +
                       timeline + alerts (webapp detail page / `outpost show`)
- GET /runs/{id}/export — JSON report or PDF (Task 21)
"""

from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, HTTPException, Query, Request, Response

from ..core import auth
from ..core.db import db_session
from ..core.schema import (
    Alert,
    AllowlistEntry,
    AllowlistIn,
    DomainIntel,
    EventOut,
    MemoryScanIn,
    NetworkConnection,
    NoteIn,
    RunDetail,
    RunNote,
    RunSummary,
)
from ..models import audit
from ..models import event as event_store
from ..models import run as run_store
from ..models import run_notes as notes_store
from ..models import samples as samples_store
from ..services import enrichment, killchain, process_tree
from ..services import risk as risk_service
from ..services.detection import allowlist_matches, load_run_sample_sha256

router = APIRouter(tags=["runs"])


@router.post("/runs/{run_id}/re-enrich", response_model=None)
async def re_enrich_run(run_id: str, request: Request) -> dict:
    """The 'I just added a key' button: drop this run's cached IP intel (and
    its sample's hash intel when a sample is attached), then re-run
    enrichment with the CURRENT keys — cache-first becomes cache-miss, so
    fresh AbuseIPDB/VT lookups happen right now and the run detail shows the
    new badges on next fetch. Audited."""
    with db_session() as conn:
        exists = conn.execute("SELECT run_id FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not exists:
            raise HTTPException(status_code=404, detail=f"Unknown run: {run_id}")
        ips = [
            r["dest_ip"]
            for r in conn.execute(
                "SELECT DISTINCT dest_ip FROM events WHERE run_id = ? AND dest_ip IS NOT NULL",
                (run_id,),
            ).fetchall()
        ]
        if ips:
            conn.executemany("DELETE FROM enrichment_cache WHERE ip = ?", [(ip,) for ip in ips])
        sample = conn.execute(
            "SELECT s.sha256, s.sample_id FROM samples s JOIN runs r ON r.sample_name = s.original_name "
            "WHERE r.run_id = ?",
            (run_id,),
        ).fetchone()
        if sample:
            conn.execute("DELETE FROM hash_cache WHERE sha256 = ?", (sample["sha256"],))

        enriched = await enrichment.enrich_run(conn, run_id)
        if sample:
            async with httpx.AsyncClient() as client:
                hi = await enrichment.enrich_hash(client, conn, sample["sha256"])
            conn.execute(
                "UPDATE samples SET vt_detections = ?, malware_family = ? WHERE sample_id = ?",
                (hi["vt_detections"], hi["malware_family"], sample["sample_id"]),
            )
        audit.log(
            conn, auth.role_from_request(request), "run.re-enrich",
            target_type="run", target_id=run_id,
            detail=f"cleared {len(ips)} IP cache row(s), re-enriched with current keys",
        )
    return {
        "run_id": run_id,
        "ips_cleared": len(ips),
        "reputation": {ip: (d.get("reputation") or "unknown") for ip, d in enriched.items()},
    }


@router.post("/runs/{run_id}/enrichment/refresh", response_model=None)
async def refresh_ip_enrichment(run_id: str, ip: str = Query(..., min_length=1, max_length=200), request: Request = None) -> dict:
    """Bypass the enrichment TTL ONCE for a single destination IP of this run:
    drop its cache row and re-query AbuseIPDB/VirusTotal with the CURRENT
    keys. The run detail network panel pairs its "checked Xh ago" age with
    this per-row force-refresh — "I just added a key / this IP changed".
    Audited; only IPs this run actually reached are refresheable."""
    with db_session() as conn:
        exists = conn.execute("SELECT run_id FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not exists:
            raise HTTPException(status_code=404, detail=f"Unknown run: {run_id}")
        member = conn.execute(
            "SELECT 1 FROM events WHERE run_id = ? AND dest_ip = ? LIMIT 1",
            (run_id, ip),
        ).fetchone()
        if not member:
            raise HTTPException(status_code=404, detail=f"{ip} is not a destination of run {run_id}")

        conn.execute("DELETE FROM enrichment_cache WHERE ip = ?", (ip,))
        async with httpx.AsyncClient() as client:
            data = await enrichment.enrich_ip(client, conn, ip)
        conn.commit()
        audit.log(
            conn, auth.role_from_request(request), "intel.refresh-ip",
            target_type="run", target_id=run_id,
            detail=f"force-refreshed reputation for {ip} (TTL bypassed)",
        )
    return {
        "ip": ip,
        "abuse_score": data.get("abuse_score"),
        "vt_malicious_count": data.get("vt_malicious_count"),
        "reputation": data.get("reputation") or "unknown",
        "checked_at": data.get("checked_at"),
    }


@router.get("/runs", response_model=list[RunSummary])
def list_runs(
    q: str = Query("", max_length=200),
    host: str = Query("", max_length=200),
    include_synthetic: bool = Query(False, description="Show seeds / webapp-synthetic detonations / the sandbox demo in the archive"),
    include_soak: bool = Query(False, description="Show soak-named collector baselines (soak-… modeled runs) in the archive"),
) -> list[RunSummary]:
    """Run history, newest first. `?q=<sample>` filters by sample-name
    substring; `?host=<host_id>` filters to runs whose events came from that
    fleet host (the Agents page links here). Both combine when given.
    Synthetic provenance (seed / webapp-demo / legacy monitor / sandbox:demo)
    AND soak-named collector baselines (soak-…) are hidden by default so the
    archive reads as real telemetry first; the CLI opts back in with
    `include_synthetic=true` / `include_soak=true` for terminal parity."""
    with db_session() as conn:
        rows = run_store.list_runs(conn, q=q.strip(), host=host.strip(), include_synthetic=include_synthetic, include_soak=include_soak)
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
        # docs/08 MVP-tier — abuse.ch domain intel over observed hostnames
        # (DNS queries / TLS SNI). Cache-first like the IP pass; degrades to
        # {} without network, never fails the run detail.
        try:
            domains_enriched = await enrichment.enrich_run_domains(conn, run_id)
        except Exception:
            domains_enriched = {}

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
                    checked_at=data.get("checked_at"),
                )
            )

        # Enrichment upserts into the cache — commit so the cache persists
        # (docs/02 rule 3: never re-query a cached IP).
        conn.commit()

        # Roadmap 2.4 — correlated kill-chain sequence over the fired alerts.
        chain = killchain.correlate_chain(alerts_rows)

        # Explainability — the tuned thresholds this run was scored under
        # (captured once at first evaluation; {} when everything was stock).
        effective_tuning: dict = {}
        tuning_row = conn.execute(
            "SELECT params FROM run_tuning_snapshot WHERE run_id = ?", (run_id,)
        ).fetchone()
        if tuning_row:
            import json as _json

            try:
                effective_tuning = _json.loads(tuning_row["params"] or "{}")
            except (ValueError, TypeError):
                effective_tuning = {}

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

        # Storm guard — per-rule alert-cap suppressed counts (first-seen /
        # enumeration-burst / network-scan), so a long live session shows
        # what the cap held back instead of hiding it.
        suppressed_alerts: dict = {}
        sup_row = conn.execute(
            "SELECT suppressed_alerts FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if sup_row and sup_row["suppressed_alerts"]:
            import json as _json

            try:
                suppressed_alerts = _json.loads(sup_row["suppressed_alerts"])
            except (ValueError, TypeError):
                suppressed_alerts = {}

        # "Why this scored N" — per-rule contributions reconciling with the
        # headline risk score.
        breakdown = risk_service.risk_breakdown(
            [a["rule_id"] for a in alerts_rows]
        )

        # Trend context — signed delta vs this sample's most recent prior
        # run on the same platform ("is this session worse than last time?").
        delta_vs_prev: int | None = None
        prev = conn.execute(
            "SELECT run_id FROM runs WHERE sample_name = ? AND platform = ? "
            "AND started_at < ? ORDER BY started_at DESC LIMIT 1",
            (run_row["sample_name"], run_row["platform"], run_row["started_at"]),
        ).fetchone()
        if prev:
            prev_alerts = event_store.list_alerts_for_run(conn, prev["run_id"])
            delta_vs_prev = summary.risk_score - risk_service.compute_risk_score(
                [a["rule_id"] for a in prev_alerts]
            )

        return RunDetail(
            run=summary,
            process_tree=tree,
            network_connections=connections,
            timeline=[EventOut(**dict(r)) for r in timeline_rows],
            alerts=[Alert(**a) for a in alerts_rows],
            kill_chain=chain,
            sample_reputation=sample_reputation,
            domains=[DomainIntel(**d) for d in domains_enriched.values()],
            effective_tuning=effective_tuning,
            suppressed_alerts=suppressed_alerts,
            risk_breakdown=breakdown,
            delta_vs_prev_run=delta_vs_prev,
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
    if format not in ("suricata", "sigma", "yara", "all"):
        raise HTTPException(status_code=422, detail="format must be suricata, sigma, yara, or all")

    from ..services import rule_generator

    with db_session() as conn:
        run = run_store.get_run(conn, run_id)
        if not run:
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
        filename = f"outpost-sigma-{run_id[:12]}.yml"
    elif format == "yara":
        text = "\n\n".join(rule_generator.generate_yara_rules(run_id, run.get("sample_name")))
        filename = f"outpost-yara-{run_id[:12]}.yar"
    elif format == "suricata":
        text = "\n".join(rule_generator.generate_suricata_rules(run_id, connections))
        if not text:
            text = "# No malicious connections observed in this run."
        filename = f"outpost-suricata-{run_id[:12]}.rules"
    else:
        sigma_txt = "\n\n".join(rule_generator.generate_sigma_rules(run_id, alerts)) or "# No Sigma rules"
        suricata_txt = "\n".join(rule_generator.generate_suricata_rules(run_id, connections)) or "# No Suricata rules"
        yara_txt = "\n\n".join(rule_generator.generate_yara_rules(run_id, run.get("sample_name")))
        text = f"# ═══ SIGMA RULES ═══\n\n{sigma_txt}\n\n# ═══ SURICATA IDS RULES ═══\n\n{suricata_txt}\n\n# ═══ YARA SIGNATURES ═══\n\n{yara_txt}"
        filename = f"outpost-detection-suite-{run_id[:12]}.txt"

    return Response(
        content=text,
        media_type="text/plain",
        headers={"Content-Disposition": f'inline; filename="{filename}"'},
    )


@router.get("/runs/{run_id}/rules/suite", response_model=None)
async def get_run_detection_suite(run_id: str) -> dict:
    """Structured detection suite (Sigma, Suricata, YARA) for UI studio preview."""
    from ..core.db import get_connection
    from ..services import rule_generator

    conn = get_connection()
    try:
        run = run_store.get_run(conn, run_id)
        if not run:
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

    return rule_generator.generate_detection_suite(
        run_id=run_id,
        alerts=alerts,
        connections=connections,
        sample_name=run.get("sample_name"),
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


# ---------------------------------------------------------------------------
# Alert triage — per-run IOC allowlists (analyst workflow)
# ---------------------------------------------------------------------------


@router.get("/runs/{run_id}/allowlist", response_model=list[AllowlistEntry])
def list_run_allowlist(run_id: str) -> list[AllowlistEntry]:
    """IOCs allowlisted for this run, oldest first."""
    with db_session() as conn:
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        rows = conn.execute(
            "SELECT * FROM run_allowlist WHERE run_id = ? ORDER BY id ASC", (run_id,)
        ).fetchall()
    return [AllowlistEntry(**dict(r)) for r in rows]


@router.post("/runs/{run_id}/allowlist", status_code=201, response_model=AllowlistEntry)
def add_run_allowlist(run_id: str, body: AllowlistIn, request: Request) -> AllowlistEntry:
    """Allowlist an IOC for this run: matching alerts stop firing on future
    batches, and any already-open matching alerts are auto-acknowledged with
    a comment so the triage trail stays honest."""
    value = body.value.strip()
    if not value:
        raise HTTPException(status_code=422, detail="value must not be empty")
    now = datetime.now(timezone.utc).isoformat()
    with db_session() as conn:
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run_id: {run_id}")
        # Hash-kind entries match the run's uploaded sample SHA-256 — resolve
        # it here so the retroactive ack agrees with the engine's gating.
        sample_sha256 = load_run_sample_sha256(conn, run_id)
        cur = conn.execute(
            "INSERT INTO run_allowlist (run_id, kind, value, note, created_at) VALUES (?, ?, ?, ?, ?)",
            (run_id, body.kind, value, (body.note or "").strip() or None, now),
        )
        entry_id = cur.lastrowid

        # Retroactive triage: acknowledge every matching alert still open.
        matching = conn.execute(
            "SELECT id, related_ip, details FROM alerts WHERE run_id = ? AND status = 'open'",
            (run_id,),
        ).fetchall()
        acked = 0
        for row in matching:
            if allowlist_matches(body.kind, value, row["related_ip"], row["details"], sample_sha256):
                conn.execute(
                    "UPDATE alerts SET status = 'acknowledged', status_comment = ?, status_at = ? WHERE id = ?",
                    (f"Allowlisted: {body.kind} {value}", now, row["id"]),
                )
                acked += 1
        row = conn.execute("SELECT * FROM run_allowlist WHERE id = ?", (entry_id,)).fetchone()
        from ..models import audit

        audit.log(
            conn, auth.role_from_request(request), "allowlist.add",
            target_type="allowlist", target_id=str(entry_id),
            detail=f"{body.kind} {value} on run {run_id}" + (f" (acked {acked})" if acked else ""),
        )
    out = dict(row)
    out["acked"] = acked  # model field — the UI toasts how many were acked
    return AllowlistEntry(**out)


@router.delete("/runs/{run_id}/allowlist/{entry_id}", status_code=204)
def delete_run_allowlist(run_id: str, entry_id: int, request: Request) -> None:
    """Remove an allowlist entry. Already-acked alerts stay acked (the analyst
    decided on them); only *future* matching alerts start firing again."""
    with db_session() as conn:
        cur = conn.execute(
            "DELETE FROM run_allowlist WHERE id = ? AND run_id = ?", (entry_id, run_id)
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail=f"Unknown allowlist entry: {entry_id}")
        from ..models import audit

        audit.log(
            conn, auth.role_from_request(request), "allowlist.remove",
            target_type="allowlist", target_id=str(entry_id),
            detail=f"run {run_id}",
        )


# ---------------------------------------------------------------------------
# docs/08 #7 — Volatility3 memory forensics (Phase 3 tier)
# ---------------------------------------------------------------------------


@router.post("/runs/{run_id}/memory-scan", response_model=None)
def memory_scan(run_id: str, body: MemoryScanIn, request: Request) -> dict:
    """Run Volatility3 against a hypervisor memory dump and cross-reference
    the observed process list with this run's collected process_create
    telemetry — a process memory sees but the collector never logged is
    itself an interesting finding. The dump is any vaulted sample holding
    the raw image (e.g. `VBoxManage debugvm <vm> dumpvmcore` output)."""
    from ..services import memory_forensics as mf

    with db_session() as conn:
        if not run_store.get_run(conn, run_id):
            raise HTTPException(status_code=404, detail=f"Unknown run: {run_id}")
        if not samples_store.get_sample(conn, body.dump_sample_id):
            raise HTTPException(status_code=404, detail=f"Unknown sample: {body.dump_sample_id}")
        status = mf.vol_status()
        if not status["available"]:
            raise HTTPException(status_code=501, detail=status["error"])
        result = mf.scan_run(conn, run_id, body.dump_sample_id)
        hidden = len((result.get("cross_reference") or {}).get("hidden_processes") or [])
        audit.log(
            conn, auth.role_from_request(request), "run.memory-scan",
            target_type="run", target_id=run_id,
            detail=(
                f"volatility3 scan of dump {body.dump_sample_id}: "
                f"{len(result.get('processes') or [])} processes, {hidden} unexplained"
            ),
        )
    return result
