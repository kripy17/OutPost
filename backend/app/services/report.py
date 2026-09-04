"""Report export generation — JSON + PDF.

Task 21 (docs/06-BUILD-PLAN.md): `GET /runs/{id}/export` returns JSON, and
`?format=pdf` returns a PDF. The PDF is built with reportlab so both the
webapp export button and `outpost export --format pdf` produce the same
artifact — same data, same service.
"""

import io
import json
from datetime import datetime, timezone

from ..core.db import db_session
from ..models import event as event_store
from ..models import run as run_store
from ..services import campaigns as campaigns_service


def build_json_report(run_id: str) -> dict:
    with db_session() as conn:
        run_row = run_store.get_run(conn, run_id)
        if not run_row:
            return {"error": f"Unknown run_id: {run_id}"}
        summary = run_store.to_summary(conn, run_row)
        events = event_store.list_events_for_run(conn, run_id)
        alerts = event_store.list_alerts_for_run(conn, run_id)
        # Explainability — the tuned thresholds this run was scored under.
        tuning_row = conn.execute(
            "SELECT params FROM run_tuning_snapshot WHERE run_id = ?", (run_id,)
        ).fetchone()
        effective_tuning = {}
        if tuning_row:
            try:
                effective_tuning = json.loads(tuning_row["params"] or "{}")
            except (ValueError, TypeError):
                effective_tuning = {}
        # Storm guard — per-rule alert-cap suppressed counts (exported so the
        # cap is visible offline, not just in the UI).
        suppressed_alerts = {}
        sup_row = conn.execute(
            "SELECT suppressed_alerts FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if sup_row and sup_row["suppressed_alerts"]:
            try:
                suppressed_alerts = json.loads(sup_row["suppressed_alerts"])
            except (ValueError, TypeError):
                suppressed_alerts = {}
        # Campaign references — links this analysis back to its cluster(s).
        campaigns = campaigns_service.campaigns_for_run(conn, run_id)
        # Network connections — cache-first reputation reads (no new external
        # calls in the export; `checked_at` shows how old each verdict is, so
        # exported analyses carry the same staleness the UI surfaces).
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
        network_connections = []
        for row in conn_rows:
            cached = conn.execute(
                "SELECT abuse_score, vt_malicious_count, reputation, checked_at FROM enrichment_cache WHERE ip = ?",
                (row["dest_ip"],),
            ).fetchone()
            network_connections.append(
                {
                    "dest_ip": row["dest_ip"],
                    "dest_port": row["dest_port"],
                    "protocol": row["protocol"],
                    "first_seen": row["first_seen"],
                    "reputation": cached["reputation"] if cached else "unknown",
                    "abuse_score": cached["abuse_score"] if cached else None,
                    "vt_malicious_count": cached["vt_malicious_count"] if cached else None,
                    "checked_at": cached["checked_at"] if cached else None,
                }
            )
    return {
        "run": summary.model_dump(mode="json"),
        "events": events,
        "alerts": alerts,
        "campaigns": campaigns,
        "network_connections": network_connections,
        "effective_tuning": effective_tuning,
        "suppressed_alerts": suppressed_alerts,
    }


def build_pdf_report(run_id: str) -> bytes | None:
    """Render a comprehensive executive & analyst incident dossier PDF."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        return None

    data = build_json_report(run_id)
    if "error" in data:
        return None

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DossierTitle",
        parent=styles["Title"],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0F172A"),
        alignment=0,
    )
    h2_style = ParagraphStyle(
        "DossierH2",
        parent=styles["Heading2"],
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=10,
        spaceAfter=4,
    )
    cell_style = ParagraphStyle(
        "CellNormal",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#334155"),
    )
    cell_bold = ParagraphStyle(
        "CellBold",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#0F172A"),
    )
    header_style = ParagraphStyle(
        "HeaderCell",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#FFFFFF"),
    )

    story = []
    run = data["run"]
    sev = (run.get("highest_severity") or "clean").lower()
    sev_color = "#DC2626" if sev == "malicious" else ("#F59E0B" if sev == "suspicious" else "#10B981")
    risk_score = run.get("risk_score", 0)

    # Header banner
    story.append(Paragraph("OUTPOST INCIDENT & BEHAVIORAL DOSSIER", ParagraphStyle("Sub", fontSize=8, textColor=colors.HexColor("#64748B"), spaceAfter=2)))
    story.append(Paragraph(f"Analysis Report: {run.get('sample_name', 'Unnamed Session')}", title_style))
    story.append(Spacer(1, 6))

    # Key Metrics Grid
    meta_data = [
        [
            Paragraph("<b>Target Sample:</b>", cell_style), Paragraph(str(run.get("sample_name", "-")), cell_bold),
            Paragraph("<b>Verdict:</b>", cell_style), Paragraph(f"<font color='{sev_color}'><b>{sev.upper()}</b></font>", cell_bold),
        ],
        [
            Paragraph("<b>Run ID:</b>", cell_style), Paragraph(str(run.get("run_id", "-"))[:24], cell_style),
            Paragraph("<b>Risk Score:</b>", cell_style), Paragraph(f"<b>{risk_score}/100</b>", cell_bold),
        ],
        [
            Paragraph("<b>Platform:</b>", cell_style), Paragraph(str(run.get("platform", "-")).title(), cell_style),
            Paragraph("<b>Session Type:</b>", cell_style), Paragraph(str(run.get("session_type", "-")), cell_style),
        ],
        [
            Paragraph("<b>Started At:</b>", cell_style), Paragraph(str(run.get("started_at", "-"))[:19], cell_style),
            Paragraph("<b>Total Alerts:</b>", cell_style), Paragraph(str(run.get("alert_count", 0)), cell_bold),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[80, 190, 80, 190])
    meta_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])
    )
    story.append(meta_table)
    story.append(Spacer(1, 8))

    # Executive Summary / Findings
    story.append(Paragraph("Executive Summary & Risk Assessment", h2_style))
    summary_text = (
        f"Automated behavioral detonation completed with a composite risk score of <b>{risk_score}/100</b>. "
        f"The host produced <b>{len(data.get('events', []))} telemetry events</b> triggering <b>{len(data.get('alerts', []))} alerts</b>. "
        f"Overall behavioral rating is <b>{sev.upper()}</b>."
    )
    story.append(Paragraph(summary_text, cell_style))
    story.append(Spacer(1, 8))

    # Alerts Table
    if data.get("alerts"):
        story.append(Paragraph(f"Detection Findings & Alerts ({len(data['alerts'])})", h2_style))
        alert_rows = [[
            Paragraph("Severity", header_style),
            Paragraph("Rule / Detection", header_style),
            Paragraph("Details & Evidence", header_style),
        ]]
        for a in data["alerts"][:15]:
            a_sev = a.get("severity", "suspicious")
            color_hex = "#DC2626" if a_sev == "malicious" else "#F59E0B"
            alert_rows.append([
                Paragraph(f"<font color='{color_hex}'><b>{a_sev.upper()}</b></font>", cell_style),
                Paragraph(str(a.get("rule_name") or a.get("rule_id", "-")), cell_bold),
                Paragraph(str(a.get("details") or "-")[:160], cell_style),
            ])
        alert_table = Table(alert_rows, colWidths=[70, 160, 310])
        alert_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F8FAFC")]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
        )
        story.append(alert_table)
        story.append(Spacer(1, 8))

    # Network Connections Table
    if data.get("network_connections"):
        story.append(Paragraph(f"Network Indicators ({len(data['network_connections'])})", h2_style))
        net_rows = [[
            Paragraph("Destination IP", header_style),
            Paragraph("Port", header_style),
            Paragraph("Protocol", header_style),
            Paragraph("Reputation Verdict", header_style),
        ]]
        for conn in data["network_connections"][:8]:
            rep = conn.get("reputation") or "clean"
            rep_hex = "#DC2626" if rep == "malicious" else ("#F59E0B" if rep == "suspicious" else "#10B981")
            net_rows.append([
                Paragraph(str(conn.get("dest_ip") or "-"), cell_style),
                Paragraph(str(conn.get("dest_port") or "-"), cell_style),
                Paragraph(str(conn.get("protocol") or "-"), cell_style),
                Paragraph(f"<font color='{rep_hex}'><b>{rep.upper()}</b></font>", cell_style),
            ])
        net_table = Table(net_rows, colWidths=[160, 80, 80, 220])
        net_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F8FAFC")]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
        )
        story.append(net_table)
        story.append(Spacer(1, 8))

    # Chronological Telemetry Events
    if data.get("events"):
        story.append(Paragraph(f"Observed Behavioral Events (First {min(10, len(data['events']))})", h2_style))
        ev_rows = [[
            Paragraph("Time", header_style),
            Paragraph("Type", header_style),
            Paragraph("Activity Details", header_style),
        ]]
        for ev in data["events"][:10]:
            ts = (ev.get("timestamp") or "")[11:19]
            ev_rows.append([
                Paragraph(ts or "-", cell_style),
                Paragraph(str(ev.get("event_type") or "-"), cell_bold),
                Paragraph(_event_detail(ev)[:120], cell_style),
            ])
        ev_table = Table(ev_rows, colWidths=[60, 130, 350])
        ev_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F8FAFC")]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
        )
        story.append(ev_table)
        story.append(Spacer(1, 10))

    # Analyst Sign-off Box
    story.append(Paragraph("Investigation & Analyst Sign-off", h2_style))
    signoff_data = [
        [Paragraph("<b>Lead Analyst:</b> ___________________________", cell_style), Paragraph("<b>Signature / Approval:</b> ___________________________", cell_style)],
        [Paragraph("<b>Disposition:</b> [ &nbsp; ] False Positive &nbsp;&nbsp; [ &nbsp; ] Contained &nbsp;&nbsp; [ &nbsp; ] Escalated to Tier 3", cell_style), Paragraph("<b>Date:</b> ____ / ____ / ________", cell_style)],
    ]
    signoff_table = Table(signoff_data, colWidths=[270, 270])
    signoff_table.setStyle(
        TableStyle([
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(signoff_table)

    doc.build(story)
    return buf.getvalue()


def _event_detail(ev: dict) -> str:
    if ev["event_type"] == "process_create":
        return f"{ev.get('process_name') or '?'} (pid {ev.get('pid')}) {ev.get('command_line') or ''}".strip()
    if ev["event_type"] == "network_connection":
        return f"{ev.get('dest_ip')}:{ev.get('dest_port')} [{ev.get('protocol')}]"
    if ev["event_type"] == "file_write":
        return ev.get("file_path") or "-"
    if ev["event_type"] == "registry_write":
        return ev.get("registry_key") or "-"
    return "-"


def synthesize_investigation_narrative(conn, investigation_id: str) -> dict:
    """Synthesize an executive incident narrative, causality stages, and actionable remediation checklist."""
    inv_row = conn.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
    if not inv_row:
        raise ValueError(f"Investigation {investigation_id} not found")

    title = inv_row["title"]
    status = inv_row["status"]

    alert_rows = conn.execute(
        "SELECT a.id, a.rule_id, a.rule_name, a.severity, a.details, a.triggered_at, a.run_id, r.sample_name "
        "FROM alerts a LEFT JOIN runs r ON a.run_id = r.run_id "
        "WHERE a.investigation_id = ? ORDER BY a.triggered_at ASC",
        (investigation_id,),
    ).fetchall()
    alerts = [dict(r) for r in alert_rows]

    ref_rows = conn.execute(
        "SELECT ref_type, ref_id FROM investigation_refs WHERE investigation_id = ?",
        (investigation_id,),
    ).fetchall()
    refs = [dict(r) for r in ref_rows]

    runs_set = {r["ref_id"] for r in refs if r["ref_type"] == "run"}
    for a in alerts:
        if a.get("run_id"):
            runs_set.add(a["run_id"])

    hosts_set = {r["ref_id"] for r in refs if r["ref_type"] == "host"}
    iocs_set = {r["ref_id"] for r in refs if r["ref_type"] == "ioc"}
    samples_set = {r["ref_id"] for r in refs if r["ref_type"] == "artifact"}

    from .risk import RULE_META
    tactics_seen: set[str] = set()
    for a in alerts:
        meta = RULE_META.get(a.get("rule_id", ""), {})
        if meta.get("tactic"):
            tactics_seen.add(meta["tactic"])

    severities = [a["severity"] for a in alerts]
    max_severity = "critical" if "malicious" in severities and len(alerts) >= 3 else "malicious" if "malicious" in severities else "suspicious" if "suspicious" in severities else "clean"

    exec_summary = (
        f"Security incident '{title}' (ID: {investigation_id}) currently in '{status.upper()}' state with {len(alerts)} "
        f"correlated detection alerts across {len(hosts_set) or 1} affected endpoint(s). "
        f"The intrusion activity spans {len(tactics_seen) or 1} MITRE ATT&CK kill-chain phases with maximum severity classified as {max_severity.upper()}."
    )

    causality_stages = []
    for idx, a in enumerate(alerts[:8], start=1):
        causality_stages.append({
            "step": idx,
            "rule": a["rule_name"],
            "severity": a["severity"],
            "details": a["details"],
            "timestamp": a["triggered_at"],
            "sample": a.get("sample_name") or "system",
        })

    remediation_checklist = []
    for h in (hosts_set or ["local"]):
        remediation_checklist.append(f"Containment: Enforce host isolation or network boundary policy on endpoint '{h}'.")
    for a in alerts:
        if "process" in a["details"].lower() or a["rule_id"] in ("masquerading", "reverse-shell", "credential-dumping"):
            remediation_checklist.append(f"Process Termination: Verify and terminate suspicious process instances matching {a['rule_name']}.")
    for ioc in (iocs_set or []):
        remediation_checklist.append(f"Network Ingress/Egress: Block malicious indicator '{ioc}' at border firewalls.")
    remediation_checklist.append("Credential Invalidation: Force password reset and session revocation for all compromised user accounts.")
    remediation_checklist.append("Host Rescan: Perform deep host memory forensics and baseline differential comparison before unisolating.")

    remediation_checklist = list(dict.fromkeys(remediation_checklist))

    return {
        "investigation_id": investigation_id,
        "title": title,
        "status": status,
        "max_severity": max_severity,
        "executive_summary": exec_summary,
        "tactics_involved": sorted(tactics_seen),
        "causality_timeline": causality_stages,
        "compromised_assets": {
            "hosts": list(hosts_set) or ["local"],
            "runs": list(runs_set),
            "samples": list(samples_set),
            "iocs": list(iocs_set),
        },
        "remediation_checklist": remediation_checklist,
    }


def build_investigation_markdown_export(conn, investigation_id: str) -> str:
    """Render a comprehensive incident response dossier in Markdown."""
    from ..models import investigation as inv_store

    inv = inv_store.get(conn, investigation_id)
    if not inv:
        return f"# Error\nInvestigation '{investigation_id}' not found."

    narrative = synthesize_investigation_narrative(conn, investigation_id)
    findings = inv_store.findings_for_investigation(conn, investigation_id)
    refs = inv_store.list_refs(conn, investigation_id)
    notes = inv_store.list_notes(conn, investigation_id)

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    md_lines = [
        "# OUTPOST INCIDENT RESPONSE CASE BRIEF",
        f"**Case ID:** `{inv['id']}`  ",
        f"**Incident Title:** {inv['title']}  ",
        f"**Classification / Max Severity:** `{narrative['max_severity'].upper()}`  ",
        f"**Current Status:** `{inv['status'].upper()}`  ",
        f"**Report Generated:** {now_utc}  ",
        f"**Traffic Light Protocol (TLP):** `AMBER+STRICT`  ",
        f"**Lead Investigator / Actor:** `{inv.get('created_by') or 'operator'}`  ",
        f"**Tags:** {', '.join(inv.get('tags') or ['general-incident'])}  ",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        narrative["executive_summary"],
        "",
    ]

    if inv.get("conclusion"):
        md_lines.extend([
            "### Incident Closure & Conclusion",
            inv["conclusion"],
            "",
        ])

    md_lines.extend([
        "## 2. Threat Classification & MITRE ATT&CK Mapping",
        f"- **Observed ATT&CK Tactics:** {', '.join(narrative['tactics_involved']) if narrative['tactics_involved'] else 'None'}",
        f"- **Correlated Alert Findings:** {len(findings)}",
        "- **Compromised Asset Inventory:**",
        f"  - **Endpoints / Hosts:** {', '.join(narrative['compromised_assets']['hosts'])}",
        f"  - **Sandbox Detonation Runs:** {', '.join(narrative['compromised_assets']['runs']) if narrative['compromised_assets']['runs'] else 'None'}",
        f"  - **Associated Payloads:** {', '.join(narrative['compromised_assets']['samples']) if narrative['compromised_assets']['samples'] else 'None'}",
        f"  - **Network & File IOCs:** {', '.join(narrative['compromised_assets']['iocs']) if narrative['compromised_assets']['iocs'] else 'None'}",
        "",
        "## 3. Incident Chronology & Causality Chain",
    ])

    if narrative["causality_timeline"]:
        md_lines.extend([
            "| Step | Timestamp | Rule / Detection | Severity | Sample / Context | Details |",
            "|:----:|:----------|:-----------------|:--------:|:-----------------|:--------|",
        ])
        for item in narrative["causality_timeline"]:
            md_lines.append(
                f"| {item['step']} | {item['timestamp']} | {item['rule']} | {item['severity'].upper()} | {item['sample']} | {item['details']} |"
            )
        md_lines.append("")
    else:
        md_lines.extend(["*No direct telemetry findings attached to this case.*", ""])

    md_lines.extend([
        "## 4. Discovered Indicators of Compromise (IOCs) & Evidence References",
    ])
    if refs:
        md_lines.extend([
            "| Ref Type | Indicator / Identifier | Attached At |",
            "|:---------|:-----------------------|:------------|",
        ])
        for r in refs:
            md_lines.append(f"| {r['ref_type'].upper()} | `{r['ref_id']}` | {r['added_at']} |")
        md_lines.append("")
    else:
        md_lines.extend(["*No explicit evidence references recorded.*", ""])

    md_lines.extend([
        "## 5. Containment & Remediation Checklist",
    ])
    for item in narrative["remediation_checklist"]:
        md_lines.append(f"- [ ] **{item}**")
    md_lines.append("")

    if notes:
        md_lines.extend([
            "## 6. Analyst Notes & Incident Log",
            "| Timestamp | Author / Actor | Note |",
            "|:----------|:---------------|:-----|",
        ])
        for n in notes:
            actor = n.get("actor") or n.get("author") or "operator"
            md_lines.append(f"| {n['created_at']} | {actor} | {n['note']} |")
        md_lines.append("")

    md_lines.extend([
        "---",
        "*Report generated by OutPost Security Operations Center Platform*",
    ])
    return "\n".join(md_lines)


def build_investigation_json_export(conn, investigation_id: str) -> dict:
    """Return complete structured incident response dossier JSON."""
    from ..models import investigation as inv_store

    inv = inv_store.get(conn, investigation_id)
    if not inv:
        return {"error": f"Unknown investigation: {investigation_id}"}
    narrative = synthesize_investigation_narrative(conn, investigation_id)
    findings = inv_store.findings_for_investigation(conn, investigation_id)
    refs = inv_store.list_refs(conn, investigation_id)
    notes = inv_store.list_notes(conn, investigation_id)
    return {
        "case": inv,
        "narrative": narrative,
        "findings": findings,
        "refs": refs,
        "notes": notes,
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }


