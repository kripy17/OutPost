"""Report export generation — JSON + PDF.

Task 21 (docs/06-BUILD-PLAN.md): `GET /runs/{id}/export` returns JSON, and
`?format=pdf` returns a PDF. The PDF is built with reportlab so both the
webapp export button and `outpost export --format pdf` produce the same
artifact — same data, same service.
"""

import io
import json

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
