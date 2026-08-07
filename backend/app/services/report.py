"""Report export generation — JSON + PDF.

Task 21 (docs/06-BUILD-PLAN.md): `GET /runs/{id}/export` returns JSON, and
`?format=pdf` returns a PDF. The PDF is built with reportlab so both the
webapp export button and `outpost export --format pdf` produce the same
artifact — same data, same service.
"""

import io
from typing import Optional

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
        # Campaign references — links this analysis back to its cluster(s).
        campaigns = campaigns_service.campaigns_for_run(conn, run_id)
    return {
        "run": summary.model_dump(mode="json"),
        "events": events,
        "alerts": alerts,
        "campaigns": campaigns,
    }


def build_pdf_report(run_id: str) -> Optional[bytes]:
    """Render a simple analyst-facing PDF of the run report."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        return None

    data = build_json_report(run_id)
    if "error" in data:
        return None

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    run = data["run"]
    story.append(Paragraph(f"OutPost Report — {run['sample_name']}", styles["Title"]))
    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            f"run_id: {run['run_id']} &nbsp;|&nbsp; platform: {run['platform']} &nbsp;|&nbsp; "
            f"type: {run['session_type']} &nbsp;|&nbsp; alerts: {run['alert_count']} &nbsp;|&nbsp; "
            f"highest severity: {run['highest_severity'] or 'clean'}",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 16))

    # Alerts section
    if data["alerts"]:
        story.append(Paragraph("Alerts", styles["Heading2"]))
        rows = [["Severity", "Rule", "Details"]]
        for a in data["alerts"]:
            rows.append([a["severity"], a["rule_name"], a["details"]])
        table = Table(rows, colWidths=[70, 170, 330])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2028")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#E4E7EB")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#2A2F3A")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 16))

    # Events timeline
    story.append(Paragraph("Events", styles["Heading2"]))
    ev_rows = [["Time", "Type", "Detail"]]
    for ev in data["events"]:
        detail = _event_detail(ev)
        ev_rows.append([(ev.get("timestamp") or "")[11:19], ev["event_type"], detail])
    ev_table = Table(ev_rows, colWidths=[60, 130, 380])
    ev_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1C2028")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#E4E7EB")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#2A2F3A")),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(ev_table)

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
