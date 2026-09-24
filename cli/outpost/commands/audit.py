"""`outpost audit` — analyst audit trail.

Terminal parity for GET /audit:
- Who did what, when
- Filtering by action kind (--action alert.status, auth.login, etc.)
- Offline SQLite fallback when backend service is offline
- CSV and JSON export options for compliance reporting
"""

import csv
import io
import json
from typing import Optional

import typer
from rich.table import Table

from ..lib import api_client, offline_store
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(help="Analyst audit log and compliance trail", add_completion=False)


@app.callback(invoke_without_command=True)
def audit_command(
    action: Optional[str] = typer.Option(None, "--action", "-a", help="Filter by action kind (e.g. alert.status, auth.login)"),
    limit: int = typer.Option(50, "--limit", "-n", min=1, max=1000, help="Maximum entries to display"),
    as_csv: bool = typer.Option(False, "--csv", help="Output entries formatted as CSV"),
    as_json: bool = typer.Option(False, "--json", help="Output raw entries as JSON"),
) -> None:
    """View analyst mutations: triage transitions, false-positive marks, containment, logins, rotations."""
    events = None
    source = "live"

    try:
        data = api_client.get_audit(limit=limit, action=action or "")
        events = data.get("events", [])
    except Exception:
        # Fall back to SQLite
        offline_events = offline_store.get_offline_audit(limit=limit, action=action)
        if offline_events is not None:
            events = offline_events
            source = "offline"

    if events is None:
        console.print("[bold #C4453B]Could not retrieve audit log (backend offline and local database unavailable).[/bold #C4453B]")
        raise typer.Exit(1)

    if as_json:
        console.print(json.dumps(events, indent=2))
        return

    if as_csv:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Timestamp", "Actor", "Action", "Target Type", "Target ID", "Detail"])
        for e in events:
            writer.writerow([
                e.get("ts", ""),
                e.get("actor", ""),
                e.get("action", ""),
                e.get("target_type", "") or "",
                e.get("target_id", "") or "",
                e.get("detail", "") or "",
            ])
        console.print(output.getvalue().strip())
        return

    show_banner(primary=False)

    if source == "offline":
        console.print("[dim yellow]Note: Backend unreachable. Displaying audit trail directly from local SQLite database (offline mode).[/dim yellow]\n")

    if not events:
        msg = f"No audit records found matching action '{action}'." if action else "Audit log is empty."
        console.print(f"[dim]{msg}[/dim]")
        return

    table = Table(title=f"Analyst Audit Trail ({len(events)} events)", border_style="dim")
    table.add_column("Timestamp", style="dim", no_wrap=True)
    table.add_column("Actor", style="bold cyan")
    table.add_column("Action", style="bold yellow")
    table.add_column("Target", style="magenta")
    table.add_column("Detail", style="white")

    for e in events:
        ts = (e.get("ts") or "")[:19].replace("T", " ")
        actor = e.get("actor") or "-"
        act = e.get("action") or "-"
        target_type = e.get("target_type") or ""
        target_id = e.get("target_id") or ""
        target = f"{target_type} #{target_id}" if target_type and target_id else target_type or target_id or "-"
        detail = (e.get("detail") or "-")[:80]
        table.add_row(ts, actor, act, target, detail)

    console.print(table)
