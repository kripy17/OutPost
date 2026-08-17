"""`outpost hosts timeline <host>` — the host aggregate timeline (P0.6).

Terminal parity for GET /hosts/{host_id}/timeline: the merged chronological
feed of events / findings / sessions / IOCs / investigations tied to one
host. Filters: --kind, --event-type, --q; --limit/--offset paginate.
"""

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(help="Host investigation (P0.6): the per-host aggregate timeline.")


@app.command("timeline")
def timeline(
    host_id: str = typer.Argument(..., help="Host id (fleet identity from events/agent heartbeats)"),
    kind: str = typer.Option(None, "--kind", help="Restrict to event | finding | session | ioc | investigation"),
    event_type: str = typer.Option(None, "--event-type", help="Narrow event rows to this event type"),
    q: str = typer.Option(None, "--q", help="Match display fields of every kind"),
    limit: int = typer.Option(50, "--limit", min=1, max=200),
    offset: int = typer.Option(0, "--offset"),
) -> None:
    show_banner(primary=False)
    try:
        data = api_client.host_timeline(
            host_id, kind=kind, event_type=event_type, q=q, limit=limit, offset=offset
        )
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Timeline failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    console.print(
        f"[bold]{data['host_id']}[/bold] — {data['platform'] or 'unknown'} "
        f"· {data['total']} timeline entr{'y' if data['total'] == 1 else 'ies'}"
    )
    if data["total"] == 0:
        console.print("[dim]No activity for this host yet.[/dim]")
        return

    table = Table(border_style="dim")
    table.add_column("When")
    table.add_column("Kind")
    table.add_column("Title")
    table.add_column("Subtitle")
    for e in data["timeline"]:
        table.add_row(
            (e["timestamp"] or "")[:19].replace("T", " "),
            e["kind"],
            e["title"][:60],
            (e.get("subtitle") or "-")[:60],
        )
    console.print(table)
