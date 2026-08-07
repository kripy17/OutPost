"""`outpost search <ioc>` — \"have I seen this before?\" across all runs (Task 24)."""

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console


def search(value: str = typer.Argument(..., help="IP, domain, hash, process name, file path, or registry key")) -> None:
    show_banner(primary=False)

    try:
        data = api_client.search_iocs(value)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Search failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    if data["count"] == 0:
        console.print(f"[dim]No prior runs contain {value!r}.[/dim]")
        return

    table = Table(title=f"{data['count']} match(es) for {value}", border_style="dim")
    table.add_column("Run ID")
    table.add_column("Sample")
    table.add_column("Event")
    table.add_column("Timestamp")
    for m in data["matches"]:
        table.add_row(m["run_id"], m["sample_name"] or "-", m["event_type"], (m["timestamp"] or "")[:19].replace("T", " "))
    console.print(table)
