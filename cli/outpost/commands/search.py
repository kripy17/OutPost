"""`outpost search <ioc>` — \"have I seen this before?\" across all runs (Task 24).

P0.5: `--global` runs the grouped GET /search over every analyst-facing
resource (findings, iocs, artifacts, hosts, sessions, investigations,
campaigns) with qualifier support, instead of the legacy event-scoped IOC
search."""

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console


def search(
    value: str = typer.Argument(..., help="IP, domain, hash, process name, file path, or registry key"),
    global_search: bool = typer.Option(False, "--global", help="Grouped search across every resource (P0.5 GET /search)"),
) -> None:
    show_banner(primary=False)

    if global_search:
        _render_global(value)
        return

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


def _render_global(value: str) -> None:
    try:
        data = api_client.global_search(value)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Search failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    if all(g["total"] == 0 for g in data["groups"].values()):
        console.print(f"[dim]No matches for {value!r} across any resource.[/dim]")
        return

    for group, res in data["groups"].items():
        if res["total"] == 0:
            continue
        table = Table(title=f"{group} · {res['total']} match(es)", border_style="dim")
        table.add_column("Kind")
        table.add_column("ID")
        table.add_column("Title")
        table.add_column("Subtitle")
        for h in res["hits"]:
            table.add_row(
                h.get("kind") or "-",
                h["id"],
                h["title"][:60],
                (h.get("subtitle") or "-")[:60],
            )
        console.print(table)
