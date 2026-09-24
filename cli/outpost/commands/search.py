"""`outpost search <ioc>` — \"have I seen this before?\" across all runs (Task 24).

P0.5: `--global` runs the grouped GET /search over every analyst-facing
resource (findings, iocs, artifacts, hosts, sessions, investigations,
campaigns) with qualifier support, instead of the legacy event-scoped IOC
search.

Includes offline SQLite fallback and JSON/CSV export support.
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


def search(
    value: str = typer.Argument(..., help="IP, domain, hash, process name, file path, or registry key"),
    global_search: bool = typer.Option(False, "--global", "-g", help="Grouped search across every resource (P0.5 GET /search)"),
    as_json: bool = typer.Option(False, "--json", help="Output results as JSON"),
    as_csv: bool = typer.Option(False, "--csv", help="Output results as CSV"),
) -> None:
    """Search for an indicator across all telemetry runs, sessions, and artifacts."""
    if global_search:
        _render_global(value, as_json=as_json, as_csv=as_csv)
        return

    matches = None
    source = "live"

    try:
        data = api_client.search_iocs(value)
        matches = data.get("matches", [])
    except Exception:
        # Fall back to offline SQLite search
        offline_matches = offline_store.search_offline_iocs(value)
        if offline_matches is not None:
            matches = offline_matches
            source = "offline"

    if matches is None:
        console.print(f"[bold #C4453B]Search failed: backend offline and local database unavailable.[/bold #C4453B]")
        raise typer.Exit(1)

    if as_json:
        console.print(json.dumps({"query": value, "count": len(matches), "matches": matches}, indent=2))
        return

    if as_csv:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Run ID", "Sample/Host", "Event Type", "Timestamp"])
        for m in matches:
            writer.writerow([
                m.get("run_id", ""),
                m.get("sample_name", "") or "",
                m.get("event_type", "") or "",
                m.get("timestamp", "") or "",
            ])
        console.print(buf.getvalue().strip())
        return

    show_banner(primary=False)

    if source == "offline":
        console.print(f"[dim yellow]Notice: Backend unreachable. Searched local SQLite database for {value!r}.[/dim yellow]\n")

    if not matches:
        console.print(f"[dim]No prior runs contain {value!r}.[/dim]")
        return

    table = Table(title=f"{len(matches)} match(es) for {value}", border_style="dim")
    table.add_column("Run ID", style="bold cyan")
    table.add_column("Sample / Host", style="white")
    table.add_column("Event Type", style="bold yellow")
    table.add_column("Timestamp", style="dim")
    for m in matches:
        table.add_row(
            m.get("run_id", "-"),
            m.get("sample_name") or "-",
            m.get("event_type", "-"),
            (m.get("timestamp") or "")[:19].replace("T", " "),
        )
    console.print(table)


def _render_global(value: str, as_json: bool = False, as_csv: bool = False) -> None:
    try:
        data = api_client.global_search(value)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Global search failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    if as_json:
        console.print(json.dumps(data, indent=2))
        return

    if as_csv:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Group", "Kind", "ID", "Title", "Subtitle"])
        for group, res in data.get("groups", {}).items():
            for h in res.get("hits", []):
                writer.writerow([
                    group,
                    h.get("kind", "") or "",
                    h.get("id", ""),
                    h.get("title", ""),
                    h.get("subtitle", "") or "",
                ])
        console.print(buf.getvalue().strip())
        return

    show_banner(primary=False)

    if all(g["total"] == 0 for g in data["groups"].values()):
        console.print(f"[dim]No matches for {value!r} across any resource.[/dim]")
        return

    for group, res in data["groups"].items():
        if res["total"] == 0:
            continue
        table = Table(title=f"{group} · {res['total']} match(es)", border_style="dim")
        table.add_column("Kind", style="bold yellow")
        table.add_column("ID", style="bold cyan")
        table.add_column("Title", style="white")
        table.add_column("Subtitle", style="dim")
        for h in res["hits"]:
            table.add_row(
                h.get("kind") or "-",
                h["id"],
                h["title"][:60],
                (h.get("subtitle") or "-")[:60],
            )
        console.print(table)
