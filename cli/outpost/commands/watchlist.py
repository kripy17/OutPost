"""`outpost watchlist add|list|remove|export|import` — personal IOC watchlist (Task 26).

Entries are checked against every run's connections during enrichment,
independent of AbuseIPDB/VirusTotal. `export`/`import` move the list as
JSON or CSV (roadmap 3.3 — shared watchlists).
"""

import json
from pathlib import Path

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(help="Personal IOC watchlist — checked against every run", add_completion=False)


@app.callback(invoke_without_command=True)
def _group(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        show_banner(primary=False)
        ctx.invoke(list_entries)


@app.command("add")
def add(
    value: str = typer.Argument(..., help="IP, domain, or hash to track"),
    label: str = typer.Option("", "--label", "-l", help="Your own description"),
) -> None:
    show_banner(primary=False)
    try:
        entry = api_client.watchlist_add(value, label)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(f"[#3FA796]Added {entry['value']} to watchlist[/#3FA796]")


@app.command("list")
def list_entries() -> None:
    show_banner(primary=False)
    entries = api_client.watchlist_list()
    if not entries:
        console.print("[dim]Watchlist is empty.[/dim]")
        return
    table = Table(title="Watchlist", border_style="dim")
    table.add_column("Value")
    table.add_column("Label")
    table.add_column("Added")
    for e in entries:
        table.add_row(e["value"], e["label"], e["added_at"][:19].replace("T", " "))
    console.print(table)


@app.command("remove")
def remove(value: str = typer.Argument(..., help="Value to stop tracking")) -> None:
    show_banner(primary=False)
    try:
        api_client.watchlist_remove(value)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(f"[#3FA796]Removed {value} from watchlist[/#3FA796]")


@app.command("export")
def export(
    format: str = typer.Option("json", "--format", help="json or csv"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Write the watchlist to a shareable file (JSON or CSV)."""
    show_banner(primary=False)
    if format not in ("json", "csv"):
        console.print(f"[bold #C4453B]Unknown format: {format}[/bold #C4453B] (use json or csv)")
        raise typer.Exit(2)
    dest = output or Path(f"outpost-watchlist.{format}")
    dest.write_bytes(api_client.watchlist_export(format))
    console.print(f"[#3FA796]Exported watchlist → {dest}[/#3FA796]")


@app.command("import")
def import_entries(
    source: Path = typer.Argument(..., help="JSON or CSV file to load"),
) -> None:
    """Import a watchlist file ({entries:[...]} JSON, or value,label CSV)."""
    show_banner(primary=False)
    if not source.exists():
        console.print(f"[bold #C4453B]No such file: {source}[/bold #C4453B]")
        raise typer.Exit(2)
    text = source.read_text()
    if source.suffix.lower() == ".csv":
        entries = [
            {"value": parts[0].strip(), "label": parts[1].strip() if len(parts) > 1 else ""}
            for line in text.splitlines()
            if (parts := [p.strip() for p in line.split(",")]) and parts[0]
        ]
    else:
        try:
            entries = [e for e in json.loads(text).get("entries", []) if e.get("value")]
        except json.JSONDecodeError as exc:
            console.print(f"[bold #C4453B]Invalid JSON: {exc}[/bold #C4453B]")
            raise typer.Exit(2)
    if not entries:
        console.print("[dim]No entries found in file.[/dim]")
        return
    try:
        res = api_client.watchlist_import(entries)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(f"[#3FA796]Imported {res['imported']} entr{'y' if res['imported'] == 1 else 'ies'} from {source}[/#3FA796]")
