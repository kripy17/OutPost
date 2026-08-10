"""`outpost intel import` — pull a threat-intel feed into the watchlist + IOC layer.

Terminal mirror of the webapp's feed import: paste a STIX 2.1 bundle or a
one-IOC-per-line list (or point at a feed URL) and every value lands in the
watchlist labeled `intel:<source>`. The response also reports which existing
runs already touch an imported value, so a fresh feed can be triaged
immediately.
"""

from pathlib import Path

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(help="Threat-intel feed import — watchlist + IOC layer", add_completion=False)


@app.command("import")
def import_feed(
    source: str = typer.Option("auto", "--source", help="stix | text | auto"),
    file: Path = typer.Option(None, "--file", "-f", help="Read the feed from this file instead of --content"),
    content: str = typer.Option("", "--content", "-c", help="Inline feed (STIX bundle JSON or IOC list)"),
    url: str = typer.Option("", "--url", "-u", help="Fetch a STIX feed from this URL"),
) -> None:
    show_banner(primary=False)
    if file:
        try:
            content = file.read_text(encoding="utf-8")
        except OSError as exc:
            console.print(f"[bold #C4453B]Cannot read {file}: {exc}[/bold #C4453B]")
            raise typer.Exit(1)
    if not content.strip() and not url:
        console.print("[bold #C4453B]Provide --file/--content or --url[/bold #C4453B]")
        raise typer.Exit(1)
    try:
        result = api_client.intel_import(source, content=content, url=url)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Import failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    console.print(
        f"[#3FA796]{result['imported']} indicator(s) imported[/#3FA796] "
        f"[dim]as {result['source']}[/dim]"
    )
    if result.get("kinds"):
        kinds = ", ".join(f"{k}={v}" for k, v in sorted(result["kinds"].items()))
        console.print(f"[dim]kinds: {kinds}[/dim]")
    if result.get("matched_values"):
        console.print(
            f"[bold #D9A441]{result['matched_values']} value(s) already touch existing runs[/bold #D9A441]"
        )
        table = Table(title="Matching runs", border_style="dim")
        table.add_column("Value")
        table.add_column("Runs")
        for value, runs in result["matched_runs"].items():
            table.add_row(value, ", ".join(runs))
        console.print(table)
    else:
        console.print("[dim]No existing run touches any imported value.[/dim]")
