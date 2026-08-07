"""`outpost rules <run_id> --format suricata|sigma` — Task 27 (docs/10 #8).

Prints auto-generated detection rules from a run's findings, ready to paste
into a Suricata/Sigma rules file.
"""

import typer

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console


def rules(
    run_id: str = typer.Argument(..., help="Run id"),
    format: str = typer.Option("suricata", "--format", "-f", help="suricata or sigma"),
) -> None:
    show_banner(primary=False)

    if format not in ("suricata", "sigma"):
        console.print(f"[bold #C4453B]Unknown format: {format}[/bold #C4453B] (use suricata or sigma)")
        raise typer.Exit(2)

    try:
        text = api_client.get_rules(run_id, format)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    console.print(f"[dim]Auto-generated {format} rules for run {run_id[:12]} — paste into your rules file:[/dim]")
    console.print(text)
