"""`outpost notes add|list` — per-run analyst notes (docs/10 Tier 2 #7).

Free-text notes attached to a run: observations, hypotheses, or reminders
for a later report. `outpost notes add <run_id> "..."` to jot one down.
"""

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(
    help="Per-run analyst notes — observations, hypotheses, reminders",
    add_completion=False,
)


@app.callback(invoke_without_command=True)
def _group(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        show_banner(primary=False)
        console.print('[dim]Usage: outpost notes add <run_id> "..." | outpost notes list <run_id>[/dim]')


@app.command("add")
def add(
    run_id: str = typer.Argument(..., help="Run to attach the note to"),
    note: str = typer.Argument(..., help="Free-text note (quote it)"),
) -> None:
    show_banner(primary=False)
    try:
        entry = api_client.notes_add(run_id, note)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(
        f"[#3FA796]Note added to {entry['run_id']} at "
        f"{entry['created_at'][:19].replace('T', ' ')} UTC[/#3FA796]"
    )


@app.command("list")
def list_notes(run_id: str = typer.Argument(..., help="Run whose notes to show")) -> None:
    show_banner(primary=False)
    try:
        notes = api_client.notes_list(run_id)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    if not notes:
        console.print(f"[dim]No notes for {run_id}.[/dim]")
        return
    table = Table(title=f"Notes — {run_id}", border_style="dim")
    table.add_column("When")
    table.add_column("Note")
    for n in notes:
        table.add_row(n["created_at"][:19].replace("T", " "), n["note"])
    console.print(table)
