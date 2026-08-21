"""`outpost allowlist add|list|remove` — per-run IOC allowlist, the terminal
mirror of the webapp's run-detail AllowlistPanel + QuickAllowlist.

Allowlisted IOCs stop matching alerts from firing on a run's future batches
and auto-acknowledge already-open matches (the `acked` count in the add
response) — the same two-click quick-add an analyst gets from the run-detail
network table and process tree, reachable from the terminal.
"""

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(
    help="Per-run IOC allowlist — suppress matching alerts going forward",
    add_completion=False,
)

KINDS = ("ip", "file", "registry", "process", "hash")


@app.callback(invoke_without_command=True)
def _group(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        show_banner(primary=False)
        ctx.invoke(list_entries)


@app.command("add")
def add_entry(
    run_id: str = typer.Argument(..., help="run id to allowlist against"),
    kind: str = typer.Argument(..., help="ip | file | registry | process | hash"),
    value: str = typer.Argument(..., help="the IOC value (e.g. 203.0.113.88 or .bashrc)"),
    note: str = typer.Option("", "--note", "-n", help="why this is allowed (e.g. your own scanner)"),
) -> None:
    """Allowlist an IOC for a run — auto-acks already-open matching alerts."""
    show_banner(primary=False)
    if kind not in KINDS:
        console.print(f"[bold #C4453B]kind must be one of: {', '.join(KINDS)}[/bold #C4453B]")
        raise typer.Exit(1)
    try:
        entry = api_client.add_run_allowlist(run_id, kind, value, note)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Allowlist failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    line = f"[#3FA796]Allowlisted {entry['kind']} {entry['value']} for run {run_id}[/#3FA796]"
    if entry.get("acked"):
        line += f" — {entry['acked']} matching alert(s) auto-acknowledged"
    console.print(line)


@app.command("list")
def list_entries(run_id: str = typer.Argument(..., help="run id to inspect")) -> None:
    """List the IOCs allowlisted for a run."""
    show_banner(primary=False)
    try:
        entries = api_client.get_run_allowlist(run_id)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Allowlist failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    if not entries:
        console.print(f"[dim]No allowlisted IOCs for run {run_id}.[/dim]")
        return
    table = Table(title=f"Allowlist · {run_id[:12]}", border_style="dim")
    table.add_column("ID")
    table.add_column("Kind")
    table.add_column("Value")
    table.add_column("Note")
    for e in entries:
        table.add_row(str(e["id"]), e["kind"], e["value"], e.get("note") or "-")
    console.print(table)


@app.command("remove")
def remove_entry(
    run_id: str = typer.Argument(..., help="run id the entry belongs to"),
    entry_id: int = typer.Argument(..., help="allowlist entry id (from `outpost allowlist list`)"),
) -> None:
    """Remove an allowlist entry. Already-acked alerts stay acked."""
    show_banner(primary=False)
    try:
        api_client.remove_run_allowlist(run_id, entry_id)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Allowlist failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(f"[#3FA796]Removed allowlist entry {entry_id} from run {run_id}[/#3FA796]")
