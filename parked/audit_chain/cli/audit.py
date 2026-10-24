"""`outpost audit` — analyst audit trail.

Terminal parity for GET /audit:
- Who did what, when
- Filtering by action kind (--action alert.status, auth.login, etc.)
- Cryptographic chain verification (`outpost audit verify`)
- Cryptographic signed checkpoints (`outpost audit checkpoint`)
- Offline SQLite fallback when backend service is offline
- CSV and JSON export options for compliance reporting
"""

import csv
import io
import json
import sqlite3
from typing import Optional

import typer
from rich.table import Table

from ..lib import api_client, offline_store
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(help="Analyst audit log and compliance trail", add_completion=False)


@app.callback(invoke_without_command=True)
def audit_command(
    ctx: typer.Context,
    action: Optional[str] = typer.Option(None, "--action", "-a", help="Filter by action kind (e.g. alert.status, auth.login)"),
    limit: int = typer.Option(50, "--limit", "-n", min=1, max=1000, help="Maximum entries to display"),
    as_csv: bool = typer.Option(False, "--csv", help="Output entries formatted as CSV"),
    as_json: bool = typer.Option(False, "--json", help="Output raw entries as JSON"),
) -> None:
    """View analyst mutations: triage transitions, false-positive marks, containment, logins, rotations."""
    if ctx.invoked_subcommand is not None:
        return

    events = None
    source = "live"
    verification = None

    try:
        data = api_client.get_audit(limit=limit, action=action or "")
        events = data.get("events", [])
        try:
            verification = api_client.verify_audit()
        except Exception:
            verification = None
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

    if verification:
        if verification.get("valid"):
            count = verification.get("entries_verified", len(events))
            through = verification.get("verified_through", count)
            console.print(f"[bold green]✓ Audit Chain Intact[/bold green] · verified through entry #{through} ({count} records)\n")
        else:
            console.print(f"[bold red]⚠ AUDIT CHAIN BREAK DETECTED[/bold red] · {verification.get('error')}\n")

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


@app.command("verify")
def verify_command(
    as_json: bool = typer.Option(False, "--json", help="Output verification report as JSON"),
) -> None:
    """Verify cryptographic hash-chain integrity of the tamper-evident audit log."""
    data = None
    try:
        data = api_client.verify_audit()
    except Exception as exc:
        try:
            from ....core import config
            from ....models import audit as audit_model
            conn = sqlite3.connect(config.DATABASE_PATH)
            conn.row_factory = sqlite3.Row
            data = audit_model.verify_audit_chain(conn)
            conn.close()
        except Exception:
            console.print(f"[bold red]Failed to verify audit log:[/bold red] {exc}")
            raise typer.Exit(1)

    if as_json:
        console.print(json.dumps(dict(data), indent=2))
        return

    show_banner(primary=False)
    if data.get("valid"):
        count = data.get("entries_verified", 0)
        verified_through = data.get("verified_through", count)
        ts = (data.get("verified_at") or "")[:19].replace("T", " ")
        console.print(f"[bold green]✓ Audit Chain Intact[/bold green] — verified through entry #{verified_through} ({count} total records) at {ts} UTC")
    else:
        first_break = data.get("first_break") or {}
        err = data.get("error", "Hash mismatch or missing link")
        console.print("[bold red]✗ AUDIT CHAIN TAMPERED / BROKEN[/bold red]")
        console.print(f"  [red]Detail:[/red] {err}")
        if first_break:
            console.print(f"  [red]Break Location:[/red] entry #{first_break.get('id')} (row index {first_break.get('index')})")
            console.print(f"  [red]Expected Hash:[/red]  {first_break.get('expected_hash')}")
            console.print(f"  [red]Found Hash:[/red]     {first_break.get('found_hash')}")
        raise typer.Exit(2)


@app.command("checkpoint")
def checkpoint_command(
    as_json: bool = typer.Option(False, "--json", help="Output checkpoint payload as JSON"),
) -> None:
    """Create a signed cryptographic checkpoint over the audit chain head."""
    try:
        data = api_client.create_audit_checkpoint()
        ckpt = data.get("checkpoint", {})
    except Exception as e:
        console.print(f"[bold red]Failed to create checkpoint:[/bold red] {e}")
        raise typer.Exit(1)

    if as_json:
        console.print(json.dumps(ckpt, indent=2))
        return

    show_banner(primary=False)
    console.print(f"[bold green]✓ Cryptographic Checkpoint Signed[/bold green] (seq #{ckpt.get('checkpoint_seq')})")
    console.print(f"  [cyan]Timestamp:[/cyan]       {ckpt.get('created_at')}")
    console.print(f"  [cyan]Audit Head ID:[/cyan]   #{ckpt.get('last_audit_id')}")
    console.print(f"  [cyan]Head Hash:[/cyan]       {ckpt.get('last_entry_hash')}")
    console.print(f"  [cyan]Key Fingerprint:[/cyan] {ckpt.get('public_key_fingerprint')}")
    console.print(f"  [cyan]Signature:[/cyan]       {ckpt.get('signature')}")
    console.print("\n[dim]Export this checkpoint out-of-band to guarantee non-repudiation against raw disk modification.[/dim]")
