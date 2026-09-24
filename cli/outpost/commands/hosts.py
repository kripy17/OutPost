"""`outpost hosts` — Fleet host investigation, containment & timeline.

Terminal parity for:
- Fleet overview (`outpost hosts list` / `outpost hosts`):
  Lists all hosts, platform, online/silent status, agent version, events, alerts, containment state.
- Host containment:
  - `outpost hosts isolate <host_id>`
  - `outpost hosts unisolate <host_id>`
  - `outpost hosts containment <host_id>`
- Live forensic triage:
  - `outpost hosts triage <host_id>`
- Host aggregate timeline:
  - `outpost hosts timeline <host_id>`
"""

from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table

from ..lib import api_client, offline_store
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(help="Fleet host investigation, containment, and aggregate timeline.", add_completion=False)


def _render_hosts_table(hosts: list[dict], source: str = "live") -> None:
    if not hosts:
        console.print("[dim]No hosts registered in the fleet yet.[/dim]")
        return

    table = Table(title=f"Fleet Hosts ({len(hosts)})", border_style="dim")
    table.add_column("Host ID", style="bold cyan", no_wrap=True)
    table.add_column("Platform", style="white")
    table.add_column("Status", style="bold")
    table.add_column("Events", justify="right")
    table.add_column("Alerts", justify="right")
    table.add_column("Containment", style="bold", no_wrap=True)
    table.add_column("Last Seen", style="dim")

    for h in hosts:
        is_isolated = h.get("isolated", False)
        cont_str = "[bold red]ISOLATED[/bold red]" if is_isolated else "[green]NORMAL[/green]"

        status_str = (
            "[red]SILENT[/red]"
            if h.get("silent")
            else "[green]ONLINE[/green]"
            if h.get("online")
            else "[dim]OFFLINE[/dim]"
        )

        last_seen = (h.get("last_seen") or h.get("last_heartbeat") or "-")[:19].replace("T", " ")
        table.add_row(
            h.get("host_id", "-"),
            str(h.get("platform") or "unknown"),
            status_str,
            str(h.get("event_count", 0)),
            str(h.get("alert_count", 0)),
            cont_str,
            last_seen,
        )

    console.print(table)


@app.callback(invoke_without_command=True)
def hosts_main(ctx: typer.Context) -> None:
    """Fleet host investigation and management."""
    if ctx.invoked_subcommand is None:
        list_hosts()


@app.command("list")
def list_hosts(
    identity: str = typer.Option("", "--identity", "-i", help="Narrow to collector | webapp | silent"),
) -> None:
    """List all monitored fleet hosts with telemetry counts and isolation status."""
    show_banner(primary=False)
    hosts = None
    source = "live"

    try:
        data = api_client.get_agents(identity=identity)
        hosts = data.get("agents", [])
    except Exception:
        # Fall back to SQLite
        offline_hosts = offline_store.get_offline_hosts()
        if offline_hosts is not None:
            hosts = offline_hosts
            source = "offline"

    if hosts is None:
        console.print("[bold #C4453B]Could not query fleet hosts (backend offline and database unreachable).[/bold #C4453B]")
        raise typer.Exit(1)

    if source == "offline":
        console.print("[dim yellow]Notice: Backend unreachable. Querying hosts directly from local SQLite database.[/dim yellow]\n")

    _render_hosts_table(hosts, source=source)


@app.command("isolate")
def isolate_host(
    host_id: str = typer.Argument(..., help="Host ID to isolate from the network"),
    reason: str = typer.Option("Operator containment request via CLI", "--reason", "-r", help="Reason for isolation"),
) -> None:
    """Enforce active host isolation (quarantine) to stop lateral movement."""
    show_banner(primary=False)
    try:
        api_client.isolate_host(host_id, isolated=True, reason=reason)
        console.print(f"[bold red]Host '{host_id}' is now ISOLATED (quarantined).[/bold red]\nReason: {reason}")
    except Exception as exc:
        console.print(f"[bold #C4453B]Failed to isolate host '{host_id}': {exc}[/bold #C4453B]")
        raise typer.Exit(1)


@app.command("unisolate")
def unisolate_host(
    host_id: str = typer.Argument(..., help="Host ID to restore network access for"),
) -> None:
    """Lift active host containment and restore normal network operations."""
    show_banner(primary=False)
    try:
        api_client.isolate_host(host_id, isolated=False)
        console.print(f"[bold green]Host '{host_id}' network isolation has been lifted.[/bold green]")
    except Exception as exc:
        console.print(f"[bold #C4453B]Failed to un-isolate host '{host_id}': {exc}[/bold #C4453B]")
        raise typer.Exit(1)


@app.command("containment")
def containment_status(
    host_id: str = typer.Argument(..., help="Host ID to inspect"),
) -> None:
    """View active network isolation status and pending remediation actions for a host."""
    show_banner(primary=False)
    try:
        data = api_client.get_host_containment(host_id)
    except Exception as exc:
        console.print(f"[bold #C4453B]Failed to fetch containment status: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    iso = data.get("isolated", False)
    iso_badge = "[bold red]ISOLATED (QUARANTINED)[/bold red]" if iso else "[bold green]NORMAL (ONLINE)[/bold green]"
    console.print(Panel(
        f"Host ID: [bold cyan]{host_id}[/bold cyan]\n"
        f"Status: {iso_badge}\n"
        f"Isolated At: {data.get('isolated_at') or 'N/A'}\n"
        f"Isolated By: {data.get('isolated_by') or 'N/A'}\n"
        f"Reason: {data.get('reason') or 'N/A'}",
        title="[bold white]Endpoint Containment Status[/bold white]",
        border_style="red" if iso else "green",
    ))

    pending = data.get("pending_actions", [])
    if pending:
        table = Table(title=f"Pending Remediation Actions ({len(pending)})", border_style="dim")
        table.add_column("Action", style="bold yellow")
        table.add_column("PID", style="cyan")
        table.add_column("Process Name")
        table.add_column("Requested At", style="dim")
        for p in pending:
            table.add_row(
                p.get("action", "-"),
                str(p.get("pid") or "-"),
                p.get("process_name") or "-",
                (p.get("requested_at") or "")[:19].replace("T", " "),
            )
        console.print(table)
    else:
        console.print("[dim]No pending remediation actions queued for this host.[/dim]")


@app.command("triage")
def triage_pack(
    host_id: str = typer.Argument(..., help="Host ID to triage"),
) -> None:
    """Trigger or inspect forensic triage probe artifacts for a host."""
    show_banner(primary=False)
    try:
        # Check available probes
        probes = api_client.list_forensic_probes(host_id)
        probe_list = probes.get("probes", [])
        if not probe_list:
            console.print(f"[dim]No triage probes available for host '{host_id}'.[/dim]")
            return

        table = Table(title=f"Forensic Triage Probes — Host '{host_id}'", border_style="dim")
        table.add_column("Probe ID", style="bold cyan")
        table.add_column("Name", style="bold")
        table.add_column("Category", style="yellow")
        table.add_column("Description", style="dim")

        for p in probe_list:
            table.add_row(
                p.get("id", "-"),
                p.get("name", "-"),
                p.get("category", "-"),
                (p.get("description") or "-")[:60],
            )
        console.print(table)
        console.print("[dim]Run `outpost forensics snapshot` or `outpost forensics network` to view live telemetry.[/dim]")
    except Exception as exc:
        console.print(f"[bold #C4453B]Failed to inspect triage probes for '{host_id}': {exc}[/bold #C4453B]")
        raise typer.Exit(1)


@app.command("timeline")
def timeline(
    host_id: str = typer.Argument(..., help="Host id (fleet identity from events/agent heartbeats)"),
    kind: str = typer.Option(None, "--kind", help="Restrict to event | finding | session | ioc | investigation"),
    event_type: str = typer.Option(None, "--event-type", help="Narrow event rows to this event type"),
    q: str = typer.Option(None, "--q", help="Match display fields of every kind"),
    limit: int = typer.Option(50, "--limit", min=1, max=200),
    offset: int = typer.Option(0, "--offset"),
) -> None:
    """The per-host aggregate chronological timeline."""
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
