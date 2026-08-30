"""`outpost forensics` — Deep Host Forensics, process causality, network matrix & differential analysis.

Provides full terminal parity for OutPost's deep forensic inspection engine:
- snapshot: Live host metrics, process counts, open sockets
- process: Deep inspection of a process PID (lineage, sockets, files, environment)
- tree: Hierarchical process causality tree
- network: Categorized network socket matrix (public, loopback, outbound)
- explanations: Behavioral heuristic explanations and finding cards
- baseline: Capture a fresh baseline for differential execution comparison
- diff: Compute differential delta (+/-) against captured baseline
- freeze: Send SIGSTOP to freeze a process
- thaw: Send SIGCONT to thaw a frozen process
- terminate: Send SIGTERM to gracefully terminate a process
"""

import typer
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(help="Deep Host Forensics — process causality, network matrix, differential deltas & controls.")


@app.command("snapshot")
def snapshot() -> None:
    """Live host system metrics, active process count, and socket status."""
    show_banner(primary=False)
    try:
        data = api_client.get_forensics_snapshot()
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Forensic snapshot failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    m = data.get("metrics", {})
    console.print(
        f"[bold #3B82F6]Host Telemetry Snapshot[/bold #3B82F6] — [dim]{m.get('platform', 'unknown').upper()}[/dim] · "
        f"[dim]{m.get('timestamp', '')[:19].replace('T', ' ')} UTC[/dim]"
    )

    metrics_table = Table(border_style="dim", title="Kernel & Resource Metrics")
    metrics_table.add_column("CPU Utilization", style="bold cyan")
    metrics_table.add_column("Memory Used / Total", style="bold magenta")
    metrics_table.add_column("Memory %", style="bold")
    metrics_table.add_column("Live Processes", style="bold green")
    metrics_table.add_column("Open Sockets", style="bold yellow")

    metrics_table.add_row(
        f"{m.get('cpu_percent', 0):.1f}%",
        f"{m.get('memory_used_mb', 0):.1f} MB / {m.get('memory_total_mb', 0):.1f} MB",
        f"{m.get('memory_percent', 0):.1f}%",
        str(data.get("process_count", 0)),
        str(data.get("socket_count", 0)),
    )
    console.print(metrics_table)

    # Top processes table
    procs = data.get("processes", [])[:15]
    if procs:
        proc_table = Table(border_style="dim", title="Top Active Processes (first 15)")
        proc_table.add_column("PID", style="bold")
        proc_table.add_column("Name", style="bold cyan")
        proc_table.add_column("User")
        proc_table.add_column("CPU %")
        proc_table.add_column("Memory (MB)")
        proc_table.add_column("Command Line", style="dim")

        for p in procs:
            proc_table.add_row(
                str(p.get("pid")),
                p.get("name", "-"),
                str(p.get("user", "-")),
                f"{p.get('cpu_percent', 0):.1f}%",
                f"{p.get('memory_mb', 0):.1f}",
                (p.get("cmdline") or p.get("exe") or "-")[:50],
            )
        console.print(proc_table)


@app.command("process")
def process(
    pid: int = typer.Argument(..., help="Process PID to inspect"),
) -> None:
    """Deep forensic inspection of a process PID (lineage, sockets, open files, env)."""
    show_banner(primary=False)
    try:
        p = api_client.get_forensics_process(pid)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Process inspection failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    status_color = "green" if p.get("status") == "running" else "dim"
    console.print(
        f"[bold #3B82F6]Process Forensic Dossier[/bold #3B82F6] — "
        f"[bold]{p.get('name')}[/bold] (PID {p.get('pid')}, PPID {p.get('ppid')}) "
        f"[{status_color}]{p.get('status', '').upper()}[/{status_color}]"
    )

    info_table = Table(show_header=False, border_style="dim")
    info_table.add_column("Field", style="bold dim", width=18)
    info_table.add_column("Value")

    info_table.add_row("Executable", p.get("exe") or "-")
    info_table.add_row("Command Line", p.get("cmdline") or "-")
    info_table.add_row("User Context", str(p.get("user") or "-"))
    info_table.add_row("Working Dir", p.get("cwd") or "-")
    info_table.add_row("Started At", str(p.get("started_at") or "-"))
    info_table.add_row("CPU / Memory", f"{p.get('cpu_percent', 0):.1f}% CPU · {p.get('memory_mb', 0):.1f} MB RAM")
    info_table.add_row("Threads", str(p.get("threads", 1)))
    console.print(info_table)

    # Lineage
    lineage = p.get("lineage", [])
    if lineage:
        console.print("\n[bold]Execution Lineage:[/bold]")
        for l in lineage:
            rel = l.get("relation", "")
            marker = "▶" if rel == "self" else "├─"
            style = "bold #3B82F6" if rel == "self" else "dim"
            console.print(f"  [{style}]{marker} {l.get('name')} (PID {l.get('pid')}) — {rel}[/{style}]")

    # Sockets
    sockets = p.get("sockets", [])
    if sockets:
        console.print(f"\n[bold]Open Sockets ({len(sockets)}):[/bold]")
        sock_table = Table(border_style="dim")
        sock_table.add_column("Proto")
        sock_table.add_column("Local Binding")
        sock_table.add_column("Remote Destination")
        sock_table.add_column("State")
        for s in sockets:
            remote = f"{s.get('remote_ip')}:{s.get('remote_port')}" if s.get("remote_ip") else "-"
            sock_table.add_row(
                s.get("protocol", "TCP"),
                f"{s.get('local_ip')}:{s.get('local_port')}",
                remote,
                s.get("status", "-"),
            )
        console.print(sock_table)


@app.command("tree")
def tree() -> None:
    """Hierarchical process causality tree for the system."""
    show_banner(primary=False)
    try:
        nodes = api_client.get_forensics_tree()
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Process tree failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    console.print("[bold #3B82F6]System Process Causality Tree[/bold #3B82F6]\n")

    def _render_tree_node(node: dict, rich_node: Tree) -> None:
        children = node.get("children", [])
        for c in children:
            sub = rich_node.add(
                f"[bold]{c.get('name')}[/bold] [dim](PID {c.get('pid')})[/dim] "
                f"[dim]— {c.get('cmdline', '')[:45]}[/dim]"
            )
            _render_tree_node(c, sub)

    root = Tree("[bold cyan]Host Root (init/systemd)[/bold cyan]")
    for n in nodes:
        branch = root.add(
            f"[bold]{n.get('name')}[/bold] [dim](PID {n.get('pid')})[/dim] "
            f"[dim]— {n.get('cmdline', '')[:45]}[/dim]"
        )
        _render_tree_node(n, branch)

    console.print(root)


@app.command("network")
def network() -> None:
    """Categorized network socket matrix (public, loopback, outbound)."""
    show_banner(primary=False)
    try:
        matrix = api_client.get_forensics_network()
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Network matrix failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    summary = matrix.get("summary", {})
    console.print(
        f"[bold #3B82F6]Network Threat Matrix[/bold #3B82F6] — "
        f"[bold red]{summary.get('public_listeners_count', 0)} public listeners[/bold red] · "
        f"[bold cyan]{summary.get('loopback_listeners_count', 0)} loopback[/bold cyan] · "
        f"[bold yellow]{summary.get('outbound_count', 0)} outbound[/bold yellow]"
    )

    # Public listeners
    publics = matrix.get("public_listeners", [])
    if publics:
        t = Table(border_style="dim", title="Public Listening Ports")
        t.add_column("PID")
        t.add_column("Process", style="bold red")
        t.add_column("Proto")
        t.add_column("Binding")
        t.add_column("Service")
        for s in publics:
            t.add_row(
                str(s.get("pid") or "-"),
                s.get("process_name", "-"),
                s.get("protocol", "TCP"),
                f"{s.get('local_ip')}:{s.get('local_port')}",
                s.get("service_hint", "-"),
            )
        console.print(t)

    # Outbound connections
    outbounds = matrix.get("outbound_connections", [])
    if outbounds:
        t = Table(border_style="dim", title="Active Outbound Remote Connections")
        t.add_column("PID")
        t.add_column("Process", style="bold yellow")
        t.add_column("Proto")
        t.add_column("Remote IP:Port")
        t.add_column("Reputation")
        for s in outbounds:
            rep = s.get("reputation", "clean")
            rep_style = "bold red" if rep == "malicious" else "bold yellow" if rep == "suspicious" else "green"
            t.add_row(
                str(s.get("pid") or "-"),
                s.get("process_name", "-"),
                s.get("protocol", "TCP"),
                f"{s.get('remote_ip')}:{s.get('remote_port')}",
                f"[{rep_style}]{rep.upper()}[/{rep_style}]",
            )
        console.print(t)


@app.command("baseline")
def baseline() -> None:
    """Capture a new system baseline for differential execution analysis."""
    show_banner(primary=False)
    try:
        res = api_client.capture_forensics_baseline()
        console.print(f"[bold green]✓ Captured host baseline:[/bold green] {res.get('message', 'Baseline established')}")
        console.print(f"  Processes: [bold]{res.get('process_count', 0)}[/bold] · Sockets: [bold]{res.get('socket_count', 0)}[/bold]")
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Baseline capture failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)


@app.command("diff")
def diff() -> None:
    """Differential delta (+/-) between baseline and current host state."""
    show_banner(primary=False)
    try:
        data = api_client.get_forensics_diff()
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Differential computation failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    s = data.get("summary", {})
    console.print(
        f"[bold #3B82F6]Differential Baseline Delta[/bold #3B82F6] — "
        f"[green]+{s.get('new_processes_count', 0)} new procs[/green] · "
        f"[red]-{s.get('removed_processes_count', 0)} terminated[/red] · "
        f"[yellow]+{s.get('new_sockets_count', 0)} new sockets[/yellow]"
    )

    new_procs = data.get("new_processes", [])
    if new_procs:
        t = Table(border_style="dim", title="Newly Spawned Processes Since Baseline")
        t.add_column("PID", style="bold green")
        t.add_column("Name", style="bold")
        t.add_column("User")
        t.add_column("Command Line", style="dim")
        for p in new_procs:
            t.add_row(str(p.get("pid")), p.get("name", "-"), str(p.get("user", "-")), (p.get("cmdline") or "-")[:50])
        console.print(t)


@app.command("freeze")
def freeze(pid: int = typer.Argument(..., help="PID to freeze via SIGSTOP")) -> None:
    """Freeze a process execution via SIGSTOP signal."""
    show_banner(primary=False)
    try:
        res = api_client.control_forensics_process(pid, action="freeze")
        console.print(f"[bold cyan]✓ {res.get('message', f'PID {pid} frozen')}[/bold cyan]")
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Freeze failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)


@app.command("thaw")
def thaw(pid: int = typer.Argument(..., help="PID to thaw via SIGCONT")) -> None:
    """Resume a frozen process via SIGCONT signal."""
    show_banner(primary=False)
    try:
        res = api_client.control_forensics_process(pid, action="resume")
        console.print(f"[bold green]✓ {res.get('message', f'PID {pid} resumed')}[/bold green]")
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Thaw failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)


@app.command("terminate")
def terminate(pid: int = typer.Argument(..., help="PID to terminate via SIGTERM")) -> None:
    """Gracefully terminate a process via SIGTERM signal."""
    show_banner(primary=False)
    try:
        res = api_client.control_forensics_process(pid, action="terminate")
        console.print(f"[bold red]✓ {res.get('message', f'PID {pid} terminated')}[/bold red]")
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Terminate failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
