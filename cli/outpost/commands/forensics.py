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
        try:
            import sys
            from pathlib import Path
            root = Path(__file__).resolve().parent.parent.parent.parent
            if str(root / "backend") not in sys.path:
                sys.path.insert(0, str(root / "backend"))
            from app.services import host_forensics
            console.print("[dim yellow]Notice: Backend offline — inspecting host system metrics directly from /proc (offline mode)[/dim yellow]\n")
            m = host_forensics.get_current_system_metrics()
            procs = host_forensics.get_live_processes()
            data = {
                "metrics": m,
                "process_count": len(procs),
                "socket_count": 0,
                "processes": procs,
            }
        except Exception:
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
        try:
            import sys
            from pathlib import Path
            root = Path(__file__).resolve().parent.parent.parent.parent
            if str(root / "backend") not in sys.path:
                sys.path.insert(0, str(root / "backend"))
            from app.services import host_forensics
            console.print("[dim yellow]Notice: Backend offline — building process causality tree directly from /proc (offline mode)[/dim yellow]\n")
            nodes = host_forensics.get_process_tree()
        except Exception:
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


@app.command("fds")
def fds(pid: int = typer.Argument(..., help="PID to inspect open file descriptors")) -> None:
    """Inspect open file descriptors, deleted inodes, and anonymous memfd handles for a PID."""
    show_banner(primary=False)
    try:
        p = api_client.get_forensics_process(pid)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed to inspect file descriptors: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    detailed_fds = p.get("detailed_fds") or []
    console.print(
        f"[bold #3B82F6]Open File Descriptors & Memory Inodes[/bold #3B82F6] — "
        f"[bold]{p.get('name')}[/bold] (PID {pid}) · {len(detailed_fds)} total FDs"
    )

    if not detailed_fds:
        console.print("[dim]No open file descriptors captured or access denied.[/dim]")
        return

    table = Table(border_style="dim", title=f"File Descriptors (PID {pid})")
    table.add_column("FD", style="bold")
    table.add_column("Path / Target", style="cyan")
    table.add_column("Kind", style="magenta")
    table.add_column("Access / Status", style="bold")

    for f in detailed_fds[:50]:
        is_del = f.get("is_deleted")
        is_mem = f.get("is_memfd")
        status = "[bold red]DELETED[/bold red]" if is_del else ("[bold purple]MEMFD[/bold purple]" if is_mem else f.get("access", "READ"))
        table.add_row(
            str(f.get("fd")),
            f.get("path", "-")[:70],
            f.get("kind", "file").upper(),
            status,
        )
    console.print(table)


@app.command("devices")
def devices() -> None:
    """List active processes holding sensitive hardware devices (Camera, Microphone, GPU)."""
    show_banner(primary=False)
    try:
        data = api_client.get_forensics_snapshot()
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Device scan failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    procs = data.get("processes", [])
    active_dev_procs = []
    for p in procs[:40]:
        try:
            det = api_client.get_forensics_process(p["pid"])
            dev = det.get("device_access") or {}
            if dev.get("microphone") or dev.get("camera") or dev.get("screen_capture") or dev.get("gpu"):
                active_dev_procs.append((det, dev))
        except Exception:
            pass

    console.print(f"[bold #3B82F6]Active Hardware Device & Sensor Handles[/bold #3B82F6] — {len(active_dev_procs)} processes")
    if not active_dev_procs:
        console.print("[dim]No processes currently holding active microphone, camera, or GPU nodes.[/dim]")
        return

    table = Table(border_style="dim", title="Hardware Device Access Matrix")
    table.add_column("PID", style="bold")
    table.add_column("Process Name", style="bold cyan")
    table.add_column("User")
    table.add_column("Microphone", style="yellow")
    table.add_column("Camera", style="magenta")
    table.add_column("GPU", style="green")

    for proc, dev in active_dev_procs:
        table.add_row(
            str(proc.get("pid")),
            proc.get("name", "-"),
            str(proc.get("user", "-")),
            "[bold yellow]ACTIVE[/bold yellow]" if dev.get("microphone") else "[dim]No[/dim]",
            "[bold magenta]ACTIVE[/bold magenta]" if dev.get("camera") else "[dim]No[/dim]",
            f"[bold green]{dev.get('gpu_clients_count', 1)} LIVE[/bold green]" if dev.get("gpu") else "[dim]No[/dim]",
        )
    console.print(table)


@app.command("caps")
def caps(pid: int = typer.Argument(..., help="PID to inspect Linux capabilities")) -> None:
    """Decode Linux capability bits (CapEff) and privilege levels for a PID."""
    show_banner(primary=False)
    try:
        p = api_client.get_forensics_process(pid)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Capability inspection failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    sec = p.get("security") or {}
    caps_eff = sec.get("capabilities_effective") or []

    console.print(
        f"[bold #3B82F6]Linux Security Capabilities[/bold #3B82F6] — "
        f"[bold]{p.get('name')}[/bold] (PID {pid}) · Seccomp: [bold]{sec.get('seccomp', 'Unknown')}[/bold]"
    )

    if not caps_eff:
        console.print("[dim]Unprivileged process (zero elevated Linux capabilities granted).[/dim]")
        return

    table = Table(border_style="dim", title=f"Decoded Effective Capabilities (PID {pid})")
    table.add_column("Capability Name", style="bold cyan")
    table.add_column("Risk / Danger", style="bold")

    for c in caps_eff:
        danger_label = "[bold red]⚠️ ELEVATED/DANGEROUS[/bold red]" if c.get("is_dangerous") else "[green]Standard[/green]"
        table.add_row(c.get("name", ""), danger_label)
    console.print(table)


@app.command("io")
def io(pid: int = typer.Argument(..., help="PID to inspect disk I/O throughput")) -> None:
    """Inspect quantitative disk I/O throughput (read/write rates) for a PID."""
    show_banner(primary=False)
    try:
        p = api_client.get_forensics_process(pid)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]I/O inspection failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    disk = p.get("disk_io") or {}
    console.print(
        f"[bold #3B82F6]Disk I/O Velocity & Throughput[/bold #3B82F6] — "
        f"[bold]{p.get('name')}[/bold] (PID {pid})"
    )

    table = Table(border_style="dim", title=f"Disk I/O Metrics (PID {pid})")
    table.add_column("Read Volume", style="bold cyan")
    table.add_column("Write Volume", style="bold magenta")
    table.add_column("Syscall Read Count (syscr)", style="bold")
    table.add_column("Syscall Write Count (syscw)", style="bold")

    table.add_row(
        f"{disk.get('read_mb', 0):.2f} MB ({disk.get('read_bytes', 0):,} B)",
        f"{disk.get('write_mb', 0):.2f} MB ({disk.get('write_bytes', 0):,} B)",
        str(disk.get("syscr", 0)),
        str(disk.get("syscw", 0)),
    )
    console.print(table)


@app.command("probes")
def list_probes(
    host: str = typer.Option("local", "--host", "-h", help="Target host identifier"),
) -> None:
    """List available on-demand live host forensic artifact hunting probes."""
    show_banner(primary=False)
    try:
        probes = api_client.get_forensic_probes(host_id=host)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed to load forensic probes: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    table = Table(title=f"OutPost — Live Host Forensic Hunt Probes ({len(probes)})", border_style="dim")
    table.add_column("Probe ID", style="cyan bold", no_wrap=True)
    table.add_column("Probe Name", style="bold")
    table.add_column("Tactic", style="magenta")
    table.add_column("Technique", style="dim")
    table.add_column("Description")

    for p in probes:
        table.add_row(
            p["id"],
            p["name"],
            p.get("tactic", ""),
            p.get("technique", ""),
            p.get("description", ""),
        )

    console.print(table)
    console.print("\n[dim]Execute a forensic probe with:[/dim] [bold cyan]outpost forensics hunt <probe_id>[/bold cyan]")


@app.command("hunt")
def hunt(
    probe_id: str = typer.Argument(..., help="Forensic hunt probe ID (e.g. deleted_binaries, crontab_persistence)"),
    host: str = typer.Option("local", "--host", "-h", help="Target host identifier"),
) -> None:
    """Execute an on-demand live host forensic hunt probe."""
    show_banner(primary=False)
    console.print(f"[#D9A441]Executing forensic hunt probe '[bold]{probe_id}[/bold]' on host '{host}'...[/#D9A441]")

    try:
        res = api_client.run_forensic_probe(probe_id, host_id=host)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Forensic hunt failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    anomalies = res.get("anomalies_count", 0)
    anom_color = "red" if anomalies > 0 else "green"

    console.print(
        Panel(
            f"[bold]{res.get('name')}[/bold]\n"
            f"[dim]Tactic:[/dim] [magenta]{res.get('tactic')}[/magenta]  ·  "
            f"[dim]Technique:[/dim] [dim]{res.get('technique')}[/dim]\n"
            f"[dim]Total Scanned:[/dim] [bold]{res.get('total_items', 0)} items[/bold]  ·  "
            f"[dim]Anomalies / Hits:[/dim] [bold {anom_color}]{anomalies}[/bold {anom_color}]",
            title="[bold #3B82F6]Live Host Forensic Hunt Results[/bold #3B82F6]",
            border_style="#3B82F6",
        )
    )

    findings = res.get("findings", [])
    if findings:
        table = Table(title=f"Discovered Hunt Findings ({len(findings)})", border_style="dim")
        # Extract keys from first finding
        keys = [k for k in findings[0].keys() if k not in ("raw", "details")][:5]
        for k in keys:
            table.add_column(k.replace("_", " ").title(), style="bold")
        if any("details" in f for f in findings):
            table.add_column("Details", style="dim")

        for f in findings:
            row = [str(f.get(k, "")) for k in keys]
            if any("details" in f for f in findings):
                row.append(str(f.get("details", "")))
            table.add_row(*row)

        console.print(table)
    else:
        console.print("[green]✓ No forensic anomalies or IOCs discovered for this hunt.[/green]")

