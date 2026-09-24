"""`outpost run <sample> [--timeout N]` — bounded analysis session.

Starts the collector in analysis mode, executes the sample, observes for the
timeout window, stops, marks the run complete, and prints the full report.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

import typer

from ..lib import api_client
from ..monitoring import session as monitor
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console, render_report


def _detect_runner_cmd(sample_path: Path) -> list[str]:
    """Resolve the appropriate command runner for a local sample file."""
    name_lower = sample_path.name.lower()
    try:
        header = sample_path.read_bytes()[:128]
    except Exception:
        header = b""

    # Shebang check
    if header.startswith(b"#!"):
        first_line = header.split(b"\n", 1)[0].decode("latin1", errors="ignore")
        if "python" in first_line:
            return [sys.executable, str(sample_path)]
        if "bash" in first_line:
            return ["bash", str(sample_path)]
        if "sh" in first_line:
            return ["sh", str(sample_path)]
        if "node" in first_line:
            return ["node", str(sample_path)]

    if name_lower.endswith(".py"):
        return [sys.executable, str(sample_path)]
    if name_lower.endswith(".sh"):
        return ["bash", str(sample_path)]
    if name_lower.endswith(".js"):
        return ["node", str(sample_path)]
    return [str(sample_path)]


def run(
    sample_path: str,
    timeout: int = typer.Option(240, "--timeout", "-t", min=2, help="Observation window in seconds"),
    isolated: bool = typer.Option(False, "--isolated", "-i", help="Execute inside an isolated temporary dynamic sandbox with process tracking"),
    native: bool = typer.Option(False, "--native", help="Explicitly allow native execution on host machine"),
    force: bool = typer.Option(False, "--force", "-f", "-y", help="Bypass native execution confirmation prompt"),
) -> None:
    show_banner(primary=True)

    path_obj = Path(sample_path)
    if not path_obj.exists():
        console.print(f"[bold #C4453B]File not found: {sample_path}[/bold #C4453B]")
        raise typer.Exit(1)

    if isolated:
        console.print(f"[bold #3B82F6]Uploading '{path_obj.name}' to sandbox vault...[/bold #3B82F6]")
        try:
            sample_meta = api_client.upload_sample(path_obj.read_bytes(), path_obj.name)
            sample_id = sample_meta.get("sample_id")
            if not sample_id:
                raise ValueError("Upload failed — missing sample_id")

            console.print(f"[bold #3FA796]Detonating sample in isolated dynamic sandbox (timeout: {timeout}s)...[/bold #3FA796]")
            data = api_client.detonate_sample(sample_id, timeout=timeout)
            console.print(f"[bold #3FA796]✔ Dynamic Detonation Completed (Run ID: {data.get('run_id')})[/bold #3FA796]")
            console.print(f"  [dim]Exit Code:[/dim] {data.get('exit_code')}")
            console.print(f"  [dim]Events Captured:[/dim] {data.get('events_count', 0)}")
            console.print(f"  [dim]Alerts Triggered:[/dim] {data.get('alerts_count', 0)}")
            console.print(f"  [dim]Risk Score:[/dim] {data.get('risk_score', 0)}")

            terminal = data.get("terminal_output")
            if terminal:
                console.print("\n[bold white]Sandbox Execution Console:[/bold white]")
                console.print(terminal)

            run_id = data.get("run_id")
            if run_id:
                report = api_client.get_run(run_id)
                render_report(report, run_id=run_id)
            return
        except Exception as exc:
            console.print(f"[bold #C4453B]Isolated dynamic execution failed: {exc}[/bold #C4453B]")
            raise typer.Exit(1)

    # Native execution safety check
    if not native and not force:
        console.print("\n[bold #D9A441]⚠️  WARNING: You are about to execute this sample natively on your host workstation.[/bold #D9A441]")
        console.print("[dim]Use '--isolated' / '-i' to safely execute in an isolated dynamic sandbox.[/dim]\n")
        try:
            if sys.stdin.isatty():
                proceed = typer.confirm("Proceed with native host execution?", default=False)
                if not proceed:
                    console.print("[yellow]Execution cancelled. Use --isolated / -i to run safely.[/yellow]")
                    raise typer.Exit(0)
        except (KeyboardInterrupt, typer.Abort):
            raise typer.Exit(0)

    platform = monitor.detect_platform()
    run_id = api_client.create_run(sample_name=sample_path, platform=platform, session_type="analysis")

    console.print(f"[#D9A441]Starting analysis session {run_id[:8]}...[/#D9A441]")
    collector_proc = monitor.start_local_collector(run_id, mode="analysis", timeout=timeout)

    exec_cmd = _detect_runner_cmd(path_obj)
    console.print(f"Executing {' '.join(exec_cmd)}...")
    subprocess.Popen(exec_cmd)

    with console.status(f"Observing for {timeout}s — Ctrl+C to stop early..."):
        try:
            deadline = time.time() + timeout
            while time.time() < deadline:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass

    monitor.stop_local_collector(collector_proc)
    api_client.complete_run(run_id)

    report = api_client.get_run(run_id)
    render_report(report, run_id=run_id)


