"""`outpost run <sample> [--timeout N]` — bounded analysis session.

Starts the collector in analysis mode, executes the sample, observes for the
timeout window, stops, marks the run complete, and prints the full report.
"""

import subprocess
import time

import typer

from ..lib import api_client
from ..monitoring import session as monitor
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console, render_report


def run(
    sample_path: str,
    timeout: int = typer.Option(240, "--timeout", "-t", min=5, help="Observation window in seconds"),
) -> None:
    show_banner(primary=True)
    platform = monitor.detect_platform()
    run_id = api_client.create_run(sample_name=sample_path, platform=platform, session_type="analysis")

    console.print(f"[#D9A441]Starting analysis session {run_id[:8]}...[/#D9A441]")
    collector_proc = monitor.start_local_collector(run_id, mode="analysis", timeout=timeout)

    console.print(f"Executing {sample_path}...")
    subprocess.Popen([sample_path])  # platform launches it in its own way

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
