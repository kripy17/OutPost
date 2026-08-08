"""`outpost agent` — one-command host-agent bootstrap.

The collectors (collectors/linux + collectors/windows) are the real telemetry
path: auditd/Sysmon events stream into a live session the webapp opened. This
command removes the manual parts:

  outpost agent run      — run the local collector in live mode right now
                           (it auto-claims the webapp's open live session).
  outpost agent install  — generate a persistent service config (systemd on
                           Linux, scheduled task on Windows) so host telemetry
                           streams continuously, plus the exact enable commands
                           the operator runs with their own privileges.
  outpost agent status   — is the service installed, and is the collector
                           process actually streaming right now?

`install` NEVER elevates itself (no sudo/schtasks admin call from the CLI) —
it writes the unit to the user's config dir and prints the exact command the
operator runs as admin. Honest bootstrap, no hidden privilege escalation.
"""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import typer
from rich.console import Console

from ..monitoring import session as monitor

app = typer.Typer(help="Host-agent bootstrap — run or install the OS collector", add_completion=False)
console = Console()

# Where generated service configs land (never /etc directly — the operator's
# own command links them there). Overridable for tests via OUTPOST_HOME.
def _config_dir() -> Path:
    base = os.environ.get("OUTPOST_HOME") or Path.home() / ".config"
    d = Path(base) / "outpost"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _backend_url() -> str:
    return os.environ.get("OUTPOST_API_URL", "http://localhost:8001")


def _python_exe() -> str:
    return sys.executable


def _collector_rel() -> str:
    """Repo-relative collector path (the unit runs it from the checkout)."""
    platform_name = monitor.detect_platform()
    return f"collectors/{platform_name}/collector_{platform_name}.py"


def _collector_abs() -> Path:
    return monitor.collector_script(monitor.detect_platform())


# ---------------------------------------------------------------------------
# outpost agent run
# ---------------------------------------------------------------------------


@app.command()
def run(
    backend_url: str = typer.Option(_backend_url, envvar="OUTPOST_API_URL", help="Backend base URL"),
):
    """Run the local collector in live mode now (claims the open live session)."""
    from ..lib import api_client
    from ..rendering.banners import show_banner

    show_banner(primary=False)
    platform_name = monitor.detect_platform()
    script = monitor.collector_script(platform_name)
    if not script.exists():
        console.print(f"[red]Collector not found: {script}[/red]")
        raise typer.Exit(2)
    console.print(f"[cyan]Starting {platform_name} collector (auditd/Sysmon → backend)…[/cyan]")
    console.print("[dim]It auto-claims the newest open live session. Open the Live Monitor in the webapp and click 'Start live monitoring' if nothing is streaming.[/dim]")
    cmd = [sys.executable, str(script), "--backend-url", backend_url, "--mode", "live"]
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        console.print("[dim]Collector stopped.[/dim]")


# ---------------------------------------------------------------------------
# outpost agent install
# ---------------------------------------------------------------------------

_SYSTEMD_UNIT = """\
[Unit]
Description=OutPost host collector ({platform})
After=network.target auditd.service

[Service]
Type=simple
ExecStart={python} {collector} --backend-url {backend_url} --mode live
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

_SCHTASKS_COMMAND = """\
schtasks /Create /TN "OutPostCollector" /SC ONSTART /RU SYSTEM /TR "\"{python}\" \"{collector}\" --backend-url {backend_url} --mode live"
"""


def _write_service_config(backend_url: str) -> tuple[Path, str]:
    """Generate the persistent service config; returns (path, enable_command).

    The enable command is what the operator runs as admin — the CLI never
    self-elevates. This is printed, not executed.
    """
    platform_name = monitor.detect_platform()
    cfg = _config_dir()
    if platform_name == "linux":
        unit = cfg / "outpost-collector.service"
        unit.write_text(
            _SYSTEMD_UNIT.format(platform=platform_name, python=_python_exe(), collector=_collector_abs(), backend_url=backend_url)
        )
        enable = (
            f"sudo cp {unit} /etc/systemd/system/ && "
            f"sudo systemctl daemon-reload && sudo systemctl enable --now outpost-collector"
        )
    else:  # windows
        unit = cfg / "outpost-collector.bat"
        cmd = (
            f'"{_python_exe()}" "{_collector_abs()}" --backend-url {backend_url} --mode live'
        )
        unit.write_text(f"@echo off\r\n{cmd}\r\n")
        enable = (
            f'schtasks /Create /TN "OutPostCollector" /SC ONSTART /RU SYSTEM /TR "{unit}"'
        )
    return unit, enable


@app.command()
def install(
    backend_url: str = typer.Option(_backend_url, envvar="OUTPOST_API_URL", help="Backend base URL"),
):
    """Generate a persistent service config (systemd / scheduled task)."""
    platform_name = monitor.detect_platform()
    script = _collector_abs()
    if not script.exists():
        console.print(f"[red]Collector not found: {script}[/red]")
        raise typer.Exit(2)
    unit, enable = _write_service_config(backend_url)
    console.print(f"[green]Wrote collector service config:[/green] {unit}")
    console.print(f"\n[bold]Platform:[/bold] {platform_name}")
    console.print("[bold]It streams:[/bold] auditd/Sysmon events → live session → webapp Live Monitor")
    console.print("\n[bold]Enable it (run with your own admin privileges):[/bold]")
    console.print(f"[cyan]{enable}[/cyan]")
    console.print("\n[dim]Or run once without installing: `outpost agent run`[/dim]")


# ---------------------------------------------------------------------------
# outpost agent status
# ---------------------------------------------------------------------------


def _is_collector_running() -> bool:
    """Is any collector process running right now? Cross-platform-ish: checks
    for our own collector script name in the process list via `pgrep` on
    POSIX, `tasklist` + findstr on Windows. Best-effort — returns False on
    any probe failure (honest "can't tell", not a crash)."""
    try:
        if os.name == "nt":
            out = subprocess.run(["tasklist", "/FO", "CSV"], capture_output=True, text=True, timeout=10).stdout
            return "python" in out.lower()  # coarse; scheduled task wraps python
        out = subprocess.run(["pgrep", "-f", "collector_"], capture_output=True, text=True, timeout=10).stdout
        return "collector_" in out
    except Exception:
        return False


@app.command()
def status():
    """Is the host agent installed, and is it streaming right now?"""
    platform_name = monitor.detect_platform()
    cfg = _config_dir()
    installed = (cfg / "outpost-collector.service").exists() or (cfg / "outpost-collector.bat").exists()
    running = _is_collector_running()

    console.print(f"[bold]Platform:[/bold] {platform_name}")
    if installed:
        console.print("[green]Service config:[/green] installed")
    else:
        console.print("[yellow]Service config:[/yellow] not installed — run `outpost agent install`")
    if running:
        console.print("[green]Collector process:[/green] running — telemetry is streaming")
    else:
        console.print("[yellow]Collector process:[/yellow] not running — run `outpost agent run`")
    return None
