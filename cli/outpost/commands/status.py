"""`outpost status` and `outpost doctor` — system health, connectivity, and diagnostics."""

import os
import platform
import shutil
import socket
import sqlite3
import sys
from pathlib import Path
from typing import Any

import requests
import typer
from rich.panel import Panel
from rich.table import Table

from ..lib import api_client, offline_store
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(help="System status, component health, and diagnostics", add_completion=False)


def _check_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ConnectionRefusedError):
        return False


def _check_web_online(port: int) -> bool:
    for url in [f"http://localhost:{port}", f"http://127.0.0.1:{port}", f"http://[::1]:{port}"]:
        try:
            resp = requests.get(url, timeout=1.0)
            if resp.ok or resp.status_code in (200, 304):
                return True
        except Exception:
            pass
    return False


def _get_db_stats() -> dict[str, Any]:
    db_path = offline_store.find_db_path()
    if not db_path or not db_path.exists():
        return {"exists": False, "path": "Not found"}

    stats: dict[str, Any] = {
        "exists": True,
        "path": str(db_path),
        "size_kb": round(db_path.stat().st_size / 1024, 1),
        "runs": 0,
        "alerts": 0,
        "samples": 0,
        "agents": 0,
    }

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = conn.cursor()
        for tbl, key in [("runs", "runs"), ("alerts", "alerts"), ("samples", "samples")]:
            try:
                cur.execute(f"SELECT COUNT(*) FROM {tbl}")
                stats[key] = cur.fetchone()[0]
            except Exception:
                pass
        try:
            cur.execute("SELECT COUNT(DISTINCT host_id) FROM agent_heartbeats")
            stats["agents"] = cur.fetchone()[0]
        except Exception:
            pass
        conn.close()
    except Exception:
        pass

    return stats


@app.callback(invoke_without_command=True)
def status(ctx: typer.Context) -> None:
    """Display real-time health for Backend API, Web Console, SQLite Database, and Agents."""
    if ctx.invoked_subcommand is not None:
        return

    show_banner(primary=False)

    api_url = api_client.get_base_url()
    api_online = False
    api_meta: dict[str, Any] = {}

    try:
        resp = requests.get(f"{api_url}/health", timeout=1.5)
        if resp.ok:
            api_online = True
            try:
                meta_resp = requests.get(f"{api_url}/meta", timeout=1.5)
                if meta_resp.ok:
                    api_meta = meta_resp.json()
            except Exception:
                pass
    except Exception:
        api_online = False

    # Check Web Console
    web_port = int(os.getenv("OUTPOST_FE_PORT", "5174"))
    web_online = _check_web_online(web_port)

    # Check Database
    db_stats = _get_db_stats()

    # Build Status Table
    table = Table(title="OutPost Platform Status", border_style="dim")
    table.add_column("Component", style="bold cyan")
    table.add_column("Target / Address", style="white")
    table.add_column("Status", justify="center")
    table.add_column("Details", style="dim")

    # API row
    api_status_badge = "[bold green]ONLINE ✓[/bold green]" if api_online else "[bold red]OFFLINE ✗[/bold red]"
    api_details = f"demo_mode={api_meta.get('demo_mode', False)}" if api_online else "Start with `./outpost.sh start`"
    table.add_row("Backend API", api_url, api_status_badge, api_details)

    # Web Console row
    web_url = f"http://localhost:{web_port}"
    web_status_badge = "[bold green]ONLINE ✓[/bold green]" if web_online else "[bold red]OFFLINE ✗[/bold red]"
    web_details = "Vite React SPA" if web_online else "Start with `./outpost.sh start`"
    table.add_row("Web Console", web_url, web_status_badge, web_details)

    # Database row
    if db_stats.get("exists"):
        db_badge = "[bold green]ONLINE ✓[/bold green]"
        db_det = f"{db_stats['size_kb']} KB · {db_stats['runs']} run(s), {db_stats['alerts']} alert(s), {db_stats['samples']} sample(s)"
    else:
        db_badge = "[bold yellow]INITIALIZING[/bold yellow]"
        db_det = "No local SQLite database found"
    table.add_row("SQLite Store", db_stats.get("path", "-"), db_badge, db_det)

    # Connected Agents
    agent_badge = "[bold green]REGISTERED ✓[/bold green]" if db_stats.get("agents", 0) > 0 else "[dim]NONE CONNECTED[/dim]"
    table.add_row("Host Agents", "Fleet Telemetry", agent_badge, f"{db_stats.get('agents', 0)} active host(s) recorded")

    console.print(table)

    # Overall recommendation footer
    if not api_online or not web_online:
        console.print(
            Panel(
                "[bold yellow]Services are currently offline.[/bold yellow]\n"
                "Launch the full OutPost stack in the background with:\n"
                "  [bold cyan]./outpost.sh start[/bold cyan]\n"
                "Or launch in interactive foreground mode with:\n"
                "  [bold cyan]./start.sh[/bold cyan]",
                title="[dim]Service Advisory[/dim]",
                border_style="yellow",
            )
        )
    else:
        console.print(f"[bold green]✔ All OutPost core services operational at {web_url}[/bold green]\n")


@app.command("doctor")
def doctor() -> None:
    """Run diagnostic checks on python runtime, virtualenv, dependencies, ports, and permissions."""
    show_banner(primary=False)

    checks: list[tuple[str, bool, str]] = []

    # 1. Python version
    py_ver = sys.version.split()[0]
    py_ok = sys.version_info >= (3, 10)
    checks.append(("Python >= 3.10", py_ok, f"v{py_ver}"))

    # 2. Virtual environment
    in_venv = sys.prefix != sys.base_prefix
    checks.append(("Virtualenv Active", in_venv, sys.prefix))

    # 3. Core dependencies
    deps = ["fastapi", "uvicorn", "typer", "rich", "pydantic", "requests"]
    missing_deps = []
    for d in deps:
        try:
            __import__(d)
        except ImportError:
            missing_deps.append(d)
    deps_ok = len(missing_deps) == 0
    checks.append(("Python Dependencies", deps_ok, "All installed" if deps_ok else f"Missing: {missing_deps}"))

    # 4. Node.js & npm
    node_path = shutil.which("node")
    npm_path = shutil.which("npm")
    node_ok = bool(node_path and npm_path)
    node_details = f"node: {node_path or 'missing'}, npm: {npm_path or 'missing'}"
    checks.append(("Node.js & npm", node_ok, node_details))

    # 5. Database readability
    db_stats = _get_db_stats()
    db_ok = db_stats.get("exists", False)
    checks.append(("SQLite Database", db_ok, f"Path: {db_stats.get('path', 'missing')}"))

    # 6. Data directories
    root = Path(__file__).resolve().parent.parent.parent.parent
    data_dir = root / "backend" / "data"
    dirs_ok = data_dir.exists() and (data_dir / "samples").exists()
    checks.append(("Data Storage Directories", dirs_ok, f"{data_dir}"))

    # 7. Network ports
    port_8001_in_use = _check_port_open("127.0.0.1", 8001, timeout=0.5)
    port_5174_in_use = _check_port_open("127.0.0.1", 5174, timeout=0.5)
    checks.append((":8001 API Port", True, "In use (Service active)" if port_8001_in_use else "Available (Ready)"))
    checks.append((":5174 Web Port", True, "In use (Service active)" if port_5174_in_use else "Available (Ready)"))

    table = Table(title="OutPost Diagnostic Doctor", border_style="dim")
    table.add_column("Diagnostic Check", style="bold cyan")
    table.add_column("Status", justify="center")
    table.add_column("Details", style="dim")

    all_passed = True
    for name, ok, det in checks:
        if not ok:
            all_passed = False
        badge = "[bold green]PASS ✓[/bold green]" if ok else "[bold red]FAIL ✗[/bold red]"
        table.add_row(name, badge, det)

    console.print(table)

    if all_passed:
        console.print("[bold green]✔ All environment diagnostic checks passed. System is fully operational.[/bold green]\n")
    else:
        console.print("[bold red]⚠ Some checks failed. Run `./setup.sh` to resolve missing dependencies.[/bold red]\n")
