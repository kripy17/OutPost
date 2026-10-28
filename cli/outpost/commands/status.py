"""`outpost status`, `outpost doctor`, and `outpost diagnostics` — system health, connectivity, and diagnostics."""

import json
import os
import shutil
import sqlite3
import sys
from pathlib import Path
from typing import Any

import typer
from rich.panel import Panel
from rich.table import Table

from ..lib import api_client, offline_store
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(help="System status, component health, and diagnostics", add_completion=False)


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
def status(
    ctx: typer.Context,
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Display real-time health for Backend API, Web Console, SQLite Database, and Agents."""
    if ctx.invoked_subcommand is not None:
        return

    api_url = api_client.get_base_url()
    api_online = False
    api_meta: dict[str, Any] = {}

    try:
        api_meta = api_client.get_meta()
        api_online = True
    except Exception:
        api_online = api_client.is_online()

    # Check Web Console
    web_port = int(os.getenv("OUTPOST_FE_PORT", "5174"))
    web_online = api_client.check_web_online(web_port)

    # Check Database
    db_stats = _get_db_stats()

    # Dynamic Sandbox Environment
    sandbox_env: dict[str, Any] = {}
    if api_online:
        try:
            sandbox_env = api_client.get_sandbox_environment()
        except Exception:
            pass

    is_json = bool(as_json) and not isinstance(as_json, typer.models.OptionInfo)
    if is_json:
        payload = {
            "backend_api": {"url": api_url, "online": api_online, "meta": api_meta},
            "web_console": {"url": f"http://localhost:{web_port}", "online": web_online},
            "database": db_stats,
            "sandbox_environment": sandbox_env,
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    show_banner(primary=False)

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

    # Dynamic Sandbox row
    if sandbox_env:
        if sandbox_env.get("is_safe_vm"):
            sb_badge = "[bold green]LAB VM ACTIVE ✓[/bold green]"
            sb_det = f"Hypervisor: {sandbox_env.get('virt_type')} (full sample detonation enabled)"
        else:
            sb_badge = "[bold yellow]DEV-PROBE ONLY[/bold yellow]"
            sb_det = sandbox_env.get("status_message", "Sample analysis disabled; only built-in probes can run")
        table.add_row("Dynamic Sandbox", "Local Boundary", sb_badge, sb_det)

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
def doctor(
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Run diagnostic checks on python runtime, virtualenv, dependencies, ports, and permissions."""
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

    # 7. Network services
    port_8001_in_use = api_client.is_online()
    port_5174_in_use = api_client.check_web_online(5174)
    checks.append((":8001 API Port", True, "In use (Service active)" if port_8001_in_use else "Available (Ready)"))
    checks.append((":5174 Web Port", True, "In use (Service active)" if port_5174_in_use else "Available (Ready)"))

    is_json = bool(as_json) and not isinstance(as_json, typer.models.OptionInfo)
    if is_json:
        payload = [
            {"check": name, "passed": ok, "details": det}
            for name, ok, det in checks
        ]
        typer.echo(json.dumps(payload, indent=2))
        return

    show_banner(primary=False)
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


@app.command("diagnostics")
def diagnostics(
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Report internal platform metrics: ingest rate, queue depth, per-collector health, DB size, and streams."""
    try:
        data = api_client.get_diagnostics()
    except api_client.APIError as exc:
        console.print(f"[bold red]Diagnostics unavailable: {exc}[/bold red]")
        raise typer.Exit(1) from exc

    is_json = bool(as_json) and not isinstance(as_json, typer.models.OptionInfo)
    if is_json:
        typer.echo(json.dumps(data, indent=2))
        return

    show_banner(primary=False)
    console.print("[bold #3FA796]OutPost Platform Internal Observability[/bold #3FA796]\n")

    # Ingest & Pipeline
    ingest = data.get("ingest", {})
    ingest_table = Table(title="Telemetry Ingest & Detection Pipeline", border_style="dim")
    ingest_table.add_column("Metric", style="bold cyan")
    ingest_table.add_column("Value", style="white")
    ingest_table.add_row("Events Ingest Rate", f"{ingest.get('events_per_second', 0)} events/sec")
    ingest_table.add_row("Events (Last 1m / 1h)", f"{ingest.get('events_last_minute', 0)} / {ingest.get('events_last_hour', 0)}")
    ingest_table.add_row("Total Ingested Events", f"{ingest.get('total_events', 0):,}")
    ingest_table.add_row("Ingest Pipeline Mode", ingest.get("pipeline_mode", "in-process"))
    ingest_table.add_row("Queue Depth", str(ingest.get("queue_depth", 0)))
    ingest_table.add_row("Dropped Events", str(ingest.get("dropped_events_count", 0)))
    console.print(ingest_table)
    console.print()

    # Collectors Inventory
    collectors = data.get("collectors", {}).get("inventory", [])
    coll_table = Table(title="Endpoint Collectors Health & Specific States", border_style="dim")
    coll_table.add_column("Host ID / Name", style="bold cyan")
    coll_table.add_column("Platform / Ver", style="white")
    coll_table.add_column("Privilege", style="dim")
    coll_table.add_column("Status", justify="center")
    coll_table.add_column("Granular Diagnostic State", style="dim")

    for c in collectors:
        badge = "[bold green]HEALTHY[/bold green]" if c["health_badge"] == "healthy" else (
            "[bold yellow]DEGRADED[/bold yellow]" if c["health_badge"] == "degraded" else "[bold red]OFFLINE[/bold red]"
        )
        coll_table.add_row(
            f"{c['host_id']} ({c['hostname']})",
            f"{c['platform']} v{c['agent_version']}",
            f"{c['privilege_level']} ({c['enforcement_capabilities']})",
            badge,
            c["diagnostic_state"],
        )
    if not collectors:
        coll_table.add_row("-", "-", "-", "[dim]NONE[/dim]", "No endpoint collectors currently enrolled")
    console.print(coll_table)
    console.print()

    # Database & Integrity
    db = data.get("database", {})
    integ = data.get("evidence_integrity", {})
    db_table = Table(title="Storage Engine & Evidence Hash-Chain", border_style="dim")
    db_table.add_column("Component", style="bold cyan")
    db_table.add_column("Details", style="white")
    db_table.add_row("Database Engine", f"{db.get('engine', 'sqlite').upper()} ({db.get('size_mb', 0)} MB, journal: {db.get('journal_mode', 'wal')})")
    schema_ver = db.get("schema_version", {})
    db_table.add_row("Schema Version", f"v{schema_ver.get('current_version', 0)} (applied: {schema_ver.get('total_applied', 0)}/{schema_ver.get('total_available', 0)})")
    db_table.add_row("Audit Trail Chain", f"{integ.get('audit_chain_length', 0)} entries ({integ.get('status', 'verified')})")
    db_table.add_row("SSE Stream Subscribers", str(data.get("stream", {}).get("active_subscribers", 0)))
    console.print(db_table)
    console.print()


@app.command("bundle")
def bundle(
    output: Path = typer.Option(None, "--output", "-o", help="Destination path for support bundle zip"),
) -> None:
    """Download a sanitized diagnostics support bundle zip archive for offline troubleshooting."""
    try:
        saved_path = api_client.download_support_bundle(output)
        console.print(f"[bold #3FA796]✔ Exported support bundle archive → {saved_path}[/bold #3FA796]")
    except api_client.APIError as exc:
        console.print(f"[bold red]Support bundle export failed: {exc}[/bold red]")
        raise typer.Exit(1) from exc
