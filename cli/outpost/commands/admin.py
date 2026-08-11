"""`outpost admin` — fleet/backend maintenance operations.

- `backfill-channels` — stamp `log_source` on legacy collector events
  without a restart: events shipped before collectors tagged their channel
  read NULL, leaving the Auditd/Sysmon views empty despite the telemetry
  being there. The backend endpoint runs the same idempotent inference as
  the startup migration (linux live-run events with a real host → auditd,
  windows → sysmon; webapp-'local' events are never touched) and returns
  how many events were newly tagged — 0 once complete, so the command
  doubles as a health check.
- `pg-migrate` — the Tier 4 Postgres migration path: exports the local
  SQLite database into Postgres-loadable artifacts (translated schema +
  per-table COPY data + a psql load script) via the shared migration core
  (backend/app/services/pg_migrate.py) and the scripts/ wrapper. No new
  dependencies: the exporter is stdlib-only; the target only needs `psql`.
"""

import os
import subprocess
import sys
from pathlib import Path

import typer
from rich.console import Console

from ..lib import api_client

app = typer.Typer(help="Fleet/backend maintenance (admin)", add_completion=False)
console = Console()


# The repo root — cli/outpost/commands/admin.py → OutPost/. Used to find the
# migration script that ships alongside the backend.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_MIGRATE_SCRIPT = _REPO_ROOT / "scripts" / "migrate_to_postgres.py"


@app.command()
def pg_migrate(
    sqlite: str = typer.Option(
        None,
        "--sqlite",
        help="SQLite database path (default: DATABASE_PATH env or backend/data/outpost.db)",
    ),
    out: str = typer.Option(
        "pg-migrate",
        "--out",
        help="Output directory for schema.sql + data/*.copy + load.sql (default: ./pg-migrate)",
    ),
    psql_url: str = typer.Option(
        os.getenv("DATABASE_URL", ""),
        "--psql-url",
        envvar="DATABASE_URL",
        help="Postgres URL — with --import runs the load, with --verify checks row counts",
    ),
    do_import: bool = typer.Option(False, "--import", help="Run the psql load against --psql-url after exporting"),
    do_verify: bool = typer.Option(False, "--verify", help="Compare SQLite vs Postgres row counts"),
):
    """Export the SQLite database for a Postgres migration (Tier 4).

    Writes schema.sql (translated DDL), data/<table>.copy (COPY-format
    rows), and load.sql into --out; with --psql-url plus --import/--verify
    it also loads into Postgres and proves the row counts match. The
    full runbook lives in docs/16-POSTGRES-MIGRATION.md.
    """
    if not _MIGRATE_SCRIPT.exists():
        console.print(
            f"[red]Migration script not found at {_MIGRATE_SCRIPT}[/red] — "
            "is this checkout the full repo?"
        )
        raise typer.Exit(2)
    if not sqlite:
        sqlite = os.getenv("DATABASE_PATH", "") or str(_REPO_ROOT / "backend" / "data" / "outpost.db")

    cmd = [sys.executable, str(_MIGRATE_SCRIPT), "--sqlite", sqlite, "--out", out]
    if psql_url:
        cmd += ["--psql-url", psql_url]
    if do_import:
        cmd.append("--import")
    if do_verify:
        cmd.append("--verify")

    console.print(f"[bold]OutPost → Postgres migration[/bold] (sqlite: {sqlite})")
    res = subprocess.run(cmd)
    raise typer.Exit(res.returncode)


@app.command()
def backfill_channels(
    backend_url: str = typer.Option(
        os.getenv("OUTPOST_API_URL", "http://localhost:8000"),
        envvar="OUTPOST_API_URL",
        help="Backend base URL",
    ),
    admin_password: str = typer.Option(
        None,
        "--admin-password",
        prompt=True,
        hide_input=True,
        envvar="OUTPOST_ADMIN_PASSWORD",
        help="Admin password (env OUTPOST_ADMIN_PASSWORD avoids the prompt)",
    ),
):
    """Stamp log_source on legacy collector events without a restart.

    Runs the same idempotent channel backfill the server applies at
    startup, but on demand — useful right after enabling the agent token
    or importing an old archive. Prints how many events were newly tagged;
    re-running with nothing left to stamp reports 0 (a healthy no-op).
    """
    base = backend_url.rstrip("/")
    old_base = api_client.BASE_URL
    api_client.BASE_URL = base
    try:
        result = api_client.backfill_channels(admin_password or "")
    except api_client.APIError as exc:
        console.print(f"[red]Backfill failed: {exc}[/red]")
        raise typer.Exit(2) from exc
    finally:
        api_client.BASE_URL = old_base

    updated = result.get("updated", 0)
    if updated:
        console.print(
            f"[bold #3FA796]✓[/bold #3FA796] Stamped [bold]{updated}[/bold] legacy event"
            f"{'s' if updated != 1 else ''} with their channel (auditd/sysmon) — "
            "the Auditd/Sysmon tabs and fleet channel mix now read the real telemetry."
        )
    else:
        console.print(
            "[#3FA796]✓ Channel data already complete — no legacy events to backfill "
            "(0 updated).[/#3FA796]"
        )
    return None
