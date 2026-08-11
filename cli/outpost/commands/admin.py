"""`outpost admin` — fleet/backend maintenance operations.

`backfill-channels` stamps `log_source` on legacy collector events without
a restart: events shipped before collectors tagged their channel read
NULL, leaving the Auditd/Sysmon views empty despite the telemetry being
there. The backend endpoint runs the same idempotent inference as the
startup migration (linux live-run events with a real host → auditd,
windows → sysmon; webapp-'local' events are never touched) and returns how
many events were newly tagged — 0 once the channel data is complete, so
the command doubles as a health check.
"""

import os

import typer
from rich.console import Console

from ..lib import api_client

app = typer.Typer(help="Fleet/backend maintenance (admin)", add_completion=False)
console = Console()


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
