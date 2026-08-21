"""`outpost refresh <run_id> <ip>` — bypass the reputation cache TTL once.

The terminal mirror of the run detail's per-row force-refresh: drop that one
IP's enrichment cache row and re-query AbuseIPDB/VirusTotal with the current
keys, so a verdict can be re-verified on demand without re-enriching the
whole run.
"""

import typer

from ..lib import api_client
from ..rendering.terminal_views import console


def refresh(
    run_id: str = typer.Argument(None, help="Run whose IP intel to refresh"),
    ip: str = typer.Argument(None, help="Destination IP to force-refresh"),
    stale: bool = typer.Option(False, "--stale", help="Stale-only sweep: re-query just the cached verdicts past the TTL (oldest first, max 50) instead of one IP"),
) -> None:
    if stale:
        try:
            data = api_client.refresh_stale(50)
        except api_client.APIError as exc:
            console.print(f"[bold #C4453B]Refresh failed: {exc}[/bold #C4453B]")
            raise typer.Exit(1)
        console.print(f"[bold #3FA796]✓[/bold #3FA796] Refreshed [bold]{data['refreshed']}[/bold] stale verdict(s)")
        return
    if not run_id or not ip:
        console.print("[bold #C4453B]outpost refresh needs <run_id> <ip> or --stale[/bold #C4453B]")
        raise typer.Exit(1)
    try:
        data = api_client.refresh_ip(run_id, ip)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Refresh failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    rep = data.get("reputation") or "unknown"
    abuse = data.get("abuse_score")
    vt = data.get("vt_malicious_count")
    console.print(
        f"[bold #3FA796]✓[/bold #3FA796] Refreshed reputation for [bold]{ip}[/bold] "
        f"→ ● {rep} (abuse {abuse if abuse is not None else '-'}, "
        f"vt {vt if vt is not None else '-'})"
    )
