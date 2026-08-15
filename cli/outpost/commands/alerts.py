"""`outpost alerts` — the analyst triage queue, terminal mirror of the
webapp's Open Findings sweep. Same status / provenance split, so host
findings and demo/seed noise can be separated from the terminal too."""

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

_VALID_STATUS = ("open", "acknowledged", "resolved", "all")
_VALID_PROVENANCE = (None, "real", "synthetic")
_SEV_STYLE = {"malicious": "bold #C4453B", "suspicious": "bold #D9A441"}


def alerts(
    status: str = typer.Option("open", "--status", "-s", help="open | acknowledged | resolved | all"),
    provenance: str | None = typer.Option(None, "--provenance", "-p", help="real | synthetic — split host telemetry from demo/seed noise"),
    q: str = typer.Option("", "--q", help="free-text across sample / rule / details"),
    limit: int = typer.Option(25, "--limit", "-l", min=1, max=200, help="rows per page"),
    offset: int = typer.Option(0, "--offset", help="page offset"),
) -> None:
    show_banner(primary=False)

    if status not in _VALID_STATUS:
        console.print("[bold #C4453B]--status must be open, acknowledged, resolved, or all[/bold #C4453B]")
        raise typer.Exit(1)
    if provenance not in _VALID_PROVENANCE:
        console.print("[bold #C4453B]--provenance must be real or synthetic[/bold #C4453B]")
        raise typer.Exit(1)

    try:
        data = api_client.get_alert_queue(status=status, provenance=provenance, q=q.strip(), limit=limit, offset=offset)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Queue failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    rows = data.get("alerts") or []
    if not rows:
        scope = f" {provenance}" if provenance else ""
        console.print(f"[dim]No {status}{scope} findings — the queue is clear.[/dim]")
        return

    title = f"{data['total']} {status} finding(s)"
    if provenance:
        title += f" · provenance={provenance}"
    title += f" — open {data['open']} · acked {data['acknowledged']} · resolved {data['resolved']}"

    table = Table(title=title, border_style="dim")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Sample")
    table.add_column("Status")
    table.add_column("Detail")
    for a in rows:
        sev = a.get("severity") or "suspicious"
        style = _SEV_STYLE.get(sev, "")
        table.add_row(
            str(a["id"]),
            f"[{style}]{sev}[/]" if style else sev,
            a.get("rule_id") or "-",
            a.get("sample_name") or "-",
            (a.get("status") or "-").upper(),
            (a.get("details") or "-")[:80],
        )
    console.print(table)
