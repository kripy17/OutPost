"""`outpost analysis` — the analysis job workflow, terminal mirror of the
webapp's P1.2 analysis workspace.

P0.2 analysis-job API parity: launch / list / show / cancel, plus the
observations-shaped payload and the run's findings. `isolated-outpost` is a
reserved enum — the backend 501s it until an isolated execution environment
exists, so the launcher rejects it up front instead of pretending.

Job state is persisted (the analysis_jobs row); the terminal renders what
the backend returns — progress/status/error are never fabricated.
"""

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(help="Analysis jobs (P0.2): launch, track, and review detonations.")

_VALID_BACKENDS = ("static", "watched-host", "external-provider", "isolated-outpost")
_VALID_STATUS = ("queued", "running", "completed", "failed", "canceled")
_SEV_STYLE = {"malicious": "bold #C4453B", "suspicious": "bold #D9A441"}
_STATUS_STYLE = {
    "queued": "#D9A441",
    "running": "#D9A441",
    "completed": "#3FA796",
    "failed": "bold #C4453B",
    "canceled": "dim",
}


def _job_table(jobs: list[dict]) -> Table:
    table = Table(border_style="dim")
    table.add_column("Run id")
    table.add_column("Backend")
    table.add_column("Status")
    table.add_column("Progress")
    table.add_column("Sample")
    table.add_column("Error")
    for j in jobs:
        status = (j.get("status") or "-").upper()
        style = _STATUS_STYLE.get(j.get("status") or "", "")
        table.add_row(
            j.get("run_id") or "-",
            j.get("backend") or "-",
            f"[{style}]{status}[/]" if style else status,
            f"{j.get('progress') or 0}%",
            (j.get("sample_name") or j.get("sample_id") or "-")[:40],
            (j.get("error") or "-")[:50],
        )
    return table


@app.command("launch")
def analysis_launch(
    backend: str = typer.Argument(..., help="static | watched-host | external-provider (isolated-outpost is reserved — the backend 501s it)"),
    sample_id: str = typer.Option(None, "--sample-id", help="vault sample id (resolves to bytes for static analysis)"),
    sample_name: str = typer.Option(None, "--sample-name", help="artifact name fallback (no stored bytes → honest static note)"),
    platform: str = typer.Option(None, "--platform", help="windows | linux | macos — auto-detected when omitted"),
    timeout_seconds: int = typer.Option(None, "--timeout", help="bounded-run window for dynamic backends"),
) -> None:
    """Start an analysis job (POST /analysis) — persisted job state."""
    show_banner(primary=False)
    if backend not in _VALID_BACKENDS:
        console.print(f"[bold #C4453B]backend must be one of: {', '.join(_VALID_BACKENDS)}[/bold #C4453B]")
        raise typer.Exit(1)
    if backend == "isolated-outpost":
        console.print(
            "[bold #C4453B]isolated-outpost is a reserved enum — there is no isolated execution "
            "backend yet, and the API 501s it rather than pretending.[/bold #C4453B]"
        )
        raise typer.Exit(1)
    try:
        job = api_client.create_analysis_job(
            backend, sample_id=sample_id, sample_name=sample_name, platform=platform, timeout_seconds=timeout_seconds
        )
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Launch failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    status = job.get("status") or "-"
    style = _STATUS_STYLE.get(status, "")
    console.print(
        f"[#3FA796]Launched {job.get('run_id')} — {job.get('backend')} · "
        f"[{style}]{status}[/][/#3FA796]"
    )


@app.command("list")
def analysis_list(
    backend: str = typer.Option(None, "--backend", "-b", help="static | watched-host | external-provider | isolated-outpost"),
    status: str = typer.Option(None, "--status", "-s", help="queued | running | completed | failed | canceled"),
    limit: int = typer.Option(50, "--limit", "-l", min=1, max=200),
    offset: int = typer.Option(0, "--offset"),
) -> None:
    """List/filter persisted analysis jobs (GET /analysis)."""
    show_banner(primary=False)
    if backend is not None and backend not in _VALID_BACKENDS:
        console.print(f"[bold #C4453B]--backend must be one of: {', '.join(_VALID_BACKENDS)}[/bold #C4453B]")
        raise typer.Exit(1)
    if status is not None and status not in _VALID_STATUS:
        console.print(f"[bold #C4453B]--status must be one of: {', '.join(_VALID_STATUS)}[/bold #C4453B]")
        raise typer.Exit(1)
    try:
        data = api_client.list_analysis_jobs(backend=backend, status=status, limit=limit, offset=offset)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Analysis list failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    jobs = data.get("jobs") or data.get("analysis_jobs") or []
    if not jobs:
        console.print("[dim]No analysis jobs match — the archive is empty.[/dim]")
        return
    console.print(_job_table(jobs))


@app.command("show")
def analysis_show(
    run_id: str = typer.Argument(..., help="the analysis run id (doubles as the job id)"),
) -> None:
    """Show one persisted job (GET /analysis/{run_id}) — status, backend,
    progress, error, plus events / alerts / risk score when the backend
    assembles them."""
    show_banner(primary=False)
    try:
        job = api_client.get_analysis_job(run_id)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Analysis job failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    status = job.get("status") or "-"
    style = _STATUS_STYLE.get(status, "")
    console.print(
        f"[bold]{job.get('run_id')}[/bold] — {job.get('backend')} · "
        f"[{style}]{status}[/] · progress {job.get('progress') or 0}%"
    )
    if job.get("sample_id") or job.get("sample_name"):
        console.print(f"  sample: {job.get('sample_name') or job.get('sample_id')}")
    if job.get("started_at"):
        console.print(f"  started {job['started_at']}")
    if job.get("finished_at"):
        console.print(f"  finished {job['finished_at']}")
    if job.get("timeout_seconds"):
        console.print(f"  timeout: {job['timeout_seconds']}s")
    if job.get("error"):
        console.print(f"  [bold #C4453B]error: {job['error']}[/bold #C4453B]")
    if job.get("events") is not None:
        console.print(f"  events: {job['events']}")
    if job.get("alerts") is not None:
        console.print(f"  alerts: {job['alerts']}")
    if job.get("risk_score") is not None:
        console.print(f"  risk score: {job['risk_score']}")


@app.command("cancel")
def analysis_cancel(
    run_id: str = typer.Argument(..., help="the analysis run id"),
) -> None:
    """Cancel a queued/running job (POST /analysis/{run_id}/cancel) — the
    terminal state comes back from the backend, never fabricated."""
    show_banner(primary=False)
    try:
        job = api_client.cancel_analysis_job(run_id)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Cancel failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    status = job.get("status") or "-"
    style = _STATUS_STYLE.get(status, "")
    console.print(f"[#3FA796]Canceled {job.get('run_id')} — [{style}]{status}[/][/#3FA796]")


@app.command("observations")
def analysis_observations(
    run_id: str = typer.Argument(..., help="the analysis run id"),
) -> None:
    """The observations-shaped payload (GET /analysis/{run_id}/observations):
    static jobs return the stored analysis result; dynamic jobs the run's
    events. No observations table exists (P0 defers it)."""
    show_banner(primary=False)
    try:
        data = api_client.get_analysis_observations(run_id)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Observations failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    backend = data.get("backend") or "-"
    obs = data.get("observations") or []
    console.print(f"[bold]{run_id}[/bold] — {backend} · {len(obs)} observation(s)")
    if not obs:
        console.print("[dim]No observations — static jobs with no stored bytes return an honest note.[/dim]")
        return
    table = Table(border_style="dim")
    table.add_column("Kind")
    table.add_column("Data")
    for o in obs:
        kind = o.get("kind") or o.get("event_type") or "-"
        if kind == "note":
            data_cell = str(o.get("data") or "")
        elif "data" in o:
            data_cell = str(o.get("data"))[:100]
        else:
            # dynamic event row — the existing event evidence verbatim
            data_cell = (
                f"{o.get('process_name') or o.get('command_line') or '-'} "
                f"→ {o.get('dest_ip') or '-'}:{o.get('dest_port') or '-'}".strip()
            )[:100]
        table.add_row(kind, data_cell)
    console.print(table)


@app.command("findings")
def analysis_findings(
    run_id: str = typer.Argument(..., help="the analysis run id"),
) -> None:
    """Findings tied to the analysis run (GET /analysis/{run_id}/findings) —
    the existing alerts/run relationship, same assembly as /runs/{id}/alerts."""
    show_banner(primary=False)
    try:
        rows = api_client.get_analysis_findings(run_id)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Findings failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    if not rows:
        console.print("[dim]No findings attached to this run.[/dim]")
        return
    table = Table(title=f"{len(rows)} finding(s)", border_style="dim")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Status")
    table.add_column("Detail")
    for a in rows:
        sev = a.get("severity") or "suspicious"
        style = _SEV_STYLE.get(sev, "")
        table.add_row(
            str(a["id"]),
            f"[{style}]{sev}[/]" if style else sev,
            a.get("rule_id") or "-",
            (a.get("status") or "-").upper(),
            (a.get("details") or "-")[:70],
        )
    console.print(table)
