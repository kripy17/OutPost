"""`outpost playbooks` — curated attack scenario detonations from the terminal.

- `outpost playbooks list` — list available attack scenarios with severity & ATT&CK techniques.
- `outpost playbooks run <id>` — detonate an attack scenario, ingest telemetry, and display the report.
"""

import typer
from rich.panel import Panel
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import SEVERITY_STYLE, console, render_report, risk_style

app = typer.Typer(
    help="Curated attack scenario playbooks — test detection logic and telemetry pipelines",
    add_completion=False,
)


@app.callback(invoke_without_command=True)
def _group(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        show_banner(primary=False)
        console.print(ctx.get_help())


@app.command("list")
def list_playbooks() -> None:
    """List all available attack scenario playbooks."""
    show_banner(primary=False)

    try:
        playbooks = api_client.get_playbooks()
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    table = Table(title="OutPost — Attack Scenario Playbooks", border_style="dim")
    table.add_column("ID", style="cyan bold", no_wrap=True)
    table.add_column("Scenario Name", style="bold")
    table.add_column("OS", style="magenta")
    table.add_column("Severity")
    table.add_column("Tactics", style="dim")
    table.add_column("Techniques", style="dim")

    for pb in playbooks:
        sev = pb.get("severity", "clean")
        style = SEVERITY_STYLE.get(sev, "white")
        table.add_row(
            pb["id"],
            pb["name"],
            {"windows": "win", "linux": "nix"}.get(pb.get("platform", ""), pb.get("platform", "")),
            f"[{style}]● {sev}[/{style}]",
            " → ".join(pb.get("tactics", [])),
            ", ".join(pb.get("techniques", [])),
        )

    console.print(table)
    console.print("\n[dim]Run any scenario with:[/dim] [bold cyan]outpost playbooks run <id>[/bold cyan]")


@app.command("run")
def run_playbook(
    playbook_id: str = typer.Argument(..., help="Playbook ID to execute (e.g. ransomware-stager)"),
) -> None:
    """Detonate an attack scenario playbook and view the synthesized detection report."""
    show_banner(primary=False)
    console.print(f"[#D9A441]Detonating playbook scenario '[bold]{playbook_id}[/bold]'...[/#D9A441]")

    try:
        res = api_client.detonate_playbook(playbook_id)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Detonation failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    run_id = res["run_id"]
    risk = res.get("risk_score", 0)
    r_style = risk_style(risk)

    console.print(
        Panel(
            f"[bold text-primary]{res.get('name')}[/bold text-primary]\n"
            f"[dim]Run ID:[/dim] [cyan]{run_id}[/cyan]  ·  "
            f"[dim]Platform:[/dim] [magenta]{res.get('platform')}[/magenta]  ·  "
            f"[dim]Telemetry Events:[/dim] [bold]{res.get('event_count')}[/bold]  ·  "
            f"[dim]Alerts Fired:[/dim] [bold #C4453B]{res.get('alert_count')}[/bold #C4453B]  ·  "
            f"[dim]Risk Score:[/dim] [{r_style}]{risk}/100[/{r_style}]",
            title="[bold green]Playbook Detonation Complete[/bold green]",
            border_style="#3FA796",
        )
    )

    try:
        report = api_client.get_run(run_id)
        render_report(report)
    except Exception:
        console.print(f"[dim]View full analysis details with:[/dim] [bold cyan]outpost show {run_id}[/bold cyan]")


@app.command("techniques")
def list_techniques(
    tactic: str | None = typer.Option(None, "--tactic", "-t", help="Filter by tactic (e.g. Persistence, Execution)"),
    query: str | None = typer.Option(None, "--query", "-q", help="Search keyword (e.g. cron, python, bash)"),
) -> None:
    """List available adversary technique unit tests from the catalog."""
    show_banner(primary=False)
    try:
        techniques = api_client.get_technique_tests(tactic=tactic, q=query)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed to load technique tests: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    table = Table(title=f"OutPost — Adversary Technique Unit Tests ({len(techniques)})", border_style="dim")
    table.add_column("Test ID", style="cyan bold", no_wrap=True)
    table.add_column("ATT&CK ID", style="bold")
    table.add_column("Tactic", style="magenta")
    table.add_column("Technique Name", style="bold")
    table.add_column("Platforms", style="dim")

    for t in techniques:
        table.add_row(
            t["id"],
            t.get("technique_id", ""),
            t.get("tactic", ""),
            t.get("name", ""),
            ", ".join(t.get("supported_platforms", [])),
        )

    console.print(table)
    console.print("\n[dim]Execute any technique test with:[/dim] [bold cyan]outpost playbooks test <test_id>[/bold cyan]")


@app.command("test")
def run_technique(
    test_id: str = typer.Argument(..., help="Technique test ID to execute (e.g. T1059.004-bash-pipe)"),
) -> None:
    """Execute an adversary technique unit test with verification, telemetry capture & cleanup."""
    show_banner(primary=False)
    console.print(f"[#D9A441]Executing adversary technique simulation '[bold]{test_id}[/bold]'...[/#D9A441]")

    try:
        res = api_client.run_technique_test(test_id)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Technique execution failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    status = res.get("status", "failed")
    status_color = "green" if status == "success" else "red"
    prereqs_color = "green" if res.get("prereqs_met") else "yellow"

    console.print(
        Panel(
            f"[bold]{res.get('technique_id')} · {res.get('name')}[/bold]\n"
            f"[dim]Tactic:[/dim] [magenta]{res.get('tactic')}[/magenta]  ·  "
            f"[dim]Status:[/dim] [bold {status_color}]{status.upper()} (exit {res.get('exit_code')})[/bold {status_color}]  ·  "
            f"[dim]Elapsed:[/dim] [bold]{res.get('elapsed_ms')}ms[/bold]\n"
            f"[dim]Prerequisites:[/dim] [{prereqs_color}]{'OK' if res.get('prereqs_met') else 'Failed'}[/{prereqs_color}]  ·  "
            f"[dim]Cleanup:[/dim] [green]{res.get('cleanup_status')}[/green]  ·  "
            f"[dim]Events:[/dim] [bold]{res.get('events_count')}[/bold]  ·  "
            f"[dim]Alerts:[/dim] [bold #C4453B]{res.get('alerts_count')}[/bold #C4453B]",
            title=f"[bold {status_color}]Adversary Technique Test Result[/bold {status_color}]",
            border_style="#3FA796",
        )
    )

    if res.get("stdout"):
        console.print("\n[dim]Command Output (stdout):[/dim]")
        console.print(f"[dim white]{res['stdout']}[/dim white]")
    if res.get("stderr"):
        console.print("\n[dim #C4453B]Command Error (stderr):[/dim #C4453B]")
        console.print(f"[#C4453B]{res['stderr']}[/#C4453B]")
