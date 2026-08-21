"""`outpost rules` — the rule surface, terminal-side.

- `outpost rules generate <run_id> --format suricata|sigma` — auto-generated
  detection rules from a run's findings (Task 27, docs/10 #8).
- `outpost rules knobs` — every tunable threshold with its default, current
  value, and tuned status — the terminal mirror of the Rules page tuning list.
- `outpost rules log-patterns` — the operator-editable anti-forensics pattern
  tables (log-service-stop / log-clearing) per platform — read-only mirror of
  the webapp editor, so the same rule surface is inspectable from a terminal.
- `outpost rules suppressions add|list|remove` — rule suppressions (global /
  run-scoped / value-scoped), the terminal mirror of the webapp's
  SuppressionPanel + Rules page, so a noisy rule can be silenced from the
  terminal without touching the webapp.
"""

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(
    help="Detection rule surface — generate run rules, inspect tuning knobs and pattern tables",
    add_completion=False,
)


@app.callback(invoke_without_command=True)
def _group(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        show_banner(primary=False)
        console.print(ctx.get_help())


@app.command("generate")
def generate(
    run_id: str = typer.Argument(..., help="Run id"),
    format: str = typer.Option("suricata", "--format", "-f", help="suricata or sigma"),
) -> None:
    """Auto-generated Suricata/Sigma rules from one run's findings."""
    show_banner(primary=False)

    if format not in ("suricata", "sigma"):
        console.print(f"[bold #C4453B]Unknown format: {format}[/bold #C4453B] (use suricata or sigma)")
        raise typer.Exit(2)

    try:
        text = api_client.get_rules(run_id, format)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    console.print(f"[dim]Auto-generated {format} rules for run {run_id[:12]} — paste into your rules file:[/dim]")
    console.print(text)


@app.command("knobs")
def knobs() -> None:
    """Every tunable threshold with default, current value, and tuned status."""
    show_banner(primary=False)
    try:
        data = api_client.get_tuning()
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    knobs_list = data.get("knobs") or []
    if not knobs_list:
        console.print("[dim]No tuning knobs exposed by this backend.[/dim]")
        return

    table = Table(title="Rule tuning knobs", border_style="dim")
    table.add_column("Knob", overflow="fold", min_width=24)
    table.add_column("Rule", overflow="fold")
    table.add_column("Type")
    table.add_column("Default", overflow="fold")
    table.add_column("Current", overflow="fold")
    table.add_column("Status")
    for k in knobs_list:
        status = "tuned" if k.get("tuned") else "default"
        status_cell = f"[#D9A441]{status}[/#D9A441]" if k.get("tuned") else "[dim]default[/dim]"
        current = k.get("current")
        default = k.get("default")
        current_cell = (
            f"[bold #E4E7EB]{current}[/bold #E4E7EB]"
            if k.get("tuned") and current != default
            else str(current)
        )
        table.add_row(
            k.get("param", ""),
            k.get("rule_id", ""),
            k.get("type", ""),
            str(default),
            current_cell,
            status_cell,
        )
    console.print(table)
    console.print(
        "[dim]Edits happen in the webapp Rules page (or the tuning API); this view is read-only.[/dim]"
    )


@app.command("log-patterns")
def log_patterns(
    kind: str = typer.Option("all", "--kind", "-k", help="service_stop | log_clear | all"),
    platform: str = typer.Option("all", "--platform", "-p", help="windows | linux | macos | all"),
) -> None:
    """The anti-forensics pattern tables (log-service-stop / log-clearing)."""
    show_banner(primary=False)
    try:
        data = api_client.get_log_patterns()
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    kinds = data.get("kinds") or {}
    valid_kinds = {"service_stop", "log_clear"}
    if kind != "all" and kind not in valid_kinds:
        console.print(f"[bold #C4453B]Unknown kind: {kind}[/bold #C4453B] (service_stop | log_clear | all)")
        raise typer.Exit(2)
    valid_platforms = {"windows", "linux", "macos"}
    if platform != "all" and platform not in valid_platforms:
        console.print(f"[bold #C4453B]Unknown platform: {platform}[/bold #C4453B] (windows | linux | macos | all)")
        raise typer.Exit(2)

    shown_kinds = sorted(valid_kinds) if kind == "all" else [kind]
    for k in shown_kinds:
        tables = kinds.get(k, {})
        console.print(f"\n[bold #D9A441]{k.upper()}[/bold #D9A441] — "
                      f"{'logging service stopped/disabled' if k == 'service_stop' else 'log stores purged'} signatures")
        any_rows = False
        for plat in sorted(tables):
            if platform != "all" and plat != platform:
                continue
            rows = tables.get(plat, [])
            if not rows:
                continue
            any_rows = True
            table = Table(title=plat, border_style="dim")
            table.add_column("Regex", overflow="fold")
            table.add_column("Label", overflow="fold")
            for r in rows:
                table.add_row(r.get("pattern", ""), r.get("label", ""))
            console.print(table)
        if not any_rows:
            console.print("[dim]  (no patterns for this kind/platform)[/dim]")
    console.print("[dim]Edits happen in the webapp Rules page (or the pattern API); this view is read-only.[/dim]")


# ── outpost rules suppressions add|list|remove ──────────────────────────────
suppressions_app = typer.Typer(
    help="Rule suppressions — stop a rule (or rule+scope) from firing",
    add_completion=False,
)
app.add_typer(suppressions_app, name="suppressions")


@suppressions_app.command("list")
def suppressions_list() -> None:
    """Every rule suppression (global + run/value scoped) — the webapp's
    SuppressionPanel + Rules-page mirror."""
    show_banner(primary=False)
    try:
        rows = api_client.get_suppressions()
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    if not rows:
        console.print("[dim]No rule suppressions — every rule fires normally.[/dim]")
        return
    table = Table(title="Rule suppressions", border_style="dim")
    table.add_column("ID")
    table.add_column("Rule")
    table.add_column("Scope")
    table.add_column("Reason")
    for s in rows:
        scope = "global"
        if s.get("run_id"):
            scope = f"run {s['run_id'][:12]}"
        elif s.get("value"):
            scope = f"value {s['value']}"
        table.add_row(str(s["id"]), s["rule_id"], scope, s.get("reason") or "-")
    console.print(table)


@suppressions_app.command("add")
def suppressions_add(
    rule_id: str = typer.Argument(..., help="rule id to suppress (e.g. beaconing)"),
    run_id: str | None = typer.Option(None, "--run-id", help="scope to one run (default: global)"),
    value: str | None = typer.Option(None, "--value", help="scope to a sample name / related IP value"),
    reason: str = typer.Option("", "--reason", "-r", help="why it's suppressed"),
) -> None:
    """Suppress a rule — global, run-scoped (--run-id), or value-scoped
    (--value), matching the webapp's SuppressionPanel + queue sweep."""
    show_banner(primary=False)
    try:
        row = api_client.add_suppression(rule_id, reason, run_id, value)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    scope = "global"
    if row.get("run_id"):
        scope = f"run {row['run_id'][:12]}"
    elif row.get("value"):
        scope = f"value {row['value']}"
    console.print(f"[#3FA796]Suppressed {row['rule_id']} ({scope})[/#3FA796]")


@suppressions_app.command("remove")
def suppressions_remove(
    suppression_id: int = typer.Argument(..., help="suppression id from `outpost rules suppressions list`"),
) -> None:
    """Remove a suppression, restoring the rule for future batches."""
    show_banner(primary=False)
    try:
        api_client.remove_suppression(suppression_id)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)
    console.print(f"[#3FA796]Removed suppression {suppression_id}[/#3FA796]")
