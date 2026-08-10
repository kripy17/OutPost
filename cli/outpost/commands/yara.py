"""`outpost yara` — the signature lab, terminal-side.

- `outpost yara list` — every persisted custom rule (name, family, strings).
- `outpost yara test --rule <text> | --file <path>` — compile a rule and scan
  it against the sample vault without persisting; shows which samples matched
  and which string atoms hit (the *why*, not just a boolean).

Mirror of the webapp's YARA lab on the Rules page — same endpoints, same
subset language (services/yara.parse_rule_text).
"""

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(
    help="YARA signature lab — list persisted rules, test a rule against the vault",
    add_completion=False,
)


@app.callback(invoke_without_command=True)
def _group(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        show_banner(primary=False)
        console.print(ctx.get_help())


@app.command("list")
def list_rules() -> None:
    """List persisted custom YARA rules."""
    show_banner(primary=False)
    data = api_client.yara_list()
    rules = data.get("rules", [])
    if not rules:
        console.print("[dim]No custom YARA rules yet — author one in the webapp lab or `outpost yara test`.[/dim]")
        return
    table = Table(title=f"{data.get('count', len(rules))} custom YARA rule(s)", box=None)
    table.add_column("Name", style="bold")
    table.add_column("Family", style="dim")
    table.add_column("Strings", style="#D9A441")
    table.add_column("Description", style="dim", overflow="fold", min_width=30)
    for r in rules:
        table.add_row(
            r.get("name") or "?",
            r.get("family") or "-",
            ", ".join(r.get("strings") or []) or "-",
            r.get("description") or "",
        )
    console.print(table)


@app.command("test")
def test_rule(
    rule: str = typer.Option("", "--rule", "-r", help="Rule source text (use --file for anything long)"),
    file: str = typer.Option("", "--file", "-f", help="Read the rule source from a file"),
    sample_ids: list[str] = typer.Option(None, "--sample", help="Restrict to these sample ids (repeatable)"),
) -> None:
    """Compile a rule and scan it against the vault (no persistence)."""
    show_banner(primary=False)
    if file:
        try:
            with open(file, "r", encoding="utf-8") as fh:
                rule = fh.read()
        except OSError as exc:
            console.print(f"[red]cannot read rule file:[/red] {exc}")
            raise typer.Exit(2)
    if not rule.strip():
        console.print("[red]rule source is empty[/red] — pass --rule or --file")
        raise typer.Exit(2)

    data = api_client.yara_test(rule, sample_ids=sample_ids or None)
    if not data.get("compiled"):
        console.print(f"[red]rule failed to compile:[/red] {data.get('error', 'unknown error')}")
        raise typer.Exit(1)

    console.print(
        f"[bold #3FA796]compiled[/bold #3FA796] [dim]rule `{data.get('rule_name', '?')}`[/dim] · "
        f"{data.get('total', 0)} vault sample(s) scanned, [bold]{data.get('matched', 0)}[/bold] matched"
    )
    samples = data.get("samples", [])
    if not samples:
        console.print("[dim]No matches — clean against the vault.[/dim]")
        return
    table = Table(box=None)
    table.add_column("Sample", style="bold")
    table.add_column("Platform", style="dim")
    table.add_column("Matched", style="#D9A441")
    table.add_column("Hits", style="dim")
    for s in samples:
        table.add_row(
            s.get("original_name") or s.get("sample_id") or "?",
            s.get("platform") or "-",
            "yes" if s.get("matched") else "no",
            ", ".join(s.get("hits") or []) or "-",
        )
    console.print(table)
