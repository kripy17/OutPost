"""`outpost coverage` — MITRE ATT&CK coverage matrix (webapp Coverage parity).

Prints every rule with its technique/tactic/weight/severity, grouped by
tactic, so a terminal user sees the same coverage story as the webapp.
`--export-navigator` writes the matrix as a MITRE ATT&CK Navigator v4.3 layer
JSON — importable into https://mitre-attack.github.io/attack-navigator/.
"""

import json
from pathlib import Path

import typer
from rich.table import Table
from typer.models import OptionInfo

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

SEVERITY_STYLE = {"malicious": "#C4453B", "suspicious": "#D9A441"}


def coverage(
    export_navigator: bool = typer.Option(False, "--export-navigator", help="Write the matrix as a MITRE Navigator layer JSON"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file for --export-navigator"),
) -> None:
    show_banner(primary=False)

    # Direct calls (e.g. unit tests) see the raw OptionInfo defaults — treat
    # them as "option not provided" so `coverage()` stays callable without typer.
    if isinstance(export_navigator, OptionInfo):
        export_navigator = False
    if isinstance(output, OptionInfo):
        output = None

    # Export mode needs no rule table — bail before touching /rules/meta.
    if export_navigator:
        _export_navigator(output)
        return

    try:
        rules = api_client.get_rules_meta()
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Coverage failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    if not rules:
        console.print("[dim]No rules registered.[/dim]")
        return

    # Group by tactic, preserving RULE_META's sorted rule order within each.
    by_tactic: dict[str, list[dict]] = {}
    for rule in rules:
        by_tactic.setdefault(rule["tactic"], []).append(rule)

    for tactic, rows in by_tactic.items():
        table = Table(title=tactic, border_style="dim")
        table.add_column("Technique")
        table.add_column("Rule")
        table.add_column("Weight", justify="right")
        table.add_column("Severity")
        for r in sorted(rows, key=lambda r: r["weight"], reverse=True):
            sev = r.get("severity") or "suspicious"
            table.add_row(
                r["technique"],
                r["rule_name"],
                f"+{r['weight']}",
                f"[{SEVERITY_STYLE.get(sev, '#3FA796')}]● {sev}[/]",
            )
        console.print(table)
        console.print("")

    covered = len(by_tactic)
    console.print(
        f"[dim]{len(rules)} rules across {covered} tactics — "
        f"re-run with --export-navigator to download the matrix as a MITRE Navigator layer.[/dim]"
    )


def _export_navigator(output: Path | None) -> None:
    """Write the Navigator layer JSON; prints the confirm line either way."""
    try:
        layer = api_client.get_navigator_layer()
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Navigator export failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    dest = output or Path("outpost-navigator-layer.json")
    dest.write_text(json.dumps(layer, indent=2))
    techniques = len(layer["techniques"])
    console.print(
        f"[#3FA796]Exported MITRE Navigator layer ({techniques} technique cells) → {dest}[/#3FA796]"
    )
    console.print(
        "[dim]Open it in https://mitre-attack.github.io/attack-navigator/ → Upload a layer.[/dim]"
    )
