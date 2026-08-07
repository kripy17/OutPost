"""`outpost samples` — the sample vault as a Rich table (webapp /samples parity).

Lists every uploaded binary with its OS sniff, family label, YARA hit count,
VirusTotal score, and detonation count — the terminal mirror of the vault
page. `--q` filters by name/hash/family substring.
"""

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

SEV_STYLE = {
    "windows": "bold #D9A441",
    "linux": "bold #3FA796",
    "macos": "bold #D9A441",
}


def samples(
    q: str = typer.Option("", "--q", "-q", help="Filter by name / hash / family"),
) -> None:
    show_banner(primary=False)
    data = api_client.list_samples(q.strip())
    rows = data.get("samples", [])

    if not rows:
        console.print("[dim]No samples in the vault yet — upload one from the webapp Monitor page.[/dim]")
        return

    table = Table(title=f"Sample Vault ({data['total']})", border_style="dim")
    table.add_column("Name")
    table.add_column("Platform")
    table.add_column("Family")
    table.add_column("YARA")
    table.add_column("VT")
    table.add_column("Runs", justify="right")

    for s in rows:
        plat = s.get("detected_platform") or "unknown"
        style = SEV_STYLE.get(plat, "white")
        table.add_row(
            s["original_name"],
            f"[{style}]{plat[:3]}[/{style}]",
            s.get("family") or "-",
            str(len(s.get("yara_rules") or [])),
            str(s.get("vt_detections")) if s.get("vt_detections") is not None else "-",
            str(s.get("runs_count") or 0),
        )
    console.print(table)
