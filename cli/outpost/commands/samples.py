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


def _show_similar(sample_id: str, threshold: int = 20) -> None:
    try:
        data = api_client.get_similar_samples(sample_id, min_similarity=threshold)
    except Exception as exc:
        console.print(f"[bold red]Failed to fetch similar samples: {exc}[/bold red]")
        raise typer.Exit(1)

    matches = data.get("similar", [])
    console.print(f"[bold white]Target Sample:[/bold white] [cyan]{sample_id}[/cyan]")
    if data.get("target_imphash"):
        console.print(f"  [dim]Imphash:[/dim] [green]{data['target_imphash']}[/green]")
    if data.get("target_fuzzy_hash"):
        console.print(f"  [dim]CTPH / Fuzzy:[/dim] [yellow]{data['target_fuzzy_hash']}[/yellow]")
    console.print()

    if not matches:
        console.print(f"[dim]No related samples found in the vault matching >= {threshold}% similarity.[/dim]")
        return

    table = Table(title=f"Binary-Similar Samples ({len(matches)})", border_style="dim")
    table.add_column("Sample ID")
    table.add_column("Filename")
    table.add_column("Similarity", justify="right")
    table.add_column("Imphash Match", justify="center")
    table.add_column("SHA256")

    for m in matches:
        sim_val = m["similarity"]
        sim_color = "bold red" if sim_val >= 80 else "bold yellow" if sim_val >= 50 else "cyan"
        table.add_row(
            m["sample_id"][:12],
            m["original_name"],
            f"[{sim_color}]{sim_val}%[/{sim_color}]",
            "[bold green]YES[/bold green]" if m.get("imphash_match") else "[dim]no[/dim]",
            m["sha256"][:16] + "...",
        )
    console.print(table)


def samples(
    q: str = typer.Option("", "--q", "-q", help="Filter by name / hash / family"),
    similar: str = typer.Option("", "--similar", "-s", help="Query binary-similar samples in the vault for a given sample ID"),
    threshold: int = typer.Option(20, "--threshold", "-t", help="Similarity percentage threshold (0-100)"),
) -> None:
    show_banner(primary=False)

    if similar:
        _show_similar(similar, threshold)
        return

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
