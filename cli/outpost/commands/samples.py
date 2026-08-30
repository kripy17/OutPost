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


def _show_static(sample_id: str) -> None:
    try:
        data = api_client.get_sample_static(sample_id)
    except Exception as exc:
        console.print(f"[bold red]Failed to fetch static analysis: {exc}[/bold red]")
        raise typer.Exit(1)

    if not data.get("available"):
        console.print(f"[yellow]Static analysis unavailable for sample {sample_id} (bytes not stored).[/yellow]")
        return

    console.print(f"[bold white]Static Analysis Dossier:[/bold white] [cyan]{sample_id}[/cyan]")
    console.print(f"  [dim]SHA256:[/dim] [white]{data.get('sha256')}[/white]")
    entropy = data.get("entropy", 0)
    ent_color = "bold red" if entropy > 7.1 else "bold yellow" if entropy > 5.5 else "green"
    console.print(f"  [dim]Entropy:[/dim] [{ent_color}]{entropy} / 8.0[/{ent_color}]" + (" [bold red](PACKED/ENCRYPTED)[/bold red]" if data.get("is_packed") else ""))

    if data.get("static_risk_score") is not None:
        r_score = data["static_risk_score"]
        r_color = "bold red" if r_score >= 70 else "bold yellow" if r_score >= 35 else "green"
        console.print(f"  [dim]Static Risk Score:[/dim] [{r_color}]{r_score}/100 ({data.get('static_severity', 'clean')})[/{r_color}]")

    factors = data.get("risk_factors") or []
    if factors:
        console.print("\n[bold yellow]Risk Factors:[/bold yellow]")
        for f in factors:
            console.print(f"  • [red]{f}[/red]")

    caps = data.get("capabilities") or []
    if caps:
        console.print("\n[bold cyan]Detected Capabilities:[/bold cyan]")
        for c in caps:
            console.print(f"  • [bold white]{c.get('category')}[/bold white] [dim]({c.get('confidence')} confidence)[/dim]: {', '.join(c.get('matched', []))}")

    iocs = data.get("iocs") or {}
    total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
    if total_iocs > 0:
        console.print(f"\n[bold green]Embedded Candidate IOCs ({total_iocs}):[/bold green]")
        for kind, vals in iocs.items():
            if vals:
                console.print(f"  [dim]{kind.upper()}:[/dim] {', '.join(vals[:10])}" + (f" (+{len(vals)-10} more)" if len(vals) > 10 else ""))

    strings = data.get("strings") or []
    console.print(f"\n[dim]Extracted printable strings: {len(strings)} (use webapp for full search explorer)[/dim]")


def _detonate_dynamic(sample_id: str, timeout: int = 15) -> None:
    console.print(f"[bold cyan]Detonating sample {sample_id} in isolated dynamic sandbox...[/bold cyan]")
    try:
        data = api_client.detonate_sample(sample_id, timeout=timeout)
    except Exception as exc:
        console.print(f"[bold red]Detonation failed: {exc}[/bold red]")
        raise typer.Exit(1)

    console.print(f"[bold green]✔ Detonation Completed (Run ID: {data.get('run_id')})[/bold green]")
    console.print(f"  [dim]Exit Code:[/dim] {data.get('exit_code')}")
    console.print(f"  [dim]Events Ingested:[/dim] {data.get('events_count', 0)}")
    console.print(f"  [dim]Alerts Triggered:[/dim] {data.get('alerts_count', 0)}")
    console.print(f"  [dim]Risk Score:[/dim] {data.get('risk_score', 0)}")

    terminal = data.get("terminal_output")
    if terminal:
        console.print("\n[bold white]Sandbox Execution Console Output:[/bold white]")
        console.print(terminal)


def samples(
    q: str = typer.Option("", "--q", "-q", help="Filter by name / hash / family"),
    similar: str = typer.Option("", "--similar", "-s", help="Query binary-similar samples in the vault for a given sample ID"),
    static_id: str = typer.Option("", "--static", help="Inspect full static analysis dossier for a sample ID"),
    detonate_id: str = typer.Option("", "--detonate", "-d", help="Detonate sample in isolated dynamic sandbox"),
    timeout: int = typer.Option(15, "--timeout", help="Detonation execution timeout in seconds"),
    threshold: int = typer.Option(20, "--threshold", "-t", help="Similarity percentage threshold (0-100)"),
) -> None:
    show_banner(primary=False)

    sim = similar if isinstance(similar, str) else ""
    stat = static_id if isinstance(static_id, str) else ""
    det = detonate_id if isinstance(detonate_id, str) else ""
    query = q if isinstance(q, str) else ""
    thresh = threshold if isinstance(threshold, int) else 20
    tout = timeout if isinstance(timeout, int) else 15

    if sim:
        _show_similar(sim, thresh)
        return

    if stat:
        _show_static(stat)
        return

    if det:
        _detonate_dynamic(det, timeout=tout)
        return

    data = api_client.list_samples(query.strip())
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
