"""`outpost footprint <sample_id>` — passive digital footprint, terminal-side.

Renders the same surface as the webapp Footprint page: the sample's observed
seed IPs, the passive expansion (reverse-DNS resolutions, Certificate
Transparency certs, sibling IPs, RDAP org/ASN), and the runs that touched it.
Live lookups are the default; `--mock` forces the clearly-labeled synthetic
demo. Offline providers render an honest empty state, never fake data.

`outpost footprint export <sample_id> --format json|csv` writes the same
threat-intel handoff artifact the webapp's Export buttons download.
"""

from pathlib import Path

import typer
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

app = typer.Typer(
    help="Passive digital footprint for one uploaded sample (reverse-DNS, CT certs, RDAP/ASN)",
    add_completion=False,
)


@app.callback(invoke_without_command=True)
def _group(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        show_banner(primary=False)
        console.print(ctx.get_help())


@app.command("show")
def show(
    sample_id: str = typer.Argument(..., help="Sample id from the vault"),
    mock: bool = typer.Option(False, "--mock", help="Force the labeled synthetic demo layer"),
) -> None:
    """Show one sample's passive footprint."""
    show_banner(primary=False)
    try:
        data = api_client.footprint(sample_id, mock=mock)
    except Exception as exc:
        console.print(f"[red]footprint lookup failed:[/red] {exc}")
        raise typer.Exit(1)

    sample = data.get("sample") or {}
    console.print(
        f"[bold]{sample.get('name', sample_id)}[/bold] "
        f"[dim]#{sample.get('sample_id', '')} · {sample.get('platform') or '?'}[/dim]"
    )
    if sample.get("sha256"):
        console.print(f"[dim]sha256 {sample['sha256'][:32]}…[/dim]")

    passive = data.get("passive") or {}
    source = passive.get("source") or "unknown"
    source_label = {
        "live": "[bold #3FA796]live passive intel[/bold #3FA796]",
        "synthetic_demo": "[bold #D9A441]synthetic demo (--mock)[/bold #D9A441]",
        "not_configured": "[bold #C4453B]no provider data — offline or unknown[/bold #C4453B]",
    }.get(source, source)
    console.print(f"source: {source_label}")

    seed_ips = data.get("seed_ips") or []
    if seed_ips:
        table = Table(title="Seed IPs (observed in this sample's runs)", box=None)
        table.add_column("IP", style="bold")
        table.add_column("Hits", style="dim")
        table.add_column("First seen", style="dim")
        table.add_column("Last seen", style="dim")
        for s in seed_ips:
            table.add_row(
                s.get("ip") or "?",
                str(s.get("hits", "")),
                (s.get("first_seen") or "")[:19],
                (s.get("last_seen") or "")[:19],
            )
        console.print(table)

    resolutions = passive.get("resolutions") or []
    if resolutions:
        table = Table(title="Passive DNS resolutions", box=None)
        table.add_column("Domain", style="bold")
        table.add_column("IP", style="dim")
        table.add_column("First", style="dim")
        table.add_column("Last", style="dim")
        for r in resolutions[:30]:
            table.add_row(
                r.get("domain") or "?",
                r.get("ip") or "-",
                (r.get("first_seen") or "")[:10],
                (r.get("last_seen") or "")[:10],
            )
        console.print(table)

    certificates = passive.get("certificates") or []
    if certificates:
        table = Table(title="Certificate Transparency certificates", box=None)
        table.add_column("CN", style="bold")
        table.add_column("Issuer", style="dim", overflow="fold")
        table.add_column("Not before", style="dim")
        table.add_column("Not after", style="dim")
        for c in certificates[:25]:
            table.add_row(
                c.get("cn") or "?",
                c.get("issuer") or "-",
                (c.get("not_before") or "")[:10],
                (c.get("not_after") or "")[:10],
            )
        console.print(table)

    subdomains = passive.get("subdomains") or []
    if subdomains:
        table = Table(title="Subdomains (CT-log discovery)", box=None)
        table.add_column("Domain", style="bold")
        table.add_column("Apex", style="dim")
        table.add_column("IP", style="dim")
        table.add_column("First", style="dim")
        table.add_column("Last", style="dim")
        for d in subdomains[:40]:
            table.add_row(
                d.get("domain") or "?",
                d.get("apex") or "-",
                d.get("source_ip") or "-",
                (d.get("first_seen") or "")[:10],
                (d.get("last_seen") or "")[:10],
            )
        console.print(table)

    asn_rows = passive.get("asn") or []
    if asn_rows:
        table = Table(title="ASN ownership", box=None)
        table.add_column("ASN", style="bold")
        table.add_column("Org", style="dim")
        table.add_column("Country", style="dim")
        for a in asn_rows:
            table.add_row(
                str(a.get("asn") or "-"),
                a.get("org") or a.get("as_name") or "-",
                a.get("country") or "-",
            )
        console.print(table)

    runs = data.get("runs") or []
    if runs:
        table = Table(title="Runs touching this sample", box=None)
        table.add_column("Run", style="bold")
        table.add_column("Started", style="dim")
        table.add_column("Completed", style="dim")
        for r in runs:
            table.add_row(
                r.get("run_id") or "?",
                (r.get("started_at") or "")[:19],
                (r.get("completed_at") or "")[:19] or "-",
            )
        console.print(table)

    if not seed_ips and not resolutions and not certificates and not runs:
        console.print("[dim]No footprint data for this sample yet — run it through a session first.[/dim]")


@app.command("export")
def export(
    sample_id: str = typer.Argument(..., help="Sample id from the vault"),
    format: str = typer.Option("json", "--format", help="json (structured) or csv (flat IOC sheet)"),
    mock: bool = typer.Option(False, "--mock", help="Export the labeled synthetic demo layer instead of live lookups"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Write the footprint's threat-intel handoff artifact to a file.

    Mirrors the webapp's Export JSON / Export CSV buttons: JSON keeps the
    full structured payload (sample identity, seed IPs, passive layer); CSV
    is the flat IOC sheet with a `collection` discriminator and source_ip.
    """
    show_banner(primary=False)

    if format not in ("json", "csv"):
        console.print(f"[bold #C4453B]Unknown format: {format}[/bold #C4453B] (use json or csv)")
        raise typer.Exit(2)

    try:
        content = api_client.export_footprint(sample_id, format=format, mock=mock)
    except Exception as exc:
        console.print(f"[red]footprint export failed:[/red] {exc}")
        raise typer.Exit(1)

    dest = output or Path(f"outpost-footprint-{sample_id[:12]}.{format}")
    dest.write_bytes(content)
    console.print(f"[#3FA796]Exported footprint ({format}) → {dest}[/#3FA796]")
