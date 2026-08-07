"""`outpost export <run_id> --format json|pdf|csv|stix` — export a report to file."""

import json
from pathlib import Path

import typer

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console


def export(
    run_id: str,
    format: str = typer.Option("json", "--format", help="json, pdf, csv, or stix"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    show_banner(primary=False)

    if format not in ("json", "pdf", "csv", "stix"):
        console.print(f"[bold #C4453B]Unknown format: {format}[/bold #C4453B] (use json, pdf, csv, or stix)")
        raise typer.Exit(2)

    if format == "json":
        report = api_client.export_run(run_id)
        dest = output or Path(f"outpost-report-{run_id[:12]}.json")
        dest.write_text(json.dumps(report, indent=2))
        console.print(f"[#3FA796]Exported JSON report → {dest}[/#3FA796]")
    elif format == "pdf":
        _export_pdf(run_id, output)
    elif format == "stix":
        # Roadmap 3.3: STIX 2.1 bundle — interoperable with MISP/Cortex/OpenCTI.
        bundle = api_client.export_stix(run_id)
        dest = output or Path(f"outpost-stix-{run_id[:12]}.json")
        dest.write_text(json.dumps(bundle, indent=2))
        console.print(f"[#3FA796]Exported STIX 2.1 bundle → {dest}[/#3FA796]")
    else:  # csv
        # Task 23: CSV export calls the IOC endpoint (deduplicated IOC list).
        dest = output or Path(f"outpost-iocs-{run_id[:12]}.csv")
        dest.write_bytes(api_client.export_iocs_csv(run_id))
        console.print(f"[#3FA796]Exported IOC CSV → {dest}[/#3FA796]")


def _export_pdf(run_id: str, output: Path | None) -> None:
    """Download the backend's generated PDF (reportlab, Task 21)."""
    import requests

    from ..lib.api_client import BASE_URL

    resp = requests.get(f"{BASE_URL}/runs/{run_id}/export?format=pdf", timeout=20)
    if not resp.ok:
        console.print(f"[bold #C4453B]PDF export failed: {resp.status_code} {resp.text[:120]}[/bold #C4453B]")
        raise typer.Exit(1)
    dest = output or Path(f"outpost-report-{run_id[:12]}.pdf")
    dest.write_bytes(resp.content)
    console.print(f"[#3FA796]Exported PDF report → {dest}[/#3FA796]")
