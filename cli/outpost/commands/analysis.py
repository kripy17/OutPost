"""`outpost analysis` — the analysis job workflow, terminal mirror of the
webapp's P1.2 analysis workspace.

P0.2 analysis-job API parity: launch / list / show / cancel, plus the
observations-shaped payload and the run's findings. Only `static` is
launchable — watched-host / external-provider / isolated-outpost have no
executor yet, so the launcher rejects them up front (and the backend 501s
them) instead of queueing jobs that could never run.

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
    backend: str = typer.Argument(..., help="static (watched-host / external-provider / isolated-outpost have no executor yet — the backend 501s them)"),
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
    if backend != "static":
        console.print(
            f"[bold #C4453B]{backend} has no executor yet — no execution path exists for it, and the API "
            "501s it rather than queueing a job that could never run. Only 'static' is launchable.[/bold #C4453B]"
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


@app.command("network")
def analysis_network(
    run_id: str = typer.Argument(..., help="the analysis run id"),
    section: str = typer.Option("all", "--section", "-s", help="Section: all, metrics, c2, dns, http, tls, flows"),
) -> None:
    """Network protocol reconstruction, DNS ledger, HTTP requests, TLS JA3 fingerprinting, and C2 beaconing analysis."""
    from rich.panel import Panel

    show_banner(primary=False)
    try:
        data = api_client.get_run_network_analysis(run_id)
    except api_client.APIError as exc:
        try:
            import sys
            from pathlib import Path
            root = Path(__file__).resolve().parent.parent.parent.parent
            if str(root / "backend") not in sys.path:
                sys.path.insert(0, str(root / "backend"))
            from app.core.database import db_session
            from app.services import network_protocol_analyzer
            with db_session() as conn:
                data = network_protocol_analyzer.analyze_run(conn, run_id)
        except Exception:
            console.print(f"[bold #C4453B]Network analysis failed: {exc}[/bold #C4453B]")
            raise typer.Exit(1)

    metrics = data.get("metrics", {})
    c2 = data.get("c2_beaconing", {})
    dns = data.get("dns_conversations", [])
    http = data.get("http_requests", [])
    tls = data.get("tls_handshakes", [])
    flows = data.get("flows", [])

    c2_detected = c2.get("beaconing_detected", False)
    c2_style = "bold #C4453B" if c2_detected else "#3FA796"
    c2_status = (
        f"[{c2_style}]DETECTED ({c2.get('beacon_count', 0)} beacon(s))[/{c2_style}]"
        if c2_detected
        else "[#3FA796]Negative (No periodic beaconing observed)[/#3FA796]"
    )

    summary_text = (
        f"[bold #3B82F6]Network Protocol Telemetry[/bold #3B82F6] — Run: [bold]{run_id}[/bold]\n"
        f"• Sockets / Flows: [bold]{metrics.get('unique_flows_count', 0)}[/bold]  ·  "
        f"Destinations: [bold]{metrics.get('unique_destinations_count', 0)}[/bold]\n"
        f"• DNS Queries: [bold]{metrics.get('total_dns_queries', 0)}[/bold] (DGA Suspects: [{'bold #C4453B' if metrics.get('dga_suspect_count', 0) > 0 else 'dim'}]{metrics.get('dga_suspect_count', 0)}[/])\n"
        f"• HTTP Transactions: [bold]{metrics.get('http_request_count', 0)}[/bold] (Suspicious: [{'bold #C4453B' if metrics.get('suspicious_http_count', 0) > 0 else 'dim'}]{metrics.get('suspicious_http_count', 0)}[/])\n"
        f"• TLS Handshakes: [bold]{metrics.get('tls_handshake_count', 0)}[/bold]\n"
        f"• C2 Periodic Beaconing: {c2_status}"
    )
    console.print(Panel(summary_text, border_style="blue", title="Protocol Analysis Overview"))

    if section in ("all", "c2") and c2.get("beacons"):
        b_table = Table(title="C2 Beaconing Detections", border_style="red")
        b_table.add_column("Destination IP")
        b_table.add_column("Count")
        b_table.add_column("Median Interval")
        b_table.add_column("Regularity")
        b_table.add_column("Verdict")
        for b in c2["beacons"]:
            b_table.add_row(
                b.get("ip", "-"),
                str(b.get("count", 0)),
                f"{b.get('median_interval_s', 0):.1f}s",
                f"{b.get('regularity_score', 0) * 100:.0f}%",
                f"[bold #C4453B]{b.get('verdict', 'Periodic C2 Beacon')}[/bold #C4453B]",
            )
        console.print(b_table)

    if section in ("all", "dns") and dns:
        d_table = Table(title=f"DNS Conversations ({len(dns)})", border_style="dim")
        d_table.add_column("Domain / Query")
        d_table.add_column("Queries")
        d_table.add_column("Resolved IPs")
        d_table.add_column("Category")
        d_table.add_column("DGA Entropy")
        for d in dns[:25]:
            dga_flag = "[bold #C4453B]YES[/bold #C4453B]" if d.get("is_dga_suspect") else "[dim]No[/dim]"
            cat = d.get("category", "regular")
            cat_style = "bold #C4453B" if cat == "malicious" else ("bold #D9A441" if cat == "suspicious" else "dim")
            d_table.add_row(
                d.get("query", "-"),
                str(d.get("query_count", 1)),
                ", ".join(d.get("resolved_ips", [])[:3]) or "-",
                f"[{cat_style}]{cat}[/]",
                f"{d.get('dga_entropy', 0.0):.2f} ({dga_flag})",
            )
        console.print(d_table)

    if section in ("all", "http") and http:
        h_table = Table(title=f"HTTP Transactions ({len(http)})", border_style="dim")
        h_table.add_column("Method")
        h_table.add_column("Host")
        h_table.add_column("Path / URL")
        h_table.add_column("Status")
        h_table.add_column("Indicator")
        for h in http[:25]:
            is_sus = h.get("is_suspicious", False)
            ind_style = "bold #C4453B" if is_sus else "dim"
            h_table.add_row(
                h.get("method", "GET"),
                h.get("host", "-"),
                (h.get("path") or h.get("url") or "-")[:50],
                str(h.get("status_code", "-")),
                f"[{ind_style}]{'Suspicious C2 URI' if is_sus else 'Benign'}[/]",
            )
        console.print(h_table)

    if section in ("all", "tls") and tls:
        t_table = Table(title=f"TLS Handshakes & JA3 Profiles ({len(tls)})", border_style="dim")
        t_table.add_column("SNI Domain")
        t_table.add_column("JA3 Hash")
        t_table.add_column("Matched Tool Profile")
        t_table.add_column("Severity")
        for t in tls[:25]:
            tool = t.get("ja3_tool") or "Standard TLS Client"
            sev = t.get("severity", "clean")
            sev_style = _SEV_STYLE.get(sev, "dim")
            t_table.add_row(
                t.get("sni", "-"),
                (t.get("ja3") or "-")[:16] + "…",
                tool,
                f"[{sev_style}]{sev}[/]" if sev_style else sev,
            )
        console.print(t_table)

    if section in ("all", "flows") and flows:
        f_table = Table(title=f"Network Flows ({len(flows)})", border_style="dim")
        f_table.add_column("Protocol")
        f_table.add_column("Source")
        f_table.add_column("Destination")
        f_table.add_column("Process")
        f_table.add_column("Direction")
        for f in flows[:25]:
            f_table.add_row(
                f.get("protocol", "tcp").upper(),
                f"{f.get('src_ip')}:{f.get('src_port')}",
                f"{f.get('dest_ip')}:{f.get('dest_port')}",
                f"{f.get('process_name') or '-'} (PID {f.get('pid') or '-'})",
                f.get("direction", "outbound"),
            )
        console.print(f_table)
