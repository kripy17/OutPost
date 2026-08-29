"""`outpost run <sample> [--timeout N]` — one-shot analysis session.

Uploads the sample, detonates it in the backend's dynamic sandbox, renders
the full report, then drops into an interactive analyst loop where you can
triage findings, export artifacts, annotate, and query IOCs — all without
leaving the session. `q` quits; every other action operates on this run.
"""

import os

import typer

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console, render_report


def _upload_sample(path: str) -> dict:
    """Upload via the api_client seam (no raw requests in command modules)."""
    return api_client.upload_sample(path)


def _detonate_dynamic(sample_id: str) -> dict:
    """Detonate via the api_client seam."""
    return api_client.detonate_dynamic(sample_id)


# ── Interactive analyst actions ───────────────────────────────────────────


def _show_alerts(run_id: str) -> list[dict]:
    """Fetch and display the run's alerts with triage controls."""
    alerts = api_client.get_alerts(run_id)
    if not alerts:
        console.print("  [dim]No alerts on this run.[/dim]")
        return []
    from rich.table import Table

    table = Table(title="Findings", border_style="dim", show_lines=False)
    table.add_column("ID", style="bold", width=5)
    table.add_column("Sev", width=10)
    table.add_column("Rule", min_width=20)
    table.add_column("Detail", max_width=50)
    table.add_column("Status", width=12)
    for a in alerts:
        sev = a.get("severity", "?")
        sev_color = "#E5484D" if sev == "malicious" else "#F59E0B"
        table.add_row(
            str(a["id"]),
            f"[{sev_color}]{sev}[/{sev_color}]",
            a.get("rule_name", a.get("rule_id", "?")),
            (a.get("details") or "")[:60],
            a.get("status", "open").upper(),
        )
    console.print(table)
    return alerts


def _triage_alert(run_id: str, alerts: list[dict]) -> None:
    """Interactive alert triage — pick an alert, pick a transition."""
    if not alerts:
        console.print("  [dim]No alerts to triage.[/dim]")
        return
    try:
        alert_id = int(console.input("[bold]Alert ID to triage ([/]q to cancel): [/bold]"))
    except (ValueError, EOFError):
        return
    alert = next((a for a in alerts if a["id"] == alert_id), None)
    if not alert:
        console.print(f"  [dim]No alert {alert_id} on this run.[/dim]")
        return
    current = alert.get("status", "open")
    transitions = {
        "open": ["acknowledged", "resolved"],
        "acknowledged": ["resolved", "open"],
        "resolved": ["open"],
    }.get(current, ["acknowledged", "resolved"])
    console.print(f"  Alert {alert_id} ({alert.get('rule_name', '?')}) — currently [bold]{current}[/bold]")
    console.print(f"  Transition to: {' / '.join(transitions)}")
    action = console.input("  [bold]Transition to[/bold] (or q to skip): ").strip().lower()
    if action in ("q", ""):
        return
    if action not in transitions:
        console.print(f"  [dim]Invalid transition: {action}[/dim]")
        return
    comment = console.input("  Comment (optional, Enter to skip): ").strip()
    try:
        updated = api_client.update_alert_status(alert_id, action, comment)
        console.print(f"  [#3FA796]Alert {alert_id} → {updated.get('status', action)}[/#3FA796]")
    except api_client.APIError as exc:
        console.print(f"  [bold #C4453B]Triage failed: {exc}[/bold #C4453B]")


def _add_note(run_id: str) -> None:
    """Add an analyst note to this run."""
    note = console.input("  [bold]Note[/bold]: ").strip()
    if not note:
        return
    try:
        result = api_client.notes_add(run_id, note)
        console.print(f"  [#3FA796]Note added at {result.get('created_at', 'now')}[/#3FA796]")
    except api_client.APIError as exc:
        console.print(f"  [bold #C4453B]Note failed: {exc}[/bold #C4453B]")


def _export_run(run_id: str) -> None:
    """Export this run's report in the chosen format."""
    fmt = console.input("  [bold]Format[/bold] (json / stix / csv / pdf) [json]: ").strip().lower() or "json"
    if fmt not in ("json", "stix", "csv", "pdf"):
        console.print("  [dim]Unknown format — skipping.[/dim]")
        return
    try:
        api_client.export_run(run_id)
        console.print(f"  [#3FA796]Exported {fmt.upper()} → outpost-{fmt}-{run_id[:12]}.*[/#3FA796]")
    except api_client.APIError as exc:
        console.print(f"  [bold #C4453B]Export failed: {exc}[/bold #C4453B]")


def _search_iocs(run_id: str) -> None:
    """Search for an IOC value across all sessions."""
    value = console.input("  [bold]IOC to search[/bold] (IP / domain / hash): ").strip()
    if not value:
        return
    try:
        result = api_client.search_iocs(value)
        matches = result.get("matches", [])
        if not matches:
            console.print(f"  [dim]No prior runs contain '{value}'.[/dim]")
            return
        console.print(f"  [#3FA796]{result.get('count', len(matches))} match(es) for '{value}':[/#3FA796]")
        for m in matches[:5]:
            console.print(f"    run {m.get('run_id', '?')[:12]} · {m.get('sample_name', '?')}")
    except api_client.APIError as exc:
        console.print(f"  [bold #C4453B]Search failed: {exc}[/bold #C4453B]")


def _watchlist_add(run_id: str) -> None:
    """Add an IOC from this run to the personal watchlist."""
    value = console.input("  [bold]IOC to watchlist[/bold] (IP / domain / hash): ").strip()
    if not value:
        return
    label = console.input("  Label (optional): ").strip()
    try:
        api_client.watchlist_add(value, label)
        console.print(f"  [#3FA796]'{value}' added to watchlist[/#3FA796]")
    except api_client.APIError as exc:
        console.print(f"  [bold #C4453B]Watchlist failed: {exc}[/bold #C4453B]")


def _show_network(run_id: str) -> None:
    """Show this run's network connections with enrichment."""
    report = api_client.get_run(run_id)
    conns = report.get("network_connections", [])
    if not conns:
        console.print("  [dim]No network connections on this run.[/dim]")
        return
    from rich.table import Table

    table = Table(title="Network connections", border_style="dim")
    table.add_column("Destination")
    table.add_column("Port", justify="right", width=6)
    table.add_column("Proto", width=6)
    table.add_column("Reputation", width=12)
    table.add_column("Abuse", justify="right", width=6)
    table.add_column("VT", justify="right", width=5)
    for c in conns:
        rep = c.get("reputation") or "unknown"
        rep_color = "#E5484D" if rep == "malicious" else "#F59E0B" if rep == "suspicious" else "#6A7480"
        table.add_row(
            c.get("dest_ip", "?"),
            str(c.get("dest_port") or "—"),
            c.get("protocol") or "—",
            f"[{rep_color}]{rep}[/{rep_color}]",
            str(c.get("abuse_score") or "—"),
            str(c.get("vt_malicious_count") or "—"),
        )
    console.print(table)


# ── Main command ──────────────────────────────────────────────────────────


def run(
    sample_path: str,
    timeout: int = typer.Option(30, "--timeout", "-t", min=5, max=300, help="Observation window in seconds"),
    no_interactive: bool = typer.Option(False, "--no-interactive", help="Skip the analyst loop — just print the report"),
) -> None:
    """Execute a sample in the backend's dynamic sandbox and enter an
    interactive analyst session: triage, export, annotate, query."""
    show_banner(primary=True)

    resolved = os.path.realpath(sample_path)
    if not os.path.isfile(resolved):
        console.print(f"[bold #C4453B]Sample not found: {sample_path}[/bold #C4453B]")
        raise typer.Exit(1)

    # 1. Upload the sample to the vault.
    console.print("[#D9A441]Uploading sample to vault...[/#D9A441]")
    try:
        sample = _upload_sample(resolved)
        sample_id = sample["sample_id"]
        console.print(f"  sample_id: {sample_id[:12]}  sha256: {sample['sha256'][:16]}…")
    except (api_client.APIError, OSError) as exc:
        console.print(f"[bold #C4453B]Upload failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    # 2. Detonate via the backend's dynamic sandbox (isolated, bounded).
    console.print(f"[#D9A441]Detonating in dynamic sandbox ({timeout}s window)...[/#D9A441]")
    try:
        result = _detonate_dynamic(sample_id)
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Detonation failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    # 3. Fetch the full run detail and render the report.
    run_id = result.get("run_id", "")
    if not run_id:
        console.print("[bold #C4453B]Detonation returned no run_id[/bold #C4453B]")
        raise typer.Exit(1)

    verdict = result.get("verdict", "unknown")
    verdict_color = "#E5484D" if verdict == "malicious" else "#F59E0B" if verdict == "suspicious" else "#3FA796"
    console.print(f"\n[#3FA796]Detonation complete — run [{verdict_color}]{run_id[:12]} ({verdict})[/#3FA796]\n")
    try:
        report = api_client.get_run(run_id)
        render_report(report, run_id=run_id)
    except api_client.APIError:
        risk = result.get("risk_score", 0)
        alert_count = result.get("alerts_count", 0)
        console.print(f"  verdict: [bold]{verdict}[/bold]  risk: {risk}/100  alerts: {alert_count}")

    if no_interactive:
        return

    # 4. Interactive analyst loop — one session, every post-analysis action.
    alerts: list[dict] = []
    while True:
        console.print()
        console.print("[dim]── analyst session ──[/dim]  "
                      "[bold]a[/bold]=alerts  "
                      "[bold]t[/bold]=triage  "
                      "[bold]n[/bold]=note  "
                      "[bold]e[/bold]=export  "
                      "[bold]s[/bold]=search IOC  "
                      "[bold]w[/bold]=watchlist  "
                      "[bold]n[/bold]et=network  "
                      "[bold]r[/bold]=report  "
                      "[bold]q[/bold]=quit")
        try:
            choice = console.input("[bold #22d3ee]outpost[/bold #22d3ee]> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if choice in ("q", "quit", "exit"):
            break
        elif choice in ("a", "alerts"):
            alerts = _show_alerts(run_id)
        elif choice in ("t", "triage"):
            if not alerts:
                alerts = _show_alerts(run_id)
            _triage_alert(run_id, alerts)
        elif choice in ("n", "note"):
            _add_note(run_id)
        elif choice in ("e", "export"):
            _export_run(run_id)
        elif choice in ("s", "search"):
            _search_iocs(run_id)
        elif choice in ("w", "watchlist"):
            _watchlist_add(run_id)
        elif choice in ("net", "network"):
            _show_network(run_id)
        elif choice in ("r", "report"):
            try:
                report = api_client.get_run(run_id)
                render_report(report, run_id=run_id)
            except api_client.APIError as exc:
                console.print(f"  [bold #C4453B]{exc}[/bold #C4453B]")
        elif choice == "":
            continue
        else:
            console.print(f"  [dim]Unknown: {choice} — a/t/n/e/s/w/net/r/q[/dim]")
