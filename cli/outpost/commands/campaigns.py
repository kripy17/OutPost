"""`outpost campaigns` — runs clustered by shared infrastructure.

Terminal mirror of the webapp "Campaigns" view: one block per signature IP
(runs that touch the same IP, known-clean IPs excluded), with member runs,
shared-IOC evidence, and the tail of the combined run-attributed timeline.
"""

import typer
from rich.panel import Panel
from rich.table import Table

from ..lib import api_client
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console

SEVERITY_STYLE = {"malicious": "#C4453B", "suspicious": "#D9A441"}

_TIMELINE_TAIL = 15


def _fmt(ts) -> str:
    return (ts or "")[:19].replace("T", " ") or "—"


def _detail(ev: dict) -> str:
    t = ev.get("event_type")
    if t == "process_create":
        base = f"{ev.get('process_name') or '?'} (pid {ev.get('pid') or '?'})"
        return f"{base} — {ev['command_line']}" if ev.get("command_line") else base
    if t == "network_connection":
        return f"{ev.get('dest_ip')}:{ev.get('dest_port') or '?'} [{ev.get('protocol') or '?'}]"
    if t == "file_write":
        return ev.get("file_path") or "-"
    if t == "registry_write":
        return ev.get("registry_key") or "-"
    return "-"


def _render_campaign(c: dict) -> None:
    rep = c.get("reputation") or "unknown"
    badge = f"★ {rep} ({c['watchlist_label']})" if c.get("watchlist") else rep
    badge_style = "#C4453B" if rep == "malicious" else "#D9A441"
    console.print(
        Panel.fit(
            f"[bold]{c['key']}[/bold]  [{badge_style}]{badge}[/{badge_style}]  "
            f"[dim]{len(c['runs'])} run(s) · {_fmt(c.get('span_start'))} → {_fmt(c.get('span_end'))}[/dim]",
            border_style="dim",
        )
    )

    runs = Table(border_style="dim", box=None, pad_edge=False)
    runs.add_column("Sample")
    runs.add_column("Run ID")
    runs.add_column("Alerts", justify="right")
    runs.add_column("Severity")
    for r in c["runs"]:
        sev = r.get("highest_severity")
        runs.add_row(
            r["sample_name"],
            r["run_id"],
            str(r["alert_count"]),
            f"[{SEVERITY_STYLE.get(sev, '#3FA796')}]● {sev or 'clean'}[/]",
        )
    console.print(runs)

    evidence: list[tuple[str, str, int]] = []
    for label, key in (
        ("IP", "ips"),
        ("Registry key", "registry_keys"),
        ("File path", "file_paths"),
        ("Process", "processes"),
    ):
        for ioc in c["iocs"][key]:
            evidence.append((label, ioc["value"], ioc["runs"]))
    if evidence:
        iocs = Table(title=f"Shared IOCs ({len(evidence)} values)", border_style="dim")
        iocs.add_column("Type")
        iocs.add_column("Value")
        iocs.add_column("Runs", justify="right")
        for label, value, runs in evidence:
            iocs.add_row(label, value, str(runs))
        console.print(iocs)

    events = c.get("timeline") or []
    if events:
        tail = Table(title=f"Timeline ({len(events)} events, last {_TIMELINE_TAIL} shown)", border_style="dim")
        tail.add_column("Sample")
        tail.add_column("Time")
        tail.add_column("Type")
        tail.add_column("Detail")
        for e in events[-_TIMELINE_TAIL:]:
            tail.add_row(e["sample_name"], (e["timestamp"] or "")[11:19], e["event_type"], _detail(e))
        console.print(tail)


def campaigns() -> None:
    show_banner(primary=False)

    try:
        data = api_client.get_campaigns()
    except api_client.APIError as exc:
        console.print(f"[bold #C4453B]Campaigns failed: {exc}[/bold #C4453B]")
        raise typer.Exit(1)

    if not data:
        console.print("[dim]No campaigns yet — two or more runs must share an IP.[/dim]")
        return

    console.print(f"[dim]{len(data)} campaign(s):[/dim]")
    for i, c in enumerate(data):
        _render_campaign(c)
        if i < len(data) - 1:
            console.print("")
