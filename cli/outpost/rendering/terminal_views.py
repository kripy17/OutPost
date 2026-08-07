"""Rich renderers shared across commands — tables, trees, alert panels.

Uses the design-system color language (docs/07-UI-DESIGN-SYSTEM.md):
clean teal / suspicious amber / malicious brick.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from .banners import show_banner

console = Console()

SEVERITY_STYLE = {
    "clean": "bold #3FA796",
    "suspicious": "bold #D9A441",
    "malicious": "bold #C4453B",
}


def risk_style(score: int | None) -> str:
    """Color bands mirroring the webapp's risk gauge (docs/07 + roadmap 1.3)."""
    s = score or 0
    if s >= 60:
        return "bold #C4453B"  # critical
    if s >= 30:
        return "bold #D9A441"  # elevated
    return "bold #3FA796"  # low / none


def risk_gauge(score: int | None, width: int = 10) -> str:
    """Compact colorized bar, e.g. `[#C4453B]█████░░░░░[/] 63`."""
    s = max(0, min(100, score or 0))
    style = risk_style(s)
    filled = round(s / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{style}]{bar}[/{style}] {s}"


def render_alert(alert: dict, rule_meta: dict | None = None) -> Panel:
    style = SEVERITY_STYLE.get(alert.get("severity", ""), "white")
    title = f"[{style}]{alert['rule_name']}[/{style}]"
    # ATT&CK technique chip — webapp parity (roadmap 1.3).
    if rule_meta and rule_meta.get("technique"):
        title += f"  [dim]{rule_meta.get('technique')} · {rule_meta.get('tactic', '')}[/dim]"
    # border_style must be a valid Rich style — raw severity strings like
    # "malicious" are not colors and would raise MissingStyle.
    return Panel(alert.get("details", ""), title=title, border_style=style)


def render_run_table(runs: list[dict]) -> Table:
    table = Table(title="OutPost — Session History", border_style="dim")
    table.add_column("Run ID", style="cyan", no_wrap=True)
    table.add_column("Sample", style="bold")
    table.add_column("Plat", style="magenta")
    table.add_column("Type")
    table.add_column("Alerts", justify="right")
    table.add_column("Risk", justify="right")
    table.add_column("Severity")
    table.add_column("Started", style="dim", no_wrap=True)

    for r in runs:
        sev = r.get("highest_severity") or "clean"
        risk = risk_style(r.get("risk_score"))
        table.add_row(
            r["run_id"][:12],
            r["sample_name"],
            {"windows": "win", "linux": "nix", "macos": "mac"}.get(r["platform"], r["platform"]),
            r["session_type"],
            str(r["alert_count"]),
            f"[{risk}]{r.get('risk_score') or 0}[/{risk}]",
            f"[{SEVERITY_STYLE.get(sev, 'white')}]● {sev}[/{SEVERITY_STYLE.get(sev, 'white')}]",
            r["started_at"][:19],
        )
    return table


def _add_tree_children(tree: Tree, node: dict) -> None:
    label = f"[bold]{node.get('process_name', '?')}[/bold]"
    if node.get("command_line"):
        label += f"  [dim]{node['command_line'][:60]}[/dim]"
    branch = tree.add(label)
    for child in node.get("children", []):
        _add_tree_children(branch, child)


def render_process_tree(roots: list[dict]) -> Tree:
    tree = Tree("Process Tree")
    for root in roots:
        _add_tree_children(tree, root)
    return tree


def render_network_table(connections: list[dict]) -> Table:
    table = Table(title="Network Connections", border_style="dim")
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Port")
    table.add_column("Proto")
    table.add_column("Reputation")
    table.add_column("Abuse")
    table.add_column("VT")
    table.add_column("First seen", style="dim", no_wrap=True)

    for c in connections:
        rep = c.get("reputation") or "unknown"
        table.add_row(
            c["dest_ip"],
            str(c.get("dest_port") or "-"),
            c.get("protocol") or "-",
            f"[{SEVERITY_STYLE.get(rep, 'white')}]● {rep}[/{SEVERITY_STYLE.get(rep, 'white')}]",
            str(c.get("abuse_score") or "-"),
            str(c.get("vt_malicious_count") or "-"),
            (c.get("first_seen") or "")[:19],
        )
    return table


def render_timeline(events: list[dict]) -> Table:
    table = Table(title="Timeline", border_style="dim")
    table.add_column("#")
    table.add_column("Time", style="dim", no_wrap=True)
    table.add_column("Type", style="bold")
    table.add_column("Detail")

    for i, ev in enumerate(events, 1):
        detail = _event_detail(ev)
        table.add_row(str(i), (ev.get("timestamp") or "")[11:19], ev["event_type"], detail)
    return table


def _event_detail(ev: dict) -> str:
    if ev["event_type"] == "process_create":
        return f"{ev.get('process_name', '?')} (pid {ev.get('pid')}) {ev.get('command_line') or ''}".strip()
    if ev["event_type"] == "network_connection":
        return f"{ev.get('dest_ip')}:{ev.get('dest_port')} [{ev.get('protocol')}]"
    if ev["event_type"] == "file_write":
        return ev.get("file_path") or "-"
    if ev["event_type"] == "registry_write":
        return ev.get("registry_key") or "-"
    return "-"


def render_kill_chain(links: list[dict]) -> Table:
    """Roadmap 2.4 — correlated stage-to-stage sequence (dropper→lolbin→beacon→persistence)."""
    table = Table(title="Kill-Chain Correlation", border_style="dim")
    table.add_column("Stage")
    table.add_column("Link", justify="center")
    table.add_column("Stage")
    table.add_column("Evidence", style="dim")
    for link in links:
        table.add_row(
            f"[bold #D9A441]{link['from']}[/bold #D9A441]",
            "→",
            f"[bold #C4453B]{link['to']}[/bold #C4453B]",
            f"{link['count']} alert(s)",
        )
    return table


def render_sample_reputation(rep: dict) -> Panel:
    """Roadmap 2.2 — uploaded-binary evidence: YARA hits + hash reputation."""
    yara = rep.get("yara_rules") or []
    dets = rep.get("vt_detections")
    fam = rep.get("malware_family")
    lines = [f"SHA-256  {rep.get('sha256', '?')}"]
    if yara:
        lines.append(f"YARA     {', '.join(yara)}")
    else:
        lines.append("YARA     no bundled rules matched")
    lines.append("VT       " + (f"{dets} detection(s)" if dets is not None else "no score"))
    lines.append("Family   " + (fam or "—"))
    border = "#C4453B" if (dets or 0) > 0 or yara else "dim"
    return Panel("\n".join(lines), title="[bold]Sample Reputation[/bold]", border_style=border)


def render_report(report: dict, run_id: str | None = None, rules_meta: list[dict] | None = None) -> None:
    run = report.get("run", {})
    rid = run_id or run.get("run_id", "?")
    show_banner(primary=False)

    sev = run.get("highest_severity") or "clean"
    console.print(
        f"\n[b]Run {rid[:12]}[/b] — {run.get('sample_name', '?')} "
        f"[{SEVERITY_STYLE.get(sev, 'white')}]● {sev}[/{SEVERITY_STYLE.get(sev, 'white')}]  "
        f"{risk_gauge(run.get('risk_score'))}"
    )

    # ATT&CK map keyed by rule_id — chips on every alert (webapp parity).
    meta_by_rule = {m.get("rule_id"): m for m in (rules_meta or []) if m.get("rule_id")}

    # Roadmap 2.2 — uploaded-binary evidence, right under the header.
    if report.get("sample_reputation"):
        console.print()
        console.print(render_sample_reputation(report["sample_reputation"]))

    # Roadmap 2.4 — correlated sequence, before the raw alert list.
    if report.get("kill_chain"):
        console.print()
        console.print(render_kill_chain(report["kill_chain"]))

    alerts = report.get("alerts", [])
    if alerts:
        console.print(f"\n[bold #C4453B]{len(alerts)} alert(s):[/bold #C4453B]")
        for a in alerts:
            console.print(render_alert(a, meta_by_rule.get(a.get("rule_id"))))
    else:
        console.print("\n[#3FA796]No alerts — session looks clean.[/#3FA796]")

    if report.get("process_tree"):
        console.print()
        console.print(render_process_tree(report["process_tree"]))

    if report.get("network_connections"):
        console.print()
        console.print(render_network_table(report["network_connections"]))

    if report.get("timeline"):
        console.print()
        console.print(render_timeline(report["timeline"]))
