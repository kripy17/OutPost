"""Rich renderers shared across commands — tables, trees, alert panels.

Uses the design-system color language (docs/07-UI-DESIGN-SYSTEM.md):
clean teal / suspicious amber / malicious brick.
"""

from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from .banners import show_banner

console = Console()


def intel_age(checked_at: str | None) -> str:
    """"checked 5h ago" — reputation cache age, mirroring the webapp's
    intelAgeLabel so the terminal and the UI read the same staleness."""
    if not checked_at:
        return "-"
    try:
        ts = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
    except ValueError:
        return "-"
    age = datetime.now(timezone.utc) - ts
    if age.total_seconds() < 0:
        return "just now"
    m = int(age.total_seconds() // 60)
    if m < 1:
        return "just now"
    if m < 60:
        return f"{m}m ago"
    h = m // 60
    if h < 24:
        return f"{h}h ago"
    return f"{h // 24}d ago"

SEVERITY_STYLE = {
    "clean": "bold #3FA796",
    "suspicious": "bold #D9A441",
    "malicious": "bold #C4453B",
}


def build_rule_summary_table(rules: dict[str, dict]) -> Table:
    """Rich table for `outpost agent summary` — one row per fired rule:
    total alerts, malicious/suspicious split, and how many agent sessions
    the rule fired in (its blast radius across the measurement window).
    """
    table = Table(show_header=True, header_style="bold")
    table.add_column("Rule", style="cyan")
    table.add_column("Alerts", justify="right")
    table.add_column("Malicious", justify="right", style="#C4453B")
    table.add_column("Suspicious", justify="right", style="yellow")
    table.add_column("Sessions", justify="right")
    for v in sorted(rules.values(), key=lambda x: -x["count"]):
        table.add_row(
            v["rule_id"],
            str(v["count"]),
            str(v["malicious"]),
            str(v["suspicious"]),
            str(len(v["runs"])),
        )
    return table


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


def _add_tree_children(tree: Tree, node: dict, recon_pids: set[int]) -> None:
    label = f"[bold]{node.get('process_name', '?')}[/bold]"
    pid = node.get("pid")
    if pid is not None:
        label += f" [dim][{pid}][/dim]"
    # Recon affordance — webapp parity: a pid behind the enumeration-burst
    # alert gets a RECON tag, matching the process tree's amber recon ring.
    if pid in recon_pids:
        label += " [bold #D9A441]● RECON[/bold #D9A441]"
    if node.get("command_line"):
        label += f"  [dim]{node['command_line'][:60]}[/dim]"
    branch = tree.add(label)
    for child in node.get("children", []):
        _add_tree_children(branch, child, recon_pids)


def render_process_tree(roots: list[dict], recon_pids: set[int] | None = None) -> Tree:
    tree = Tree("Process Tree")
    for root in roots:
        _add_tree_children(tree, root, recon_pids or set())
    return tree


def render_network_table(connections: list[dict]) -> Table:
    table = Table(title="Network Connections", border_style="dim")
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Port")
    table.add_column("Proto")
    table.add_column("Reputation")
    table.add_column("Abuse")
    table.add_column("VT")
    table.add_column("Checked", style="dim", no_wrap=True)
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
            intel_age(c.get("checked_at")),
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


def _enum_kinds(details: str) -> list[str]:
    """The alert reads "N distinct enumeration commands within 120s: a, b, c"
    — the trailing comma-separated labels are the distinct recon *kinds*,
    shown as chips (webapp ReconActorsPanel parity)."""
    if ": " not in details:
        return []
    return [k for k in (k.strip() for k in details.split(": ", 1)[1].split(", ")) if k]


def render_enum_kinds(kinds: list[str]) -> str:
    """One-line amber chip row for the distinct enumeration commands."""
    chips = " ".join(f"[bold #D9A441]▪ {k}[/bold #D9A441]" for k in kinds)
    return f"[dim]enum:[/dim] {chips}"


def _recon_summary(alerts: list[dict]) -> tuple[set[int], str | None, list[str]]:
    """Recon affordance (webapp parity): union the enumeration-burst actors,
    build the distinct-commands summary, and list the command kinds.
    Returns (recon_pids, sweep_line, enum_kinds)."""
    bursts = [a for a in alerts if a.get("rule_id") == "enumeration-burst"]
    if not bursts:
        return set(), None, []
    pids: set[int] = set()
    for a in bursts:
        for p in a.get("related_pids") or []:
            if p is not None:
                pids.add(p)
    details = bursts[0].get("details") or ""
    # The alert reads "N distinct enumeration commands within 120s: a, b, c".
    head = details.split(": ")[0] if ": " in details else details
    line = f"[bold #D9A441]recon sweep[/bold #D9A441] — {head.lower()}, {len(pids)} process{'es' if len(pids) != 1 else ''} [dim](T1082 · Discovery)[/dim]"
    return pids, line, _enum_kinds(details)


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

    recon_pids, recon_line, enum_kinds = _recon_summary(report.get("alerts", []))
    if report.get("process_tree"):
        console.print()
        if recon_line:
            console.print(recon_line)
            if enum_kinds:
                console.print(render_enum_kinds(enum_kinds))
        console.print(render_process_tree(report["process_tree"], recon_pids))

    if report.get("network_connections"):
        console.print()
        console.print(render_network_table(report["network_connections"]))

    if report.get("timeline"):
        console.print()
        console.print(render_timeline(report["timeline"]))
