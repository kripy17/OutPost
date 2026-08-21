"""`outpost watch` — the flagship command: live monitoring dashboard.

Starts the collector in live mode and renders a real-time dashboard (Rich
`Live` layout): process activity + alert feed, updating in place. A
`malicious`-severity alert also fires an OS-level desktop notification via
plyer, deduplicated so the same alert doesn't notify twice.
"""

import datetime
import time

from rich.console import Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel

from ..lib import api_client
from ..monitoring import session as monitor
from ..rendering.banners import show_banner
from ..rendering.terminal_views import (
    _recon_summary,
    console,
    render_alert,
    render_enum_kinds,
    render_network_table,
    render_process_tree,
    risk_gauge,
)


def _today() -> str:
    return datetime.date.today().isoformat()


def _notify(title: str, message: str) -> None:
    try:
        from plyer import notification

        notification.notify(title=title, message=message, timeout=5)
    except Exception:
        pass  # desktop notifications are best-effort


def render_dashboard(run_id: str, notified: set, meta_by_rule: dict) -> Layout:
    detail = api_client.get_run(run_id)
    alerts = api_client.get_alerts(run_id)

    layout = Layout()
    layout.split_row(
        Layout(name="left"),
        Layout(name="right", ratio=2),
    )
    layout["left"].split_column(
        Layout(name="alerts", ratio=2),
        Layout(name="net"),
    )

    run = detail.get("run", {})
    # Recon affordance — the moment enumeration-burst lands, its actors are
    # tagged in the live tree and a sweep line + command-kind chips appear
    # above it (webapp parity with the Monitor's recon highlight). Group
    # keeps the lines and the Tree as separate renderables (a str + Tree
    # concatenation would stringify the Tree to '<rich.tree.Tree object>').
    recon_pids, recon_line, enum_kinds = _recon_summary(alerts)
    # Build the tree panel's renderables conditionally so an empty kinds list
    # never leaves a stray blank line between the sweep line and the tree.
    if recon_line:
        tree_renderables: list = [recon_line]
        if enum_kinds:
            tree_renderables.append(render_enum_kinds(enum_kinds))
        tree_renderables.append(render_process_tree(detail.get("process_tree", []), recon_pids))
        tree_renderable = Group(*tree_renderables)
    else:
        tree_renderable = render_process_tree(detail.get("process_tree", []), recon_pids)
    layout["right"].update(
        Panel(
            tree_renderable,
            title=f"Process Tree — {run.get('sample_name', run_id[:12])}",
            border_style="dim",
        )
    )

    # Alert feed (with ATT&CK chips — webapp parity) + desktop notifications.
    alert_panels = [render_alert(a, meta_by_rule.get(a.get("rule_id"))) for a in alerts[-8:]] or [
        Panel("[dim]Watching… no alerts yet[/dim]")
    ]
    # Live risk readout — same gauge as `outpost show`, ticking every refresh.
    risk_line = risk_gauge(run.get("risk_score"))
    layout["alerts"].update(
        Panel(
            "\n".join(str(p) for p in alert_panels),
            title=f"Alerts — risk {risk_line}",
            border_style="#C4453B",
        )
    )

    for a in alerts:
        key = (a.get("id"), a.get("rule_id"))
        if a.get("severity") == "malicious" and key not in notified:
            _notify(f"OutPost — {a['rule_name']}", a.get("details", ""))
            notified.add(key)

    layout["net"].update(
        Panel(
            render_network_table(detail.get("network_connections", [])),
            title="Network",
            border_style="dim",
        )
    )
    return layout


def watch() -> None:
    show_banner(primary=True)
    run_id = api_client.create_run(sample_name=f"Live monitor — {_today()}", platform=monitor.detect_platform(), session_type="live")
    console.print(f"[#D9A441]Starting live monitoring session {run_id[:8]}...[/#D9A441]")

    collector_proc = monitor.start_local_collector(run_id, mode="live")
    notified: set = set()
    # Fetch the ATT&CK map once — alert chips are stable per rule, so the
    # per-refresh dashboard just looks the rule_id up in this dict.
    try:
        meta_by_rule = {m.get("rule_id"): m for m in api_client.get_rules_meta() if m.get("rule_id")}
    except Exception:
        meta_by_rule = {}

    with Live(render_dashboard(run_id, notified, meta_by_rule), refresh_per_second=2, console=console) as live:
        try:
            while True:
                time.sleep(0.5)
                live.update(render_dashboard(run_id, notified, meta_by_rule))
        except KeyboardInterrupt:
            pass

    monitor.stop_local_collector(collector_proc)
    console.print("[#D9A441]Monitoring stopped.[/#D9A441]")
