"""`outpost watch` — the flagship command: live monitoring dashboard.

Starts the collector in live mode and renders a real-time dashboard (Rich
`Live` layout): process activity + alert feed, updating in place. A
`malicious`-severity alert also fires an OS-level desktop notification via
plyer, deduplicated so the same alert doesn't notify twice.
"""

import datetime
import time

from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel

from ..lib import api_client
from ..monitoring import session as monitor
from ..rendering.banners import show_banner
from ..rendering.terminal_views import console, render_alert, render_network_table, render_process_tree


def _today() -> str:
    return datetime.date.today().isoformat()


def _notify(title: str, message: str) -> None:
    try:
        from plyer import notification

        notification.notify(title=title, message=message, timeout=5)
    except Exception:
        pass  # desktop notifications are best-effort


def render_dashboard(run_id: str, notified: set) -> Layout:
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
    layout["right"].update(
        Panel(
            render_process_tree(detail.get("process_tree", [])),
            title=f"Process Tree — {run.get('sample_name', run_id[:12])}",
            border_style="dim",
        )
    )

    # Alert feed + desktop notifications for malicious severity.
    alert_panels = [render_alert(a) for a in alerts[-8:]] or [Panel("[dim]Watching… no alerts yet[/dim]")]
    layout["alerts"].update(Panel("\n".join(str(p) for p in alert_panels), title="Alerts", border_style="#C4453B"))

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

    with Live(render_dashboard(run_id, notified), refresh_per_second=2, console=console) as live:
        try:
            while True:
                time.sleep(0.5)
                live.update(render_dashboard(run_id, notified))
        except KeyboardInterrupt:
            pass

    monitor.stop_local_collector(collector_proc)
    console.print("[#D9A441]Monitoring stopped.[/#D9A441]")
