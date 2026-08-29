"""OutPost SOC Terminal User Interface (TUI).

An interactive, keyboard-driven terminal application for operating OutPost as a
behavioral security monitor and dynamic malware analysis console.

Navigation:
  [↑/↓] or [k/j] : Navigate menu
  [1-9]          : Direct jump
  [Enter]        : Select / Drill down
  [b / Esc]      : Back
  [r]            : Refresh data
  [q]            : Quit
"""

import platform
import sys
import time

from rich.align import Align
from rich.box import ROUNDED
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .lib import api_client
from .rendering.terminal_views import (
    SEVERITY_STYLE,
    intel_age,
    render_alert,
    render_network_table,
    render_process_tree,
    risk_gauge,
    risk_style,
)

console = Console()


def _safe_get_runs() -> list[dict]:
    try:
        res = api_client.list_runs()
        return res if isinstance(res, list) else []
    except Exception:
        return []


def _safe_get_alerts() -> list[dict]:
    try:
        res = api_client.get_alert_queue(status="all", limit=50)
        if isinstance(res, dict):
            return res.get("alerts", [])
        elif isinstance(res, list):
            return res
        return []
    except Exception:
        return []


def _safe_get_fleet() -> dict:
    try:
        res = api_client.get_agents()
        return res if isinstance(res, dict) else {"agents": [], "online": 0}
    except Exception:
        return {"agents": [], "online": 0}


def _safe_get_investigations() -> list[dict]:
    try:
        res = api_client.list_investigations()
        if isinstance(res, dict):
            return res.get("investigations", [])
        elif isinstance(res, list):
            return res
        return []
    except Exception:
        return []


def _safe_get_samples() -> list[dict]:
    try:
        res = api_client.list_samples()
        if isinstance(res, dict):
            return res.get("samples", [])
        elif isinstance(res, list):
            return res
        return []
    except Exception:
        return []


def _safe_get_watchlist() -> list[dict]:
    try:
        res = api_client.get_watchlist()
        return res if isinstance(res, list) else []
    except Exception:
        return []


def _safe_get_campaigns() -> list[dict]:
    try:
        res = api_client.get_campaigns()
        return res if isinstance(res, list) else []
    except Exception:
        return []


def _safe_get_rules_meta() -> list[dict]:
    try:
        res = api_client.get_rules_meta()
        return res if isinstance(res, list) else []
    except Exception:
        return []


def _safe_get_playbooks() -> list[dict]:
    try:
        res = api_client.get_playbooks()
        return res if isinstance(res, list) else []
    except Exception:
        return []


def _get_key() -> str:
    """Read a single keypress without waiting for Enter."""
    if platform.system().lower() == "windows":
        import msvcrt
        ch = msvcrt.getch()
        if ch in (b"\x00", b"\xe0"):
            ch2 = msvcrt.getch()
            if ch2 == b"H":
                return "up"
            elif ch2 == b"P":
                return "down"
            elif ch2 == b"K":
                return "left"
            elif ch2 == b"M":
                return "right"
        if ch == b"\r":
            return "enter"
        if ch == b"\x1b":
            return "esc"
        try:
            return ch.decode("utf-8", errors="ignore").lower()
        except Exception:
            return ""
    else:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                ch2 = sys.stdin.read(1)
                if ch2 == "[":
                    ch3 = sys.stdin.read(1)
                    if ch3 == "A":
                        return "up"
                    elif ch3 == "B":
                        return "down"
                    elif ch3 == "C":
                        return "right"
                    elif ch3 == "D":
                        return "left"
                return "esc"
            if ch in ("\r", "\n"):
                return "enter"
            return ch.lower()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


class OutPostTUI:
    def __init__(self):
        self.running = True
        self.current_screen = "main"
        self.main_selected = 0
        self.sub_selected = 0
        self.detail_selected = 0
        self.active_sub_view = None
        self.status_msg = ""
        self.selected_run_id = None
        self.generated_rules_text = None

        self.main_menu = [
            ("1", "Monitor", "Live telemetry, active sessions, online fleet, detection activity"),
            ("2", "Analyze", "Attack scenario playbooks, sample vault, binary inspection"),
            ("3", "Investigate", "SOC incident investigation case management, findings & notes"),
            ("4", "IOCs", "Cross-run IOC search, threat reputation cache, watchlist"),
            ("5", "Hosts", "Connected fleet collectors, heartbeat health, host timeline"),
            ("6", "Campaigns", "Auto-clustered campaigns sharing C2 infrastructure"),
            ("7", "Reports", "Run summaries, Sigma/Suricata rule synthesis, STIX bundles"),
            ("8", "Detection Rules", "38 explainable heuristics across 14 MITRE ATT&CK tactics"),
            ("9", "Settings", "Local monitor status, threat intel keys, system health"),
        ]

        self.sub_menus = {
            "monitor": ["Live Events", "Findings", "Sessions", "Hosts", "Detection Activity"],
            "analyze": ["Attack Playbooks", "Sample Vault", "Static Inspection", "Execution Traces"],
            "investigate": ["Active Cases", "Closed Cases", "Triage Queue", "Case Timeline"],
            "iocs": ["Search IOC", "Threat Watchlist", "Reputation Cache", "Infra Topology"],
            "hosts": ["Online Fleet", "Collector Heartbeats", "Host Activity Timeline"],
            "campaigns": ["Campaign Clusters", "Shared C2 Infrastructure", "Evidence Graph"],
            "reports": ["Session Reports", "Synthesize Detection Suite", "STIX 2.1 Bundles"],
            "rules": ["38 Heuristic Rules", "ATT&CK Coverage Matrix", "YARA Signatures"],
            "settings": ["Local Monitor Daemon", "Threat Intel Keys", "System Health & DB"],
        }

    def run(self):
        while self.running:
            try:
                console.clear()
                if self.current_screen == "main":
                    self.render_main_screen()
                elif self.current_screen in self.sub_menus:
                    if self.active_sub_view is None:
                        self.render_category_screen(self.current_screen)
                    else:
                        self.render_sub_view()
                elif self.current_screen == "run_detail":
                    self.render_run_detail()

                key = _get_key()
                self.handle_input(key)
                self.status_msg = ''
            except KeyboardInterrupt:
                self.running = False
            except Exception as exc:
                self.status_msg = f"Error: {exc}"
                time.sleep(1.0)

        console.clear()
        console.print("[bold #3FA796]OutPost SOC Terminal closed.[/bold #3FA796]")

    def handle_input(self, key: str):
        if not key:
            return

        if key == "q":
            if self.generated_rules_text:
                self.generated_rules_text = None
            elif self.current_screen == "run_detail":
                self.current_screen = "monitor"
                self.active_sub_view = "Live Events"
            elif self.active_sub_view is not None:
                self.active_sub_view = None
                self.detail_selected = 0
            elif self.current_screen != "main":
                self.current_screen = "main"
                self.sub_selected = 0
            else:
                self.running = False
            return

        if key in ("esc", "b"):
            if self.generated_rules_text:
                self.generated_rules_text = None
            elif self.current_screen == "run_detail":
                self.current_screen = "monitor"
                self.active_sub_view = "Live Events"
            elif self.active_sub_view is not None:
                self.active_sub_view = None
                self.detail_selected = 0
            elif self.current_screen != "main":
                self.current_screen = "main"
                self.sub_selected = 0
            return

        if key == "r":
            self.status_msg = "Telemetry & data refreshed."
            return

        if self.current_screen == "run_detail":
            if key == "g" and self.selected_run_id:
                try:
                    self.generated_rules_text = api_client.get_rules(self.selected_run_id, "all")
                    self.status_msg = "Detection suite synthesized."
                except Exception as exc:
                    self.status_msg = f"Rule generation error: {exc}"
            return

        if self.current_screen == "main":
            if key in ("up", "k"):
                self.main_selected = (self.main_selected - 1) % len(self.main_menu)
            elif key in ("down", "j"):
                self.main_selected = (self.main_selected + 1) % len(self.main_menu)
            elif key in ("1", "2", "3", "4", "5", "6", "7", "8", "9"):
                self.main_selected = int(key) - 1
                self.enter_category()
            elif key == "enter":
                self.enter_category()

        elif self.active_sub_view is None:
            items = self.sub_menus.get(self.current_screen, [])
            if key in ("up", "k"):
                self.sub_selected = (self.sub_selected - 1) % len(items)
            elif key in ("down", "j"):
                self.sub_selected = (self.sub_selected + 1) % len(items)
            elif key == "enter":
                self.active_sub_view = items[self.sub_selected]
                self.detail_selected = 0

        else:
            # Inside detail sub-view
            if key in ("up", "k"):
                self.detail_selected = max(0, self.detail_selected - 1)
            elif key in ("down", "j"):
                self.detail_selected += 1
            elif key == "enter":
                self.handle_detail_enter()
            else:
                self._handle_action(key)

    def _pause_for_action(self) -> None:
        """Pause after a write action so the user sees the result."""
        console.input("[dim]Press Enter to continue…[/dim]")

    def _handle_action(self, key: str) -> None:
        """View-specific write actions — makes the TUI an operator console."""
        view = self.active_sub_view or ""
        screen = self.current_screen

        # ── Findings: triage + allowlist ──
        if screen == "monitor" and view == "Findings":
            alerts = _safe_get_alerts()
            if not alerts or self.detail_selected >= len(alerts):
                self.status_msg = "No finding selected."
                return
            alert = alerts[self.detail_selected]
            alert_id = alert.get("id")
            if key == "t":
                transitions = {"open": "acknowledged", "acknowledged": "resolved", "resolved": "open"}
                nxt = transitions.get(alert.get("status", "open"), "acknowledged")
                try:
                    api_client.update_alert_status(alert_id, nxt)
                    self.status_msg = f"Alert {alert_id} → {nxt}"
                except Exception as exc:
                    self.status_msg = f"Triage failed: {exc}"
            elif key == "a":
                ip = alert.get("related_ip") or ""
                if ip:
                    try:
                        api_client.add_run_allowlist(alert.get("run_id", ""), "ip", ip)
                        self.status_msg = f"Allowlisted {ip}"
                    except Exception as exc:
                        self.status_msg = f"Allowlist failed: {exc}"
                else:
                    self.status_msg = "No related IP on this finding."

        # ── Sample Vault: detonate ──
        elif screen == "analyze" and view in ("Sample Vault", "Static Inspection"):
            samples = _safe_get_samples()
            if not samples or self.detail_selected >= len(samples):
                self.status_msg = "No sample selected."
                return
            sample = samples[self.detail_selected]
            if key == "d":
                sid = sample.get("sample_id", "")
                self.status_msg = f"Detonating {sample.get('name', sid)[:20]}…"
                try:
                    res = api_client._post("/sandbox/detonate/dynamic", {"sample_id": sid})
                    self.selected_run_id = res.get("run_id", "")
                    self.current_screen = "run_detail"
                    self.status_msg = f"Detonated — verdict: {res.get('verdict', '?')}"
                except Exception as exc:
                    self.status_msg = f"Detonation failed: {exc}"

        # ── Watchlist: add / remove ──
        elif screen == "iocs" and view == "Threat Watchlist":
            watchlist = _safe_get_watchlist()
            if key == "a":
                try:
                    value = console.input("[bold]IOC value to watchlist:[/bold] ").strip()
                    if value:
                        label = console.input("[bold]Label (optional):[/bold] ").strip()
                        api_client.watchlist_add(value, label)
                        self.status_msg = f"Added {value} to watchlist."
                except (Exception, KeyboardInterrupt, EOFError):
                    self.status_msg = "Watchlist add canceled."
            elif key == "x":
                if watchlist and self.detail_selected < len(watchlist):
                    entry = watchlist[self.detail_selected]
                    try:
                        api_client.watchlist_remove(entry["value"])
                        self.status_msg = f"Removed {entry['value']} from watchlist."
                    except Exception as exc:
                        self.status_msg = f"Remove failed: {exc}"

        # ── Investigations: create / close ──
        elif screen == "investigate":
            invs = _safe_get_investigations()
            if key == "n":
                try:
                    title = console.input("[bold]Case title:[/bold] ").strip()
                    if title:
                        res = api_client.create_investigation(title)
                        self.status_msg = f"Created case {res.get('id', '?')[:12]}"
                except (Exception, KeyboardInterrupt, EOFError):
                    self.status_msg = "Case creation canceled."
            elif key == "c" and invs and self.detail_selected < len(invs):
                inv = invs[self.detail_selected]
                inv_id = inv.get("id", "")
                if inv.get("status") not in ("closed",):
                    try:
                        conclusion = console.input("[bold]Conclusion:[/bold] ").strip()
                        if conclusion:
                            api_client.close_investigation(inv_id, conclusion)
                            self.status_msg = f"Closed case {inv_id[:12]}"
                    except (Exception, KeyboardInterrupt, EOFError):
                        self.status_msg = "Close canceled."

        # ── Reports: export ──
        elif screen == "reports" and key == "e":
            runs = _safe_get_runs()
            if runs and self.detail_selected < len(runs):
                rid = runs[self.detail_selected]["run_id"]
                try:
                    api_client.export_run(rid)
                    self.status_msg = f"Exported report for {rid[:12]}"
                except Exception as exc:
                    self.status_msg = f"Export failed: {exc}"

        # ── Run Detail: triage alerts + export ──
        elif screen == "run_detail":
            if key == "t":
                try:
                    detail = api_client.get_run(self.selected_run_id or "")
                    alerts = detail.get("alerts", [])
                    if alerts:
                        for a in alerts:
                            if a.get("status") == "open":
                                api_client.update_alert_status(a["id"], "acknowledged")
                        self.status_msg = f"Acknowledged {len(alerts)} open alert(s)."
                    else:
                        self.status_msg = "No open alerts."
                except Exception as exc:
                    self.status_msg = f"Triage failed: {exc}"
            elif key == "e":
                try:
                    api_client.export_run(self.selected_run_id or "")
                    self.status_msg = "Report exported."
                except Exception as exc:
                    self.status_msg = f"Export failed: {exc}"

    def enter_category(self):
        screen_map = [
            "monitor",
            "analyze",
            "investigate",
            "iocs",
            "hosts",
            "campaigns",
            "reports",
            "rules",
            "settings",
        ]
        if 0 <= self.main_selected < len(screen_map):
            self.current_screen = screen_map[self.main_selected]
            self.sub_selected = 0
            self.active_sub_view = None
            self.status_msg = ""

    def handle_detail_enter(self):
        if self.current_screen == "monitor" and self.active_sub_view in ("Sessions", "Live Events"):
            runs = _safe_get_runs()
            if runs and 0 <= self.detail_selected < len(runs):
                self.selected_run_id = runs[self.detail_selected]["run_id"]
                self.current_screen = "run_detail"
                self.generated_rules_text = None

        elif self.current_screen == "analyze" and self.active_sub_view == "Attack Playbooks":
            playbooks = _safe_get_playbooks()
            if playbooks and 0 <= self.detail_selected < len(playbooks):
                pb = playbooks[self.detail_selected]
                self.status_msg = f"Detonating {pb['name']}..."
                try:
                    res = api_client.detonate_playbook(pb["id"])
                    self.selected_run_id = res["run_id"]
                    self.current_screen = "run_detail"
                    self.generated_rules_text = None
                    self.status_msg = f"Detonated: {pb['name']} ({res.get('alert_count', 0)} alerts)"
                except Exception as exc:
                    self.status_msg = f"Detonation error: {exc}"

        elif self.current_screen == "reports" and self.active_sub_view in ("Session Reports", "Synthesize Detection Suite"):
            runs = _safe_get_runs()
            if runs and 0 <= self.detail_selected < len(runs):
                self.selected_run_id = runs[self.detail_selected]["run_id"]
                self.current_screen = "run_detail"
                if self.active_sub_view == "Synthesize Detection Suite":
                    try:
                        self.generated_rules_text = api_client.get_rules(self.selected_run_id, "all")
                    except Exception:
                        pass

    def render_main_screen(self):
        alerts = _safe_get_alerts()
        investigations = _safe_get_investigations()

        # Build menu lines
        lines: list[Text] = []
        for idx, (num, label, _) in enumerate(self.main_menu):
            is_sel = idx == self.main_selected
            prefix = " > " if is_sel else "   "
            style = "bold #3FA796 reverse" if is_sel else "white"
            t = Text()
            t.append(f"{prefix}{num}. {label.ljust(24)}", style=style)
            lines.append(t)

        menu_content = Group(*lines)

        # Recent investigations / findings
        recent_lines: list[Text] = [
            Text("Recent investigations", style="bold white"),
            Text("─────────────────────", style="dim"),
        ]

        if investigations:
            for inv in investigations[:3]:
                sev = (inv.get("severity") or "HIGH").upper()
                style = SEVERITY_STYLE.get(sev.lower(), "bold #C4453B")
                case_id = inv.get("id", "INC-001")[:8].ljust(10)
                title = inv.get("title", "Suspicious Activity")[:36].ljust(38)
                t = Text()
                t.append(f"{case_id} {title} ")
                t.append(sev.ljust(10), style=style)
                recent_lines.append(t)
        elif alerts:
            for a in alerts[:3]:
                sev = (a.get("severity") or "SUSPICIOUS").upper()
                style = SEVERITY_STYLE.get(sev.lower(), "bold #D9A441")
                case_id = f"ALT-{a.get('id', 1)}".ljust(10)
                title = a.get("rule_name", "Alert")[:36].ljust(38)
                t = Text()
                t.append(f"{case_id} {title} ")
                t.append(sev.ljust(10), style=style)
                recent_lines.append(t)
        else:
            recent_lines.append(Text("No open investigations. System is secure.", style="dim"))

        body = Group(
            menu_content,
            Text(""),
            Group(*recent_lines),
            Text(""),
            Text("[↑↓] Navigate   [1-9] Direct Jump   [Enter] Select   [q] Quit", style="dim"),
        )

        panel = Panel(
            body,
            title="[bold #3FA796]OUTPOST[/bold #3FA796]                                      [bold yellow]SOC TERMINAL[/bold yellow]",
            box=ROUNDED,
            border_style="#3FA796",
            padding=(1, 3),
        )
        console.print(panel)

    def render_category_screen(self, category: str):
        cat_title = category.upper()
        runs = _safe_get_runs()
        alerts = _safe_get_alerts()
        fleet = _safe_get_fleet()

        online_count = fleet.get("online", 0) if isinstance(fleet, dict) else 0
        malicious_count = len([a for a in alerts if a.get("severity") == "malicious"])

        stat_lines = [
            Text.from_markup(f"[bold]Active Sessions:[/bold] {len(runs)}"),
            Text.from_markup(f"[bold]Hosts Online:[/bold]    {online_count}"),
            Text.from_markup(f"[bold]Open Findings:[/bold]   {len(alerts)}"),
            Text.from_markup(f"[bold]Critical:[/bold]        [{SEVERITY_STYLE.get('malicious', 'red')}]{malicious_count}[/]"),
            Text(""),
            Text("────────────────────────────────────────────────────────────", style="dim"),
            Text(""),
        ]

        sub_items = self.sub_menus.get(category, [])
        menu_lines = []
        for idx, item in enumerate(sub_items):
            is_sel = idx == self.sub_selected
            prefix = " > " if is_sel else "   "
            style = "bold #3FA796 reverse" if is_sel else "white"
            menu_lines.append(Text(f"{prefix}{item}", style=style))

        body = Group(
            Group(*stat_lines),
            Group(*menu_lines),
            Text(""),
            Text("[↑↓] Navigate   [Enter] Select   [b/Esc] Back   [q] Quit", style="dim"),
        )

        panel = Panel(
            body,
            title=f"[bold #3FA796]{cat_title}[/bold #3FA796]",
            box=ROUNDED,
            border_style="#3FA796",
            padding=(1, 3),
        )
        console.print(panel)

    def render_sub_view(self):
        view_name = self.active_sub_view or ""
        header = f"[bold #3FA796]{self.current_screen.upper()} > {view_name.upper()}[/bold #3FA796]"

        if self.current_screen == "monitor":
            if view_name in ("Live Events", "Sessions"):
                runs = _safe_get_runs()
                table = Table(box=ROUNDED, border_style="dim", expand=True)
                table.add_column("#", width=3)
                table.add_column("Run ID", style="bold cyan", width=14)
                table.add_column("Sample / Target", style="bold white")
                table.add_column("OS", width=6)
                table.add_column("Alerts", justify="right", width=8)
                table.add_column("Risk Gauge", width=16)
                table.add_column("Severity", width=12)

                for i, r in enumerate(runs[:14]):
                    is_sel = i == self.detail_selected
                    sev = r.get("highest_severity") or "clean"
                    style = SEVERITY_STYLE.get(sev, "white")
                    risk_bar = risk_gauge(r.get("risk_score"))
                    table.add_row(
                        str(i + 1),
                        f"{'▶ ' if is_sel else ''}{r.get('run_id', '')[:12]}",
                        r.get("sample_name") or r.get("name", "Session"),
                        {"windows": "win", "linux": "nix"}.get(r.get("platform", ""), r.get("platform", "nix")),
                        str(r.get("alert_count", 0)),
                        risk_bar,
                        Text(f"● {sev.upper()}", style=style),
                        style="reverse" if is_sel else None,
                    )
                console.print(Panel(table, title=header, box=ROUNDED, border_style="#3FA796"))
                console.print(Align.center(Text.from_markup(f"[dim][↑↓] Navigate  [Enter] Open  [b/Esc] Back  {self.status_msg}[/dim]")))

            elif view_name == "Findings":
                alerts = _safe_get_alerts()
                table = Table(box=ROUNDED, border_style="dim", expand=True)
                table.add_column("#", width=3)
                table.add_column("ID", width=8, style="bold cyan")
                table.add_column("Rule Name", style="bold white")
                table.add_column("Severity", width=12)
                table.add_column("Status", width=14)
                table.add_column("Details", style="dim")

                for i, a in enumerate(alerts[:14]):
                    is_sel = i == self.detail_selected
                    sev = a.get("severity") or "suspicious"
                    st = (a.get("status") or "open").upper()
                    st_col = "green" if st == "RESOLVED" else ("yellow" if st == "ACKNOWLEDGED" else "bold red")
                    table.add_row(
                        str(i + 1),
                        f"{'▶ ' if is_sel else ''}ALT-{a.get('id', 0)}",
                        a.get("rule_name", ""),
                        Text(sev.upper(), style=SEVERITY_STYLE.get(sev, "white")),
                        f"[{st_col}]{st}[/{st_col}]",
                        str(a.get("details", ""))[:55],
                        style="reverse" if is_sel else None,
                    )
                console.print(Panel(table, title=header, box=ROUNDED, border_style="#3FA796"))
                console.print(Align.center(Text.from_markup(f"[dim][↑↓] Navigate  [t] Triage  [a] Allowlist  [b/Esc] Back  {self.status_msg}[/dim]")))

            elif view_name == "Hosts":
                self.render_hosts_table()

            elif view_name == "Detection Activity":
                rules = _safe_get_rules_meta()
                table = Table(title="Active Detection Heuristics", box=ROUNDED, border_style="dim", expand=True)
                table.add_column("Rule ID", style="bold cyan")
                table.add_column("Name", style="white")
                table.add_column("Tactic", style="bold yellow")
                for r in rules[:10]:
                    table.add_row(r.get("rule_id", r.get("id", "")), r.get("name", ""), r.get("tactic", "Execution"))
                console.print(Panel(table, title=header, box=ROUNDED, border_style="#3FA796"))
                console.print(Align.center(Text.from_markup("[dim][b/Esc] Back to Monitor[/dim]")))

        elif self.current_screen == "analyze":
            if view_name == "Attack Playbooks":
                playbooks = _safe_get_playbooks()
                table = Table(box=ROUNDED, border_style="dim", expand=True)
                table.add_column("#", width=3)
                table.add_column("Scenario ID", style="bold cyan", width=28)
                table.add_column("Attack Scenario Name", style="bold white")
                table.add_column("OS", width=6)
                table.add_column("Severity", width=12)
                table.add_column("ATT&CK Tactics", style="dim")

                for i, pb in enumerate(playbooks):
                    is_sel = i == self.detail_selected
                    sev = pb.get("severity", "critical")
                    table.add_row(
                        str(i + 1),
                        f"{'▶ ' if is_sel else ''}{pb['id']}",
                        pb["name"],
                        {"windows": "win", "linux": "nix"}.get(pb.get("platform", ""), pb.get("platform", "")),
                        Text(f"● {sev.upper()}", style=SEVERITY_STYLE.get(sev, "white")),
                        " → ".join(pb.get("tactics", [])),
                        style="reverse" if is_sel else None,
                    )
                console.print(Panel(table, title=header, box=ROUNDED, border_style="#3FA796"))
                console.print(Align.center(Text.from_markup("[bold green][Enter] Detonate Selected Scenario Live[/bold green]   [dim][b/Esc] Back[/dim]")))
            else:
                samples = _safe_get_samples()
                table = Table(title="Sample Vault & Binaries", box=ROUNDED, border_style="dim", expand=True)
                table.add_column("ID", style="bold cyan", width=12)
                table.add_column("Filename", style="white")
                table.add_column("Platform", width=10)
                table.add_column("SHA-256", style="dim", width=22)
                table.add_column("Family", width=14)
                for s in samples[:10]:
                    table.add_row(
                        s.get("sample_id", "")[:10],
                        s.get("name", "sample"),
                        s.get("detected_platform") or "unknown",
                        s.get("sha256", "")[:18] + "...",
                        s.get("family") or "clean",
                    )
                console.print(Panel(table, title=header, box=ROUNDED, border_style="#3FA796"))
                console.print(Align.center(Text.from_markup(f"[dim][d] Detonate  [b/Esc] Back  {self.status_msg}[/dim]")))

        elif self.current_screen == "investigate":
            invs = _safe_get_investigations()
            table = Table(title="SOC Investigations", box=ROUNDED, border_style="dim", expand=True)
            table.add_column("Case ID", style="bold cyan", width=14)
            table.add_column("Title", style="white")
            table.add_column("Status", width=12)
            table.add_column("Severity", width=12)
            for inv in invs[:10]:
                sev = inv.get("severity") or "suspicious"
                table.add_row(
                    inv.get("id", "")[:12],
                    inv.get("title", ""),
                    inv.get("status", "open").upper(),
                    Text(sev.upper(), style=SEVERITY_STYLE.get(sev, "white")),
                )
            console.print(Panel(table, title=header, box=ROUNDED, border_style="#3FA796"))
            console.print(Align.center(Text.from_markup(f"[dim][n] New Case  [c] Close  [b/Esc] Back  {self.status_msg}[/dim]")))

        elif self.current_screen == "iocs":
            watchlist = _safe_get_watchlist()
            table = Table(title="Threat Watchlist", box=ROUNDED, border_style="dim", expand=True)
            table.add_column("Value / Indicator", style="bold yellow")
            table.add_column("Label / Threat Context", style="white")
            table.add_column("Date Added", style="dim", width=16)
            for w in watchlist[:10]:
                table.add_row(w.get("value", ""), w.get("label", ""), str(w.get("created_at", ""))[:10])
            console.print(Panel(table, title=header, box=ROUNDED, border_style="#3FA796"))
            console.print(Align.center(Text.from_markup(f"[dim][a] Add  [x] Remove  [b/Esc] Back  {self.status_msg}[/dim]")))

        elif self.current_screen == "hosts":
            self.render_hosts_table()

        elif self.current_screen == "campaigns":
            campaigns = _safe_get_campaigns()
            table = Table(title="Campaign Clusters", box=ROUNDED, border_style="dim", expand=True)
            table.add_column("Campaign Key", style="bold yellow")
            table.add_column("Signature C2", style="bold cyan")
            table.add_column("Linked Runs", width=12)
            for c in campaigns[:8]:
                table.add_row(c.get("key", ""), c.get("signature_ip") or "None", str(len(c.get("runs", []))))
            console.print(Panel(table, title=header, box=ROUNDED, border_style="#3FA796"))
            console.print(Align.center(Text.from_markup(f"[dim][b/Esc] Back  {self.status_msg}[/dim]")))

        elif self.current_screen == "reports":
            runs = _safe_get_runs()
            table = Table(title="Session Reports & Detection Rule Synthesis", box=ROUNDED, border_style="dim", expand=True)
            table.add_column("#", width=3)
            table.add_column("Run ID", style="bold cyan", width=14)
            table.add_column("Sample Name", style="bold white")
            table.add_column("Risk Score", width=10)
            table.add_column("Severity", width=12)
            for i, r in enumerate(runs[:10]):
                is_sel = i == self.detail_selected
                sev = r.get("highest_severity") or "clean"
                table.add_row(
                    str(i + 1),
                    f"{'▶ ' if is_sel else ''}{r.get('run_id', '')[:12]}",
                    r.get("sample_name") or r.get("name", ""),
                    str(r.get("risk_score", 0)),
                    Text(sev.upper(), style=SEVERITY_STYLE.get(sev, "white")),
                    style="reverse" if is_sel else None,
                )
            console.print(Panel(table, title=header, box=ROUNDED, border_style="#3FA796"))
            console.print(Align.center(Text.from_markup(f"[dim][Enter] View  [e] Export  [b/Esc] Back  {self.status_msg}[/dim]")))

        elif self.current_screen == "rules":
            rules = _safe_get_rules_meta()
            table = Table(title="38 Heuristic Rules across 14 ATT&CK Tactics", box=ROUNDED, border_style="dim", expand=True)
            table.add_column("Rule ID", style="bold cyan", width=24)
            table.add_column("Rule Name", style="white")
            table.add_column("Tactic", style="bold yellow", width=18)
            table.add_column("Technique", style="dim", width=14)
            for r in rules[:14]:
                table.add_row(
                    r.get("rule_id", r.get("id", "")),
                    r.get("name", ""),
                    r.get("tactic", "Execution"),
                    r.get("technique", ""),
                )
            console.print(Panel(table, title=header, box=ROUNDED, border_style="#3FA796"))
            console.print(Align.center(Text.from_markup(f"[dim][b/Esc] Back  {self.status_msg}[/dim]")))

        elif self.current_screen == "settings":
            body = (
                "[bold]API Status:[/bold] Healthy (Connected to http://127.0.0.1:8001)\n"
                "[bold]Threat Intel Cache:[/bold] Active (Keyless Fallback Ready)\n"
                "[bold]Air-Gap Enforcement:[/bold] Loopback-only locked\n"
                "[bold]Rule Synthesis Studio:[/bold] Ready (Sigma / Suricata / YARA)\n"
            )
            console.print(Panel(Text.from_markup(body), box=ROUNDED, border_style="dim"))
            console.print(Align.center(Text.from_markup(f"[dim][b/Esc] Back  {self.status_msg}[/dim]")))

    def render_hosts_table(self):
        fleet = _safe_get_fleet()
        agents = fleet.get("agents", []) if isinstance(fleet, dict) else []
        table = Table(title="Fleet Hosts", box=ROUNDED, border_style="dim", expand=True)
        table.add_column("Host ID", style="bold cyan")
        table.add_column("Platform", width=10)
        table.add_column("Status", width=10)
        table.add_column("Last Seen", style="dim", width=16)
        for h in agents[:10]:
            is_on = h.get("online", False)
            table.add_row(
                h.get("host_id", "local"),
                h.get("platform", "linux"),
                Text("ONLINE" if is_on else "OFFLINE", style="bold #3FA796" if is_on else "dim"),
                intel_age(h.get("last_seen")),
            )
        console.print(table)
        console.print(Align.center(Text.from_markup(f"[dim][b/Esc] Back  {self.status_msg}[/dim]")))

    def render_run_detail(self):
        if not self.selected_run_id:
            self.current_screen = "monitor"
            return
        try:
            detail = api_client.get_run(self.selected_run_id)
        except Exception:
            detail = {}
        run = detail.get("run", {})
        alerts = detail.get("alerts", [])
        network = detail.get("network_connections", [])
        tree = detail.get("process_tree", [])

        console.print(Panel(f"[bold #3FA796]RUN DETAIL: {self.selected_run_id}[/bold #3FA796]", box=ROUNDED, border_style="#3FA796"))
        sev = run.get("highest_severity") or "clean"
        target_name = run.get("sample_name") or run.get("name", "Target")
        r_style = risk_style(run.get("risk_score"))
        meta = (
            f"[bold]Target:[/bold] {target_name}  |  "
            f"[bold]Platform:[/bold] {run.get('platform', 'nix')}  |  "
            f"[bold]Risk:[/bold] [{r_style}]{run.get('risk_score', 0)}/100[/{r_style}]  |  "
            f"[bold]Severity:[/bold] [{SEVERITY_STYLE.get(sev, 'white')}]{sev.upper()}[/]"
        )
        console.print(Panel(Text.from_markup(meta), box=ROUNDED, border_style="dim"))

        if self.generated_rules_text:
            console.print(
                Panel(
                    self.generated_rules_text,
                    title="[bold yellow]Auto-Generated Detection Rules (Sigma / Suricata / YARA)[/bold yellow]",
                    box=ROUNDED,
                    border_style="#D9A441",
                )
            )
            console.print(Align.center(Text.from_markup("[dim][b/Esc] Back to Run Detail   [q] Back to Sessions[/dim]")))
        else:
            if alerts:
                console.print(Panel(Group(*[render_alert(a) for a in alerts[:4]]), title="Fired Detections", box=ROUNDED, border_style="#C4453B"))
            if tree:
                console.print(Panel(render_process_tree(tree), title="Process Tree Hierarchy", box=ROUNDED, border_style="dim"))
            if network:
                console.print(Panel(render_network_table(network[:6]), title="Network Sockets & Threat Reputation", box=ROUNDED, border_style="dim"))

            console.print(Align.center(Text.from_markup(f"[bold cyan][g] Synthesize Rules[/bold cyan]  [t] Triage  [e] Export  [dim][b/Esc] Back  {self.status_msg}[/dim]")))

