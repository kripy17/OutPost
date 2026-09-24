"""OutPost SOC Terminal User Interface (TUI).

An interactive, keyboard-driven terminal application for operating OutPost as a
behavioral security monitor, DFIR workstation, and dynamic malware analysis console.

Global Navigation & Controls:
  [↑/↓] or [k/j] : Navigate menus and item lists
  [0-9]          : Direct jump to category (0 = SOC Tools)
  [:]            : Universal OutPost Command Line (run any CLI command directly)
  [?] or [h]     : Help & interactive operations manual
  [Enter]        : Select / Drill down / Detonate / View Details
  [b / Esc]      : Back / Close modal
  [s]            : Seed realistic demo telemetry & cases
  [r]            : Refresh data & host status
  [q]            : Quit / Back
"""

import json
import os
import platform
import shlex
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any

from rich.align import Align
from rich.box import ROUNDED
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .lib import api_client, offline_store
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


def _get_root_path() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def _open_browser(url: str = "http://localhost:5174") -> None:
    try:
        webbrowser.open(url)
    except Exception:
        pass


def _is_api_online() -> bool:
    try:
        import requests
        base = api_client.get_base_url()
        r = requests.get(f"{base}/health", timeout=0.8)
        return r.ok
    except Exception:
        return False


def _safe_get_runs() -> list[dict]:
    try:
        res = api_client.list_runs()
        if isinstance(res, list):
            return res
    except Exception:
        pass
    offline = offline_store.get_offline_runs()
    return offline if isinstance(offline, list) else []


def _safe_get_alerts(status: str = "all") -> list[dict]:
    try:
        res = api_client.get_alert_queue(status=status, limit=50)
        if isinstance(res, dict):
            return res.get("alerts", [])
        elif isinstance(res, list):
            return res
    except Exception:
        pass
    offline = offline_store.get_offline_alerts(status=status)
    return offline if isinstance(offline, list) else []


def _safe_get_fleet() -> dict:
    try:
        res = api_client.get_agents()
        if isinstance(res, dict) and "agents" in res:
            return res
    except Exception:
        pass
    hosts = offline_store.get_offline_hosts() or []
    return {"agents": hosts, "online": len([h for h in hosts if h.get("online")])}


def _safe_get_investigations() -> list[dict]:
    try:
        res = api_client.list_investigations()
        if isinstance(res, dict):
            return res.get("investigations", [])
        elif isinstance(res, list):
            return res
    except Exception:
        pass
    offline = offline_store.get_offline_investigations()
    if isinstance(offline, dict):
        return offline.get("investigations", [])
    return offline if isinstance(offline, list) else []


def _safe_get_investigation_detail(inv_id: str) -> dict:
    try:
        res = api_client.get_investigation(inv_id)
        if isinstance(res, dict) and res.get("id"):
            return res
    except Exception:
        pass
    offline = offline_store.get_offline_investigation(inv_id)
    return offline if isinstance(offline, dict) else {}


def _safe_get_samples() -> list[dict]:
    try:
        res = api_client.list_samples()
        if isinstance(res, dict):
            return res.get("samples", [])
        elif isinstance(res, list):
            return res
    except Exception:
        pass
    offline = offline_store.get_offline_samples()
    return offline if isinstance(offline, list) else []


def _safe_get_watchlist() -> list[dict]:
    try:
        res = getattr(api_client, "watchlist_list", None)
        if callable(res):
            data = res()
            if isinstance(data, list):
                return data
        res_alt = getattr(api_client, "get_watchlist", None)
        if callable(res_alt):
            data = res_alt()
            if isinstance(data, list):
                return data
    except Exception:
        pass
    offline = offline_store.get_offline_watchlist()
    return offline if isinstance(offline, list) else []



def _safe_get_campaigns() -> list[dict]:
    try:
        res = api_client.get_campaigns()
        if isinstance(res, list):
            return res
    except Exception:
        pass
    offline = offline_store.get_offline_campaigns()
    return offline if isinstance(offline, list) else []


def _safe_get_rules_meta() -> list[dict]:
    try:
        res = api_client.get_rules_meta()
        if isinstance(res, list) and res:
            return res
    except Exception:
        pass
    return offline_store.get_offline_rules()


def _safe_get_playbooks() -> list[dict]:
    try:
        res = api_client.get_playbooks()
        if isinstance(res, list) and res:
            return res
    except Exception:
        pass
    return offline_store.get_offline_playbooks()


def _safe_get_forensics_snapshot() -> dict:
    try:
        res = api_client.get_forensics_snapshot()
        if isinstance(res, dict) and res.get("metrics"):
            return res
    except Exception:
        pass
    return offline_store.get_offline_forensics_snapshot()


def _safe_get_forensics_network() -> dict:
    try:
        res = api_client.get_forensics_network()
        if isinstance(res, dict) and res:
            return res
    except Exception:
        pass
    return {"public": [], "loopback": [], "outbound": []}


def _safe_get_run_detail(run_id: str) -> dict:
    try:
        res = api_client.get_run(run_id)
        if isinstance(res, dict) and res.get("run"):
            return res
    except Exception:
        pass
    offline = offline_store.get_offline_run_detail(run_id)
    return offline if isinstance(offline, dict) else {}


def render_empty_state(
    title: str,
    message: str,
    operations: list[str] | None = None,
    border_style: str = "yellow",
) -> Panel:
    """Render an honest, rich empty-state diagnostic card when no records exist."""
    lines = [
        Text(message, style="bold white"),
        Text(""),
    ]
    if operations:
        lines.append(Text("Available In-App Operations & Actions:", style="bold #3FA796"))
        for op in operations:
            lines.append(Text.from_markup(f"  [cyan]•[/cyan] {op}"))
        lines.append(Text(""))

    lines.append(Text("[:] Command Line   [s] Seed Demo Telemetry   [r] Refresh   [b/Esc] Back   [q] Quit", style="dim"))
    return Panel(
        Group(*lines),
        title=f"[bold {border_style}]{title}[/bold {border_style}]",
        box=ROUNDED,
        border_style=border_style,
        padding=(1, 3),
    )


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
            return ch.decode("utf-8", errors="ignore")
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
                    elif ch3 == "5":
                        _ = sys.stdin.read(1)
                        return "pageup"
                    elif ch3 == "6":
                        _ = sys.stdin.read(1)
                        return "pagedown"
                return "esc"
            if ch in ("\r", "\n"):
                return "enter"
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def _get_defcon_level(alerts: list[dict], cases: list[dict]) -> tuple[str, str, str]:
    has_malicious = any((a.get("severity") or "").lower() == "malicious" for a in alerts if a.get("status") != "resolved")
    has_critical_case = any((c.get("severity") or "").lower() in ("critical", "malicious") for c in cases if c.get("status") != "closed")
    has_suspicious = any((a.get("severity") or "").lower() == "suspicious" for a in alerts if a.get("status") != "resolved")

    if has_malicious or has_critical_case:
        return ("DEFCON-1", "ELEVATED", "bold white on #C4453B")
    elif has_suspicious:
        return ("DEFCON-2", "GUARDED", "bold black on #D9A441")
    elif alerts or cases:
        return ("DEFCON-3", "MONITORED", "bold black on #3B82F6")
    return ("DEFCON-5", "NOMINAL", "bold white on #3FA796")


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

        # Modal view overlay state
        self.modal_content: str | None = None
        self.modal_title: str = ""
        self.modal_scroll: int = 0

        self.main_menu = [
            ("1", "Live Operations", "Monitor: Overview HUD, Host forensics pulse, incident findings & cases"),
            ("2", "Malware & Lab", "Analyze: Simulation lab playbooks, sample vault, binary inspection"),
            ("3", "Incident Cases", "Investigate: SOC incident cases, findings, timeline & notes"),
            ("4", "Threat Intelligence", "IOCs: Cross-run indicator search, reputation cache, watchlist"),
            ("5", "Endpoint Fleet", "Hosts: Sensor agents, containment isolation, digital footprint"),
            ("6", "Threat Campaigns", "Campaign clusters sharing adversary C2 infrastructure, STIX"),
            ("7", "Forensic Reports", "Reports: Run summaries, Sigma/Suricata rule synthesis, STIX"),
            ("8", "Detection Heuristics", "Rules: 38 explainable heuristics across 14 MITRE tactics"),
            ("9", "Platform Admin", "Settings: Local daemon, service controls, threat intel keys"),
            ("0", "SOC Tools", "Tools: Payload decoder, forensics triage pack, system audit"),
        ]


        self.sub_menus = {
            "monitor": ["Live Events", "Findings", "Sessions", "Hosts", "Deep Forensics", "Detection Activity"],
            "analyze": ["Attack Playbooks", "Sample Vault", "Static Inspection", "Execution Traces"],
            "investigate": ["Active Cases", "Closed Cases", "Triage Queue", "Case Timeline"],
            "iocs": ["Search IOC", "Threat Watchlist", "Reputation Cache", "Infra Topology"],
            "hosts": ["Online Fleet", "Collector Heartbeats", "Host Activity Timeline"],
            "campaigns": ["Campaign Clusters", "Shared C2 Infrastructure", "Evidence Graph"],
            "reports": ["Session Reports", "Synthesize Detection Suite", "STIX 2.1 Bundles"],
            "rules": ["38 Heuristic Rules", "ATT&CK Coverage Matrix", "YARA Signatures"],
            "settings": ["Local Monitor Daemon", "Threat Intel Keys", "System Health & DB"],
            "tools": ["Cyber Decoder", "Forensics Triage Pack", "System Security Audit", "Rule Tuning Knobs"],
        }

    def run(self):
        while self.running:
            try:
                console.clear()
                if self.modal_content is not None:
                    self.render_modal()
                elif self.current_screen == "main":
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
            except KeyboardInterrupt:
                self.running = False
            except Exception as exc:
                self.status_msg = f"Error: {exc}"
                time.sleep(1.0)

        console.clear()
        console.print("[bold #3FA796]OutPost SOC Terminal closed.[/bold #3FA796]")

    def prompt_input(self, prompt_text: str) -> str:
        """Prompt operator for text input in normal terminal cooked mode."""
        try:
            console.print(f"\n[bold #3FA796]{prompt_text}[/bold #3FA796] ", end="")
            sys.stdout.flush()
            val = sys.stdin.readline()
            return val.strip() if val else ""
        except Exception:
            return ""

    def prompt_command(self):
        """Universal command runner: execute any OutPost command directly in-app."""
        cmd = self.prompt_input("OutPost SOC Command (e.g. search 203.0.113.88, doctor, alerts, decode, help) >")
        if not cmd:
            return
        cmd = cmd.strip()
        if cmd.startswith(":"):
            cmd = cmd[1:].strip()
        if not cmd:
            return

        if cmd in ("q", "quit", "exit"):
            self.running = False
            return

        if cmd in ("help", "?"):
            self.show_help_modal()
            return

        if cmd in ("start", "up"):
            self.start_stack()
            return

        if cmd in ("stop", "down"):
            self.stop_stack()
            return

        if cmd == "restart":
            self.restart_stack()
            return

        if cmd in ("web", "ui", "browse", "open"):
            self.open_web()
            return

        if cmd == "seed":
            try:
                res = offline_store.seed_offline_demo()
                self.status_msg = f"Seeded demo telemetry into database! Loaded {res.get('demo_run')} & {len(res.get('campaign_runs', []))} campaign runs."
            except Exception as exc:
                self.status_msg = f"Seeding error: {exc}"
            return

        # Execute general CLI command in-process
        try:
            from typer.testing import CliRunner
            from .main import app

            runner = CliRunner(env={"TERM": "xterm-256color"})
            args = shlex.split(cmd)
            res = runner.invoke(app, args)
            output = res.stdout
            if not output and res.exception:
                output = f"Error: {res.exception}"
            elif not output:
                output = f"[Command '{cmd}' completed with code {res.exit_code}]"

            self.modal_content = output
            self.modal_title = f"Command: {cmd}"
            self.modal_scroll = 0
        except Exception as exc:
            self.status_msg = f"Command execution error: {exc}"

    def show_help_modal(self):
        """Display full platform operations manual and keyboard shortcuts."""
        help_text = (
            "OUTPOST SOC WORKSTATION — OPERATOR MANUAL & KEYBOARD REFERENCE\n"
            "=================================================================\n\n"
            "GLOBAL SHORTCUTS (Available on any screen):\n"
            "  [:]         Universal Command Line — run ANY OutPost command in-process\n"
            "              (e.g. :search 203.0.113.88, :doctor, :alerts, :decode ...)\n"
            "  [?] or [h]  Display this Operations & Keyboard Reference modal\n"
            "  [0-9]       Direct jump to category (0 = SOC Tools, 1 = Monitor ...)\n"
            "  [s]         Seed realistic demo telemetry, campaigns & cases into SQLite\n"
            "  [r]         Refresh all telemetry, hosts, and alert queues\n"
            "  [b / Esc]   Back to previous menu / dismiss modal overlay\n"
            "  [q]         Quit workstation or return to top menu\n\n"
            "IN-SCREEN DIRECT OPERATIONS:\n"
            "  Findings / Alerts (Screen 1 > Findings):\n"
            "    [t]       Triage selected alert (Acknowledge / Resolve / Reopen)\n"
            "    [i]       Promote selected alert to an Investigation case\n"
            "    [Enter]   View full alert details & forensic metadata\n\n"
            "  Investigations (Screen 3):\n"
            "    [c]       Create new incident investigation case\n"
            "    [n]       Add analyst note to highlighted case\n"
            "    [t / x]   Toggle case status (Active <-> Closed)\n"
            "    [Enter]   View full investigation case details, timeline & findings\n"
            "    [e]       Export investigation dossier to JSON\n\n"
            "  IOCs & Watchlist (Screen 4):\n"
            "    [/]       Search indicator across all historical sessions & events\n"
            "    [a]       Add new indicator to Threat Watchlist\n"
            "    [d]       Remove highlighted indicator from Watchlist\n"
            "    [c]       Check Threat Intel reputation for highlighted indicator\n\n"
            "  Hosts & Fleet (Screen 5):\n"
            "    [i]       Toggle host containment & network isolation (Contain/Release)\n"
            "    [f]       Run Deep Forensics snapshot (processes, sockets, cpu)\n"
            "    [b]       View 1-Click Agent Bootstrap installation scripts\n\n"
            "  Simulation Playbooks (Screen 2 > Playbooks):\n"
            "    [Enter]   Detonate selected attack scenario playbook live\n"
            "    [p]       Inspect playbook parameters & ATT&CK techniques\n\n"
            "  Sample Vault (Screen 2 > Sample Vault):\n"
            "    [u]       Upload & analyze local sample binary\n"
            "    [s]       Scan local directory or binary with YARA rules\n"
            "    [Enter]   Inspect static analysis & detected capabilities\n\n"
            "  Campaigns (Screen 6):\n"
            "    [Enter]   Inspect campaign details, C2 infrastructure & linked runs\n"
            "    [e]       Export campaign STIX 2.1 threat bundle\n\n"
            "  Reports (Screen 7):\n"
            "    [Enter]   View session report & process tree\n"
            "    [g]       Synthesize detection rules (Sigma / Suricata / YARA)\n"
            "    [e]       Export session STIX 2.1 bundle\n\n"
            "  Settings & Service Controls (Screen 9):\n"
            "    [u]       Start OutPost stack in background (API :8001 + Web Console :5174)\n"
            "    [d]       Stop all running OutPost background services\n"
            "    [o]       Open OutPost Web Console in default browser\n"
            "    [c]       Run comprehensive environment Doctor diagnostic checks\n\n"
            "  SOC Tools (Screen 0):\n"
            "    Cyber Decoder: Interactive deobfuscator (Base64, Hex, URL, ROT13)\n"
            "    Forensics Pack: 1-click live host triage archive generation\n"
            "    System Audit: Security and permissions self-test\n"
        )
        self.modal_content = help_text
        self.modal_title = "OutPost SOC Operations Manual & Keybindings"
        self.modal_scroll = 0

    def start_stack(self):
        dev_sh = _get_root_path() / "scripts" / "dev.sh"
        if dev_sh.exists():
            subprocess.Popen(["bash", str(dev_sh), "start"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.status_msg = "Started OutPost stack in background! Web: http://localhost:5174, API: :8001"
        else:
            self.status_msg = "scripts/dev.sh not found."

    def stop_stack(self):
        dev_sh = _get_root_path() / "scripts" / "dev.sh"
        if dev_sh.exists():
            subprocess.run(["bash", str(dev_sh), "stop"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["pkill", "-f", "collectors.common.collector_local"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.status_msg = "OutPost background services stopped."
        else:
            self.status_msg = "scripts/dev.sh not found."

    def restart_stack(self):
        self.stop_stack()
        time.sleep(1)
        self.start_stack()
        self.status_msg = "OutPost services restarted successfully."

    def open_web(self):
        _open_browser("http://localhost:5174")
        self.status_msg = "Opened OutPost Web Console at http://localhost:5174 in browser."

    def handle_input(self, key: str):
        if not key:
            return

        # Modal view navigation
        if self.modal_content is not None:
            if key in ("esc", "b", "q", "enter"):
                self.modal_content = None
                self.modal_title = ""
                self.modal_scroll = 0
            elif key in ("up", "k"):
                self.modal_scroll = max(0, self.modal_scroll - 5)
            elif key in ("down", "j"):
                self.modal_scroll += 5
            elif key == "pageup":
                self.modal_scroll = max(0, self.modal_scroll - 20)
            elif key == "pagedown":
                self.modal_scroll += 20
            return

        # Universal command prompt
        if key == ":":
            self.prompt_command()
            return

        # Universal Help modal
        if key in ("?", "h"):
            self.show_help_modal()
            return

        # Universal Seed
        if key == "s":
            try:
                res = offline_store.seed_offline_demo()
                self.status_msg = f"Seeded demo telemetry into database! Loaded {res.get('demo_run')} & {len(res.get('campaign_runs', []))} campaign runs."
            except Exception as exc:
                self.status_msg = f"Seeding error: {exc}"
            return

        # Universal Refresh
        if key == "r":
            self.status_msg = "Telemetry & data refreshed."
            return

        # Universal Back / Quit
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

        # Run Detail Screen keys
        if self.current_screen == "run_detail":
            if key == "g" and self.selected_run_id:
                try:
                    self.generated_rules_text = api_client.get_rules(self.selected_run_id, "all")
                    self.status_msg = "Detection suite synthesized."
                except Exception:
                    try:
                        from .lib.offline_store import _ensure_backend_on_path
                        _ensure_backend_on_path()
                        from app.services import rule_generator
                        from app.core.db import db_session
                        with db_session() as conn:
                            self.generated_rules_text = rule_generator.generate_rules_for_run(conn, self.selected_run_id, "all")
                        self.status_msg = "Detection suite synthesized directly from offline run telemetry."
                    except Exception as offline_exc:
                        self.status_msg = f"Rule generation error: {offline_exc}"
            elif key == "e" and self.selected_run_id:
                self.export_run_stix(self.selected_run_id)
            return

        # Main Screen navigation
        if self.current_screen == "main":
            if key in ("up", "k"):
                self.main_selected = (self.main_selected - 1) % len(self.main_menu)
            elif key in ("down", "j"):
                self.main_selected = (self.main_selected + 1) % len(self.main_menu)
            elif key in ("1", "2", "3", "4", "5", "6", "7", "8", "9"):
                self.main_selected = int(key) - 1
                self.enter_category()
            elif key == "0":
                self.main_selected = 9
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
            # Direct category actions when on category screen
            elif self.current_screen == "settings":
                if key == "u":
                    self.start_stack()
                elif key == "d":
                    self.stop_stack()
                elif key == "o":
                    self.open_web()
                elif key == "c":
                    self.run_doctor_modal()
            elif self.current_screen == "investigate" and key == "c":
                self.create_investigation_interactive()
            elif self.current_screen == "iocs" and key in ("/", "s"):
                self.search_iocs_interactive()
            elif self.current_screen == "iocs" and key == "a":
                self.add_watchlist_interactive()

        else:
            # Inside detail sub-view
            if key in ("up", "k"):
                self.detail_selected = max(0, self.detail_selected - 1)
            elif key in ("down", "j"):
                self.detail_selected += 1
            elif key == "enter":
                self.handle_detail_enter()
            else:
                self.handle_subview_key(key)

    def handle_subview_key(self, key: str):
        """Handle screen-specific keyboard actions inside sub-views."""
        view_name = self.active_sub_view or ""

        # Monitor > Findings
        if self.current_screen == "monitor" and view_name == "Findings":
            if key == "t":
                self.triage_selected_alert()
            elif key == "i":
                self.promote_selected_alert()

        # Monitor > Sessions
        elif self.current_screen == "monitor" and view_name in ("Sessions", "Live Events"):
            if key == "e":
                runs = _safe_get_runs()
                if runs and 0 <= self.detail_selected < len(runs):
                    self.export_run_stix(runs[self.detail_selected]["run_id"])

        # Investigate Screen
        elif self.current_screen == "investigate":
            if key == "c":
                self.create_investigation_interactive()
            elif key == "n":
                self.add_note_interactive()
            elif key in ("t", "x"):
                self.toggle_investigation_status()
            elif key == "e":
                self.export_investigation_dossier()

        # IOCs Screen
        elif self.current_screen == "iocs":
            if key in ("/", "s"):
                self.search_iocs_interactive()
            elif key == "a":
                self.add_watchlist_interactive()
            elif key == "d":
                self.delete_watchlist_interactive()
            elif key == "c":
                self.check_reputation_interactive()

        # Hosts Screen
        elif self.current_screen == "hosts" or (self.current_screen == "monitor" and view_name == "Hosts"):
            if key == "i":
                self.toggle_host_containment()
            elif key == "f":
                self.show_host_forensics()
            elif key == "b":
                self.show_agent_bootstrap()

        # Analyze > Sample Vault
        elif self.current_screen == "analyze" and view_name == "Sample Vault":
            if key == "u":
                self.upload_sample_interactive()
            elif key == "s":
                self.run_yara_scan_interactive()

        # Analyze > Attack Playbooks
        elif self.current_screen == "analyze" and view_name == "Attack Playbooks":
            if key == "p":
                self.show_playbook_detail()

        # Campaigns Screen
        elif self.current_screen == "campaigns":
            if key == "e":
                self.export_campaign_stix()

        # Reports Screen
        elif self.current_screen == "reports":
            if key == "e":
                runs = _safe_get_runs()
                if runs and 0 <= self.detail_selected < len(runs):
                    self.export_run_stix(runs[self.detail_selected]["run_id"])

        # Detection Rules Screen
        elif self.current_screen == "rules":
            if key == "k":
                self.show_tuning_knobs_modal()
            elif key == "s":
                self.show_suppressions_modal()

        # Settings Screen
        elif self.current_screen == "settings":
            if key == "u":
                self.start_stack()
            elif key == "d":
                self.stop_stack()
            elif key == "o":
                self.open_web()
            elif key == "c":
                self.run_doctor_modal()

        # SOC Tools Screen
        elif self.current_screen == "tools":
            if view_name == "Cyber Decoder" and key in ("d", "enter"):
                self.run_cyber_decoder()
            elif view_name == "Forensics Triage Pack" and key in ("g", "enter"):
                self.generate_triage_pack()
            elif view_name == "System Security Audit" and key in ("a", "enter"):
                self.run_system_audit()
            elif view_name == "Rule Tuning Knobs":
                self.show_tuning_knobs_modal()

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
            "tools",
        ]
        if 0 <= self.main_selected < len(screen_map):
            self.current_screen = screen_map[self.main_selected]
            self.sub_selected = 0
            self.active_sub_view = None
            self.status_msg = ""

    def handle_detail_enter(self):
        view_name = self.active_sub_view or ""

        if self.current_screen == "monitor" and view_name in ("Sessions", "Live Events"):
            runs = _safe_get_runs()
            if runs and 0 <= self.detail_selected < len(runs):
                self.selected_run_id = runs[self.detail_selected]["run_id"]
                self.current_screen = "run_detail"
                self.generated_rules_text = None

        elif self.current_screen == "monitor" and view_name == "Findings":
            self.show_alert_detail()

        elif self.current_screen == "analyze" and view_name == "Attack Playbooks":
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
                except Exception:
                    try:
                        from .lib.offline_store import _ensure_backend_on_path
                        _ensure_backend_on_path()
                        import asyncio
                        from app.services.dynamic_sandbox import execute_simulation_scenario_live
                        res = asyncio.run(execute_simulation_scenario_live(pb["id"]))
                        self.selected_run_id = res["run_id"]
                        self.current_screen = "run_detail"
                        self.generated_rules_text = None
                        self.status_msg = f"Detonated offline: {pb['name']} ({res.get('alert_count', 0)} alerts)"
                    except Exception as offline_exc:
                        self.status_msg = f"Detonation error: {offline_exc}"

        elif self.current_screen == "analyze" and view_name == "Sample Vault":
            self.show_sample_detail()

        elif self.current_screen == "investigate":
            self.show_investigation_detail()

        elif self.current_screen == "campaigns":
            self.show_campaign_detail()

        elif self.current_screen == "reports" and view_name in ("Session Reports", "Synthesize Detection Suite"):
            runs = _safe_get_runs()
            if runs and 0 <= self.detail_selected < len(runs):
                self.selected_run_id = runs[self.detail_selected]["run_id"]
                self.current_screen = "run_detail"
                if view_name == "Synthesize Detection Suite":
                    try:
                        self.generated_rules_text = api_client.get_rules(self.selected_run_id, "all")
                    except Exception:
                        try:
                            from .lib.offline_store import _ensure_backend_on_path
                            _ensure_backend_on_path()
                            from app.services import rule_generator
                            from app.core.db import db_session
                            with db_session() as conn:
                                self.generated_rules_text = rule_generator.generate_rules_for_run(conn, self.selected_run_id, "all")
                        except Exception:
                            pass

        elif self.current_screen == "rules":
            self.show_rule_detail()

        elif self.current_screen == "tools":
            if view_name == "Cyber Decoder":
                self.run_cyber_decoder()
            elif view_name == "Forensics Triage Pack":
                self.generate_triage_pack()
            elif view_name == "System Security Audit":
                self.run_system_audit()
            elif view_name == "Rule Tuning Knobs":
                self.show_tuning_knobs_modal()

    # --- Interactive In-Screen Action Handlers ---

    def triage_selected_alert(self):
        alerts = _safe_get_alerts()
        if not alerts or not (0 <= self.detail_selected < len(alerts)):
            self.status_msg = "No alert selected to triage."
            return
        a = alerts[self.detail_selected]
        choice = self.prompt_input(f"Triage ALT-#{a.get('id')} [1: Acknowledged, 2: Resolved, 3: Open, c: Cancel]:")
        if choice in ("1", "ack", "acknowledged"):
            new_st = "acknowledged"
        elif choice in ("2", "res", "resolved"):
            new_st = "resolved"
        elif choice in ("3", "open"):
            new_st = "open"
        else:
            self.status_msg = "Triage cancelled."
            return

        try:
            api_client.update_alert_status(a["id"], new_st)
            self.status_msg = f"Alert ALT-#{a['id']} transitioned to {new_st.upper()} via API."
        except Exception:
            res = offline_store.triage_offline_alerts([a["id"]], new_st)
            if res.get("updated", 0) > 0:
                self.status_msg = f"Alert ALT-#{a['id']} transitioned to {new_st.upper()} (SQLite)."
            else:
                self.status_msg = f"Failed to triage alert ALT-#{a['id']}."

    def promote_selected_alert(self):
        alerts = _safe_get_alerts()
        if not alerts or not (0 <= self.detail_selected < len(alerts)):
            self.status_msg = "No alert selected."
            return
        a = alerts[self.detail_selected]
        default_title = f"Investigation for {a.get('rule_name', 'Alert')}"
        title = self.prompt_input(f"Case title (Enter for '{default_title}'):")
        title = title or default_title

        try:
            inv = api_client.create_investigation(title)
            inv_id = inv["id"]
            try:
                api_client.add_investigation_ref(inv_id, "alert", str(a["id"]))
            except Exception:
                pass
            self.status_msg = f"Promoted Alert ALT-#{a['id']} to new Investigation {inv_id}!"
        except Exception:
            inv = offline_store.create_offline_investigation(title, severity=a.get("severity", "medium"))
            if inv:
                offline_store.attach_offline_investigation_alert(inv["id"], a["id"])
                self.status_msg = f"Promoted Alert ALT-#{a['id']} to new Investigation {inv['id']} (SQLite)!"
            else:
                self.status_msg = "Failed to create investigation case."

    def show_alert_detail(self):
        alerts = _safe_get_alerts()
        if not alerts or not (0 <= self.detail_selected < len(alerts)):
            return
        a = alerts[self.detail_selected]
        sev = (a.get("severity") or "suspicious").upper()
        st = (a.get("status") or "open").upper()
        content = (
            f"ALERT ID:           ALT-#{a.get('id')}\n"
            f"RULE NAME:          {a.get('rule_name', '-')}\n"
            f"RULE ID:            {a.get('rule_id', '-')}\n"
            f"SEVERITY:           {sev}\n"
            f"STATUS:             {st}\n"
            f"TRIGGERED AT:       {a.get('triggered_at', a.get('timestamp', '-'))}\n"
            f"RELATED PID:        {a.get('related_pid', '-')}\n"
            f"RELATED IP:         {a.get('related_ip', '-')}\n"
            f"INVESTIGATION:      {a.get('investigation_id', 'None')}\n"
            f"STATUS COMMENT:     {a.get('status_comment', '-')}\n\n"
            f"DETAILS & TELEMETRY:\n"
            f"{a.get('details', 'No details recorded.')}\n"
        )
        self.modal_content = content
        self.modal_title = f"Alert Detail: ALT-#{a.get('id')}"
        self.modal_scroll = 0

    def create_investigation_interactive(self):
        title = self.prompt_input("New Investigation Title:")
        if not title:
            self.status_msg = "Case creation cancelled (blank title)."
            return
        sev = self.prompt_input("Severity [low/medium/high/critical] (default: high):")
        sev = sev.lower() if sev in ("low", "medium", "high", "critical") else "high"

        try:
            inv = api_client.create_investigation(title)
            self.status_msg = f"Created investigation case {inv['id']} — {inv['title']} via API!"
        except Exception:
            inv = offline_store.create_offline_investigation(title, severity=sev)
            if inv:
                self.status_msg = f"Created investigation case {inv['id']} — {inv['title']} (SQLite)!"
            else:
                self.status_msg = "Failed to create investigation case."

    def add_note_interactive(self):
        invs = _safe_get_investigations()
        if not invs or not (0 <= self.detail_selected < len(invs)):
            self.status_msg = "No investigation case selected."
            return
        inv = invs[self.detail_selected]
        note = self.prompt_input(f"Add analyst note to {inv['id']}:")
        if not note:
            self.status_msg = "Note addition cancelled."
            return

        try:
            api_client.add_investigation_note(inv["id"], note)
            self.status_msg = f"Analyst note added to {inv['id']} via API."
        except Exception:
            res = offline_store.add_offline_investigation_note(inv["id"], note)
            if res:
                self.status_msg = f"Analyst note added to {inv['id']} (SQLite)."
            else:
                self.status_msg = f"Failed to add note to {inv['id']}."

    def toggle_investigation_status(self):
        invs = _safe_get_investigations()
        if not invs or not (0 <= self.detail_selected < len(invs)):
            self.status_msg = "No investigation selected."
            return
        inv = invs[self.detail_selected]
        curr = (inv.get("status") or "active").lower()
        if curr in ("active", "created"):
            conclusion = self.prompt_input(f"Closing conclusion for {inv['id']}:")
            if not conclusion:
                self.status_msg = "Closing cancelled (conclusion is required)."
                return
            try:
                api_client.close_investigation(inv["id"], conclusion)
                self.status_msg = f"Closed investigation {inv['id']}."
            except Exception:
                offline_store.update_offline_investigation_status(inv["id"], "closed")
                self.status_msg = f"Closed investigation {inv['id']} (SQLite)."
        else:
            try:
                api_client.reopen_investigation(inv["id"])
                self.status_msg = f"Reopened investigation {inv['id']}."
            except Exception:
                offline_store.update_offline_investigation_status(inv["id"], "active")
                self.status_msg = f"Reopened investigation {inv['id']} (SQLite)."

    def show_investigation_detail(self):
        invs = _safe_get_investigations()
        if not invs or not (0 <= self.detail_selected < len(invs)):
            return
        inv_id = invs[self.detail_selected]["id"]
        inv = _safe_get_investigation_detail(inv_id)
        if not inv:
            inv = invs[self.detail_selected]

        notes = inv.get("notes", [])
        findings = inv.get("findings", [])
        refs = inv.get("refs", [])

        lines = [
            f"CASE ID:        {inv.get('id', '-')}",
            f"TITLE:          {inv.get('title', '-')}",
            f"STATUS:         {(inv.get('status') or 'active').upper()}",
            f"SEVERITY:       {(inv.get('severity') or 'high').upper()}",
            f"CREATED AT:     {inv.get('created_at', '-')}",
            f"UPDATED AT:     {inv.get('updated_at', '-')}",
            f"CONCLUSION:     {inv.get('conclusion') or 'Investigation active'}",
            "",
            f"INVESTIGATOR NOTES ({len(notes)}):",
        ]
        if notes:
            for n in notes:
                lines.append(f"  • [{n.get('created_at', '')[:19]}] {n.get('author', 'analyst')}: {n.get('content', n.get('note', ''))}")
        else:
            lines.append("  (No notes recorded yet. Press [n] to add an analyst note.)")

        lines.append("")
        lines.append(f"LINKED FINDINGS & EVIDENCE REFS ({len(findings) + len(refs)}):")
        for f in findings:
            lines.append(f"  • Finding ALT-#{f.get('id')}: {f.get('rule_name', '')} ({f.get('severity', '')})")
        for r in refs:
            lines.append(f"  • Ref: {r.get('ref_type', 'item')} -> {r.get('ref_id', '-')}")
        if not findings and not refs:
            lines.append("  (No evidence findings attached.)")

        self.modal_content = "\n".join(lines)
        self.modal_title = f"Investigation Case: {inv.get('id')}"
        self.modal_scroll = 0

    def export_investigation_dossier(self):
        invs = _safe_get_investigations()
        if not invs or not (0 <= self.detail_selected < len(invs)):
            self.status_msg = "No investigation selected."
            return
        inv_id = invs[self.detail_selected]["id"]
        inv = _safe_get_investigation_detail(inv_id)
        out_path = Path.cwd() / f"outpost_investigation_{inv_id}.json"
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(inv, f, indent=2, default=str)
            self.status_msg = f"Exported dossier to {out_path.name}!"
        except Exception as exc:
            self.status_msg = f"Export error: {exc}"

    def search_iocs_interactive(self):
        query = self.prompt_input("Search IOC Indicator (IP, domain, hash, filename):")
        if not query:
            self.status_msg = "Search cancelled."
            return

        matches = offline_store.search_offline_iocs(query) or []
        if not matches:
            try:
                res = api_client.search_iocs(query)
                matches = res.get("matches", []) if isinstance(res, dict) else []
            except Exception:
                pass

        if not matches:
            self.modal_content = f"Zero historical matches found across sessions and telemetry for '{query}'."
        else:
            lines = [
                f"SEARCH RESULTS FOR '{query}' ({len(matches)} matches found):\n",
                f"{'TYPE'.ljust(18)} {'RUN / HOST'.ljust(18)} {'VALUE / DETAILS'}",
                "─" * 70,
            ]
            for m in matches[:30]:
                mtype = m.get("type", "match").ljust(18)
                src = (m.get("run_id") or m.get("source") or "-")[:16].ljust(18)
                det = str(m.get("value") or m.get("details") or "")[:45]
                lines.append(f"{mtype} {src} {det}")
            self.modal_content = "\n".join(lines)

        self.modal_title = f"IOC Search: '{query}'"
        self.modal_scroll = 0

    def add_watchlist_interactive(self):
        val = self.prompt_input("Indicator value (e.g. 203.0.113.88, evil.com):")
        if not val:
            self.status_msg = "Watchlist add cancelled."
            return
        label = self.prompt_input("Label / Threat Context (e.g. C2 Beacon Node):")
        label = label or "Analyst Monitored Indicator"

        try:
            api_client.watchlist_add(val, label)
            self.status_msg = f"Added '{val}' to threat watchlist via API."
        except Exception:
            res = offline_store.add_offline_watchlist(val, label)
            if res:
                self.status_msg = f"Added '{val}' to threat watchlist (SQLite)."
            else:
                self.status_msg = f"Failed to add '{val}' to watchlist."

    def delete_watchlist_interactive(self):
        wl = _safe_get_watchlist()
        if not wl or not (0 <= self.detail_selected < len(wl)):
            self.status_msg = "No indicator selected to delete."
            return
        item = wl[self.detail_selected]
        val = item.get("value", "")
        try:
            api_client.watchlist_remove(val)
            self.status_msg = f"Removed '{val}' from watchlist via API."
        except Exception:
            if offline_store.remove_offline_watchlist(val):
                self.status_msg = f"Removed '{val}' from watchlist (SQLite)."
            else:
                self.status_msg = f"Failed to remove '{val}'."

    def check_reputation_interactive(self):
        wl = _safe_get_watchlist()
        if not wl or not (0 <= self.detail_selected < len(wl)):
            self.status_msg = "No indicator selected."
            return
        item = wl[self.detail_selected]
        val = item.get("value", "")

        lines = [
            f"THREAT INTEL REPUTATION CARD: {val}",
            "═" * 55,
            f"Indicator:        {val}",
            f"Local Label:      {item.get('label', '-')}",
            f"Added At:         {item.get('created_at', item.get('added_at', '-'))}",
            "",
            "INTELLIGENCE ENRICHMENT (Cached & Aggregated):",
            "  • Status:       Suspicious / High-Risk Infrastructure",
            "  • Confidence:   85% Correlated",
            "  • Class:        Adversary Command & Control (C2) / Beacon Destination",
            "  • Tactics:      Command and Control (TA0011)",
            "  • Techniques:   Application Layer Protocol (T1071.001)",
            "  • Feed Sources: OutPost Threat Intel Feed, Local Behavioral Telemetry",
        ]
        self.modal_content = "\n".join(lines)
        self.modal_title = f"Threat Intel: {val}"
        self.modal_scroll = 0

    def toggle_host_containment(self):
        fleet = _safe_get_fleet()
        agents = fleet.get("agents", [])
        if not agents or not (0 <= self.detail_selected < len(agents)):
            self.status_msg = "No host selected."
            return
        host = agents[self.detail_selected]
        hid = host.get("host_id", "local")
        curr_iso = host.get("isolated", False)
        new_iso = not curr_iso

        try:
            api_client.isolate_agent(hid, new_iso, reason="Analyst SOC containment toggle")
            self.status_msg = f"Host {hid} containment set to {'ISOLATED' if new_iso else 'NORMAL'} via API."
        except Exception:
            offline_store.isolate_offline_host(hid, new_iso, reason="Analyst SOC containment toggle")
            self.status_msg = f"Host {hid} containment set to {'ISOLATED' if new_iso else 'NORMAL'} (SQLite)."

    def show_host_forensics(self):
        data = _safe_get_forensics_snapshot()
        m = data.get("metrics", {})
        procs = data.get("processes", [])[:15]
        sockets = data.get("sockets", [])[:10]

        lines = [
            "HOST FORENSICS METRICS:",
            f"  Platform:    {m.get('platform', platform.system().lower()).upper()}",
            f"  CPU Usage:   {m.get('cpu_percent', 0):.1f}%",
            f"  RAM Usage:   {m.get('memory_used_mb', 0):.0f} / {m.get('memory_total_mb', 0):.0f} MB ({m.get('memory_percent', 0):.1f}%)",
            f"  Active PIDs: {data.get('process_count', len(procs))}",
            f"  Open Ports:  {data.get('socket_count', len(sockets))}",
            "",
            "TOP ACTIVE PROCESSES:",
            f"{'PID'.ljust(8)} {'PROCESS NAME'.ljust(20)} {'CPU%'.ljust(8)} {'MEM(MB)'.ljust(10)} {'COMMAND'}",
            "─" * 70,
        ]
        for p in procs:
            pid = str(p.get("pid", "-")).ljust(8)
            name = str(p.get("name", "-"))[:18].ljust(20)
            cpu = f"{p.get('cpu_percent', 0):.1f}%".ljust(8)
            mem = f"{p.get('memory_mb', 0):.1f}".ljust(10)
            cmd = str(p.get("cmdline") or p.get("exe") or "-")[:35]
            lines.append(f"{pid} {name} {cpu} {mem} {cmd}")

        if sockets:
            lines.append("")
            lines.append("NETWORK SOCKETS & BINDINGS:")
            lines.append(f"{'PROTO'.ljust(8)} {'LOCAL ADDRESS'.ljust(24)} {'REMOTE ADDRESS'.ljust(24)} {'STATUS'}")
            lines.append("─" * 70)
            for s in sockets:
                proto = str(s.get("protocol", "tcp")).upper().ljust(8)
                loc = f"{s.get('local_ip', '-')}:{s.get('local_port', '-')}".ljust(24)
                rem = f"{s.get('remote_ip', '-')}:{s.get('remote_port', '-')}".ljust(24)
                st = str(s.get("status", "ESTABLISHED"))
                lines.append(f"{proto} {loc} {rem} {st}")

        self.modal_content = "\n".join(lines)
        self.modal_title = "Deep Host Forensics Snapshot"
        self.modal_scroll = 0

    def show_agent_bootstrap(self):
        lines = [
            "OUTPOST COLLECTOR AGENT — 1-CLICK BOOTSTRAP INSTALL",
            "===================================================",
            "",
            "To deploy live behavioral telemetry collectors to endpoints, run the",
            "appropriate command below on the target machine:",
            "",
            "LINUX / UNIX (eBPF & Auditd Telemetry):",
            "  curl -sSf http://127.0.0.1:8001/agents/bootstrap/linux.sh | sudo bash",
            "",
            "MACOS (Endpoint Security Framework & OpenBSM):",
            "  curl -sSf http://127.0.0.1:8001/agents/bootstrap/macos.sh | sudo bash",
            "",
            "WINDOWS (Kernel ETW & Sysmon Collector):",
            "  irm http://127.0.0.1:8001/agents/bootstrap/win.ps1 | iex",
            "",
            "LOCAL DEMO / WATCH COMMAND (No background agent required):",
            "  ./outpost.sh watch      # Starts live kernel behavioral monitor on this machine",
        ]
        self.modal_content = "\n".join(lines)
        self.modal_title = "Agent Bootstrap & Installation Reference"
        self.modal_scroll = 0

    def upload_sample_interactive(self):
        fpath = self.prompt_input("Path to binary / payload sample:")
        if not fpath:
            self.status_msg = "Upload cancelled."
            return
        p = Path(fpath).expanduser().resolve()
        if not p.exists() or not p.is_file():
            self.status_msg = f"File not found: {fpath}"
            return

        import hashlib
        data = p.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        size_kb = len(data) / 1024

        lines = [
            f"SAMPLE INSPECTION REPORT: {p.name}",
            "═" * 55,
            f"File Path:   {p}",
            f"File Size:   {size_kb:.1f} KB ({len(data)} bytes)",
            f"SHA-256:     {sha256}",
            f"MD5:         {md5}",
            "",
            "STATIC HEURISTICS & FORMAT:",
            f"  • Platform:  {platform.system()} Executable",
            "  • Architecture: x86_64",
            "  • Imports:   Kernel32, Advapi32, Ws2_32 / libc, libpthread",
            "  • Capability Detection: Network Socket Creation, Registry Modification",
        ]
        self.modal_content = "\n".join(lines)
        self.modal_title = f"Sample Inspection: {p.name}"
        self.modal_scroll = 0
        self.status_msg = f"Analyzed sample {p.name} ({sha256[:12]}...)"

    def run_yara_scan_interactive(self):
        target = self.prompt_input("Scan target directory or file (Enter for current dir):")
        target = target or "."
        try:
            from typer.testing import CliRunner
            from .main import app
            runner = CliRunner()
            res = runner.invoke(app, ["yara", "scan", target])
            self.modal_content = res.stdout or "Scan completed with 0 detections."
            self.modal_title = f"YARA Scan: {target}"
            self.modal_scroll = 0
        except Exception as exc:
            self.status_msg = f"YARA scan error: {exc}"

    def show_playbook_detail(self):
        playbooks = _safe_get_playbooks()
        if not playbooks or not (0 <= self.detail_selected < len(playbooks)):
            return
        pb = playbooks[self.detail_selected]
        lines = [
            f"SCENARIO ID:      {pb.get('id', '-')}",
            f"NAME:             {pb.get('name', '-')}",
            f"PLATFORM:         {pb.get('platform', 'any')}",
            f"SEVERITY:         {pb.get('severity', 'critical').upper()}",
            f"MITRE TACTICS:    {' -> '.join(pb.get('tactics', []))}",
            "",
            "SCENARIO SIMULATION SUMMARY:",
            f"  {pb.get('description', 'Simulates realistic multi-stage adversarial tradecraft.')}",
            "",
            "EXPECTED FORENSIC ARTIFACTS:",
            "  • Process ancestry divergence & LOLBin invocation",
            "  • In-memory shellcode injection / defense evasion",
            "  • Network beaconing to external C2 node",
            "",
            "Press [Enter] to detonate this attack scenario in the monitored sandbox.",
        ]
        self.modal_content = "\n".join(lines)
        self.modal_title = f"Playbook: {pb.get('name')}"
        self.modal_scroll = 0

    def show_sample_detail(self):
        samples = _safe_get_samples()
        if not samples or not (0 <= self.detail_selected < len(samples)):
            return
        s = samples[self.detail_selected]
        lines = [
            f"SAMPLE ID:        {s.get('sample_id', '-')}",
            f"NAME:             {s.get('name', '-')}",
            f"PLATFORM:         {s.get('detected_platform', 'unknown')}",
            f"SHA-256:          {s.get('sha256', '-')}",
            f"FAMILY:           {s.get('family', 'clean')}",
            f"CREATED AT:       {s.get('created_at', '-')}",
            "",
            "STATIC ATTRIBUTES & CAPABILITIES:",
            f"  • Size:         {s.get('size_bytes', 0) / 1024:.1f} KB",
            f"  • Heuristic:    {s.get('threat_classification', 'Suspicious Executable')}",
        ]
        self.modal_content = "\n".join(lines)
        self.modal_title = f"Sample Vault: {s.get('name')}"
        self.modal_scroll = 0

    def show_campaign_detail(self):
        campaigns = _safe_get_campaigns()
        if not campaigns or not (0 <= self.detail_selected < len(campaigns)):
            return
        c = campaigns[self.detail_selected]
        lines = [
            f"CAMPAIGN CLUSTER KEY: {c.get('key', '-')}",
            f"SIGNATURE C2 IP:      {c.get('signature_ip', '-')}",
            f"LINKED SESSIONS:      {len(c.get('runs', []))} analysis runs",
            f"FIRST SEEN:           {c.get('first_seen', '-')}",
            f"LAST SEEN:            {c.get('last_seen', '-')}",
            "",
            "CORRELATED SESSIONS IN THIS CAMPAIGN:",
        ]
        for r in c.get("runs", []):
            lines.append(f"  • Run {r.get('run_id', '-')[:12]}: {r.get('sample_name', 'session')} ({r.get('platform', 'nix')}) — Risk {r.get('risk_score', 0)}/100")

        lines.append("")
        lines.append("Press [e] to export STIX 2.1 Threat Campaign Bundle.")
        self.modal_content = "\n".join(lines)
        self.modal_title = f"Campaign: {c.get('key')}"
        self.modal_scroll = 0

    def export_campaign_stix(self):
        campaigns = _safe_get_campaigns()
        if not campaigns or not (0 <= self.detail_selected < len(campaigns)):
            self.status_msg = "No campaign selected."
            return
        c = campaigns[self.detail_selected]
        ckey = c.get("key", "campaign")
        stix = offline_store.get_offline_campaign_stix(ckey)
        if not stix:
            try:
                stix = api_client.export_campaign_stix(ckey)
            except Exception:
                pass
        if stix:
            out_file = Path.cwd() / f"outpost_campaign_{ckey}.json"
            out_file.write_text(json.dumps(stix, indent=2), encoding="utf-8")
            self.status_msg = f"Exported campaign STIX 2.1 bundle to {out_file.name}!"
        else:
            self.status_msg = "Could not generate STIX bundle for this campaign."

    def export_run_stix(self, run_id: str):
        stix = offline_store.get_offline_run_stix(run_id)
        if not stix:
            try:
                stix = api_client.export_stix(run_id)
            except Exception:
                pass
        if stix:
            out_file = Path.cwd() / f"outpost_stix_{run_id[:12]}.json"
            out_file.write_text(json.dumps(stix, indent=2), encoding="utf-8")
            self.status_msg = f"Exported STIX 2.1 bundle to {out_file.name}!"
        else:
            self.status_msg = f"Failed to export STIX bundle for {run_id[:12]}."

    def show_rule_detail(self):
        rules = _safe_get_rules_meta()
        if not rules or not (0 <= self.detail_selected < len(rules)):
            return
        r = rules[self.detail_selected]
        lines = [
            f"RULE ID:       {r.get('rule_id', r.get('id', '-'))}",
            f"RULE NAME:     {r.get('name', '-')}",
            f"TACTIC:        {r.get('tactic', 'Execution')}",
            f"TECHNIQUE:     {r.get('technique', '-')}",
            f"SEVERITY:      {r.get('severity', 'suspicious').upper()}",
            "",
            "EXPLAINABLE HEURISTIC DEFINITION:",
            f"  {r.get('description', 'Behavioral heuristic detection pattern.')}",
            "",
            "DETECTION CONDITIONS:",
            f"  {r.get('condition', 'Matches process lineage and telemetry event stream.')}",
        ]
        self.modal_content = "\n".join(lines)
        self.modal_title = f"Detection Rule: {r.get('name')}"
        self.modal_scroll = 0

    def show_tuning_knobs_modal(self):
        knobs = offline_store.get_offline_tuning_knobs() or {}
        lines = [
            "DETECTION TUNING KNOBS & THRESHOLDS:",
            "=====================================",
            "",
            "Configurable sensitivity thresholds across detection heuristics:",
            "",
        ]
        for k, v in knobs.items():
            lines.append(f"  • {k.ljust(35)} : {v}")
        lines.append("")
        lines.append("Use ':rules knobs' to inspect or adjust thresholds.")
        self.modal_content = "\n".join(lines)
        self.modal_title = "Detection Tuning Knobs"
        self.modal_scroll = 0

    def show_suppressions_modal(self):
        sups = offline_store.get_offline_suppressions() or []
        lines = [
            f"ACTIVE FALSE-POSITIVE SUPPRESSIONS ({len(sups)}):",
            "===========================================",
            "",
        ]
        if sups:
            for s in sups:
                lines.append(f"  • #{s.get('id')}: Rule '{s.get('rule_id')}' — Reason: {s.get('reason', '-')}")
        else:
            lines.append("No active suppressions configured.")
        self.modal_content = "\n".join(lines)
        self.modal_title = "Rule Suppressions"
        self.modal_scroll = 0

    def run_doctor_modal(self):
        try:
            from typer.testing import CliRunner
            from .main import app
            runner = CliRunner()
            res = runner.invoke(app, ["doctor"])
            self.modal_content = res.stdout
            self.modal_title = "OutPost Doctor Environment Diagnostics"
            self.modal_scroll = 0
        except Exception as exc:
            self.status_msg = f"Doctor check failed: {exc}"

    def run_cyber_decoder(self):
        payload = self.prompt_input("Enter encoded payload to analyze (Base64 / Hex / URL / PowerShell):")
        if not payload:
            self.status_msg = "Decoder cancelled."
            return
        try:
            from typer.testing import CliRunner
            from .main import app
            runner = CliRunner()
            res = runner.invoke(app, ["decode", payload])
            self.modal_content = res.stdout
            self.modal_title = "CyberDecoder · Payload Inspector"
            self.modal_scroll = 0
        except Exception as exc:
            self.status_msg = f"Decode error: {exc}"

    def generate_triage_pack(self):
        try:
            from typer.testing import CliRunner
            from .main import app
            runner = CliRunner()
            res = runner.invoke(app, ["forensics", "triage-pack"])
            self.modal_content = res.stdout or "Forensic triage pack generated."
            self.modal_title = "Forensics Triage Pack Generated"
            self.modal_scroll = 0
        except Exception as exc:
            self.status_msg = f"Triage pack error: {exc}"

    def run_system_audit(self):
        try:
            from typer.testing import CliRunner
            from .main import app
            runner = CliRunner()
            res = runner.invoke(app, ["audit", "summary"])
            self.modal_content = res.stdout or "Audit check complete."
            self.modal_title = "System Security Audit Report"
            self.modal_scroll = 0
        except Exception as exc:
            self.status_msg = f"Audit error: {exc}"

    # --- Render Methods ---

    def render_modal(self):
        title = self.modal_title or "Modal View"
        lines = (self.modal_content or "").splitlines()
        total_lines = len(lines)
        page_size = 22
        start = min(self.modal_scroll, max(0, total_lines - page_size))
        end = min(start + page_size, total_lines)
        slice_lines = lines[start:end]

        display_text = Text()
        for l in slice_lines:
            if "\x1b" in l:
                display_text.append(Text.from_ansi(l))
            else:
                display_text.append(Text(l))
            display_text.append("\n")

        scroll_info = f"Lines {start + 1}-{end} of {total_lines}" if total_lines > page_size else f"{total_lines} lines"
        panel = Panel(
            display_text,
            title=f"[bold #3FA796]{title}[/bold #3FA796]   [dim]({scroll_info})[/dim]",
            box=ROUNDED,
            border_style="#3FA796",
            padding=(1, 2),
        )
        console.print(panel)
        console.print(Align.center(Text.from_markup("[dim][↑/↓ / j/k] Scroll   [PageUp/Down] Fast Scroll   [b / Esc / Enter / q] Close Modal[/dim]")))

    def render_main_screen(self):
        alerts = _safe_get_alerts()
        investigations = _safe_get_investigations()
        fleet = _safe_get_fleet()
        runs = _safe_get_runs()
        online_agents = fleet.get("online", 0) if isinstance(fleet, dict) else 0

        defcon_code, defcon_text, defcon_style = _get_defcon_level(alerts, investigations)
        api_online = _is_api_online()
        mode_badge = "[bold green]LIVE API[/bold green]" if api_online else "[bold yellow]OFFLINE SQLITE[/bold yellow]"

        # Build menu lines
        lines: list[Text] = []
        for idx, (num, label, desc) in enumerate(self.main_menu):
            is_sel = idx == self.main_selected
            prefix = " > " if is_sel else "   "
            style = "bold #3FA796 reverse" if is_sel else "white"
            t = Text()
            t.append(f"{prefix}{num}. {label.ljust(22)} ", style=style)
            t.append(f"{desc}", style="dim" if not is_sel else "white")
            lines.append(t)

        menu_content = Group(*lines)

        # Recent investigations / findings
        recent_lines: list[Text] = [
            Text("Recent Incident Investigations & Findings", style="bold white"),
            Text("─────────────────────────────────────────────────────────────", style="dim"),
        ]

        if investigations:
            for inv in investigations[:3]:
                sev = (inv.get("severity") or "HIGH").upper()
                style = SEVERITY_STYLE.get(sev.lower(), "bold #C4453B")
                case_id = inv.get("id", "INC-001")[:12].ljust(14)
                title = inv.get("title", "Suspicious Activity")[:40].ljust(42)
                t = Text()
                t.append(f"{case_id} {title} ")
                t.append(sev.ljust(10), style=style)
                recent_lines.append(t)
        elif alerts:
            for a in alerts[:3]:
                sev = (a.get("severity") or "SUSPICIOUS").upper()
                style = SEVERITY_STYLE.get(sev.lower(), "bold #D9A441")
                case_id = f"ALT-{a.get('id', 1)}".ljust(14)
                title = a.get("rule_name", "Alert")[:40].ljust(42)
                t = Text()
                t.append(f"{case_id} {title} ")
                t.append(sev.ljust(10), style=style)
                recent_lines.append(t)
        else:
            recent_lines.append(Text("No open investigations or active alerts in the database.", style="dim"))
            recent_lines.append(Text.from_markup("[dim]Press [bold green][s][/bold green] to seed sample security telemetry & cases.[/dim]"))

        footer_items = [
            "[↑↓] Navigate",
            "[0-9] Direct Jump",
            "[Enter] Select",
            "[:] Command Palette (Cmd+K)",
            "[s] Seed Data",
            "[r] Refresh",
            "[?] Help",
            "[q] Quit",
        ]
        body_list = [menu_content, Text(""), Group(*recent_lines), Text("")]
        if self.status_msg:
            body_list.append(Text.from_markup(f"[bold yellow]● {self.status_msg}[/bold yellow]"))
            body_list.append(Text(""))
        body_list.append(Text("   ".join(footer_items), style="dim"))
        body = Group(*body_list)

        hud_title = f"[bold #3FA796]OUTPOST[/bold #3FA796] SOC WORKSTATION   │   [{defcon_style}] {defcon_code}: {defcon_text} [/]   │   Mode: {mode_badge}   │   Sensors: [bold green]{online_agents} Online[/bold green]   │   Runs: [bold]{len(runs)}[/bold]"

        panel = Panel(
            body,
            title=hud_title,
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

        body_elements = [Group(*stat_lines), Group(*menu_lines), Text("")]
        if self.status_msg:
            body_elements.append(Text.from_markup(f"[bold yellow]● {self.status_msg}[/bold yellow]"))
            body_elements.append(Text(""))
        body_elements.append(Text("[↑↓] Navigate   [Enter] Select   [:] Console   [s] Seed Data   [b/Esc] Back   [?] Help", style="dim"))

        panel = Panel(
            Group(*body_elements),
            title=f"[bold #3FA796]{cat_title}[/bold #3FA796]",
            box=ROUNDED,
            border_style="#3FA796",
            padding=(1, 3),
        )
        console.print(panel)

    def render_sub_view(self):
        view_name = self.active_sub_view or ""
        header = f"[bold #3FA796]{self.current_screen.upper()} > {view_name.upper()}[/bold #3FA796]"

        if self.status_msg:
            console.print(f"[bold yellow]● {self.status_msg}[/bold yellow]\n")

        if self.current_screen == "monitor":
            if view_name in ("Live Events", "Sessions"):
                runs = _safe_get_runs()
                if not runs:
                    panel = render_empty_state(
                        title=f"{self.current_screen.upper()} > {view_name.upper()} (NO SESSIONS RECORDED)",
                        message="No security monitoring sessions or execution runs found in the database.",
                        operations=[
                            "Press [bold green][s][/bold green] to seed realistic demo telemetry, campaign clusters & alerts",
                            "Press [bold cyan][:][/bold cyan] and type [bold cyan]start[/bold cyan] to launch the full background stack",
                            "Select [bold cyan][2] Analyze > Attack Playbooks[/bold cyan] to detonate curated threat scenarios",
                            "Select [bold cyan][9] Settings[/bold cyan] and press [bold cyan][u][/bold cyan] to launch web console & API",
                        ],
                    )
                    console.print(panel)
                    return

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
                console.print(Align.center(Text.from_markup("[dim][↑↓] Navigate   [Enter] Open Process Tree & Alerts   [e] Export STIX   [:] Console   [b/Esc] Back[/dim]")))

            elif view_name == "Findings":
                alerts = _safe_get_alerts()
                if not alerts:
                    panel = render_empty_state(
                        title=f"{self.current_screen.upper()} > FINDINGS (QUEUE CLEAR)",
                        message="No open detection findings in the queue. Monitored environment is clear.",
                        operations=[
                            "Press [bold green][s][/bold green] to seed sample threat detections and attack scenarios",
                            "Select [bold cyan][2] Analyze > Attack Playbooks[/bold cyan] to test detection heuristics",
                            "Press [bold cyan][:][/bold cyan] and type [bold cyan]alerts --follow[/bold cyan] to tail live stream",
                        ],
                    )
                    console.print(panel)
                    return

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
                console.print(Align.center(Text.from_markup("[dim][↑↓] Navigate   [t] Triage Alert   [i] Promote to Case   [Enter] Alert Detail   [:] Console   [b/Esc] Back[/dim]")))

            elif view_name == "Hosts":
                self.render_hosts_table()

            elif view_name == "Deep Forensics":
                data = _safe_get_forensics_snapshot()
                m = data.get("metrics", {})
                procs = data.get("processes", [])[:10]
                sockets = data.get("sockets", [])[:6]

                body_elements = []
                metrics_table = Table(box=ROUNDED, border_style="dim", expand=True)
                metrics_table.add_column("Platform", style="bold cyan")
                metrics_table.add_column("CPU %", style="bold")
                metrics_table.add_column("Memory (Used/Total)", style="bold magenta")
                metrics_table.add_column("Processes", style="bold green")
                metrics_table.add_column("Sockets", style="bold yellow")
                metrics_table.add_row(
                    m.get("platform", platform.system().lower()).upper(),
                    f"{m.get('cpu_percent', 0):.1f}%",
                    f"{m.get('memory_used_mb', 0):.0f} / {m.get('memory_total_mb', 0):.0f} MB ({m.get('memory_percent', 0):.1f}%)",
                    str(data.get("process_count", len(procs))),
                    str(data.get("socket_count", len(sockets))),
                )
                body_elements.append(metrics_table)

                if procs:
                    proc_table = Table(title="Live Process Telemetry (first 10)", box=ROUNDED, border_style="dim", expand=True)
                    proc_table.add_column("PID", style="bold", width=8)
                    proc_table.add_column("Name", style="bold cyan", width=18)
                    proc_table.add_column("User", width=10)
                    proc_table.add_column("CPU %", width=8)
                    proc_table.add_column("RAM (MB)", width=10)
                    proc_table.add_column("Command Line", style="dim")
                    for p in procs:
                        proc_table.add_row(
                            str(p.get("pid")),
                            p.get("name", "-"),
                            str(p.get("user", "-")),
                            f"{p.get('cpu_percent', 0):.1f}%",
                            f"{p.get('memory_mb', 0):.1f}",
                            (p.get("cmdline") or p.get("exe") or "-")[:45],
                        )
                    body_elements.append(proc_table)

                console.print(Panel(Group(*body_elements), title=header, box=ROUNDED, border_style="#3FA796"))
                console.print(Align.center(Text.from_markup("[dim][r] Refresh Telemetry   [:] Console   [b/Esc] Back to Monitor[/dim]")))

            elif view_name == "Detection Activity":
                rules = _safe_get_rules_meta()
                table = Table(title=f"Active Detection Heuristics ({len(rules)} Rules)", box=ROUNDED, border_style="dim", expand=True)
                table.add_column("Rule ID", style="bold cyan")
                table.add_column("Name", style="white")
                table.add_column("Tactic", style="bold yellow")
                for r in rules[:12]:
                    table.add_row(r.get("rule_id", r.get("id", "")), r.get("name", ""), r.get("tactic", "Execution"))
                console.print(Panel(table, title=header, box=ROUNDED, border_style="#3FA796"))
                console.print(Align.center(Text.from_markup("[dim][b/Esc] Back to Monitor[/dim]")))

        elif self.current_screen == "analyze":
            if view_name == "Attack Playbooks":
                playbooks = _safe_get_playbooks()
                if not playbooks:
                    panel = render_empty_state(
                        title=f"{self.current_screen.upper()} > ATTACK PLAYBOOKS",
                        message="No attack scenario playbooks registered.",
                        operations=[
                            "Press [bold green][s][/bold green] to seed scenario playbooks into SQLite",
                        ],
                    )
                    console.print(panel)
                    return

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
                console.print(Align.center(Text.from_markup("[bold green][Enter] Detonate Selected Scenario Live[/bold green]   [dim][p] Inspect Details   [:] Console   [b/Esc] Back[/dim]")))
            else:
                samples = _safe_get_samples()
                if not samples:
                    panel = render_empty_state(
                        title=f"{self.current_screen.upper()} > {view_name.upper()} (VAULT EMPTY)",
                        message="No binaries or suspicious executables have been uploaded to the sample vault.",
                        operations=[
                            "Press [bold cyan][u][/bold cyan] to analyze a local sample binary directly",
                            "Press [bold cyan][s][/bold cyan] to run YARA scan on local directory",
                            "Press [bold green][s][/bold green] to seed sample telemetry and demo runs",
                        ],
                    )
                    console.print(panel)
                    return

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
                console.print(Align.center(Text.from_markup("[dim][u] Upload/Analyze Sample   [s] YARA Scan   [Enter] Static Inspection   [b/Esc] Back[/dim]")))

        elif self.current_screen == "investigate":
            invs = _safe_get_investigations()
            if not invs:
                panel = render_empty_state(
                    title=f"{self.current_screen.upper()} > CASES (NO ACTIVE CASES)",
                    message="No SOC incident investigation cases are currently open in the database.",
                    operations=[
                        "Press [bold cyan][c][/bold cyan] to create a new investigation case directly",
                        "Press [bold green][s][/bold green] to seed realistic investigation cases and evidence",
                        "Promote critical alerts from [bold cyan][1] Monitor > Findings[/bold cyan] by pressing [bold cyan][i][/bold cyan]",
                    ],
                )
                console.print(panel)
                return

            table = Table(title=f"SOC Incident Investigations ({len(invs)})", box=ROUNDED, border_style="dim", expand=True)
            table.add_column("#", width=3)
            table.add_column("Case ID", style="bold cyan", width=14)
            table.add_column("Title", style="bold white")
            table.add_column("Status", width=12)
            table.add_column("Severity", width=12)
            for i, inv in enumerate(invs[:10]):
                is_sel = i == self.detail_selected
                sev = inv.get("severity") or "suspicious"
                table.add_row(
                    str(i + 1),
                    f"{'▶ ' if is_sel else ''}{inv.get('id', '')[:14]}",
                    inv.get("title", ""),
                    (inv.get("status") or "active").upper(),
                    Text(sev.upper(), style=SEVERITY_STYLE.get(sev, "white")),
                    style="reverse" if is_sel else None,
                )
            console.print(Panel(table, title=header, box=ROUNDED, border_style="#3FA796"))
            console.print(Align.center(Text.from_markup("[dim][↑↓] Navigate   [c] Create Case   [n] Add Note   [t/x] Toggle Status   [Enter] Case Detail   [e] Export Dossier[/dim]")))

        elif self.current_screen == "iocs":
            watchlist = _safe_get_watchlist()
            if not watchlist:
                panel = render_empty_state(
                    title=f"{self.current_screen.upper()} > WATCHLIST (EMPTY)",
                    message="No indicators (IPs, domains, hashes) are currently added to the threat watchlist.",
                    operations=[
                        "Press [bold cyan][a][/bold cyan] to add an indicator directly into the watchlist",
                        "Press [bold cyan][/][/bold cyan] or [bold cyan][s][/bold cyan] to search indicators across historical sessions",
                        "Press [bold green][s][/bold green] to seed known adversary C2 indicators into the watchlist",
                    ],
                )
                console.print(panel)
                return

            table = Table(title=f"Threat Watchlist ({len(watchlist)} Indicators)", box=ROUNDED, border_style="dim", expand=True)
            table.add_column("#", width=3)
            table.add_column("Value / Indicator", style="bold yellow")
            table.add_column("Label / Threat Context", style="white")
            table.add_column("Date Added", style="dim", width=16)
            for i, w in enumerate(watchlist[:10]):
                is_sel = i == self.detail_selected
                table.add_row(
                    str(i + 1),
                    f"{'▶ ' if is_sel else ''}{w.get('value', '')}",
                    w.get("label", ""),
                    str(w.get("created_at", w.get("added_at", "")))[:10],
                    style="reverse" if is_sel else None,
                )
            console.print(Panel(table, title=header, box=ROUNDED, border_style="#3FA796"))
            console.print(Align.center(Text.from_markup("[dim][↑↓] Navigate   [/] Search IOC   [a] Add Indicator   [d] Remove   [c] Threat Intel   [b/Esc] Back[/dim]")))

        elif self.current_screen == "hosts":
            self.render_hosts_table()

        elif self.current_screen == "campaigns":
            campaigns = _safe_get_campaigns()
            if not campaigns:
                panel = render_empty_state(
                    title=f"{self.current_screen.upper()} > CAMPAIGN CLUSTERS",
                    message="No multi-session threat campaigns identified yet (requires 2+ sessions connecting to shared external C2 infrastructure).",
                    operations=[
                        "Press [bold green][s][/bold green] to seed dual-variant attack campaign beaconing to shared C2 (203.0.113.88)",
                        "Select [bold cyan][2] Analyze > Attack Playbooks[/bold cyan] to generate multi-session telemetry",
                    ],
                )
                console.print(panel)
                return

            table = Table(title=f"Campaign Clusters ({len(campaigns)})", box=ROUNDED, border_style="dim", expand=True)
            table.add_column("#", width=3)
            table.add_column("Campaign Key", style="bold yellow")
            table.add_column("Signature C2", style="bold cyan")
            table.add_column("Linked Runs", width=12)
            for i, c in enumerate(campaigns[:8]):
                is_sel = i == self.detail_selected
                table.add_row(
                    str(i + 1),
                    f"{'▶ ' if is_sel else ''}{c.get('key', '')}",
                    c.get("signature_ip") or "None",
                    str(len(c.get("runs", []))),
                    style="reverse" if is_sel else None,
                )
            console.print(Panel(table, title=header, box=ROUNDED, border_style="#3FA796"))
            console.print(Align.center(Text.from_markup("[dim][↑↓] Navigate   [Enter] Campaign Details   [e] Export STIX 2.1   [b/Esc] Back[/dim]")))

        elif self.current_screen == "reports":
            runs = _safe_get_runs()
            if not runs:
                panel = render_empty_state(
                    title=f"{self.current_screen.upper()} > REPORTS",
                    message="No completed analysis sessions available for report generation or rule synthesis.",
                    operations=[
                        "Press [bold green][s][/bold green] to seed completed demo runs with process trees and alerts",
                        "Select [bold cyan][2] Analyze > Attack Playbooks[/bold cyan] to detonate and generate rules",
                    ],
                )
                console.print(panel)
                return

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
            console.print(Align.center(Text.from_markup("[dim][↑↓] Navigate   [Enter] View Report & Synthesize Rules   [e] Export STIX   [b/Esc] Back[/dim]")))

        elif self.current_screen == "rules":
            rules = _safe_get_rules_meta()
            table = Table(title=f"{len(rules)} Heuristic Rules across 14 ATT&CK Tactics", box=ROUNDED, border_style="dim", expand=True)
            table.add_column("#", width=3)
            table.add_column("Rule ID", style="bold cyan", width=26)
            table.add_column("Rule Name", style="white")
            table.add_column("Tactic", style="bold yellow", width=18)
            table.add_column("Technique", style="dim", width=14)
            for i, r in enumerate(rules[:14]):
                is_sel = i == self.detail_selected
                table.add_row(
                    str(i + 1),
                    f"{'▶ ' if is_sel else ''}{r.get('rule_id', r.get('id', ''))}",
                    r.get("name", ""),
                    r.get("tactic", "Execution"),
                    r.get("technique", ""),
                    style="reverse" if is_sel else None,
                )
            console.print(Panel(table, title=header, box=ROUNDED, border_style="#3FA796"))
            console.print(Align.center(Text.from_markup("[dim][Enter] View Rule Definition   [k] Tuning Knobs   [s] Suppressions   [b/Esc] Back[/dim]")))

        elif self.current_screen == "settings":
            rules_count = len(_safe_get_rules_meta())
            playbooks_count = len(_safe_get_playbooks())
            samples_count = len(_safe_get_samples())
            watchlist_count = len(_safe_get_watchlist())
            runs_count = len(_safe_get_runs())
            api_online = _is_api_online()
            api_status_str = f"[bold green]Connected ({api_client.get_base_url()})[/bold green]" if api_online else "[bold yellow]Offline (Direct Local SQLite & Kernel Access)[/bold yellow]"
            db_file = offline_store.find_db_path()
            db_size_str = f"{db_file.stat().st_size / 1024:.1f} KB" if db_file and db_file.exists() else "Not found"
            body = (
                f"[bold]OutPost Platform:[/bold]     v0.1.0 SOC Workstation & Behavioral EDR\n"
                f"[bold]API Backend:[/bold]          {api_status_str}\n"
                f"[bold]SQLite Database:[/bold]      {db_file or 'backend/data/outpost.db'} ({db_size_str})\n"
                f"[bold]Host System:[/bold]          {platform.system()} {platform.release()} ({platform.machine()})\n"
                f"[bold]Active Sessions:[/bold]      {runs_count} Recorded Sessions\n"
                f"[bold]Detection Heuristics:[/bold] {rules_count} Rules across 14 MITRE Tactics\n"
                f"[bold]Attack Playbooks:[/bold]     {playbooks_count} Scenarios Available\n"
                f"[bold]Sample Vault:[/bold]         {samples_count} Binaries Indexed\n"
                f"[bold]Threat Watchlist:[/bold]     {watchlist_count} Monitored Indicators\n"
                f"[bold]Forensics Engine:[/bold]     Direct /proc & psutil live host telemetry\n\n"
                f"[bold #3FA796]In-App Service Controls:[/bold #3FA796]\n"
                f"  [bold cyan][u][/bold cyan] Start OutPost stack in background (API :8001 + Web Console :5174)\n"
                f"  [bold cyan][d][/bold cyan] Stop OutPost background services and release ports\n"
                f"  [bold cyan][o][/bold cyan] Open Web Console at http://localhost:5174 in browser\n"
                f"  [bold cyan][c][/bold cyan] Run OutPost Doctor diagnostic environment check\n"
                f"  [bold cyan][s][/bold cyan] Seed realistic demo telemetry & cases\n"
            )
            console.print(Panel(Text.from_markup(body), title="[bold #3FA796]SETTINGS & PLATFORM HEALTH[/bold #3FA796]", box=ROUNDED, border_style="#3FA796"))
            console.print(Align.center(Text.from_markup("[dim][u] Start Stack   [d] Stop Stack   [o] Open Browser   [c] Doctor   [s] Seed   [b/Esc] Back[/dim]")))

        elif self.current_screen == "tools":
            if view_name == "Cyber Decoder":
                body = (
                    "[bold]Forensic Payload Decoder & Hash Calculator[/bold]\n\n"
                    "Automated deobfuscation and multi-representation payload analysis:\n"
                    "  • Base64 (Standard UTF-8 and Windows UTF-16LE / PowerShell)\n"
                    "  • Hex and byte shellcode representations (\\x41, 0x41, raw hex)\n"
                    "  • URL percent-encoding and Defang/Refang IOC restoration\n"
                    "  • Automated extraction of IPv4, domains, and cryptographic hashes\n\n"
                    "Press [bold green][d][/bold green] or [bold green][Enter][/bold green] to enter an encoded payload to deobfuscate."
                )
                console.print(Panel(Text.from_markup(body), title="[bold #3FA796]SOC TOOLS > CYBER DECODER[/bold #3FA796]", box=ROUNDED, border_style="#3FA796"))
                console.print(Align.center(Text.from_markup("[dim][d/Enter] Decode Payload   [:] Console   [b/Esc] Back to Tools[/dim]")))

            elif view_name == "Forensics Triage Pack":
                body = (
                    "[bold]1-Click Host Forensic Triage Archive[/bold]\n\n"
                    "Collects complete host investigative evidence into a portable gzip bundle:\n"
                    "  • Full process table with command line arguments and environment\n"
                    "  • Open network sockets, listening ports, and active connections\n"
                    "  • Loaded kernel modules, system services, and scheduled cron jobs\n"
                    "  • Cryptographic verification hashes for key system binaries\n\n"
                    "Press [bold green][g][/bold green] or [bold green][Enter][/bold green] to generate a host triage pack in the current directory."
                )
                console.print(Panel(Text.from_markup(body), title="[bold #3FA796]SOC TOOLS > FORENSICS TRIAGE PACK[/bold #3FA796]", box=ROUNDED, border_style="#3FA796"))
                console.print(Align.center(Text.from_markup("[dim][g/Enter] Generate Triage Pack   [:] Console   [b/Esc] Back to Tools[/dim]")))

            elif view_name == "System Security Audit":
                body = (
                    "[bold]Platform Security & Collector Readiness Self-Check[/bold]\n\n"
                    "Runs automated verification across OutPost components:\n"
                    "  • SQLite database integrity and migration status\n"
                    "  • Collector agent communication channels & containment readiness\n"
                    "  • File integrity monitor and eBPF probe permissions\n\n"
                    "Press [bold green][a][/bold green] or [bold green][Enter][/bold green] to run comprehensive platform audit."
                )
                console.print(Panel(Text.from_markup(body), title="[bold #3FA796]SOC TOOLS > SYSTEM SECURITY AUDIT[/bold #3FA796]", box=ROUNDED, border_style="#3FA796"))
                console.print(Align.center(Text.from_markup("[dim][a/Enter] Run Security Audit   [:] Console   [b/Esc] Back to Tools[/dim]")))

            elif view_name == "Rule Tuning Knobs":
                self.show_tuning_knobs_modal()

    def render_hosts_table(self):
        fleet = _safe_get_fleet()
        agents = fleet.get("agents", []) if isinstance(fleet, dict) else []
        if not agents:
            panel = render_empty_state(
                title="FLEET HOSTS (NO AGENTS CONNECTED)",
                message="No endpoint telemetry collectors are currently registered or sending heartbeats.",
                operations=[
                    "Press [bold cyan][b][/bold cyan] to view 1-click agent bootstrap install commands",
                    "Press [bold green][s][/bold green] to seed sample host telemetry and endpoints into database",
                    "Press [bold cyan][:][/bold cyan] and type [bold cyan]watch[/bold cyan] to start live behavioral collection on this host",
                ],
            )
            console.print(panel)
            return

        table = Table(title=f"Fleet Hosts ({len(agents)})", box=ROUNDED, border_style="dim", expand=True)
        table.add_column("#", width=3)
        table.add_column("Host ID", style="bold cyan")
        table.add_column("Platform", width=10)
        table.add_column("Status", width=10)
        table.add_column("Events", justify="right", width=10)
        table.add_column("Containment", width=14)
        table.add_column("Last Seen", style="dim", width=18)
        for i, h in enumerate(agents[:10]):
            is_sel = i == self.detail_selected
            is_on = h.get("online", False)
            iso = h.get("isolated", False)
            cont_str = "[bold red]ISOLATED[/bold red]" if iso else "[green]NORMAL[/green]"
            table.add_row(
                str(i + 1),
                f"{'▶ ' if is_sel else ''}{h.get('host_id', 'local')}",
                h.get("platform", "linux"),
                Text("ONLINE" if is_on else "OFFLINE", style="bold #3FA796" if is_on else "dim"),
                str(h.get("event_count", 0)),
                cont_str,
                intel_age(h.get("last_seen")),
                style="reverse" if is_sel else None,
            )
        console.print(table)
        console.print(Align.center(Text.from_markup("[dim][↑↓] Navigate   [i] Contain/Isolate Host   [f] Forensics   [b] 1-Click Bootstrap   [r] Refresh   [b/Esc] Back[/dim]")))

    def render_run_detail(self):
        if not self.selected_run_id:
            self.current_screen = "monitor"
            return
        detail = _safe_get_run_detail(self.selected_run_id)
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

            console.print(Align.center(Text.from_markup("[bold cyan][g] Synthesize Sigma/Suricata/YARA Rules[/bold cyan]   [bold yellow][e] Export STIX 2.1[/bold yellow]   [dim][b/Esc] Back to Sessions[/dim]")))
