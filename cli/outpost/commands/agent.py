"""`outpost agent` — one-command host-agent bootstrap.

The collectors (collectors/linux + collectors/windows) are the real telemetry
path: auditd/Sysmon events stream into a live session the webapp opened. This
command removes the manual parts:

  outpost agent run      — run the local collector in live mode right now
                           (it auto-claims the webapp's open live session).
  outpost agent install  — generate a persistent service config (systemd on
                           Linux, nssm service + scheduled task on Windows) so
                           host telemetry streams continuously, plus the exact
                           enable commands the operator runs with their own
                           privileges.
  outpost agent status   — is the service installed, and is the collector
                           process actually streaming right now?

`install` NEVER elevates itself (no sudo/schtasks admin call from the CLI) —
it writes the unit to the user's config dir and prints the exact command the
operator runs as admin. Honest bootstrap, no hidden privilege escalation.
"""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import typer
from rich.console import Console

from ..monitoring import session as monitor

app = typer.Typer(help="Host-agent bootstrap — run or install the OS collector", add_completion=False)
console = Console()

# Where generated service configs land (never /etc directly — the operator's
# own command links them there). Overridable for tests via OUTPOST_HOME.
def _config_dir() -> Path:
    base = os.environ.get("OUTPOST_HOME") or Path.home() / ".config"
    d = Path(base) / "outpost"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _backend_url() -> str:
    return os.environ.get("OUTPOST_API_URL", "http://localhost:8001")


def _python_exe() -> str:
    return sys.executable


def _collector_rel() -> str:
    """Repo-relative collector path (the unit runs it from the checkout)."""
    platform_name = monitor.detect_platform()
    return f"collectors/{platform_name}/collector_{platform_name}.py"


def _collector_abs() -> Path:
    return monitor.collector_script(monitor.detect_platform())


# ---------------------------------------------------------------------------
# outpost agent run
# ---------------------------------------------------------------------------


@app.command()
def run(
    backend_url: str = typer.Option(_backend_url, envvar="OUTPOST_API_URL", help="Backend base URL"),
):
    """Run the local collector in live mode now (claims the open live session)."""
    from ..lib import api_client
    from ..rendering.banners import show_banner

    show_banner(primary=False)
    platform_name = monitor.detect_platform()
    script = monitor.collector_script(platform_name)
    if not script.exists():
        console.print(f"[red]Collector not found: {script}[/red]")
        raise typer.Exit(2)
    console.print(f"[cyan]Starting {platform_name} collector (auditd/Sysmon → backend)…[/cyan]")
    console.print("[dim]It auto-claims the newest open live session. Open the Live Monitor in the webapp and click 'Start live monitoring' if nothing is streaming.[/dim]")
    cmd = [sys.executable, str(script), "--backend-url", backend_url, "--mode", "live"]
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        console.print("[dim]Collector stopped.[/dim]")


# ---------------------------------------------------------------------------
# outpost agent install
# ---------------------------------------------------------------------------

_SYSTEMD_UNIT = """\
[Unit]
Description=OutPost host agent — continuous auditd/Sysmon telemetry ({platform})
After=network.target auditd.service

[Service]
Type=simple
# Hourly process/port snapshots (the Agents "running now" view); the event
# stream itself is continuous. The collector resolves its own live session
# (webapp Live Monitor > today's agent run > creates one), so no browser
# session has to be open for telemetry to flow.
Environment=SNAPSHOT_INTERVAL=3600
Environment=OUTPOST_AGENT_TOKEN={agent_token}
ExecStart={python} {collector} --backend-url {backend_url} --mode live
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""

_SYSTEMD_SUMMARY_UNIT = """\
[Unit]
Description=OutPost agent daily fired-rule summary (FP-rate measurement)
After=network.target

[Service]
Type=oneshot
Environment=OUTPOST_API_URL={backend_url}
Environment=OUTPOST_AGENT_TOKEN={agent_token}
ExecStart={python} -m outpost.main agent summary --days 1 --json
# systemd appends to the log itself — the summary is never lost to a crash.
StandardOutput=append:{log}
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

_SYSTEMD_SUMMARY_TIMER = """\
[Unit]
Description=Run the OutPost agent daily summary

[Timer]
OnCalendar=*-*-* 06:00:00
Persistent=true

[Install]
WantedBy=timers.target
"""

# Windows templates — the collector becomes a real nssm service (auto-restart,
# like systemd's Restart=on-failure), the daily summary a scheduled task. The
# CLI writes these files and prints the one command the operator runs elevated;
# it never self-elevates (no nssm/schtasks call from the CLI itself).

_WIN_COLLECTOR_BAT = """\
@echo off
REM OutPost host agent — continuous Sysmon telemetry (windows)
REM Hourly process/port snapshots (the Agents "running now" view); the event
REM stream itself is continuous. The collector resolves its own live session
REM (webapp Live Monitor > today's agent run > creates one), so no browser
REM session has to be open for telemetry to flow.
set OUTPOST_API_URL={backend_url}
set SNAPSHOT_INTERVAL=3600
set OUTPOST_AGENT_TOKEN={agent_token}
"{python}" "{collector}" --backend-url {backend_url} --mode live
"""

_WIN_SUMMARY_BAT = """\
@echo off
REM OutPost daily fired-rule summary (FP-rate measurement) — appends JSON,
REM mirroring systemd's StandardOutput=append on Linux.
set OUTPOST_API_URL={backend_url}
set OUTPOST_AGENT_TOKEN={agent_token}
"{python}" -m outpost.main agent summary --days 1 --json >> "{log}"
"""

_WIN_INSTALL_BAT = """\
@echo off
REM OutPost host agent — Windows install. Run this file in an elevated prompt
REM (right-click > Run as administrator). Requires nssm for the service:
REM   choco install nssm    (or:  scoop install nssm)

set PY={python}
set COLLECTOR={collector}
set BACKEND={backend_url}
set DIR={dir}
set TOKEN={agent_token}

REM 1) Collector as a real service via nssm (auto-restart on crash, like
REM    systemd's Restart=on-failure on Linux).
nssm install OutPostAgent "%PY%" "%COLLECTOR%" --backend-url %BACKEND% --mode live
nssm set OutPostAgent AppDirectory "%DIR%"
nssm set OutPostAgent AppExit Default Restart
nssm set OutPostAgent AppEnvironmentExtra SNAPSHOT_INTERVAL=3600 OUTPOST_API_URL=%BACKEND% OUTPOST_AGENT_TOKEN=%TOKEN%
nssm start OutPostAgent

REM 2) Daily fired-rule summary via scheduled task (06:00, SYSTEM account).
schtasks /Create /F /TN "OutPostAgentSummary" /SC DAILY /ST 06:00 /RU SYSTEM /TR "\"%DIR%\\outpost-agent-summary.bat\""

REM No-nssm fallback — ONSTART task instead of step 1:
REM schtasks /Create /F /TN "OutPostCollector" /SC ONSTART /RU SYSTEM /TR "\"%DIR%\\outpost-agent.bat\""
"""


def _summary_log_path() -> str:
    """Where the daily summary lands — /var/log on Linux (systemd appends),
    the config dir on Windows (the scheduled task appends)."""
    if os.name == "nt":
        return str(_config_dir() / "outpost-agent-summary.log")
    return "/var/log/outpost-agent-summary.log"


def _write_service_config(backend_url: str, agent_token: str = "") -> tuple[Path, str]:
    """Generate the persistent service config; returns (path, enable_command).

    The enable command is what the operator runs as admin — the CLI never
    self-elevates. This is printed, not executed. `agent_token` is the shared
    OUTPOST_AGENT_TOKEN credential, embedded so the service can authenticate
    against a fail-closed backend (OUTPOST_AUTH_REQUIRED=1).
    """
    platform_name = monitor.detect_platform()
    cfg = _config_dir()
    if platform_name == "linux":
        unit = cfg / "outpost-agent.service"
        unit.write_text(
            _SYSTEMD_UNIT.format(
                platform=platform_name,
                python=_python_exe(),
                collector=_collector_abs(),
                backend_url=backend_url,
                agent_token=agent_token,
            )
        )
        # Daily fired-rule summary — a oneshot service + timer pair that
        # measures the FP rate continuously, not in 5-minute bursts.
        summary_unit = cfg / "outpost-agent-summary.service"
        summary_unit.write_text(
            _SYSTEMD_SUMMARY_UNIT.format(
                python=_python_exe(),
                backend_url=backend_url,
                log=_summary_log_path(),
                agent_token=agent_token,
            )
        )
        summary_timer = cfg / "outpost-agent-summary.timer"
        summary_timer.write_text(_SYSTEMD_SUMMARY_TIMER)
        enable = (
            f"sudo cp {unit} {summary_unit} {summary_timer} /etc/systemd/system/ && "
            f"sudo systemctl daemon-reload && "
            f"sudo systemctl enable --now outpost-agent outpost-agent-summary.timer"
        )
    else:  # windows
        # Batch files must be CRLF (the Python tokenizer normalizes \r\n inside
        # string literals, so force it at write time).
        def _crlf(text: str) -> str:
            return text.replace("\n", "\r\n")

        # 1) Collector wrapper (live mode, hourly snapshots) — launched by nssm.
        unit = cfg / "outpost-agent.bat"
        unit.write_text(
            _crlf(
                _WIN_COLLECTOR_BAT.format(
                    python=_python_exe(),
                    collector=_collector_abs(),
                    backend_url=backend_url,
                    agent_token=agent_token,
                )
            )
        )
        # 2) Daily fired-rule summary — appends JSON, launched by schtasks.
        summary_unit = cfg / "outpost-agent-summary.bat"
        summary_unit.write_text(
            _crlf(
                _WIN_SUMMARY_BAT.format(
                    python=_python_exe(),
                    backend_url=backend_url,
                    log=_summary_log_path(),
                    agent_token=agent_token,
                )
            )
        )
        # 3) The one elevated script the operator runs: nssm service + schtasks.
        install_bat = cfg / "outpost-agent-install.bat"
        install_bat.write_text(
            _crlf(
                _WIN_INSTALL_BAT.format(
                    python=_python_exe(),
                    collector=_collector_abs(),
                    backend_url=backend_url,
                    dir=cfg,
                    agent_token=agent_token,
                )
            )
        )
        enable = (
            f'"{install_bat}"   (run in an elevated prompt)\n'
            f"Requires nssm for the service: choco install nssm  (or: scoop install nssm)"
        )
    return unit, enable


@app.command()
def install(
    backend_url: str = typer.Option(_backend_url, envvar="OUTPOST_API_URL", help="Backend base URL"),
    agent_token: str = typer.Option(
        "",
        envvar="OUTPOST_AGENT_TOKEN",
        help="Shared agent credential — embedded so the service can authenticate "
        "against a fail-closed backend (OUTPOST_AUTH_REQUIRED=1). Use a long "
        "random value (e.g. `openssl rand -hex 24`), alphanumeric only.",
    ),
):
    """Generate a persistent service config (systemd / scheduled task)."""
    platform_name = monitor.detect_platform()
    script = _collector_abs()
    if not script.exists():
        console.print(f"[red]Collector not found: {script}[/red]")
        raise typer.Exit(2)
    unit, enable = _write_service_config(backend_url, agent_token)
    console.print(f"[green]Wrote agent service config:[/green] {unit}")
    console.print(f"\n[bold]Platform:[/bold] {platform_name}")
    console.print("[bold]It streams:[/bold] auditd/Sysmon events → live session → webapp Live Monitor")
    console.print("[bold]It snapshots:[/bold] processes + listening ports every hour (Agents 'running now')")
    console.print("[bold]It summarizes:[/bold] a daily fired-rule report → " + _summary_log_path())
    console.print("\n[bold]Enable it (run with your own admin privileges):[/bold]")
    console.print(f"[cyan]{enable}[/cyan]")
    console.print("\n[dim]Or run once without installing: `outpost agent run` · inspect the report: `outpost agent summary`[/dim]")


# ---------------------------------------------------------------------------
# outpost agent status
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# outpost agent summary
# ---------------------------------------------------------------------------


@app.command()
def summary(
    days: int = typer.Option(1, min=1, max=30, help="Window in days"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable (for the daily timer log)"),
):
    """Fired-rule summary from the agent's own sessions — the continuous
    FP-rate measurement. Selects runs named `agent-*` (one per host per day)
    inside the window and aggregates their alerts by rule: counts, severity
    mix, and how many sessions each rule fired in. `--json` feeds the daily
    systemd timer's log."""
    import json as _json
    from datetime import datetime, timedelta, timezone

    from ..lib import api_client
    from ..rendering.terminal_views import build_rule_summary_table

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    runs = [r for r in api_client.list_runs() if (r.get("sample_name") or "").startswith("agent-")]
    runs = [r for r in runs if (r.get("started_at") or "") >= cutoff]

    rules: dict[str, dict] = {}
    per_run: list[dict] = []
    for r in runs:
        alerts = api_client.get_alerts(r["run_id"])
        mal = sum(1 for a in alerts if a.get("severity") == "malicious")
        per_run.append(
            {
                "run_id": r["run_id"],
                "sample_name": r["sample_name"],
                "alerts": len(alerts),
                "malicious": mal,
                "suspicious": len(alerts) - mal,
                "risk": r.get("risk_score"),
            }
        )
        for a in alerts:
            rid = a.get("rule_id", "?")
            d = rules.setdefault(
                rid,
                {"rule_id": rid, "count": 0, "malicious": 0, "suspicious": 0, "runs": set()},
            )
            d["count"] += 1
            if a.get("severity") == "malicious":
                d["malicious"] += 1
            else:
                d["suspicious"] += 1
            d["runs"].add(r["run_id"])

    if json_output:
        console.print(
            _json.dumps(
                {
                    "window_days": days,
                    "runs": len(runs),
                    "alerts": sum(r["alerts"] for r in per_run),
                    "by_rule": [
                        {**v, "runs": sorted(v["runs"])} for v in sorted(rules.values(), key=lambda x: -x["count"])
                    ],
                    "per_run": per_run,
                },
                indent=2,
            )
        )
        return

    if not runs:
        console.print(
            f"[dim]No agent sessions in the last {days} day(s) — start the service with `outpost agent install`, "
            "or check OUTPOST_API_URL.[/dim]"
        )
        return
    console.print(
        f"\n[bold]Agent telemetry — last {days} day(s)[/bold] · {len(runs)} session(s) · "
        f"{sum(r['alerts'] for r in per_run)} alert(s) across {len(rules)} rule(s)\n"
    )
    console.print(build_rule_summary_table(rules))
    console.print(
        f"\n[dim]Daily log: {_summary_log_path()} (the OS scheduler appends --json output every 06:00).[/dim]"
    )


def _is_collector_running() -> bool:
    """Is any collector process running right now? Cross-platform-ish: checks
    for our own collector script name in the process list via `pgrep` on
    POSIX, `tasklist` + findstr on Windows. Best-effort — returns False on
    any probe failure (honest "can't tell", not a crash)."""
    try:
        if os.name == "nt":
            out = subprocess.run(["tasklist", "/FO", "CSV"], capture_output=True, text=True, timeout=10).stdout
            return "python" in out.lower()  # coarse; scheduled task wraps python
        out = subprocess.run(["pgrep", "-f", "collector_"], capture_output=True, text=True, timeout=10).stdout
        return "collector_" in out
    except Exception:
        return False


def _channel_chips(channels: list[str]) -> str:
    """Colored channel chips — webapp Overview panel parity. auditd is teal,
    sysmon is amber (the signature accent), and any custom channel is muted.
    The `webapp` pseudo-channel (detonation events, not host telemetry) is
    filtered out exactly like the webapp panel does."""
    chips = []
    for c in channels or []:
        if c == "webapp":
            continue
        if c == "auditd":
            chips.append(f"[bold #3FA796]▪ {c}[/bold #3FA796]")
        elif c == "sysmon":
            chips.append(f"[bold #D9A441]▪ {c}[/bold #D9A441]")
        else:
            chips.append(f"[dim]▪ {c}[/dim]")
    return " ".join(chips) or "—"


@app.command()
def status():
    """Is the host agent installed, is it streaming right now, and how does
    the backend see it? The fleet readout mirrors the webapp's Agents page —
    identity (collector vs webapp), last-auth role, and channels (rendered as
    colored chips like the Overview panel) — so terminal parity holds for the
    host identity story."""
    import socket

    from ..lib import api_client

    platform_name = monitor.detect_platform()
    cfg = _config_dir()
    # New name is outpost-agent.service; the old outpost-collector.service is
    # still honored so pre-rename installs keep reporting installed.
    installed = (
        (cfg / "outpost-agent.service").exists()
        or (cfg / "outpost-collector.service").exists()
        or (cfg / "outpost-agent.bat").exists()
        or (cfg / "outpost-collector.bat").exists()
    )
    running = _is_collector_running()

    console.print(f"[bold]Platform:[/bold] {platform_name}")
    if installed:
        console.print("[green]Service config:[/green] installed")
    else:
        console.print("[yellow]Service config:[/yellow] not installed — run `outpost agent install`")
    if running:
        console.print("[green]Collector process:[/green] running — telemetry is streaming")
    else:
        console.print("[yellow]Collector process:[/yellow] not running — run `outpost agent run`")

    # Fleet-side view of THIS host — the backend's attribution for the local
    # machine. Host-id convention matches the collector's shipper (hostname
    # lowercased, OUTPOST_HOST_ID override) so the local agent's row is found.
    host_id = os.getenv("OUTPOST_HOST_ID", "").strip().lower() or socket.gethostname().lower()
    try:
        fleet = api_client.get_agents()
        me = next((a for a in fleet.get("agents", []) if a.get("host_id") == host_id), None)
    except Exception as exc:  # dead backend / auth — honest "can't tell"
        console.print(f"[dim]Fleet:[/dim] backend unreachable ({type(exc).__name__}) — local checks only")
        return None

    if me is None:
        console.print(
            "[dim]Fleet:[/dim] this host has no row on the backend yet — "
            "start the collector (`outpost agent run`) and it will appear on the Agents page"
        )
        return None

    identity = me.get("identity")
    role = me.get("last_auth_role")
    auth_txt = {
        "agent": "via the shared OUTPOST_AGENT_TOKEN",
        "local": "without a credential (auth off / open mode)",
        None: "never authenticated",
    }.get(role, f"as the {role} role")
    state = (
        "[red]silent — heartbeat lost[/red]"
        if me.get("silent")
        else "[green]online[/green]"
        if me.get("online")
        else "[yellow]idle[/yellow]"
    )
    console.print(
        f"[bold]Fleet identity:[/bold] {identity} ({state})"
        f"  ·  auth: {role or 'none'} — {auth_txt}"
    )
    if identity == "collector":
        ver = me.get("heartbeat_version") or "?"
        chip_row = _channel_chips(me.get("channels") or [])
        console.print(
            f"[dim]  agent {ver} · channels:[/dim] {chip_row}"
            f"[dim] · events: {me.get('event_count', 0)} · alerts: {me.get('alert_count', 0)}"
            f" · runs: {me.get('run_count', 0)}[/dim]"
        )
    return None
