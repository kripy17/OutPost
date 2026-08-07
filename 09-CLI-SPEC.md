# CLI Specification

The CLI (`outpost`) is a full peer to the webapp — it can start a monitoring session, watch it live, and report on it entirely from the terminal. Built with **Typer** (command framework) and **Rich** (terminal tables, trees, live-updating output).

## Commands

| Command | Purpose |
|---|---|
| `outpost watch` | **Flagship command.** Starts the local collector in live mode and shows a real-time monitoring dashboard right in the terminal — running processes, network connections, and alerts as they fire. This is the everyday "watch my system" use case. |
| `outpost run <sample> [--timeout 240]` | Starts a bounded analysis session: collector in analysis mode, run the sample, observe for the timeout window, then stop. Prints the completed report. |
| `outpost list` | Table of all past sessions — sample/label, platform, session type, alert count, timestamp |
| `outpost show <run_id>` | Full report for one session: process tree, network connections, timeline, alerts |
| `outpost export <run_id> --format json\|pdf\|csv` | Export a report to file |
| `outpost search <ioc>` | Search all past sessions for a given IP/domain/hash (Phase 6, `docs/10-STANDOUT-FEATURES.md`) |
| `outpost compare <run_id> <other_run_id>` | Diff two sessions (Phase 6) |
| `outpost notes add <run_id> "<note>"` | Attach a personal note to a session (Phase 6) |

Deliberately no VM/hypervisor commands — the CLI starts a collector process and talks to the backend. If you're running the target inside a VM you set up yourself, you run the collector inside that VM the same way you'd run it anywhere else (see `docs/05-DEPLOYMENT-SETUP.md`); orchestrating that VM isn't this tool's job.

## `outpost watch` — Live Monitoring Dashboard

This is the command that makes OutPost feel like a real tool rather than a one-shot analysis script. It should feel closer to `htop` or `btop` than to a static report:

```python
# cli/outpost/commands/watch.py — logic outline
def watch():
    run_id = api_client.create_run(session_type="live", sample_name=f"Live monitor — {today()}")
    show_banner()
    console.print(f"[amber]Starting live monitoring session {run_id[:8]}...[/amber]")

    collector_proc = monitoring.session.start_local_collector(run_id, mode="live")

    with Live(render_dashboard(run_id), refresh_per_second=2, console=console) as live:
        try:
            while True:
                time.sleep(0.5)
                live.update(render_dashboard(run_id))
        except KeyboardInterrupt:
            pass
    monitoring.session.stop_local_collector(collector_proc)
    console.print("[amber]Monitoring stopped.[/amber]")
```

`render_dashboard(run_id)` polls `GET /runs/{run_id}` and `GET /runs/{run_id}/alerts` and composes a Rich layout: recent process activity on one side, an alert feed on the other, updating in place rather than scrolling — the terminal equivalent of the webapp's live-updating run detail page.

**Desktop notifications for high-severity alerts:** while `watch` is running, a `malicious`-severity alert should also fire an OS-level desktop notification (not just a terminal line) so you notice it even if you've alt-tabbed away. Use a small cross-platform wrapper — `plyer` covers Windows/Linux/macOS with one call — triggered from the same polling loop, deduplicated so the same alert doesn't notify twice.

## `outpost run` — Bounded Analysis Session

```python
# cli/outpost/commands/run.py — logic outline
def run(sample_path: str, timeout_seconds: int = 240):
    platform = detect_platform()
    run_id = api_client.create_run(session_type="analysis", sample_name=sample_path, platform=platform)

    show_banner()
    collector_proc = monitoring.session.start_local_collector(run_id, mode="analysis", timeout=timeout_seconds)

    console.print(f"Executing {sample_path}...")
    subprocess.Popen([sample_path])   # or however the target platform expects it launched

    with console.status(f"Observing for {timeout_seconds}s..."):
        time.sleep(timeout_seconds)

    monitoring.session.stop_local_collector(collector_proc)
    api_client.mark_complete(run_id)

    report = api_client.get_run(run_id)
    terminal_views.render_report(report)
```

## Terminal Aesthetics — Make It Feel Like a Real Tool

A few deliberate touches that separate "a script that prints JSON" from something that feels built:

**Startup banner.** Primary commands (`watch`, `run`, no-args, `--help`) print the full banner before doing anything else; frequent read commands (`list`, `show`, `search`) use a compact version or skip it — see `docs/12-BRANDING-ASSETS.md` for the actual verified ASCII art (generated with `pyfiglet`, not hand-drawn, so the alignment is guaranteed correct) and the exact `show_banner()` implementation, including suppressing it entirely on non-TTY output.

**Consistent severity styling everywhere** — reuse `docs/07-UI-DESIGN-SYSTEM.md`'s color language:

```python
SEVERITY_STYLE = {
    "clean": "bold green",
    "suspicious": "bold yellow",
    "malicious": "bold red",
}
```

**Alert panels, not plain lines.** When an alert fires (live in `watch`, or listed in `show`), render it as a bordered `rich.panel.Panel` with the rule name as the title and severity-colored border — a flat text line for something titled "malicious" undersells it:

```python
from rich.panel import Panel

def render_alert(alert: dict) -> Panel:
    style = SEVERITY_STYLE.get(alert["severity"], "white")
    return Panel(alert["details"], title=f"[{style}]{alert['rule_name']}[/{style}]", border_style=style)
```

**Progress feedback, never a silent hang.** Any operation over ~1 second (starting a collector, waiting out an observation window, running enrichment) uses `console.status(...)` or a `rich.progress` bar — never leave the terminal looking frozen.

## API Client (`cli/outpost/lib/api_client.py`)

Thin wrapper mirroring `frontend/src/lib/api.ts` — same endpoints, same response shapes, just Python `requests` instead of `fetch`. Keeping these two clients structurally parallel (same function names, same call shapes) makes it easy to add a new backend endpoint once and wire both clients to it without redesigning either.
