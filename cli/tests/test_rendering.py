"""Regression tests for the CLI's risk/ATT&CK rendering (webapp parity).

Locks `outpost list`'s colorized risk column, `outpost show`'s risk gauge +
ATT&CK chips, and the recon-sweep affordance (RECON markers on enumerating
pids + a sweep line), matching the webapp's visual language.

Run from cli/:  ../.venv/bin/pytest
"""

from outpost.rendering.terminal_views import _recon_summary, render_enum_kinds, render_process_tree, render_report, render_run_table, risk_gauge, risk_style


def _run(risk: int = 0, sev: str | None = None) -> dict:
    return {
        "run_id": "abcdef1234567890",
        "sample_name": "demo.bin",
        "platform": "windows",
        "session_type": "analysis",
        "started_at": "2026-08-07T09:33:49+00:00",
        "alert_count": 3,
        "highest_severity": sev,
        "risk_score": risk,
    }


def test_risk_style_bands():
    assert "C4453B" in risk_style(60)  # critical
    assert "D9A441" in risk_style(45)  # elevated
    assert "3FA796" in risk_style(12)  # low
    assert "3FA796" in risk_style(0)  # none
    assert "3FA796" in risk_style(None)  # defensive


def test_risk_gauge_shape():
    g = risk_gauge(63)
    assert "█" * 6 in g  # 6 of 10 cells filled
    assert "░" * 4 in g
    assert "63" in g


def test_run_table_has_risk_column():
    # Render at a realistic terminal width — the default 80-col console would
    # ellipsize the Severity cell ("mal…") before the risk column settles.
    from rich.console import Console

    wide = Console(width=140)
    table = render_run_table([_run(risk=63, sev="malicious")])
    with wide.capture() as capture:
        wide.print(table)
    out = capture.get()
    assert "Risk" in out
    assert "63" in out
    assert "● malicious" in out


def test_render_report_shows_risk_gauge_and_attack_chips():
    report = {
        "run": _run(risk=45, sev="suspicious"),
        "alerts": [
            {
                "rule_id": "lolbin-abuse",
                "rule_name": "Living-off-the-land binary abuse",
                "severity": "malicious",
                "details": "base64-encoded PowerShell command",
            }
        ],
        "process_tree": [],
        "network_connections": [],
        "timeline": [],
    }
    rules_meta = [{"rule_id": "lolbin-abuse", "rule_name": "x", "technique": "T1059", "tactic": "Execution", "weight": 14}]

    # Console capture needs the shared console object (banner prints to its own).
    from outpost.rendering.terminal_views import console

    with console.capture() as capture:
        render_report(report, run_id="abcdef123456", rules_meta=rules_meta)
    out = capture.get()

    assert "45" in out  # risk score
    assert "T1059 · Execution" in out  # ATT&CK chip on the alert
    assert "Living-off-the-land binary abuse" in out


def _recon_report() -> dict:
    return {
        "run": _run(risk=42, sev="suspicious"),
        "alerts": [
            {
                "rule_id": "enumeration-burst",
                "rule_name": "Discovery enumeration burst",
                "severity": "suspicious",
                "details": "3 distinct enumeration commands within 120s: identity check (whoami), system info (uname -a), account enumeration (/etc/passwd)",
                "related_pids": [3003, 3004, 3005],
            }
        ],
        "process_tree": [
            {
                "pid": 3000,
                "ppid": 1,
                "process_name": "bash",
                "command_line": "/tmp/bash -i",
                "children": [
                    {"pid": 3003, "ppid": 3000, "process_name": "whoami", "command_line": "whoami", "children": []},
                    {"pid": 3004, "ppid": 3000, "process_name": "uname", "command_line": "uname -a", "children": []},
                    {"pid": 3005, "ppid": 3000, "process_name": "getent", "command_line": "getent passwd", "children": []},
                ],
            }
        ],
        "network_connections": [],
        "timeline": [],
    }


def test_recon_summary_unions_pids_and_parses_details():
    pids, line, kinds = _recon_summary([{"rule_id": "enumeration-burst", "related_pids": [1, 2], "details": "3 distinct enumeration commands within 120s: whoami, uname -a, getent passwd"}, {"rule_id": "enumeration-burst", "related_pids": [2, 3]}]
                                      + [{"rule_id": "other", "related_pids": [99]}])
    assert pids == {1, 2, 3}
    assert line is not None
    assert "recon sweep" in line and "T1082" in line
    assert kinds == ["whoami", "uname -a", "getent passwd"]
    # No enumeration-burst → empty set, no line, no kinds.
    assert _recon_summary([]) == (set(), None, [])


def test_render_enum_kinds_chips():
    out = render_enum_kinds(["whoami", "uname -a"])
    assert "whoami" in out and "uname -a" in out
    assert "[dim]enum:[/dim]" in out
    assert render_enum_kinds([]) == "[dim]enum:[/dim] "


def test_process_tree_marks_recon_pids():
    tree = render_process_tree(_recon_report()["process_tree"], recon_pids={3003, 3004, 3005})
    from rich.console import Console

    console = Console()
    with console.capture() as cap:
        console.print(tree)
    out = cap.get()
    assert out.count("● RECON") == 3  # one per enumerating pid
    assert "whoami" in out and "getent" in out


def test_render_report_shows_recon_sweep_line():
    from outpost.rendering.terminal_views import console

    with console.capture() as capture:
        render_report(_recon_report(), run_id="abcdef123456")
    out = capture.get()
    assert "recon sweep" in out
    assert "3 distinct enumeration commands" in out
    assert "3 processes" in out
    assert "● RECON" in out
    assert "enum:" in out  # command-kind chips above the tree
    assert "identity check (whoami)" in out
    assert "system info (uname -a)" in out


def test_watch_dashboard_tags_recon_actors_live(monkeypatch):
    """The moment enumeration-burst lands, `outpost watch` tags its actors
    in the live tree and shows the sweep line above it."""
    import outpost.commands.watch as watch_mod

    def fake_get_run(run_id: str) -> dict:
        return {"run": _run(risk=42, sev="suspicious"), "process_tree": _recon_report()["process_tree"], "network_connections": [], "timeline": []}

    def fake_get_alerts(run_id: str) -> list[dict]:
        return _recon_report()["alerts"]

    monkeypatch.setattr(watch_mod.api_client, "get_run", fake_get_run)
    monkeypatch.setattr(watch_mod.api_client, "get_alerts", fake_get_alerts)

    layout = watch_mod.render_dashboard("run123", notified=set(), meta_by_rule={})
    # A Rich Layout captures only its frame — inspect the process-tree panel's
    # renderable instead (the Group holding the sweep line + chips + tree).
    group = layout["right"].renderable.renderable
    assert "recon sweep" in str(group.renderables[0])
    assert "3 distinct enumeration commands" in str(group.renderables[0])
    # Command-kind chips row (renderables[1]) mirrors the webapp badges.
    assert "identity check (whoami)" in str(group.renderables[1])
    assert "account enumeration (/etc/passwd)" in str(group.renderables[1])
    # The tree is a Rich object — render it separately.
    from rich.console import Console

    console = Console(width=120)
    with console.capture() as cap:
        console.print(group.renderables[2])
    out = cap.get()
    assert out.count("● RECON") == 3
    assert "whoami [3003]" in out and "uname [3004]" in out and "getent [3005]" in out


def test_render_report_without_meta_omits_chips():
    report = {
        "run": _run(risk=0),
        "alerts": [
            {"rule_id": "beaconing", "rule_name": "C2-style beaconing", "severity": "suspicious", "details": "x"}
        ],
        "process_tree": [],
        "network_connections": [],
        "timeline": [],
    }
    from outpost.rendering.terminal_views import console

    with console.capture() as capture:
        render_report(report, run_id="abcdef123456", rules_meta=None)
    out = capture.get()

    assert "C2-style beaconing" in out  # alert still renders without meta
    assert "T1071.001" not in out  # no chips when meta unavailable
