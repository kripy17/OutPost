"""Regression tests for the CLI's risk/ATT&CK rendering (webapp parity).

Locks `outpost list`'s colorized risk column and `outpost show`'s risk gauge +
ATT&CK chips, matching the new visual language of the webapp (roadmap 1.3).

Run from cli/:  ../.venv/bin/pytest
"""

from outpost.rendering.terminal_views import render_report, render_run_table, risk_gauge, risk_style


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
