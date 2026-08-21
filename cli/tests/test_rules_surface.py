"""Regression tests for the read-only rule-surface mirrors (mocked API):
`outpost rules knobs` and `outpost rules log-patterns`.

These lock the terminal parity contract: the same tuning knobs and
anti-forensics pattern tables the webapp Rules page shows, printable from a
terminal, with tuned-vs-default and per-kind/per-platform structure intact.

Run from cli/:  ../.venv/bin/pytest
"""

from rich.console import Console

import outpost.commands.rules as rules_mod
from outpost.commands.rules import knobs, log_patterns
from outpost.lib import api_client
from outpost.rendering.terminal_views import console


# The command prints to the module-level console; tests render at a realistic
# 160-col terminal width so long knob names / pattern regexes aren't wrapped
# (the fold behavior is for real narrow terminals, not for these assertions).
def _wide(monkeypatch) -> Console:
    wide = Console(width=160)
    monkeypatch.setattr(rules_mod, "console", wide)
    return wide


def _tuning_fixture() -> dict:
    return {
        "knobs": [
            {"param": "DNS_TUNNEL_MIN_DISTINCT", "rule_id": "dns-tunneling", "type": "int",
             "default": 6, "current": 3, "tuned": True},
            {"param": "FANOUT_MIN_PROCESSES", "rule_id": "fanout-contact", "type": "int",
             "default": 5, "current": 5, "tuned": False},
        ]
    }


def _log_patterns_fixture() -> dict:
    return {
        "kinds": {
            "service_stop": {
                "linux": [{"pattern": r"systemctl\s+(stop|disable)\s+(auditd|rsyslog|syslog)",
                           "label": "auditd/rsyslog service stopped/disabled"}],
                "windows": [],
            },
            "log_clear": {
                "windows": [{"pattern": r"wevtutil\s+(cl|clear-log)\b", "label": "Windows event log cleared (wevtutil)"}],
            },
        }
    }


def test_rules_knobs_renders_tuned_vs_default(monkeypatch):
    wide = _wide(monkeypatch)
    monkeypatch.setattr(api_client, "get_tuning", lambda: _tuning_fixture())
    with wide.capture() as capture:
        knobs()
    out = capture.get()

    assert "Rule tuning knobs" in out
    assert "DNS_TUNNEL_MIN_DISTINCT" in out
    assert "FANOUT_MIN_PROCESSES" in out
    assert "dns-tunneling" in out and "fanout-contact" in out
    # Tuned knob shows its override; default knob shows default.
    assert "3" in out and "6" in out
    assert "tuned" in out and "default" in out


def test_rules_knobs_empty_state(monkeypatch):
    monkeypatch.setattr(api_client, "get_tuning", lambda: {"knobs": []})
    with console.capture() as capture:
        knobs()
    out = capture.get()
    assert "No tuning knobs exposed" in out


def test_rules_log_patterns_renders_kinds_and_platforms(monkeypatch):
    wide = _wide(monkeypatch)
    monkeypatch.setattr(api_client, "get_log_patterns", lambda: _log_patterns_fixture())
    with wide.capture() as capture:
        log_patterns(kind="all", platform="all")
    out = capture.get()

    assert "SERVICE_STOP" in out and "LOG_CLEAR" in out
    assert "auditd/rsyslog service stopped/disabled" in out
    assert r"wevtutil\s+(cl|clear-log)\b" in out
    assert "Windows event log cleared (wevtutil)" in out
    assert "linux" in out and "windows" in out


def test_rules_log_patterns_kind_filter(monkeypatch):
    wide = _wide(monkeypatch)
    monkeypatch.setattr(api_client, "get_log_patterns", lambda: _log_patterns_fixture())
    with wide.capture() as capture:
        log_patterns(kind="log_clear", platform="windows")
    out = capture.get()
    assert "LOG_CLEAR" in out
    assert "SERVICE_STOP" not in out
    assert "wevtutil" in out


def test_rules_log_patterns_rejects_bad_kind(monkeypatch, capsys):
    monkeypatch.setattr(api_client, "get_log_patterns", lambda: _log_patterns_fixture())
    import typer

    with console.capture() as capture:
        try:
            log_patterns(kind="bogus", platform="all")
        except typer.Exit:
            pass
    out = capture.get()
    assert "Unknown kind" in out
