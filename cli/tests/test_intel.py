"""Regression tests for `outpost intel import` rendering (mocked API).

The command is the terminal mirror of the webapp's threat-intel feed import;
these tests lock its output: the imported count + source label, kind
breakdown, and the matching-runs table when a value already appears in the
store.

Run from cli/:  ../.venv/bin/pytest
"""

import typer

from outpost.commands.intel import import_feed
from outpost.lib import api_client
from outpost.rendering.terminal_views import console


def _fixture() -> dict:
    return {
        "imported": 4,
        "source": "intel:stix",
        "kinds": {"ip": 1, "domain": 2, "hash": 1},
        "matched_values": 1,
        "matched_runs": {"203.0.113.88": ["c09f56bddca4", "0302aa600d1d"]},
    }


def test_intel_import_renders_counts_source_and_matching_runs(monkeypatch, capsys):
    monkeypatch.setattr(api_client, "intel_import", lambda source, content="", url="": _fixture())

    with console.capture() as capture:
        import_feed(source="stix", file=None, content='{"type": "bundle"}', url="")
    out = capture.get()

    assert "4 indicator(s) imported" in out
    assert "intel:stix" in out
    assert "ip=1" in out and "domain=2" in out and "hash=1" in out
    assert "1 value(s) already touch existing runs" in out
    assert "203.0.113.88" in out
    assert "c09f56bddca4" in out and "0302aa600d1d" in out


def test_intel_import_no_match_line(monkeypatch):
    fixture = _fixture()
    fixture["matched_values"] = 0
    fixture["matched_runs"] = {}
    monkeypatch.setattr(api_client, "intel_import", lambda source, content="", url="": fixture)

    with console.capture() as capture:
        import_feed(source="text", file=None, content="203.0.113.88\n", url="")
    out = capture.get()

    assert "4 indicator(s) imported" in out
    assert "No existing run touches any imported value." in out


def test_intel_import_requires_input(monkeypatch):
    monkeypatch.setattr(api_client, "intel_import", lambda source, content="", url="": _fixture())
    with console.capture() as capture:
        try:
            import_feed(source="auto", file=None, content="", url="")
        except typer.Exit:
            pass
    out = capture.get()
    assert "Provide --file/--content or --url" in out
