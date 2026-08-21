"""CLI regression tests for `outpost settings clear-prefs` — the terminal
mirror of the webapp's one-click queue-preference wipe: the per-status-tab
provenance split the alerts command saves with --save is wiped in one command,
restoring the fresh-install defaults."""

from outpost.lib import prefs
from outpost.main import app
from typer.testing import CliRunner

runner = CliRunner()


def test_clear_prefs_empty_state(monkeypatch, tmp_path):
    monkeypatch.setenv("OUTPOST_HOME", str(tmp_path))
    result = runner.invoke(app, ["settings", "clear-prefs"])
    assert result.exit_code == 0
    assert "No saved preferences — nothing to clear." in result.output


def test_clear_prefs_wipes_saved_keys(monkeypatch, tmp_path):
    monkeypatch.setenv("OUTPOST_HOME", str(tmp_path))
    prefs.write_pref("queue_provenance_open", "real")
    prefs.write_pref("queue_provenance_acknowledged", "synthetic")
    assert prefs.read_prefs()["queue_provenance_open"] == "real"

    result = runner.invoke(app, ["settings", "clear-prefs"])
    assert result.exit_code == 0
    assert "Cleared preferences:" in result.output
    assert "· Open: real hosts" in result.output
    assert "· Acknowledged: synthetic" in result.output
    assert "Defaults restored" in result.output
    assert prefs.read_prefs() == {}
    assert not prefs.prefs_path().exists()


def test_prefs_store_roundtrip_and_corruption(monkeypatch, tmp_path):
    monkeypatch.setenv("OUTPOST_HOME", str(tmp_path))
    assert prefs.read_prefs() == {}
    prefs.write_pref("queue_provenance_all", "real")
    prefs.write_pref("queue_provenance_resolved", "synthetic")
    assert prefs.read_prefs()["queue_provenance_all"] == "real"
    assert prefs.read_prefs()["queue_provenance_resolved"] == "synthetic"

    # Clearing a key ("") removes it; the rest survive.
    prefs.write_pref("queue_provenance_all", "")
    assert "queue_provenance_all" not in prefs.read_prefs()
    assert prefs.read_prefs()["queue_provenance_resolved"] == "synthetic"

    # A corrupted file reads as empty — never throws.
    prefs.prefs_path().write_text("{not json", encoding="utf-8")
    assert prefs.read_prefs() == {}
    assert prefs.clear_prefs() == {}
