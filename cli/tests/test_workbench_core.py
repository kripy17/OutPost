"""Tests for core OutPost malware workbench CLI commands.

Covers:
- `outpost list` (session history)
- `outpost show <run_id>` (run details and process tree)
- `outpost export <run_id>` (JSON report export)
- `outpost scan <path>` (static analysis & YARA inspection)
"""

import json
from pathlib import Path
from typer.testing import CliRunner

from outpost.main import app

runner = CliRunner()


def test_cli_list_runs():
    result = runner.invoke(app, ["list"])
    assert result.exit_code == 0
    assert "OutPost — Session History" in result.output


def test_cli_show_run():
    # Show against real run in database
    list_res = runner.invoke(app, ["list"])
    assert list_res.exit_code == 0
    # Query database for an existing run
    from outpost.lib import offline_store
    runs = offline_store.get_offline_runs()
    if runs:
        rid = runs[0]["run_id"]
        show_res = runner.invoke(app, ["show", rid])
        assert show_res.exit_code == 0
        assert f"Run {rid[:8]}" in show_res.output


def test_cli_export_json(tmp_path):
    from outpost.lib import offline_store
    runs = offline_store.get_offline_runs()
    if runs:
        rid = runs[0]["run_id"]
        out_file = tmp_path / f"export_{rid[:8]}.json"
        export_res = runner.invoke(app, ["export", rid, "--format", "json", "--output", str(out_file)])
        assert export_res.exit_code == 0
        assert out_file.exists()
        payload = json.loads(out_file.read_text())
        assert "run" in payload
        assert "process_tree" in payload
        assert payload["run"]["run_id"] == rid


def test_cli_scan_readme():
    readme_path = Path(__file__).resolve().parent.parent.parent / "README.md"
    assert readme_path.exists()
    scan_res = runner.invoke(app, ["scan", str(readme_path)])
    assert scan_res.exit_code == 0
    assert "Static Analysis & YARA Inspection Results" in scan_res.output
    assert "0 file(s) flagged with threats" in scan_res.output
    assert "passed static pipeline and signature verification cleanly" in scan_res.output
