from typer.testing import CliRunner
from outpost.main import app
from outpost.lib import api_client
from outpost.rendering.terminal_views import console

runner = CliRunner()


def test_rules_backtest_cli(monkeypatch):
    monkeypatch.setattr(console, "width", 160)
    monkeypatch.setattr(
        api_client,
        "backtest_rule",
        lambda rid, max_events=2000: {
            "rule_id": rid,
            "rule_name": "Reverse shell connection",
            "tactic": "Command and Control",
            "events_scanned": 1500,
            "matches_count": 2,
            "match_rate_pct": 0.13,
            "affected_runs_count": 1,
            "estimated_fp_risk": "low",
            "sample_matches": [
                {
                    "event_id": 42,
                    "timestamp": "2026-08-30T10:00:00Z",
                    "process_name": "nc",
                    "match_reason": "Outbound connection to port 4444",
                }
            ],
        },
    )

    result = runner.invoke(app, ["rules", "backtest", "reverse-shell", "--events", "1500"])
    assert result.exit_code == 0
    assert "Historical Rule Backtest" in result.output
    assert "Reverse shell connection" in result.output
    assert "Trigger Hits:   2 (0.13% hit rate)" in result.output
    assert "Est. FP Risk:   LOW" in result.output
    assert "Outbound connection to port 4444" in result.output
