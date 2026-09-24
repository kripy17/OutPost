from unittest.mock import patch
from typer.testing import CliRunner

from outpost.main import app

runner = CliRunner()


def test_audit_list_live():
    mock_events = [
        {
            "id": 1,
            "ts": "2026-09-23T20:00:00Z",
            "actor": "analyst",
            "action": "alert.status",
            "target_type": "alert",
            "target_id": "42",
            "detail": "acknowledged malicious beacon",
        }
    ]
    with patch("outpost.lib.api_client.get_audit", return_value={"total": 1, "events": mock_events}):
        result = runner.invoke(app, ["audit"])
        assert result.exit_code == 0
        assert "analyst" in result.stdout
        assert "alert.status" in result.stdout
        assert "alert #42" in result.stdout


def test_audit_json_output():
    mock_events = [
        {
            "id": 2,
            "ts": "2026-09-23T20:05:00Z",
            "actor": "admin",
            "action": "auth.login",
            "target_type": "user",
            "target_id": "1",
            "detail": "successful password login",
        }
    ]
    with patch("outpost.lib.api_client.get_audit", return_value={"total": 1, "events": mock_events}):
        result = runner.invoke(app, ["audit", "--json"])
        assert result.exit_code == 0
        assert '"action": "auth.login"' in result.stdout


def test_audit_csv_output():
    mock_events = [
        {
            "id": 3,
            "ts": "2026-09-23T20:10:00Z",
            "actor": "admin",
            "action": "allowlist.add",
            "target_type": "ioc",
            "target_id": "10.0.0.1",
            "detail": "whitelisted internal dns",
        }
    ]
    with patch("outpost.lib.api_client.get_audit", return_value={"total": 1, "events": mock_events}):
        result = runner.invoke(app, ["audit", "--csv"])
        assert result.exit_code == 0
        assert "Timestamp,Actor,Action,Target Type,Target ID,Detail" in result.stdout
        assert "allowlist.add" in result.stdout


def test_audit_offline_fallback():
    mock_offline = [
        {
            "id": 4,
            "ts": "2026-09-23T20:15:00Z",
            "actor": "system",
            "action": "backup.create",
            "target_type": "backup",
            "target_id": "snapshot-1",
            "detail": "automated snapshot",
        }
    ]
    with patch("outpost.lib.api_client.get_audit", side_effect=Exception("Connection refused")), \
         patch("outpost.lib.offline_store.get_offline_audit", return_value=mock_offline):
        result = runner.invoke(app, ["audit"])
        assert result.exit_code == 0
        assert "offline" in result.stdout.lower()
        assert "backup.create" in result.stdout
