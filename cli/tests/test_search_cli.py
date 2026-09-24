from unittest.mock import patch
from typer.testing import CliRunner

from outpost.main import app

runner = CliRunner()


def test_search_ioc_live():
    mock_matches = [
        {
            "run_id": "run-test-01",
            "sample_name": "malware.exe",
            "event_type": "network_connection",
            "timestamp": "2026-09-23T20:00:00Z",
        }
    ]
    with patch("outpost.lib.api_client.search_iocs", return_value={"count": 1, "matches": mock_matches}):
        result = runner.invoke(app, ["search", "185.220.101.34"])
        assert result.exit_code == 0
        assert "run-test-01" in result.stdout
        assert "malware.exe" in result.stdout
        assert "network_connection" in result.stdout


def test_search_json_export():
    mock_matches = [
        {
            "run_id": "run-test-02",
            "sample_name": "drop.sh",
            "event_type": "process_create",
            "timestamp": "2026-09-23T20:05:00Z",
        }
    ]
    with patch("outpost.lib.api_client.search_iocs", return_value={"count": 1, "matches": mock_matches}):
        result = runner.invoke(app, ["search", "drop.sh", "--json"])
        assert result.exit_code == 0
        assert '"run-test-02"' in result.stdout
        assert '"event_type": "process_create"' in result.stdout


def test_search_csv_export():
    mock_matches = [
        {
            "run_id": "run-test-03",
            "sample_name": "c2.top",
            "event_type": "dns_query",
            "timestamp": "2026-09-23T20:10:00Z",
        }
    ]
    with patch("outpost.lib.api_client.search_iocs", return_value={"count": 1, "matches": mock_matches}):
        result = runner.invoke(app, ["search", "c2.top", "--csv"])
        assert result.exit_code == 0
        assert "Run ID,Sample/Host,Event Type,Timestamp" in result.stdout
        assert "run-test-03,c2.top,dns_query" in result.stdout


def test_search_offline_fallback():
    mock_offline_matches = [
        {
            "run_id": "run-offline-99",
            "sample_name": "local",
            "event_type": "process_create",
            "timestamp": "2026-09-23T19:30:00Z",
        }
    ]
    with patch("outpost.lib.api_client.search_iocs", side_effect=Exception("Connection refused")), \
         patch("outpost.lib.offline_store.search_offline_iocs", return_value=mock_offline_matches):
        result = runner.invoke(app, ["search", "nc -e /bin/sh"])
        assert result.exit_code == 0
        assert "run-offline-99" in result.stdout
        assert "offline" in result.stdout.lower()
