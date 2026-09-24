from unittest.mock import patch
from typer.testing import CliRunner

from outpost.main import app

runner = CliRunner()


def test_hosts_list_live():
    mock_agents = [
        {
            "host_id": "endpoint-prod-01",
            "platform": "linux",
            "online": True,
            "version": "0.1.0",
            "event_count": 150,
            "alert_count": 2,
            "isolated": False,
            "last_seen": "2026-09-23T20:00:00Z",
        }
    ]
    with patch("outpost.lib.api_client.get_agents", return_value={"agents": mock_agents}):
        result = runner.invoke(app, ["hosts", "list"])
        assert result.exit_code == 0
        assert "endpoint-prod-01" in result.stdout
        assert "ONLINE" in result.stdout
        assert "NORMAL" in result.stdout


def test_hosts_isolate():
    with patch("outpost.lib.api_client.isolate_host", return_value={"isolated": True}):
        result = runner.invoke(app, ["hosts", "isolate", "endpoint-prod-01", "--reason", "Malware outbreak"])
        assert result.exit_code == 0
        assert "ISOLATED" in result.stdout
        assert "endpoint-prod-01" in result.stdout


def test_hosts_unisolate():
    with patch("outpost.lib.api_client.isolate_host", return_value={"isolated": False}):
        result = runner.invoke(app, ["hosts", "unisolate", "endpoint-prod-01"])
        assert result.exit_code == 0
        assert "lifted" in result.stdout


def test_hosts_containment():
    mock_containment = {
        "host_id": "endpoint-prod-01",
        "isolated": True,
        "isolated_at": "2026-09-23T20:10:00Z",
        "isolated_by": "analyst",
        "reason": "Lateral movement detected",
        "pending_actions": [
            {
                "action": "kill_process",
                "pid": 1337,
                "process_name": "beacon.elf",
                "requested_at": "2026-09-23T20:11:00Z",
            }
        ],
    }
    with patch("outpost.lib.api_client.get_host_containment", return_value=mock_containment):
        result = runner.invoke(app, ["hosts", "containment", "endpoint-prod-01"])
        assert result.exit_code == 0
        assert "ISOLATED (QUARANTINED)" in result.stdout
        assert "beacon.elf" in result.stdout


def test_hosts_offline_fallback():
    mock_offline_hosts = [
        {
            "host_id": "endpoint-airgap-01",
            "platform": "windows",
            "online": False,
            "version": "0.1.0",
            "event_count": 42,
            "alert_count": 0,
            "isolated": True,
            "last_seen": "2026-09-23T19:00:00Z",
        }
    ]
    with patch("outpost.lib.api_client.get_agents", side_effect=Exception("Connection refused")), \
         patch("outpost.lib.offline_store.get_offline_hosts", return_value=mock_offline_hosts):
        result = runner.invoke(app, ["hosts"])
        assert result.exit_code == 0
        assert "endpoint-airgap-01" in result.stdout
        assert "ISOLATED" in result.stdout
