"""Test suite for sandbox limits (Defect 7):
1. Verifies memory (RLIMIT_AS), process-count (RLIMIT_NPROC), and wall-clock/CPU (RLIMIT_CPU) limits are set.
2. Verifies rlimit application fails visibly (raises/reports) if an rlimit cannot be applied, rather than silently swallowing.
3. Verifies synthetic PCAP generation logs describe synthetic metadata reconstruction and not 'Captured ... network packet(s)'.
"""

import resource

import pytest

from app.services import dynamic_sandbox


def test_sandbox_rlimits_enforce_memory_and_proc_limits(monkeypatch):
    """Sandbox must enforce RLIMIT_AS (memory) and RLIMIT_NPROC (processes) without swallowing failures."""
    applied_limits = {}

    def mock_setrlimit(res, limits):
        applied_limits[res] = limits

    monkeypatch.setattr(dynamic_sandbox.resource, "setrlimit", mock_setrlimit)

    fn = dynamic_sandbox._build_sandbox_rlimits(timeout_seconds=15)
    fn()

    assert resource.RLIMIT_CPU in applied_limits
    assert resource.RLIMIT_FSIZE in applied_limits
    assert resource.RLIMIT_CORE in applied_limits
    # Memory limit must be applied
    assert resource.RLIMIT_AS in applied_limits, "RLIMIT_AS (memory limit) was not applied"
    # Process count limit must be applied
    assert resource.RLIMIT_NPROC in applied_limits, "RLIMIT_NPROC (process count limit) was not applied"


def test_sandbox_rlimits_fail_visibly_on_error(monkeypatch):
    """If an rlimit cannot be applied, it must fail visibly and raise an error, not pass silently."""
    def mock_setrlimit_fail(res, limits):
        if res == resource.RLIMIT_AS:
            raise OSError("Permission denied setting memory limit")

    monkeypatch.setattr(dynamic_sandbox.resource, "setrlimit", mock_setrlimit_fail)

    fn = dynamic_sandbox._build_sandbox_rlimits(timeout_seconds=15)
    with pytest.raises(OSError, match="Permission denied setting memory limit"):
        fn()


def test_network_pcap_logs_reworded_away_from_captured_traffic():
    """Telemetry/log lines must describe PCAP as synthetic/reconstructed, never 'Captured ... network packet(s)'."""
    from app.services import sandbox_forensics

    events = [
        {
            "event_type": "network_connection",
            "dest_ip": "198.51.100.23",
            "dest_port": 4444,
            "protocol": "TCP",
            "timestamp": "2026-08-01T12:00:00Z",
        }
    ]
    pcap_art = sandbox_forensics.generate_pcap_capture(events, None, "test_run_limits")
    assert pcap_art is not None
    assert pcap_art["capture_type"] == "reconstructed_metadata"

    # Test the formatted log line helper
    log_line = dynamic_sandbox._format_pcap_log_line(pcap_art)
    assert "Captured " not in log_line
    assert "reconstructed" in log_line.lower() or "synthes" in log_line.lower()
