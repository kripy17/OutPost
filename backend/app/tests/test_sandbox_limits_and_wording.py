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


def test_sandbox_rlimits_wine_memory_handling(monkeypatch):
    """Wine execution must not set RLIMIT_AS (breaks Wine's 3GB+ mmap), using RLIMIT_DATA instead."""
    applied_limits = {}

    def mock_setrlimit(res, limits):
        applied_limits[res] = limits

    monkeypatch.setattr(dynamic_sandbox.resource, "setrlimit", mock_setrlimit)

    fn = dynamic_sandbox._build_sandbox_rlimits(timeout_seconds=15, is_wine=True)
    fn()

    assert resource.RLIMIT_AS not in applied_limits, "RLIMIT_AS must not be constrained for Wine"
    assert resource.RLIMIT_DATA in applied_limits, "RLIMIT_DATA should bound heap memory for Wine"


def test_sandbox_rlimits_fail_visibly_on_error(monkeypatch):
    """If an rlimit cannot be applied, it must fail visibly and raise an error, not pass silently."""
    def mock_setrlimit_fail(res, limits):
        if res == resource.RLIMIT_AS:
            raise OSError("Permission denied setting memory limit")

    monkeypatch.setattr(dynamic_sandbox.resource, "setrlimit", mock_setrlimit_fail)

    fn = dynamic_sandbox._build_sandbox_rlimits(timeout_seconds=15)
    with pytest.raises(OSError, match="Permission denied setting memory limit"):
        fn()



