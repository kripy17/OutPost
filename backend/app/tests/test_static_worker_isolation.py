"""Tests for isolated static analysis worker subprocess, resource limits, and crash resilience."""

from app.services.static import worker


def test_isolated_worker_normal_execution():
    """Verify clean execution inside isolated worker subprocess."""
    data = b"#!/bin/bash\necho 'hello world'\n"
    res = worker.execute_in_isolated_worker(data, timeout_sec=5.0)

    assert "verdict" in res
    assert "analysis_fidelity" in res
    assert res["analysis_fidelity"]["environment"] == "isolated_static_worker"
    assert res["analysis_fidelity"]["environment_tier"] == "offline_static"
    assert res["format"] == "script"


def test_isolated_worker_timeout_handling():
    """Verify that a worker timeout is caught cleanly without crashing the API."""
    data = b"sample_timeout_test_data"
    # Set a tiny timeout to trigger timeout handler
    res = worker.execute_in_isolated_worker(data, timeout_sec=0.0001)

    assert res["status"] == "parser_timeout"
    assert "timed out" in res["error"]
    assert res["verdict"] == "parser_failed"
    assert "analysis_fidelity" in res


def test_isolated_worker_malformed_hostile_input_resilience():
    """Verify that corrupted binary headers never raise unhandled exceptions."""
    corrupted_data = b"MZ" + b"\xFF" * 100 + b"PE\x00\x00" + b"\x00" * 20
    res = worker.execute_in_isolated_worker(corrupted_data, timeout_sec=5.0)

    assert "verdict" in res
    # Should complete with structured result
    assert res.get("status") in ("parser_failed", None) or res["verdict"] in ("no_indicators_found_limited", "parser_failed", "insufficient_evidence")
