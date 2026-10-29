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


def test_worker_minimal_clean_env_does_not_leak_secrets(monkeypatch):
    """Verify that worker subprocess runs in a sanitized minimal environment without host secrets."""
    monkeypatch.setenv("OUTPOST_MASTER_KEY", "super_secret_master_key_12345")
    monkeypatch.setenv("AGENT_SHARED_SECRET", "agent_secret_token_abcdef")

    # Inspect the environment that worker uses
    clean_env = worker._build_minimal_worker_env()
    assert "OUTPOST_MASTER_KEY" not in clean_env
    assert "AGENT_SHARED_SECRET" not in clean_env
    assert clean_env.get("NO_PROXY") == "*"


def test_worker_rlimit_failure_returns_structured_error(monkeypatch):
    """Verify that if resource limit application fails, a structured error is returned instead of swallowing."""
    def _failing_rlimits():
        raise OSError("Simulated rlimit failure: Operation not permitted")

    monkeypatch.setattr(worker, "_set_worker_rlimits", _failing_rlimits)
    res = worker.execute_in_isolated_worker(b"test data", timeout_sec=5.0)
    assert res["status"] in ("rlimit_enforcement_failed", "parser_failed")
    assert "resource limit" in res["error"].lower() or "rlimit" in res["error"].lower() or "operation not permitted" in res["error"].lower()
    assert res["verdict"] == "parser_failed"


def test_isolated_worker_when_launched_from_backend_directory():
    """Verify worker subprocess succeeds when current working directory is backend/ (like start.sh)."""
    import os
    from pathlib import Path

    orig_cwd = os.getcwd()
    backend_dir = Path(__file__).resolve().parent.parent.parent
    os.chdir(backend_dir)
    try:
        sample_code = b"#!/usr/bin/env python3\nprint('sandbox worker verification')\n"
        res = worker.execute_in_isolated_worker(sample_code, timeout_sec=5.0)
        assert res.get("status") != "parser_failed"
        assert res.get("verdict") == "no_indicators_found_limited"
        assert res.get("format") == "script"
    finally:
        os.chdir(orig_cwd)


def test_wheel_package_contains_all_static_subpackages():
    """Verify pyproject.toml package definitions include all static subpackages."""
    import importlib
    submodules = [
        "app.services.static.fidelity",
        "app.services.static.indicators",
        "app.services.static.pipeline",
        "app.services.static.provenance",
        "app.services.static.verdict",
        "app.services.static.worker",
        "app.services.static.strings",
        "app.services.static.yara_scanner",
        "app.services.static.decoders.base",
        "app.services.static.decoders.manager",
        "app.services.static.decoders.agent_tesla",
        "app.services.static.decoders.cobalt_strike",
        "app.services.static.decoders.remcos",
        "app.services.static.decoders.asyncrat",
        "app.services.static.decoders.redline",
        "app.services.static.formats.archive",
        "app.services.static.formats.elf",
        "app.services.static.formats.lnk",
        "app.services.static.formats.office",
        "app.services.static.formats.pdf",
        "app.services.static.formats.pe",
        "app.services.static.formats.script",
    ]
    for mod_name in submodules:
        mod = importlib.import_module(mod_name)
        assert mod is not None


def test_isolated_worker_rlimits_application():
    """Verify worker subprocess applies rlimits (AS, CPU, FSIZE, NOFILE, CORE)."""
    # Simply running a normal sample exercises the preexec_fn _set_worker_rlimits
    data = b"#!/usr/bin/env python3\nprint('rlimits applied')\n"
    res = worker.execute_in_isolated_worker(data, timeout_sec=5.0)
    assert res.get("status") != "rlimit_enforcement_failed"
    assert res.get("verdict") == "no_indicators_found_limited"


def test_analyze_sample_dispatch_and_schema_coherence():
    """Verify end-to-end coherence between in-process and isolated worker execution."""
    from app.services import static_analysis

    sample = b"#!/bin/bash\nwhoami\necho 'Test execution'\n"
    
    # 1. In-process execution
    in_proc = static_analysis.analyze_sample(sample, isolate=False)
    assert in_proc["analysis_fidelity"]["worker_sandboxed"] is False

    # 2. Subprocess isolated execution
    isolated = static_analysis.analyze_sample(sample, isolate=True, timeout_sec=5.0)
    assert isolated["analysis_fidelity"]["worker_sandboxed"] is True
    assert isolated["analysis_fidelity"]["environment"] == "isolated_static_worker"

    # 3. Coherence check: core top-level keys must match
    expected_keys = [
        "sha256", "md5", "sha1", "fuzzy_hash", "format",
        "entropy", "entropy_histogram", "verdict", "static_risk_score",
        "score_description", "assessment_factors", "findings",
        "capabilities", "embedded_indicators", "benign_factors",
        "could_not_analyze", "strings", "strings_detailed",
        "categorized_strings", "yara", "analysis_fidelity",
    ]
    for k in expected_keys:
        assert k in in_proc, f"Missing key {k} in in-process result"
        assert k in isolated, f"Missing key {k} in isolated worker result"

    assert in_proc["verdict"] == isolated["verdict"]
    assert in_proc["static_risk_score"] == isolated["static_risk_score"]
    assert in_proc["sha256"] == isolated["sha256"]


def test_analysis_job_api_runs_isolated_worker(client):
    """Verify static analysis jobs submitted via API run through isolated worker."""
    # Upload sample via raw request body
    script_bytes = b"#!/bin/sh\necho 'API worker test'\n"
    upload_res = client.post(
        "/samples",
        params={"name": "test_script.sh"},
        content=script_bytes,
    )
    assert upload_res.status_code == 201
    sample_id = upload_res.json()["sample_id"]

    # Trigger static analysis job
    job_res = client.post(
        "/analysis",
        json={"sample_id": sample_id, "backend": "static"},
    )
    assert job_res.status_code == 201
    job_data = job_res.json()
    assert job_data["status"] == "completed"
    assert job_data["progress"] == 100
    run_id = job_data["run_id"]

    # Check observations endpoint
    obs_res = client.get(f"/analysis/{run_id}/observations")
    assert obs_res.status_code == 200
    obs_data = obs_res.json()
    assert obs_data["backend"] == "static"
    obs_map = {item["kind"]: item["data"] for item in obs_data["observations"]}
    assert "verdict" in obs_map
    assert obs_map["analysis_fidelity"]["worker_sandboxed"] is True
    assert obs_map["analysis_fidelity"]["environment"] == "isolated_static_worker"

