"""Tests for Adversary Technique Simulation Catalog & Execution."""

import pytest
from app.services import technique_catalog
from app.services.dynamic_sandbox import execute_technique_test, execute_simulation_scenario_stage


def test_technique_catalog_queries():
    tests = technique_catalog.list_technique_tests()
    assert len(tests) >= 10

    # Filter by tactic
    persist = technique_catalog.list_technique_tests(tactic="Persistence")
    assert len(persist) >= 2
    assert all(t["tactic"] == "Persistence" for t in persist)

    # Filter by platform
    linux_tests = technique_catalog.list_technique_tests(platform="linux")
    assert len(linux_tests) >= 8

    # Query search
    cron_search = technique_catalog.list_technique_tests(q="cron")
    assert any("cron" in t["name"].lower() or "cron" in t["description"].lower() for t in cron_search)

    # Get single test
    t = technique_catalog.get_technique_test("T1053.003-cron-canary")
    assert t is not None
    assert t["technique_id"] == "T1053.003"


@pytest.mark.asyncio
async def test_execute_technique_test_lifecycle():
    # Test execution of a benign discovery or execution technique test
    res = await execute_technique_test("T1082-sysinfo-discovery")
    assert res["status"] == "success"
    assert res["exit_code"] == 0
    assert res["prereqs_met"] is True
    assert res["cleanup_status"] in ("success", "not_needed")
    assert res["run_id"].startswith("tech_")


@pytest.mark.asyncio
async def test_execute_simulation_stage_with_facts():
    # Test dynamic facts interpolation
    res = await execute_simulation_scenario_stage(
        scenario_id="apt29-cloud-intrusion",
        stage_number=1,
        facts={"CUSTOM_FLAG": "RUNTIME_TEST_FACT"},
    )
    assert res["status"] in ("success", "failed")
    assert "facts" in res
    assert isinstance(res["facts"], dict)

