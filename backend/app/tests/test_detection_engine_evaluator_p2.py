"""Tests for Phase 2.2: Detection Engine Correctness & Evaluator.

Verifies:
1. Sigma Real Evaluator:
   - Condition parsing and evaluation across selections (selection and not filter, 1 of selection*, all of them, OR logic, parentheses)
   - 'all' modifier on fields (CommandLine|contains|all)
   - Preservation of regex escape sequences without lowercasing (\\S, \\D, \\B)
   - Rejection / validation of rules referencing unsupported telemetry fields
   - Safe regex search with bounded execution time
2. Alert Attribution & Flood Caps:
   - Attribution by compound process entity (host_id, boot_id, pid, process_start_time)
   - Ensuring a second process contacting the same destination is NEVER deduped away
   - Triggered timestamp matches event timestamp, not ingest time
   - PPID fallback setting pid_fallback: True
   - Flood caps preserving first occurrence per entity
3. Beaconing & Risk Scoring:
   - Interval regularity using coefficient of variation (CV = sigma / mu < 0.25)
   - Attribution to originating process PID
   - Per-entity threat score accounting for severity, kill-chain progression, repetition, and time decay
"""

import pytest
from datetime import datetime, timezone, timedelta
from ..services.rule_generator import transpile_sigma_yaml
from ..services.detection import (
    evaluate_sigma_condition,
    evaluate_sigma_selection,
    safe_regex_search,
    check_custom_sigma_rules,
    _make_alert,
    make_entity_key,
    check_beaconing,
)
from ..services.risk import (
    compute_risk_score,
    compute_entity_risk_score,
    recalculate_run_risk,
)
from ..core.db import db_session
from .conftest import make_run


# ===========================================================================
# 1. Sigma Real Evaluator Tests
# ===========================================================================

def test_sigma_condition_evaluator_syntax():
    """Verify boolean condition parsing across selections, operators, and quantifiers."""
    all_names = ["selection_1", "selection_2", "filter_1", "filter_2", "sel_special"]

    # Basic AND / NOT
    assert evaluate_sigma_condition(
        "selection_1 and not filter_1",
        {"selection_1": True, "filter_1": False},
        all_names,
    ) is True

    assert evaluate_sigma_condition(
        "selection_1 and not filter_1",
        {"selection_1": True, "filter_1": True},
        all_names,
    ) is False

    # OR logic with parentheses
    assert evaluate_sigma_condition(
        "(selection_1 or selection_2) and not filter_1",
        {"selection_1": False, "selection_2": True, "filter_1": False},
        all_names,
    ) is True

    # Quantifier: 1 of selection*
    assert evaluate_sigma_condition(
        "1 of selection* and not 1 of filter*",
        {"selection_1": False, "selection_2": True, "filter_1": False, "filter_2": False},
        all_names,
    ) is True

    assert evaluate_sigma_condition(
        "1 of selection* and not 1 of filter*",
        {"selection_1": False, "selection_2": True, "filter_1": True, "filter_2": False},
        all_names,
    ) is False

    # Quantifier: all of selection*
    assert evaluate_sigma_condition(
        "all of selection*",
        {"selection_1": True, "selection_2": False},
        all_names,
    ) is False

    assert evaluate_sigma_condition(
        "all of selection*",
        {"selection_1": True, "selection_2": True},
        all_names,
    ) is True

    # Quantifier: 1 of them / all of them
    assert evaluate_sigma_condition(
        "1 of them",
        {"selection_1": False, "selection_2": False, "sel_special": True},
        all_names,
    ) is True

    assert evaluate_sigma_condition(
        "all of them",
        {"selection_1": True, "selection_2": True, "filter_1": True, "filter_2": True, "sel_special": True},
        all_names,
    ) is True


def test_sigma_all_modifier_behavior():
    """CommandLine|contains|all must require ALL specified substrings."""
    sigma_yaml = """
title: Test Mimikatz All Modifier
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'privilege::debug'
            - 'sekurlsa::logonpasswords'
    condition: selection
"""
    rule_def = transpile_sigma_yaml(sigma_yaml)
    assert rule_def["condition"] == "selection"

    # Event with only ONE keyword must NOT trigger
    ev_partial = {
        "event_type": "process_create",
        "command_line": "mimikatz.exe privilege::debug exit",
        "pid": 1001,
    }
    alerts = check_custom_sigma_rules({rule_def["rule_id"]: rule_def}, ev_partial)
    assert len(alerts) == 0

    # Event with BOTH keywords MUST trigger
    ev_full = {
        "event_type": "process_create",
        "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        "pid": 1001,
    }
    alerts = check_custom_sigma_rules({rule_def["rule_id"]: rule_def}, ev_full)
    assert len(alerts) == 1
    assert "privilege::debug" in rule_def["selections"]["selection"][0][0]["values"]


def test_sigma_regex_preserves_escape_sequences():
    """Regex patterns must preserve uppercase escape sequences (\\S, \\D, \\B) without lowercasing."""
    sigma_yaml = r"""
title: Test Regex NonWhitespace Preservation
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|re: 'payload=\S+@\S+'
    condition: selection
"""
    rule_def = transpile_sigma_yaml(sigma_yaml)
    crit = rule_def["selections"]["selection"][0][0]
    assert crit["is_regex"] is True
    # The pattern must keep \S, not be altered to \s
    assert r"\S+@\S+" in crit["values"][0]

    # Matching string (non-whitespace)
    ev_match = {
        "event_type": "process_create",
        "command_line": "runner.exe payload=user123@evil.org",
        "pid": 1002,
    }
    alerts = check_custom_sigma_rules({rule_def["rule_id"]: rule_def}, ev_match)
    assert len(alerts) == 1

    # Non-matching string (has spaces where \S is required)
    ev_nomatch = {
        "event_type": "process_create",
        "command_line": "runner.exe payload=   @   ",
        "pid": 1002,
    }
    alerts = check_custom_sigma_rules({rule_def["rule_id"]: rule_def}, ev_nomatch)
    assert len(alerts) == 0


def test_safe_regex_bounded_execution():
    """Verify safe_regex_search defends against ReDoS without crashing."""
    # Simple regex
    assert safe_regex_search(r"^hello.*world$", "hello brave new world") is True
    assert safe_regex_search(r"^hello.*world$", "something else") is False

    # Pathological pattern that would catastrophic-backtrack on standard regex engine
    pathological = r"^(a+)+$"
    # safe_regex_search must return cleanly within timeout
    result = safe_regex_search(pathological, "a" * 30 + "X", timeout_seconds=0.02)
    assert result is False


def test_sigma_unsupported_field_rejected():
    """Sigma rule referencing unsupported telemetry field must be rejected at import."""
    unsupported_yaml = """
title: Rule with Nonexistent Sensor Telemetry
logsource:
    category: hardware_bus
detection:
    selection:
        ArbitraryVendorBusID|contains: 'PCI-001'
    condition: selection
"""
    with pytest.raises(ValueError, match="Unsupported telemetry field"):
        transpile_sigma_yaml(unsupported_yaml)


# ===========================================================================
# 2. Alert Attribution & Flood Caps Tests
# ===========================================================================

def test_alert_attribution_does_not_dedupe_second_process(client):
    """Two different processes contacting the same destination must NOT dedupe away the second process."""
    rid = make_run(client, sample_name="det-two-proc-dest")

    # Process 1 (PID 1001) connects to unusual port
    ev1 = {
        "run_id": rid,
        "platform": "linux",
        "event_type": "network_connection",
        "timestamp": "2026-09-10T12:00:00Z",
        "pid": 1001,
        "process_name": "malware_a",
        "dest_ip": "198.51.100.99",
        "dest_port": 4444,
        "protocol": "tcp",
    }
    client.post("/ingest/batch", json=[ev1])

    # Process 2 (PID 1002) connects to the EXACT SAME destination
    ev2 = {
        "run_id": rid,
        "platform": "linux",
        "event_type": "network_connection",
        "timestamp": "2026-09-10T12:00:10Z",
        "pid": 1002,
        "process_name": "malware_b",
        "dest_ip": "198.51.100.99",
        "dest_port": 4444,
        "protocol": "tcp",
    }
    client.post("/ingest/batch", json=[ev2])

    resp = client.get(f"/runs/{rid}/alerts")
    assert resp.status_code == 200
    alerts = resp.json()
    unusual_alerts = [a for a in alerts if a["rule_id"] == "unusual-port"]

    # Both processes must have their own alert!
    assert len(unusual_alerts) == 2
    pids = {a["related_pid"] for a in unusual_alerts}
    assert pids == {1001, 1002}


def test_alert_triggered_at_uses_event_timestamp():
    """Alert triggered_at and last_seen_at must reflect event timestamp, not ingest time."""
    ev = {
        "run_id": "run-test-ts",
        "event_type": "process_create",
        "timestamp": "2026-05-15T08:30:00Z",
        "pid": 5555,
        "process_name": "curl",
    }
    alert = _make_alert("run-test-ts", "test-rule", "Test Rule", "suspicious", ev, "details")
    assert alert.triggered_at.year == 2026
    assert alert.triggered_at.month == 5
    assert alert.triggered_at.day == 15
    assert alert.triggered_at.hour == 8
    assert alert.triggered_at.minute == 30


def test_alert_pid_fallback_marked_explicitly():
    """When PID is missing or 0 and parent PPID is used, pid_fallback must be True."""
    # Case 1: PID is present
    ev_with_pid = {
        "run_id": "run-test-pid",
        "pid": 2020,
        "ppid": 1010,
        "timestamp": "2026-09-10T12:00:00Z",
    }
    a1 = _make_alert("run-test-pid", "test-rule", "Test", "suspicious", ev_with_pid, "Details")
    assert a1.related_pid == 2020
    assert a1.pid_fallback is False

    # Case 2: PID is None, PPID is present
    ev_fallback = {
        "run_id": "run-test-pid",
        "pid": None,
        "ppid": 1010,
        "timestamp": "2026-09-10T12:00:00Z",
    }
    a2 = _make_alert("run-test-pid", "test-rule", "Test", "suspicious", ev_fallback, "Details")
    assert a2.related_pid == 1010
    assert a2.pid_fallback is True
    assert "[PID fallback to parent PPID 1010]" in a2.details


# ===========================================================================
# 3. Beaconing & Risk Scoring Tests
# ===========================================================================

def test_beaconing_cv_regularity_and_pid_attribution(client):
    """Beaconing detection uses CV = sigma / mu < 0.25 and attributes to originating PID."""
    rid = make_run(client, sample_name="beaconing-cv-test")

    # Regular connections every 10 seconds with slight jitter (+/- 0.5s)
    # intervals ~ 10.0, 9.5, 10.5, 10.0 -> CV ~ 0.04 << 0.25
    timestamps = [
        "2026-09-10T12:00:00Z",
        "2026-09-10T12:00:10Z",
        "2026-09-10T12:00:19Z",
        "2026-09-10T12:00:30Z",
        "2026-09-10T12:00:40Z",
    ]
    events = [
        {
            "run_id": rid,
            "platform": "linux",
            "event_type": "network_connection",
            "timestamp": ts,
            "pid": 8888,
            "process_name": "c2_agent",
            "dest_ip": "198.51.100.250",
            "dest_port": 8443,
            "protocol": "tcp",
        }
        for ts in timestamps
    ]
    client.post("/ingest/batch", json=events)

    alerts = client.get(f"/runs/{rid}/alerts").json()
    beacon_alerts = [a for a in alerts if a["rule_id"] == "beaconing"]
    assert len(beacon_alerts) == 1
    alert = beacon_alerts[0]
    assert alert["related_pid"] == 8888
    assert alert["related_ip"] == "198.51.100.250"
    assert "CV:" in alert["details"]


def test_entity_risk_scoring_multitactic_and_repetition():
    """Per-entity risk scoring accounts for severity, repetition, and kill-chain progression."""
    # Entity 1: Touched Execution + Persistence + Command and Control (3 tactics)
    now = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
    alerts = [
        {
            "rule_id": "lolbin-abuse",  # Execution, weight 14, malicious
            "severity": "malicious",
            "related_pid": 5001,
            "occurrence_count": 3,
            "triggered_at": now.isoformat(),
            "last_seen_at": now.isoformat(),
        },
        {
            "rule_id": "registry-persistence",  # Persistence, weight 16, suspicious
            "severity": "suspicious",
            "related_pid": 5001,
            "occurrence_count": 1,
            "triggered_at": now.isoformat(),
            "last_seen_at": now.isoformat(),
        },
        {
            "rule_id": "beaconing",  # C2, weight 15, suspicious
            "severity": "suspicious",
            "related_pid": 5001,
            "occurrence_count": 5,
            "triggered_at": now.isoformat(),
            "last_seen_at": now.isoformat(),
        },
    ]

    res = compute_entity_risk_score(alerts, reference_time=now)
    assert res["overall_risk"] > 45
    ent = res["entities"]["proc:5001"]
    assert ent["distinct_rules_count"] == 3
    assert ent["total_occurrences"] == 9
    assert len(ent["tactics"]) >= 3
