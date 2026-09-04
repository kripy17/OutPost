"""Tests for Network Protocol & C2 Beaconing Analytics Engine."""

import pytest
from starlette.testclient import TestClient

from app.main import app
from app.core.db import db_session
from app.services.network_protocol_analyzer import (
    analyze_beaconing_intervals,
    analyze_run_network_telemetry,
    calculate_string_entropy,
    evaluate_dga_score,
)


def test_entropy_and_dga_evaluation():
    # Standard domain
    std_score, std_indicators = evaluate_dga_score("update.microsoft.com")
    assert std_score < 0.5
    assert not any("Abused high-risk TLD" in ind for ind in std_indicators)

    # Randomized DGA domain with high entropy and suspicious TLD
    dga_score, dga_indicators = evaluate_dga_score("xkq92bzm981kqzp5.top")
    assert dga_score >= 0.65
    assert any("entropy" in ind.lower() for ind in dga_indicators)
    assert any(".top" in ind for ind in dga_indicators)


def test_beaconing_interval_regularity():
    # Regular periodic beacon: exactly ~10s interval
    regular_ts = [
        "2026-09-04T12:00:00Z",
        "2026-09-04T12:00:10Z",
        "2026-09-04T12:00:20.1Z",
        "2026-09-04T12:00:29.9Z",
        "2026-09-04T12:00:40Z",
    ]
    beacon_stats = analyze_beaconing_intervals(regular_ts)
    assert beacon_stats["is_beaconing"] is True
    assert beacon_stats["beaconing_score"] >= 60
    assert beacon_stats["jitter_pct"] < 20.0
    assert "Beacon" in beacon_stats["verdict"]

    # Irregular interactive traffic: variable intervals
    random_ts = [
        "2026-09-04T12:00:00Z",
        "2026-09-04T12:00:03Z",
        "2026-09-04T12:00:45Z",
        "2026-09-04T12:02:10Z",
        "2026-09-04T12:02:15Z",
    ]
    random_stats = analyze_beaconing_intervals(random_ts)
    assert random_stats["is_beaconing"] is False
    assert random_stats["jitter_pct"] > 50.0


def test_analyze_run_network_telemetry_flow():
    events = [
        # DNS query
        {
            "event_type": "network_connection",
            "protocol": "udp",
            "dest_port": 53,
            "dest_ip": "198.51.100.99",
            "timestamp": "2026-09-04T12:00:00Z",
            "process_name": "curl",
            "pid": 1001,
            "query": "c2-gate.xyz",
        },
        # HTTP C2 beacon request
        {
            "event_type": "network_connection",
            "protocol": "tcp",
            "dest_ip": "198.51.100.99",
            "dest_port": 80,
            "timestamp": "2026-09-04T12:00:05Z",
            "command_line": "curl -X POST http://198.51.100.99/gate.php?id=node1",
            "process_name": "curl",
            "pid": 1001,
        },
        # TLS Handshake with known Cobalt Strike JA3
        {
            "event_type": "network_connection",
            "protocol": "tcp",
            "dest_ip": "198.51.100.99",
            "dest_port": 443,
            "timestamp": "2026-09-04T12:00:10Z",
            "tls_sni": "cdn-cloud-sync.com",
            "tls_ja3": "a0e9f5d64349fb13191bc781f81f42e1",
            "process_name": "beacon.bin",
            "pid": 1002,
        },
    ]

    analysis = analyze_run_network_telemetry(events)

    # Verify DNS
    dns = analysis["dns_conversations"]
    assert len(dns) == 1
    assert dns[0]["query"] == "c2-gate.xyz"
    assert "198.51.100.99" in dns[0]["resolved_ips"]
    assert dns[0]["category"] == "Suspicious TLD"

    # Verify HTTP
    http = analysis["http_requests"]
    assert len(http) == 1
    assert http[0]["method"] == "POST"
    assert "/gate.php" in http[0]["path"]
    assert http[0]["is_suspicious"] is True
    assert any("gate.php" in ind for ind in http[0]["threat_indicators"])

    # Verify TLS
    tls = analysis["tls_handshakes"]
    assert len(tls) == 1
    assert tls[0]["known_tool"] == "Cobalt Strike Malleable C2"
    assert tls[0]["severity"] == "malicious"

    # Verify Flows
    flows = analysis["flows"]
    assert len(flows) >= 1
    mal_flow = next((f for f in flows if f["dest_ip"] == "198.51.100.99" and f["dest_port"] == 443), None)
    assert mal_flow is not None
    assert mal_flow["reputation"] == "malicious"


def test_api_run_network_analysis_endpoint():
    client = TestClient(app)
    run_id = "test-net-run-001"
    with db_session() as conn:
        from app.models import run as run_store
        run_store.create_run(conn, run_id, "test_net_sample", "linux")

    # 1. Ingest run with network event
    ev = {
        "run_id": run_id,
        "platform": "linux",
        "event_type": "network_connection",
        "timestamp": "2026-09-04T12:00:00Z",
        "dest_ip": "203.0.113.50",
        "dest_port": 443,
        "protocol": "tcp",
        "tls_sni": "telemetry-update.top",
        "query": "telemetry-update.top",
        "command_line": "curl https://telemetry-update.top/api/v1/beacon",
    }
    client.post("/ingest/batch", json=[ev])

    # 2. Call GET /runs/{run_id}/network-analysis
    resp = client.get(f"/runs/{run_id}/network-analysis")
    assert resp.status_code == 200
    data = resp.json()

    assert "dns_conversations" in data
    assert "http_requests" in data
    assert "tls_handshakes" in data
    assert "c2_beaconing" in data
    assert "metrics" in data
    assert data["metrics"]["unique_flows_count"] >= 1
