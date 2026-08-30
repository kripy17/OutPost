import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import host_forensics

client = TestClient(app)


def test_redact_sensitive_content():
    sample_text = "curl -u user:SuperSecretPassword123 https://api.com --token my_secret_token_abc"
    redacted = host_forensics.redact_sensitive_content(sample_text)
    assert "SuperSecretPassword123" not in redacted
    assert "my_secret_token_abc" not in redacted
    assert "******" in redacted

    bearer_text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDNJS3eedStdBux"
    redacted_bearer = host_forensics.redact_sensitive_content(bearer_text)
    assert "eyJ" not in redacted_bearer
    assert "******" in redacted_bearer

    privkey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    redacted_key = host_forensics.redact_sensitive_content(privkey)
    assert "[REDACTED_PRIVATE_KEY]" in redacted_key
    assert "MIIEow" not in redacted_key


def test_extract_cgroup_and_container_info():
    info = host_forensics.extract_cgroup_and_container_info(1)
    assert "container_runtime" in info
    assert "systemd_service" in info
    assert "cgroup_slice" in info
    assert "is_containerized" in info


def test_baseline_and_diff_endpoints():
    # 1. Capture baseline snapshot
    res_base = client.post("/system/xray/snapshot/baseline")
    assert res_base.status_code == 200
    base_data = res_base.json()
    assert "timestamp" in base_data
    assert "processes" in base_data
    assert "network" in base_data
    assert "metrics" in base_data
    assert base_data["process_count"] >= 0

    # 2. Get differential comparison
    res_diff = client.get("/system/xray/snapshot/diff")
    assert res_diff.status_code == 200
    diff_data = res_diff.json()
    assert "baseline_timestamp" in diff_data
    assert "current_timestamp" in diff_data
    assert "added_processes" in diff_data
    assert "removed_processes" in diff_data
    assert "new_listeners" in diff_data
    assert "closed_listeners" in diff_data
    assert "new_outbound" in diff_data
    assert "closed_outbound" in diff_data
    assert "metrics_delta" in diff_data
    assert "summary" in diff_data
    assert "added_processes_count" in diff_data["summary"]


def test_capsule_compare_endpoint():
    capsule_a = {
        "exported_at": "2026-08-29T10:00:00Z",
        "process_dossier": {
            "name": "nginx",
            "pid": 100,
            "user": "root",
            "command_line": "nginx -g 'daemon off;'",
            "executable_path": "/usr/sbin/nginx",
        },
        "security_posture": {
            "seccomp": "disabled",
            "capabilities_effective": [{"name": "CAP_NET_BIND_SERVICE"}],
            "mapped_libraries": [{"name": "libc.so.6"}],
        },
    }
    capsule_b = {
        "exported_at": "2026-08-29T10:05:00Z",
        "process_dossier": {
            "name": "malware_dropped",
            "pid": 500,
            "user": "root",
            "command_line": "/tmp/malware --c2 1.2.3.4",
            "executable_path": "/tmp/malware",
        },
        "security_posture": {
            "seccomp": "disabled",
            "capabilities_effective": [{"name": "CAP_SYS_ADMIN"}, {"name": "CAP_NET_RAW"}],
            "mapped_libraries": [{"name": "libc.so.6"}, {"name": "libcrypto.so.3"}],
        },
    }

    res = client.post("/system/xray/capsule/compare", json={"capsule_a": capsule_a, "capsule_b": capsule_b})
    assert res.status_code == 200
    data = res.json()
    assert "capsule_a" in data
    assert "capsule_b" in data
    assert "capabilities_diff" in data
    assert "CAP_NET_BIND_SERVICE" in data["capabilities_diff"]["only_in_a"]
    assert "CAP_SYS_ADMIN" in data["capabilities_diff"]["only_in_b"]
    assert "libcrypto.so.3" in data["libraries_diff"]["only_in_b"]
