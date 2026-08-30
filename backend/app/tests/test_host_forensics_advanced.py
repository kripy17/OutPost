"""Tests for advanced Omarchy X-Ray inspired features: capabilities, security posture, target resolver, lifecycle controls, forensic capsules."""

import os
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.services import host_forensics

client = TestClient(app)


def test_decode_capabilities():
    """Verify Linux capability decoding from hex bitmasks."""
    # Test CAP_SYS_ADMIN (bit 21 = 0x200000)
    caps = host_forensics.decode_capabilities("0000000000200000")
    assert len(caps) == 1
    assert caps[0]["name"] == "CAP_SYS_ADMIN"
    assert caps[0]["is_dangerous"] is True

    # Test multiple caps (e.g. NET_ADMIN + NET_RAW)
    # NET_ADMIN is bit 12 (0x1000), NET_RAW is bit 13 (0x2000) -> 0x3000
    multi_caps = host_forensics.decode_capabilities("0000000000003000")
    names = [c["name"] for c in multi_caps]
    assert "CAP_NET_ADMIN" in names
    assert "CAP_NET_RAW" in names


def test_extract_security_posture_current_process():
    """Verify security posture extraction on current running test process."""
    my_pid = os.getpid()
    posture = host_forensics.extract_security_posture(my_pid)

    assert "seccomp" in posture
    assert "no_new_privs" in posture
    assert "capabilities_effective" in posture
    assert "namespaces" in posture
    assert "mapped_libraries" in posture
    assert "package_provenance" in posture


def test_universal_target_resolver():
    """Verify target resolver syntax: :port, pid:, file:, and text."""
    my_pid = os.getpid()

    # PID query
    res_pid = host_forensics.resolve_target_search(f"pid:{my_pid}")
    assert res_pid["target_type"] == "pid"
    assert any(p["pid"] == my_pid for p in res_pid["matched_processes"])

    # Port query (e.g. :65534)
    res_port = host_forensics.resolve_target_search(":80")
    assert res_port["target_type"] == "port"

    # Text query
    res_text = host_forensics.resolve_target_search("python")
    assert res_text["target_type"] == "text"


def test_forensic_capsule_generation():
    """Verify forensic capsule (.xray.json) schema and contents."""
    my_pid = os.getpid()
    capsule = host_forensics.generate_forensic_capsule(my_pid)

    assert capsule is not None
    assert capsule["target_pid"] == my_pid
    assert "host_context" in capsule
    assert "process_dossier" in capsule
    assert "security_posture" in capsule
    assert "correlated_telemetry" in capsule


def test_api_xray_capsule_endpoint():
    """Verify GET /system/xray/process/{pid}/capsule."""
    my_pid = os.getpid()
    resp = client.get(f"/system/xray/process/{my_pid}/capsule")
    assert resp.status_code == 200
    data = resp.json()
    assert data["target_pid"] == my_pid
    assert data["version"] == "1.0.0"


def test_api_xray_process_action_endpoint():
    """Verify POST /system/xray/process/{pid}/action invalid action handling."""
    my_pid = os.getpid()
    # Test unsupported action
    resp = client.post(
        f"/system/xray/process/{my_pid}/action",
        json={"action": "unknown_action"},
        headers={"X-User-Role": "admin"},
    )
    assert resp.status_code == 200
    assert resp.json()["success"] is False
    assert "Unsupported" in resp.json()["message"]


def test_api_xray_universal_search_endpoint():
    """Verify GET /system/xray/search with port syntax."""
    resp = client.get("/system/xray/search?q=:8000")
    assert resp.status_code == 200
    data = resp.json()
    assert data["target_type"] == "port"


def test_process_tree_service_and_endpoint():
    """Verify process causality tree generation and API route."""
    tree = host_forensics.get_process_tree()
    assert isinstance(tree, list)
    assert len(tree) > 0
    root = tree[0]
    assert "pid" in root
    assert "children" in root

    resp = client.get("/system/xray/tree")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) > 0


def test_network_matrix_service_and_endpoint():
    """Verify categorized network matrix and API route."""
    matrix = host_forensics.get_categorized_network_matrix()
    assert "public_listeners" in matrix
    assert "loopback_listeners" in matrix
    assert "outbound_connections" in matrix
    assert "summary" in matrix

    resp = client.get("/system/xray/network")
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data
    assert "total_sockets" in data["summary"]


def test_behavioral_explanations_service_and_endpoint():
    """Verify automated behavioral explanations engine and API route."""
    explanations = host_forensics.generate_behavioral_explanations()
    assert isinstance(explanations, list)

    resp = client.get("/system/xray/explanations")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
