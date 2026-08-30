import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import host_forensics

client = TestClient(app)


def test_device_access_inspection():
    # Inspect current process (PID 1 or self)
    res = host_forensics.get_process_device_access(1)
    assert "microphone" in res
    assert "camera" in res
    assert "screen_capture" in res
    assert "audio_capture" in res
    assert "audio_playback" in res
    assert "gpu" in res
    assert "sleep_inhibition" in res


def test_open_inodes_inspection():
    inodes = host_forensics.get_process_open_inodes(1)
    assert isinstance(inodes, list)
    if inodes:
        i = inodes[0]
        assert "fd" in i
        assert "path" in i
        assert "is_deleted" in i
        assert "is_memfd" in i
        assert "kind" in i
        assert "access" in i


def test_launch_chain_inspection():
    chain = host_forensics.get_process_launch_chain(1)
    assert "supervisor" in chain
    assert "service_scope" in chain
    assert "chain" in chain
    assert len(chain["chain"]) >= 2


def test_target_catalog_endpoint():
    res = client.get("/system/xray/catalog")
    assert res.status_code == 200
    data = res.json()
    assert "total_targets_count" in data
    assert "quick_inspect" in data
    assert "open_apps" in data
    assert "active_devices" in data
    assert "processes" in data
    assert "ports" in data
    assert "gpu" in data["quick_inspect"]
    assert "audio" in data["quick_inspect"]


def test_full_target_dossier_endpoint():
    # Test on PID 1 (init/systemd)
    res = client.get("/system/xray/process/1/full")
    assert res.status_code == 200
    data = res.json()
    assert "target" in data
    assert "launch_chain" in data
    assert "device_access" in data
    assert "security" in data
    assert "process_tree" in data
    assert "connections" in data
    assert "files_ipc" in data
    assert "findings" in data
    assert data["target"]["pid"] == 1
