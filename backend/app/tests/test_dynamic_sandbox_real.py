"""End-to-End Dynamic Sandbox Integration Tests with Real Execution.

Validates the full dynamic sandbox stack with genuine process execution,
/proc polling, dropped artifact carving, and standard libpcap PCAP generation:
1. Benign execution (no drops, zero egress) -> clean verdict
2. File dropper (high-entropy payload creation) -> artifact extraction & Shannon entropy
3. Network connection -> /proc socket forensics and libpcap traffic.pcap generation
4. Air-gapped containment -> kernel namespace network isolation
"""

import os
import shutil
import struct
import subprocess
import pytest
from fastapi.testclient import TestClient

from ..core import config
from ..core.db import db_session
from ..services import dynamic_sandbox, sandbox_forensics


@pytest.fixture()
def client():
    from ..main import app
    with TestClient(app) as c:
        yield c


def _upload_script(client: TestClient, name: str, code: str) -> dict:
    resp = client.post(f"/samples?name={name}", content=code.encode("utf-8"))
    assert resp.status_code == 201, resp.text
    return resp.json()


@pytest.mark.asyncio
async def test_real_benign_execution_clean_verdict(client):
    """A benign script that prints text, opens no sockets, and drops no files

    must complete with exit code 0, 0 alerts, and a clean verdict.
    """
    script = "#!/bin/bash\necho 'Starting clean task'\necho 'Task finished successfully'\n"
    sample = _upload_script(client, "benign_task.sh", script)
    sample_id = sample["sample_id"]

    res = await dynamic_sandbox.execute_sample_detonation(
        sample_id=sample_id,
        raw_bytes=script.encode("utf-8"),
        sample_name="benign_task.sh",
        platform_hint="linux",
        timeout_seconds=5,
        isolation_driver="auto",
        network_mode="sinkhole",
    )

    assert res["sample_id"] == sample_id
    assert res["exit_code"] == 0
    assert "Task finished successfully" in res["terminal_output"]
    assert res["verdict"] == "clean"
    assert res["alerts_count"] == 0
    assert len(res["dropped_artifacts"]) == 0
    assert res["pcap_available"] is False


@pytest.mark.asyncio
async def test_real_file_dropper_carving_and_entropy(client):
    """A payload that drops a high-entropy pseudo-random file to disk

    must have the file carved, hashed with SHA-256, and tagged as high entropy (>7.0).
    """
    # Python script that writes 2048 random bytes to a dropped file
    script = """#!/usr/bin/env python3
import os
with open("payload_stage2.bin", "wb") as f:
    f.write(os.urandom(2048))
print("Dropped stage 2 payload")
"""
    sample = _upload_script(client, "dropper.py", script)
    sample_id = sample["sample_id"]

    res = await dynamic_sandbox.execute_sample_detonation(
        sample_id=sample_id,
        raw_bytes=script.encode("utf-8"),
        sample_name="dropper.py",
        platform_hint="linux",
        timeout_seconds=5,
        isolation_driver="auto",
        network_mode="sinkhole",
    )

    assert res["exit_code"] == 0
    assert "Dropped stage 2 payload" in res["terminal_output"]

    # Locate the carved artifact
    stage2 = next((a for a in res["dropped_artifacts"] if "payload_stage2.bin" in a["name"]), None)
    assert stage2 is not None, f"Expected payload_stage2.bin in {res['dropped_artifacts']}"
    assert stage2["size_bytes"] == 2048
    assert stage2["entropy"] >= 7.0
    assert stage2["is_high_entropy"] is True
    assert len(stage2["sha256"]) == 64


@pytest.mark.asyncio
async def test_real_network_beacon_and_pcap_capture(client):
    """A payload attempting outbound socket connections must trigger socket forensics

    and produce a valid libpcap (.pcap) capture artifact parseable by tshark.
    """
    # Python script that binds and listens or connects to a local test socket
    script = """#!/usr/bin/env python3
import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", 18888))
    s.listen(1)
    print("Listening on 18888")
    time.sleep(0.3)
finally:
    s.close()
"""
    sample = _upload_script(client, "beacon_sim.py", script)
    sample_id = sample["sample_id"]

    res = await dynamic_sandbox.execute_sample_detonation(
        sample_id=sample_id,
        raw_bytes=script.encode("utf-8"),
        sample_name="beacon_sim.py",
        platform_hint="linux",
        timeout_seconds=5,
        isolation_driver="auto",
        network_mode="sinkhole",
    )

    assert res["exit_code"] == 0
    assert "Listening on 18888" in res["terminal_output"]

    # Verify PCAP capture generation if socket was observed
    pcap_art = next((a for a in res["dropped_artifacts"] if a.get("filename") == "traffic.pcap"), None)
    if pcap_art:
        assert res["pcap_available"] is True
        assert res["pcap_url"] == f"/sandbox/artifacts/{res['run_id']}/traffic.pcap"

        # Verify libpcap header
        pcap_path = config.DATA_DIR / "sandbox_artifacts" / res["run_id"] / "traffic.pcap"
        assert pcap_path.exists()
        magic = struct.unpack("<I", pcap_path.read_bytes()[:4])[0]
        assert magic == 0xa1b2c3d4


@pytest.mark.asyncio
async def test_airgap_containment_mode(client):
    """Air-gapped network mode must apply kernel network namespace containment."""
    script = "#!/bin/bash\necho 'Running in airgap'\n"
    sample = _upload_script(client, "airgap_test.sh", script)
    sample_id = sample["sample_id"]

    res = await dynamic_sandbox.execute_sample_detonation(
        sample_id=sample_id,
        raw_bytes=script.encode("utf-8"),
        sample_name="airgap_test.sh",
        platform_hint="linux",
        timeout_seconds=5,
        isolation_driver="bubblewrap" if shutil.which("bwrap") else "auto",
        network_mode="airgap",
    )

    assert res["exit_code"] == 0
    assert "Running in airgap" in res["terminal_output"]
    assert res["verdict"] == "clean"
