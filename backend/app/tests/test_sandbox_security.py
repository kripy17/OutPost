"""Security + verdict-band regression tests for the dynamic sandbox.

Covers the audit findings:
- payload filenames can never escape the mkdtemp cage (traversal/absolute),
- the detonated child never inherits operator secret env vars,
- a nonzero exit code alone no longer flips the verdict to suspicious.
"""

import json
import os

import pytest
from fastapi.testclient import TestClient

# NOTE: app/db imports are deliberately LAZY (inside fixtures/helpers) — a
# module-level `from app.main import app` would import the whole API surface
# at collection time, BEFORE conftest's session fixture reassigns
# config.DATABASE_PATH, freezing the real DB path into any by-value
# importers (routes_admin). Keep it lazy.


class _FakeProc:
    def __init__(self, returncode: int = 0):
        self.returncode = returncode

    async def communicate(self):
        return b"", b""


def _cleanup(run_id: str | None, sample_id: str | None) -> None:
    from app.core.db import db_session

    with db_session() as conn:
        if run_id:
            conn.execute("DELETE FROM events WHERE run_id = ?", (run_id,))
            conn.execute("DELETE FROM alerts WHERE run_id = ?", (run_id,))
            conn.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
        if sample_id:
            for table in ("ioc_provenance", "samples"):
                try:
                    if table == "samples":
                        conn.execute("DELETE FROM samples WHERE sample_id = ?", (sample_id,))
                    else:
                        conn.execute("DELETE FROM ioc_provenance WHERE ref_type='sample' AND ref_id = ?", (sample_id,))
                except Exception:
                    pass
        try:
            os.unlink(os.path.join(str(__import__("pathlib").Path(__file__).resolve().parents[3] / "data" / "samples"), f"{sample_id}.bin"))
        except Exception:
            pass
        conn.commit()


@pytest.fixture()
def client():
    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def dynamic_sandbox():
    from app.services import dynamic_sandbox as ds

    return ds


@pytest.mark.asyncio
async def test_traversal_filename_stays_in_cage(client, monkeypatch, tmp_path, dynamic_sandbox):
    """A hostile original_name must not write or execute outside the cage."""
    resp = client.post("/samples?name=..%2F..%2Fevil.bin", content=b"#!/bin/sh\necho hi\n")
    assert resp.status_code == 201, resp.text
    sample_id = resp.json()["sample_id"]

    captured: dict = {}

    async def fake_exec(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["cwd"] = kwargs.get("cwd")
        return _FakeProc(0)

    monkeypatch.setattr(dynamic_sandbox.asyncio, "create_subprocess_exec", fake_exec)

    try:
        result = await dynamic_sandbox.execute_and_trace(sample_id)
        # Hostile name is replaced wholesale by the fixed payload name.
        target = captured["cmd"][-1]
        assert os.path.basename(target) == "sample.bin"
        # The executed path lives inside the run's own temp cage.
        assert os.path.dirname(target) == str(captured["cwd"])
        assert "outpost_sandbox_" in str(captured["cwd"])
        _cleanup(result["run_id"], sample_id)
    except Exception:
        raise


@pytest.mark.asyncio
async def test_child_env_excludes_secrets(client, monkeypatch, dynamic_sandbox):
    """Secrets in the parent environment must not reach the detonated child."""
    resp = client.post("/samples?name=envcheck.sh", content=b"#!/bin/sh\necho hi\n")
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    seen_env: dict = {}

    async def fake_exec(*cmd, **kwargs):
        seen_env.update(kwargs.get("env") or {})
        return _FakeProc(0)

    monkeypatch.setenv("ABUSEIPDB_API_KEY", "super-secret-value")
    monkeypatch.setattr(dynamic_sandbox.asyncio, "create_subprocess_exec", fake_exec)

    try:
        result = await dynamic_sandbox.execute_and_trace(sample_id)
        assert "ABUSEIPDB_API_KEY" not in seen_env
        assert seen_env.get("OUTPOST_SANDBOX") == "1"
        assert seen_env.get("OUTPOST_RUN_ID") == result["run_id"]
        _cleanup(result["run_id"], sample_id)
    finally:
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)


@pytest.mark.asyncio
async def test_nonzero_exit_alone_is_clean(client, monkeypatch, dynamic_sandbox):
    """Benign crash: nonzero exit, zero alerts ⇒ verdict stays clean."""
    resp = client.post("/samples?name=crasher.py", content=b"#!/usr/bin/env python3\nraise SystemExit(3)\n")
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    async def fake_exec(*cmd, **kwargs):
        return _FakeProc(3)

    monkeypatch.setattr(dynamic_sandbox.asyncio, "create_subprocess_exec", fake_exec)

    result = await dynamic_sandbox.execute_and_trace(sample_id)
    assert result["exit_code"] != 0
    assert result["alerts_count"] == 0
    assert result["verdict"] == "no_indicators_found_limited"
    _cleanup(result["run_id"], sample_id)


@pytest.mark.asyncio
async def test_missing_isolation_returns_422_and_blocks_host_execution(client, monkeypatch, dynamic_sandbox):
    """Missing isolation provider must raise 422 and never execute on host."""
    resp = client.post("/samples?name=untrusted_payload.sh", content=b"#!/bin/sh\necho malicious\n")
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    spawn_called = False

    async def spy_exec(*cmd, **kwargs):
        nonlocal spawn_called
        spawn_called = True
        return _FakeProc(0)

    monkeypatch.setattr(dynamic_sandbox.asyncio, "create_subprocess_exec", spy_exec)
    monkeypatch.setattr(dynamic_sandbox, "is_bwrap_usable", lambda: False)

    # Calling execute_and_trace must raise HTTPException with 422
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await dynamic_sandbox.execute_and_trace(sample_id)

    assert exc_info.value.status_code == 422
    assert exc_info.value.detail == "Safe isolation provider unavailable. Execution blocked to prevent host contamination."
    assert not spawn_called, "Host execution occurred despite missing isolation provider!"

    # Calling via HTTP endpoint must return 422 with exact detail
    api_resp = client.post("/sandbox/detonate/dynamic", json={"sample_id": sample_id})
    assert api_resp.status_code == 422
    assert api_resp.json()["detail"] == "Safe isolation provider unavailable. Execution blocked to prevent host contamination."
    assert not spawn_called

    _cleanup(None, sample_id)


@pytest.mark.asyncio
async def test_unusable_bwrap_returns_422_and_blocks_host_execution(client, monkeypatch, dynamic_sandbox):
    """Present but unusable bwrap (e.g. user namespaces blocked) must return 422 and prevent host execution."""
    resp = client.post("/samples?name=untrusted_elf.bin", content=b"\x7fELFfakebinary")
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    spawn_called = False

    async def spy_exec(*cmd, **kwargs):
        nonlocal spawn_called
        spawn_called = True
        return _FakeProc(0)

    monkeypatch.setattr(dynamic_sandbox.asyncio, "create_subprocess_exec", spy_exec)
    # bwrap exists on disk...
    monkeypatch.setattr(dynamic_sandbox.shutil, "which", lambda cmd: "/usr/bin/bwrap" if cmd == "bwrap" else None)
    # ...but kernel probe fails (unusable)
    monkeypatch.setattr(dynamic_sandbox, "is_bwrap_usable", lambda: False)

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await dynamic_sandbox.execute_and_trace(sample_id)

    assert exc_info.value.status_code == 422
    assert exc_info.value.detail == "Safe isolation provider unavailable. Execution blocked to prevent host contamination."
    assert not spawn_called, "Subprocess executed on host when isolation provider was unusable!"

    _cleanup(None, sample_id)


@pytest.mark.asyncio
async def test_tempdir_driver_rejected_with_422(client, monkeypatch, dynamic_sandbox):
    """Explicit request for tempdir must be rejected with 422 and blocked from host execution."""
    resp = client.post("/samples?name=test_tempdir.py", content=b"#!/usr/bin/env python3\nprint('hello')\n")
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    spawn_called = False

    async def spy_exec(*cmd, **kwargs):
        nonlocal spawn_called
        spawn_called = True
        return _FakeProc(0)

    monkeypatch.setattr(dynamic_sandbox.asyncio, "create_subprocess_exec", spy_exec)

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await dynamic_sandbox.execute_and_trace(sample_id, isolation_driver="tempdir")

    assert exc_info.value.status_code == 422
    assert exc_info.value.detail == "Safe isolation provider unavailable. Execution blocked to prevent host contamination."
    assert not spawn_called

    _cleanup(None, sample_id)


@pytest.mark.asyncio
async def test_samples_detonate_endpoint_returns_422_when_unisolated(client, monkeypatch, dynamic_sandbox):
    """POST /samples/{sample_id}/detonate must return 422 if isolation provider is unavailable."""
    resp = client.post("/samples?name=sample_detonate.sh", content=b"#!/bin/sh\necho test\n")
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    monkeypatch.setattr(dynamic_sandbox, "is_bwrap_usable", lambda: False)

    detonate_resp = client.post(f"/samples/{sample_id}/detonate")
    assert detonate_resp.status_code == 422
    assert detonate_resp.json()["detail"] == "Safe isolation provider unavailable. Execution blocked to prevent host contamination."

    _cleanup(None, sample_id)


@pytest.mark.asyncio
async def test_wine_unconfined_override_required_and_audited(client, monkeypatch, dynamic_sandbox):
    """Windows binaries under Wine must refuse unconfined execution without explicit operator override, and override must write to audit trail."""
    resp = client.post("/samples?name=test_wine.exe", content=b"MZ\x90\x00\x03\x00\x00\x00")
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    # Emulate Wine present but bwrap unavailable
    monkeypatch.setattr(dynamic_sandbox.shutil, "which", lambda cmd: "/usr/bin/wine" if "wine" in cmd else None)
    monkeypatch.setattr(dynamic_sandbox, "is_bwrap_usable", lambda: False)

    from fastapi import HTTPException
    # Without override -> 422
    with pytest.raises(HTTPException) as exc_info:
        await dynamic_sandbox.execute_and_trace(sample_id, allow_unconfined_override=False)
    assert exc_info.value.status_code == 422

    # With override -> proceeds, driver is wine_unconfined_override, audit entry recorded
    spawn_called = False
    async def fake_exec(*cmd, **kwargs):
        nonlocal spawn_called
        spawn_called = True
        return _FakeProc(0)

    monkeypatch.setattr(dynamic_sandbox.asyncio, "create_subprocess_exec", fake_exec)

    res = await dynamic_sandbox.execute_and_trace(sample_id, allow_unconfined_override=True)
    assert spawn_called
    assert res["isolation_driver"] == "wine_unconfined_override"

    from app.core.db import db_session
    with db_session() as conn:
        audit_rows = conn.execute("SELECT * FROM audit_log WHERE action = 'sandbox.wine.unconfined_override'").fetchall()
        assert len(audit_rows) > 0
        assert audit_rows[-1]["outcome"] == "allowed_override"

    _cleanup(res["run_id"], sample_id)


@pytest.mark.asyncio
async def test_resource_limits_applied(client, monkeypatch, dynamic_sandbox):
    """Execution must enforce rlimits on POSIX hosts and pass preexec_fn."""
    resp = client.post("/samples?name=limited.sh", content=b"#!/bin/sh\necho hi\n")
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    captured_preexec = None
    async def fake_exec(*cmd, **kwargs):
        nonlocal captured_preexec
        captured_preexec = kwargs.get("preexec_fn")
        return _FakeProc(0)

    monkeypatch.setattr(dynamic_sandbox.asyncio, "create_subprocess_exec", fake_exec)
    res = await dynamic_sandbox.execute_and_trace(sample_id)
    assert captured_preexec is not None
    _cleanup(res["run_id"], sample_id)


@pytest.mark.asyncio
async def test_simulation_scenario_provenance_labels(client, dynamic_sandbox):
    """Simulation scenario events must carry provenance='scripted_simulation' and is_simulated=True."""
    res = await dynamic_sandbox.execute_simulation_scenario_live("recon_sweep")
    assert res["events_count"] > 0
    from app.core.db import db_session
    with db_session() as conn:
        events = conn.execute("SELECT * FROM events WHERE run_id = ?", (res["run_id"],)).fetchall()
        assert len(events) > 0
        proc_evs = [dict(e) for e in events if e["event_type"] == "process_create"]
        assert len(proc_evs) > 0
        for pe in proc_evs:
            assert pe.get("log_source") == "scripted_simulation"
            raw = json.loads(pe.get("raw_record") or "{}")
            assert raw.get("is_simulated") is True
            assert raw.get("provenance") == "scripted_simulation"
    _cleanup(res["run_id"], None)


@pytest.mark.asyncio
async def test_lab_vm_guard_blocks_bare_metal_host_detonation(client, monkeypatch, dynamic_sandbox):
    """Refuse dynamic detonation on a bare-metal host workstation without OUTPOST_LAB_VM or override."""
    resp = client.post("/samples?name=host_safety_probe.sh", content=b"#!/bin/sh\necho host_escape\n")
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    monkeypatch.delenv("OUTPOST_LAB_VM", raising=False)
    monkeypatch.delenv("OUTPOST_DANGEROUS_ALLOW_HOST_DETONATION", raising=False)
    monkeypatch.setattr(dynamic_sandbox, "detect_hypervisor", lambda: (False, "none"))

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await dynamic_sandbox.execute_and_trace(sample_id)

    assert exc_info.value.status_code == 422
    assert "bare-metal workstation host is forbidden" in exc_info.value.detail
    assert "OUTPOST_LAB_VM" in exc_info.value.detail

    _cleanup(None, sample_id)


@pytest.mark.asyncio
async def test_lab_vm_guard_allows_verified_hypervisor(client, monkeypatch, dynamic_sandbox):
    """Allow detonation when verified inside a hypervisor VM with OUTPOST_LAB_VM=1."""
    resp = client.post("/samples?name=vm_clean_probe.sh", content=b"#!/bin/sh\necho in_vm\n")
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    monkeypatch.setenv("OUTPOST_LAB_VM", "1")
    monkeypatch.delenv("OUTPOST_DANGEROUS_ALLOW_HOST_DETONATION", raising=False)
    monkeypatch.setattr(dynamic_sandbox, "detect_hypervisor", lambda: (True, "kvm"))

    spawn_called = False
    async def fake_exec(*cmd, **kwargs):
        nonlocal spawn_called
        spawn_called = True
        return _FakeProc(0)

    monkeypatch.setattr(dynamic_sandbox.asyncio, "create_subprocess_exec", fake_exec)

    res = await dynamic_sandbox.execute_and_trace(sample_id)
    assert spawn_called
    assert res["host_detonation_warning"] is False
    assert res["bwrap_argv"] is not None
    assert "--clearenv" in res["bwrap_argv"]
    assert "--cap-drop" in res["bwrap_argv"]

    _cleanup(res["run_id"], sample_id)


@pytest.mark.asyncio
async def test_lab_vm_guard_override_audited_and_disclosed(client, monkeypatch, dynamic_sandbox):
    """When OUTPOST_DANGEROUS_ALLOW_HOST_DETONATION=1 is set, detonation is permitted, audited, and flagged."""
    resp = client.post("/samples?name=override_probe.sh", content=b"#!/bin/sh\necho override_active\n")
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    monkeypatch.delenv("OUTPOST_LAB_VM", raising=False)
    monkeypatch.setenv("OUTPOST_DANGEROUS_ALLOW_HOST_DETONATION", "1")
    monkeypatch.setattr(dynamic_sandbox, "detect_hypervisor", lambda: (False, "none"))

    async def fake_exec(*cmd, **kwargs):
        return _FakeProc(0)

    monkeypatch.setattr(dynamic_sandbox.asyncio, "create_subprocess_exec", fake_exec)

    res = await dynamic_sandbox.execute_and_trace(sample_id)
    assert res["host_detonation_warning"] is True

    from app.core.db import db_session
    with db_session() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE action = 'sandbox.host_detonation_override' AND target_id = ?",
            (res["run_id"],),
        ).fetchall()
        assert len(rows) > 0
        assert rows[-1]["outcome"] == "allowed_override"

    # Confirm warning event in timeline
    assert any(t.get("category") == "security_warning" for t in res["timeline"])

    _cleanup(res["run_id"], sample_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("container_type", ["docker", "podman", "lxc", "wsl", "systemd-nspawn"])
async def test_lab_vm_guard_strictly_rejects_containers_even_with_flag(container_type, client, monkeypatch, dynamic_sandbox):
    """Containers share the host kernel and must be rejected even if OUTPOST_LAB_VM=1 is set."""
    resp = client.post(f"/samples?name=container_probe_{container_type}.sh", content=b"#!/bin/sh\necho in_container\n")
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    monkeypatch.setenv("OUTPOST_LAB_VM", "1")
    monkeypatch.delenv("OUTPOST_DANGEROUS_ALLOW_HOST_DETONATION", raising=False)
    monkeypatch.setattr(dynamic_sandbox, "detect_hypervisor", lambda: (False, f"container:{container_type}"))

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await dynamic_sandbox.execute_bytes_sandbox("r1", "p.sh", "linux", b"#!/bin/sh\n")

    assert exc_info.value.status_code == 422
    assert "shared-kernel container" in exc_info.value.detail
    assert container_type in exc_info.value.detail

    _cleanup(None, sample_id)


@pytest.mark.asyncio
async def test_api_cannot_bypass_lab_vm_guard(client, monkeypatch, dynamic_sandbox):
    """API query parameters (?allow_unconfined_override=true) must NOT bypass the Lab VM guard."""
    resp = client.post("/samples?name=api_bypass_probe.sh", content=b"#!/bin/sh\necho api_bypass\n")
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    monkeypatch.delenv("OUTPOST_LAB_VM", raising=False)
    monkeypatch.delenv("OUTPOST_DANGEROUS_ALLOW_HOST_DETONATION", raising=False)
    monkeypatch.setattr(dynamic_sandbox, "detect_hypervisor", lambda: (False, "none"))

    # Attempt detonation via API endpoint passing query parameter
    detonate_resp = client.post(f"/samples/{sample_id}/detonate?allow_unconfined_override=true")
    assert detonate_resp.status_code == 422
    assert "bare-metal workstation host is forbidden" in detonate_resp.json()["detail"]

    _cleanup(None, sample_id)


@pytest.mark.asyncio
async def test_sys_prefix_not_bound_for_non_python_samples(client, monkeypatch, dynamic_sandbox):
    """sys.prefix (repo venv) must NOT be bound into the sandbox for non-python binaries."""
    resp = client.post("/samples?name=bash_script.sh", content=b"#!/bin/bash\necho hello\n")
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    monkeypatch.setenv("OUTPOST_LAB_VM", "1")
    monkeypatch.delenv("OUTPOST_DANGEROUS_ALLOW_HOST_DETONATION", raising=False)
    monkeypatch.setattr(dynamic_sandbox, "detect_hypervisor", lambda: (True, "kvm"))

    async def fake_exec(*cmd, **kwargs):
        return _FakeProc(0)

    monkeypatch.setattr(dynamic_sandbox.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(dynamic_sandbox.sys, "prefix", "/home/kripy/repo/.venv")

    res = await dynamic_sandbox.execute_and_trace(sample_id)
    assert res["bwrap_argv"] is not None
    # For bash script, /home/kripy/repo/.venv must NOT appear in bwrap_argv
    assert "/home/kripy/repo/.venv" not in res["bwrap_argv"]

    _cleanup(res["run_id"], sample_id)


@pytest.mark.asyncio
async def test_simulation_and_technique_runners_blocked_on_bare_metal(monkeypatch, dynamic_sandbox):
    """Playbook scenarios and adversary technique executions must also fail-closed on bare metal."""
    from fastapi import HTTPException

    monkeypatch.delenv("OUTPOST_LAB_VM", raising=False)
    monkeypatch.delenv("OUTPOST_DANGEROUS_ALLOW_HOST_DETONATION", raising=False)
    monkeypatch.setattr(dynamic_sandbox, "detect_hypervisor", lambda: (False, "none"))

    with pytest.raises(HTTPException) as exc1:
        await dynamic_sandbox.execute_simulation_scenario_live("recon_sweep")
    assert exc1.value.status_code == 422
    assert "bare-metal workstation host is forbidden" in exc1.value.detail

    with pytest.raises(HTTPException) as exc2:
        await dynamic_sandbox.execute_simulation_scenario_stage("recon_sweep", 1)
    assert exc2.value.status_code == 422
    assert "bare-metal workstation host is forbidden" in exc2.value.detail

    with pytest.raises(HTTPException) as exc3:
        await dynamic_sandbox.execute_technique_test("T1082-sysinfo-discovery")
    assert exc3.value.status_code == 422
    assert "bare-metal workstation host is forbidden" in exc3.value.detail


@pytest.mark.asyncio
async def test_dev_probe_mode_arbitrary_file_refused(monkeypatch, dynamic_sandbox):
    """On bare-metal non-VM host, an arbitrary non-probe file is refused with HTTP 422."""
    from fastapi import HTTPException

    monkeypatch.delenv("OUTPOST_LAB_VM", raising=False)
    monkeypatch.delenv("OUTPOST_DANGEROUS_ALLOW_HOST_DETONATION", raising=False)
    monkeypatch.setattr(dynamic_sandbox, "detect_hypervisor", lambda: (False, "none"))

    arbitrary_bytes = b"echo 'malicious or user payload'"
    with pytest.raises(HTTPException) as exc:
        await dynamic_sandbox.execute_bytes_sandbox("run-arb-1", "test.sh", "linux", arbitrary_bytes)
    assert exc.value.status_code == 422
    assert "bare-metal workstation host is forbidden" in exc.value.detail


@pytest.mark.asyncio
async def test_dev_probe_mode_modified_probe_refused(monkeypatch, dynamic_sandbox):
    """If a probe program's bytes are modified, the hash mismatch causes refusal with HTTP 422."""
    from pathlib import Path

    from fastapi import HTTPException

    monkeypatch.delenv("OUTPOST_LAB_VM", raising=False)
    monkeypatch.delenv("OUTPOST_DANGEROUS_ALLOW_HOST_DETONATION", raising=False)
    monkeypatch.setattr(dynamic_sandbox, "detect_hypervisor", lambda: (False, "none"))

    repo_root = Path(__file__).resolve().parents[3]
    probe_path = repo_root / "tests/probes/shell_probe/probe.sh"
    if not probe_path.exists():
        probe_path = Path("tests/probes/shell_probe/probe.sh")
    if not probe_path.exists():
        pytest.skip(f"probe.sh fixture missing at {probe_path}")
    genuine_bytes = probe_path.read_bytes()
    tampered_bytes = genuine_bytes + b"\n# tampered byte"

    with pytest.raises(HTTPException) as exc:
        await dynamic_sandbox.execute_bytes_sandbox("run-tamp-1", "probe.sh", "linux", tampered_bytes)
    assert exc.value.status_code == 422
    assert "bare-metal workstation host is forbidden" in exc.value.detail


@pytest.mark.asyncio
async def test_dev_probe_mode_correct_hash_runs(monkeypatch, dynamic_sandbox, client):
    """A probe with the exact fixed SHA-256 hash is permitted to run on a non-VM host."""
    from pathlib import Path

    monkeypatch.delenv("OUTPOST_LAB_VM", raising=False)
    monkeypatch.delenv("OUTPOST_DANGEROUS_ALLOW_HOST_DETONATION", raising=False)
    monkeypatch.setattr(dynamic_sandbox, "detect_hypervisor", lambda: (False, "none"))

    async def fake_exec(*cmd, **kwargs):
        return _FakeProc(0)

    monkeypatch.setattr(dynamic_sandbox.asyncio, "create_subprocess_exec", fake_exec)

    repo_root = Path(__file__).resolve().parents[3]
    probe_path = repo_root / "tests/probes/shell_probe/probe.sh"
    if not probe_path.exists():
        probe_path = Path("tests/probes/shell_probe/probe.sh")
    if not probe_path.exists():
        pytest.skip(f"probe.sh fixture missing at {probe_path}")
    genuine_bytes = probe_path.read_bytes()

    resp = client.post("/samples?name=probe.sh", content=genuine_bytes)
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    res = await dynamic_sandbox.execute_and_trace(sample_id)
    assert res["exit_code"] == 0
    _cleanup(res["run_id"], sample_id)


@pytest.mark.asyncio
async def test_dev_probe_mode_uploads_cannot_widen_or_match(monkeypatch, dynamic_sandbox, client):
    """Uploaded user samples cannot bypass the hash guard on bare metal."""
    monkeypatch.delenv("OUTPOST_LAB_VM", raising=False)
    monkeypatch.delenv("OUTPOST_DANGEROUS_ALLOW_HOST_DETONATION", raising=False)
    monkeypatch.setattr(dynamic_sandbox, "detect_hypervisor", lambda: (False, "none"))

    resp = client.post(
        "/samples?name=untrusted_sample.bin",
        content=b"\x7fELF\x02\x01\x01\x00user_payload_data",
    )
    assert resp.status_code == 201
    sample_id = resp.json()["sample_id"]

    det_resp = client.post(f"/samples/{sample_id}/detonate")
    assert det_resp.status_code == 422
    assert "bare-metal workstation host is forbidden" in det_resp.json()["detail"]


def test_sandbox_environment_endpoint(monkeypatch, client, dynamic_sandbox):
    """GET /sandbox/environment accurately reflects VM vs Dev-Probe state."""
    # 1. Bare metal non-VM host
    monkeypatch.delenv("OUTPOST_LAB_VM", raising=False)
    monkeypatch.delenv("OUTPOST_DANGEROUS_ALLOW_HOST_DETONATION", raising=False)
    monkeypatch.setattr(dynamic_sandbox, "detect_hypervisor", lambda: (False, "none"))

    r1 = client.get("/sandbox/environment")
    assert r1.status_code == 200
    data1 = r1.json()
    assert data1["is_safe_vm"] is False
    assert data1["dev_probe_only"] is True
    assert "Not running inside a VM: sample analysis disabled; only built-in probes can run" in data1["status_message"]
    assert len(data1["allowed_probe_hashes"]) >= 3

    # 2. Verified Lab VM
    monkeypatch.setenv("OUTPOST_LAB_VM", "1")
    monkeypatch.setattr(dynamic_sandbox, "detect_hypervisor", lambda: (True, "kvm"))

    r2 = client.get("/sandbox/environment")
    assert r2.status_code == 200
    data2 = r2.json()
    assert data2["is_safe_vm"] is True
    assert data2["dev_probe_only"] is False
    assert "dynamic sample detonation enabled" in data2["status_message"]


def test_dev_probe_allowed_hashes_integrity(dynamic_sandbox):
    """DEV_PROBE_ALLOWED_HASHES must only contain files under tests/probes/ with matching hashes."""
    import hashlib
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[3]
    assert len(dynamic_sandbox.DEV_PROBE_ALLOWED_HASHES) >= 3

    for expected_hash, rel_path in dynamic_sandbox.DEV_PROBE_ALLOWED_HASHES.items():
        assert rel_path.startswith("tests/probes/"), f"Path {rel_path} not under tests/probes/"
        assert ".." not in rel_path, f"Path {rel_path} contains traversal '..'"

        full_path = repo_root / rel_path
        assert full_path.exists(), f"Probe file does not exist: {full_path}"
        assert full_path.is_file(), f"Probe path is not a file: {full_path}"

        content = full_path.read_bytes()
        actual_hash = hashlib.sha256(content).hexdigest()
        assert actual_hash == expected_hash, (
            f"Hash mismatch for {rel_path}: constant has {expected_hash}, file has {actual_hash}"
        )


@pytest.mark.asyncio
async def test_dev_probe_toctou_prevented_exact_buffer_executed(monkeypatch, dynamic_sandbox, client):
    """TOCTOU defense: execute_bytes_sandbox executes from verified buffer and ignores disk tampering."""
    import hashlib
    from pathlib import Path

    from fastapi import HTTPException

    repo_root = Path(__file__).resolve().parents[3]
    probe_path = repo_root / "tests/probes/shell_probe/probe.sh"
    original_bytes = probe_path.read_bytes()

    monkeypatch.delenv("OUTPOST_LAB_VM", raising=False)
    monkeypatch.delenv("OUTPOST_DANGEROUS_ALLOW_HOST_DETONATION", raising=False)
    monkeypatch.setattr(dynamic_sandbox, "detect_hypervisor", lambda: (False, "none"))

    captured_payload = None

    async def fake_exec(*cmd, **kwargs):
        nonlocal captured_payload
        target_path = None
        for arg in cmd:
            if str(arg).endswith(".sh"):
                target_path = Path(arg)
                break
        if target_path and target_path.exists():
            captured_payload = target_path.read_bytes()
        return _FakeProc(0)

    monkeypatch.setattr(dynamic_sandbox.asyncio, "create_subprocess_exec", fake_exec)

    verified_buffer = bytes(original_bytes)
    tampered_bytes = original_bytes + b"\n# MALICIOUS SWAPPED CONTENT AFTER HASH CHECK\n"

    try:
        probe_path.write_bytes(tampered_bytes)

        resp = client.post("/samples?name=probe.sh", content=verified_buffer)
        assert resp.status_code == 201
        sample_id = resp.json()["sample_id"]

        res = await dynamic_sandbox.execute_and_trace(sample_id)
        assert res["exit_code"] == 0

        assert captured_payload is not None
        assert captured_payload == verified_buffer
        assert hashlib.sha256(captured_payload).hexdigest() == hashlib.sha256(verified_buffer).hexdigest()
        assert b"MALICIOUS SWAPPED CONTENT" not in captured_payload

        resp2 = client.post("/samples?name=probe.sh", content=tampered_bytes)
        assert resp2.status_code == 201
        tampered_sample_id = resp2.json()["sample_id"]

        with pytest.raises(HTTPException) as exc:
            await dynamic_sandbox.execute_and_trace(tampered_sample_id)
        assert exc.value.status_code == 422
        assert "bare-metal workstation host is forbidden" in exc.value.detail

        _cleanup(res["run_id"], sample_id)
        _cleanup(None, tampered_sample_id)
    finally:
        probe_path.write_bytes(original_bytes)




