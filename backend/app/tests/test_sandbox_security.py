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
    assert result["verdict"] == "clean"
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


