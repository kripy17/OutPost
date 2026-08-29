"""Security + verdict-band regression tests for the dynamic sandbox.

Covers the audit findings:
- payload filenames can never escape the mkdtemp cage (traversal/absolute),
- the detonated child never inherits operator secret env vars,
- a nonzero exit code alone no longer flips the verdict to suspicious.
"""

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
