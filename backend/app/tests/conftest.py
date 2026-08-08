"""Shared test fixtures — isolated temp DB per test session."""

import os
import tempfile

import pytest

from ..core import config

_TEST_DB = tempfile.mktemp(suffix=".db")
_TEST_SAMPLES = tempfile.mkdtemp(suffix="-samples")


@pytest.fixture(scope="session", autouse=True)
def _isolated_db():
    """Point the app at a throwaway DB + samples dir before anything imports
    it, so tests never touch the real data/ directory."""
    old_db = config.DATABASE_PATH
    old_samples = config.SAMPLES_DIR
    config.DATABASE_PATH = _TEST_DB
    config.SAMPLES_DIR = __import__("pathlib").Path(_TEST_SAMPLES)
    from ..core.db import init_db

    init_db()
    yield
    config.DATABASE_PATH = old_db
    config.SAMPLES_DIR = old_samples
    if os.path.exists(_TEST_DB):
        os.remove(_TEST_DB)
    import shutil

    shutil.rmtree(_TEST_SAMPLES, ignore_errors=True)


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from ..main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def conn():
    from ..core.db import get_connection

    c = get_connection()
    yield c
    c.close()


def make_run(client, sample_name="synthetic-test.bin", platform="windows", session_type="analysis") -> str:
    resp = client.post(
        "/runs",
        json={"sample_name": sample_name, "platform": platform, "session_type": session_type},
    )
    assert resp.status_code == 201
    return resp.json()["run_id"]
