"""Shared test fixtures — isolated temp DB per test session."""

import os
import tempfile

import pytest

from ..core import config

_TEST_DB = tempfile.mktemp(suffix=".db")


@pytest.fixture(scope="session", autouse=True)
def _isolated_db():
    """Point the app at a throwaway DB before anything imports it."""
    old = config.DATABASE_PATH
    config.DATABASE_PATH = _TEST_DB
    from ..core.db import init_db

    init_db()
    yield
    config.DATABASE_PATH = old
    if os.path.exists(_TEST_DB):
        os.remove(_TEST_DB)


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
