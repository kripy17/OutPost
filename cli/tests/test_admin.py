"""`outpost admin` — on-demand channel backfill (login → POST, healthy
idempotent no-op, bad-login failure, auth-off degradation) and the Tier 4
Postgres migration command (subprocess wiring to the shared exporter)."""

from typer.testing import CliRunner

from outpost.main import app

runner = CliRunner()


def _fake_requests(login_status: int = 200, updated: int = 3, login_text: str = ""):
    """requests.post stand-in: login returns an admin token, backfill ok."""

    class _Resp:
        def __init__(self, status_code: int, payload: dict | None = None, text: str | None = None):
            self.status_code = status_code
            self.ok = status_code < 400  # requests.Response contract
            self._payload = payload or {}
            self.text = text or str(payload or {})

        def json(self):
            return self._payload

    calls: list[tuple[str, dict | None]] = []

    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append((url, json))
        if url.endswith("/auth/login"):
            if login_status != 200:
                return _Resp(login_status, text=login_text)
            return _Resp(200, {"token": "admin-tok"})
        if url.endswith("/admin/backfill-channels"):
            if login_status == 200:
                assert headers == {"Authorization": "Bearer admin-tok"}
            return _Resp(200, {"updated": updated})
        return _Resp(404)

    fake_post.calls = calls  # type: ignore[attr-defined]
    return fake_post


def test_backfill_channels_stamps_and_reports_count(monkeypatch):
    import outpost.commands.admin as admin_mod

    fake_post = _fake_requests(updated=3)
    monkeypatch.setattr(admin_mod.api_client.requests, "post", fake_post)

    result = runner.invoke(
        app,
        ["admin", "backfill-channels", "--backend-url", "http://127.0.0.1:8123"],
        env={"OUTPOST_ADMIN_PASSWORD": "admin-secret"},
    )
    assert result.exit_code == 0, result.output
    assert "Stamped" in result.output
    assert "3 legacy events" in result.output
    assert "auditd/sysmon" in result.output
    # Both API calls happened: login then the backfill, with the admin token.
    urls = [u for u, _ in fake_post.calls]  # type: ignore[attr-defined]
    assert any(u.endswith("/auth/login") for u in urls)
    assert any(u.endswith("/admin/backfill-channels") for u in urls)


def test_backfill_channels_idempotent_noop(monkeypatch):
    import outpost.commands.admin as admin_mod

    fake_post = _fake_requests(updated=0)
    monkeypatch.setattr(admin_mod.api_client.requests, "post", fake_post)

    result = runner.invoke(
        app,
        ["admin", "backfill-channels"],
        env={"OUTPOST_ADMIN_PASSWORD": "admin-secret"},
    )
    assert result.exit_code == 0, result.output
    assert "already complete" in result.output
    assert "0 updated" in result.output


def test_backfill_channels_fails_on_bad_login(monkeypatch):
    import outpost.commands.admin as admin_mod

    fake_post = _fake_requests(login_status=401)
    monkeypatch.setattr(admin_mod.api_client.requests, "post", fake_post)

    result = runner.invoke(
        app,
        ["admin", "backfill-channels"],
        env={"OUTPOST_ADMIN_PASSWORD": "wrong"},
    )
    assert result.exit_code == 2
    assert "Backfill failed" in result.output


def test_pg_migrate_runs_the_exporter_subprocess(monkeypatch, tmp_path):
    """The command shells out to scripts/migrate_to_postgres.py with the
    same interpreter, forwarding --sqlite/--out/--import/--verify."""
    import subprocess as sp
    import outpost.commands.admin as admin_mod

    fake_script = tmp_path / "migrate_to_postgres.py"
    fake_script.write_text("#!/usr/bin/env python3\nimport sys; sys.exit(0)\n")
    monkeypatch.setattr(admin_mod, "_MIGRATE_SCRIPT", fake_script)
    captured: list[list[str]] = []

    def fake_run(cmd):
        captured.append(cmd)
        return sp.CompletedProcess(cmd, 0)

    monkeypatch.setattr(admin_mod.subprocess, "run", fake_run)

    result = runner.invoke(
        app,
        ["admin", "pg-migrate", "--sqlite", "/tmp/x.db", "--out", "/tmp/out", "--import", "--verify", "--psql-url", "postgres://u:p@h/db"],
    )
    assert result.exit_code == 0, result.output
    assert len(captured) == 1
    cmd = captured[0]
    assert str(fake_script) in cmd
    # The exporter is driven by the same interpreter that runs the CLI.
    import sys
    assert cmd[0] == sys.executable
    for flag in ("--sqlite", "/tmp/x.db", "--out", "/tmp/out", "--import", "--verify", "--psql-url", "postgres://u:p@h/db"):
        assert flag in cmd


def test_pg_migrate_fails_loudly_when_script_missing(monkeypatch, tmp_path):
    import outpost.commands.admin as admin_mod

    monkeypatch.setattr(admin_mod, "_MIGRATE_SCRIPT", tmp_path / "nope.py")
    result = runner.invoke(app, ["admin", "pg-migrate"])
    assert result.exit_code == 2
    assert "not found" in result.output


def test_backfill_channels_works_with_auth_off(monkeypatch):
    """Zero-config default: the backend has no auth (login 404s with the
    'not configured' body) — the endpoint is open, so the command still
    runs and reports the count without any credential."""
    import outpost.commands.admin as admin_mod

    fake_post = _fake_requests(login_status=404, updated=5, login_text='{"detail":"Authentication is not configured on this server"}')
    monkeypatch.setattr(admin_mod.api_client.requests, "post", fake_post)

    result = runner.invoke(
        app,
        ["admin", "backfill-channels"],
        env={"OUTPOST_ADMIN_PASSWORD": "whatever"},
    )
    assert result.exit_code == 0, result.output
    assert "5 legacy events" in result.output
    urls = [u for u, _ in fake_post.calls]  # type: ignore[attr-defined]
    assert any(u.endswith("/auth/login") for u in urls)
    assert any(u.endswith("/admin/backfill-channels") for u in urls)
