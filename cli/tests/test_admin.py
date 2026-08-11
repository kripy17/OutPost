"""`outpost admin backfill-channels` — on-demand channel backfill: admin
login → POST /admin/backfill-channels, the healthy idempotent no-op output
when there is nothing left to stamp, and the failure path when the admin
login is refused."""

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
