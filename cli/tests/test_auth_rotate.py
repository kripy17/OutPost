"""`outpost auth rotate-agent-token` — end-to-end agent-credential rotation:
admin login → POST /auth/agent-token → re-embed the new token into the local
agent service config (systemd unit / .bat), and the failure path when the
admin login is refused."""

from typer.testing import CliRunner

from outpost.main import app

runner = CliRunner()


def _fake_requests(tok: str):
    """requests.post stand-in: login returns an admin token, rotation ok."""

    class _Resp:
        def __init__(self, status_code: int, payload: dict | None = None):
            self.status_code = status_code
            self._payload = payload or {}
            self.text = str(payload or {})

        def json(self):
            return self._payload

    calls: list[tuple[str, dict]] = []

    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append((url, json or {}))
        if url.endswith("/auth/login"):
            return _Resp(200, {"token": "admin-tok"})
        if url.endswith("/auth/agent-token"):
            assert headers == {"Authorization": "Bearer admin-tok"}
            return _Resp(200, {"status": "ok"})
        return _Resp(404)

    fake_post.calls = calls  # type: ignore[attr-defined]
    return fake_post


def test_rotate_generates_token_and_reembeds_config(tmp_path, monkeypatch):
    import outpost.commands.agent as agent_mod
    import outpost.commands.auth as auth_mod

    fake_post = _fake_requests("t")
    monkeypatch.setattr(auth_mod.requests, "post", fake_post)

    written: list[tuple[str, str]] = []

    def fake_write(backend_url: str, agent_token: str = ""):
        written.append((backend_url, agent_token))
        return tmp_path / "outpost-agent.service", "sudo systemctl enable outpost-agent"

    monkeypatch.setattr(agent_mod, "_write_service_config", fake_write)

    result = runner.invoke(
        app,
        [
            "auth", "rotate-agent-token",
            "--backend-url", "http://127.0.0.1:8123",
            "--token", "new-rotated-token-0042",
        ],
        env={"OUTPOST_ADMIN_PASSWORD": "admin-secret"},
    )
    assert result.exit_code == 0, result.output
    assert "rotated on the backend" in result.output
    assert "New OUTPOST_AGENT_TOKEN: new-rotated-token-0042" in result.output
    assert "Re-embedded local agent config" in result.output
    # Both API calls happened: login then rotation, with the new token.
    urls = [u for u, _ in fake_post.calls]  # type: ignore[attr-defined]
    assert any(u.endswith("/auth/login") for u in urls)
    assert any(u.endswith("/auth/agent-token") for u in urls)
    assert any(b.get("token") == "new-rotated-token-0042" for _, b in fake_post.calls)  # type: ignore[attr-defined]
    # The local config was regenerated with (backend, new token).
    assert written == [("http://127.0.0.1:8123", "new-rotated-token-0042")]


def test_rotate_generates_token_when_omitted(tmp_path, monkeypatch):
    import outpost.commands.agent as agent_mod
    import outpost.commands.auth as auth_mod

    fake_post = _fake_requests("t")
    monkeypatch.setattr(auth_mod.requests, "post", fake_post)
    monkeypatch.setattr(agent_mod, "_write_service_config", lambda u, t="": (tmp_path / "u.service", ""))

    result = runner.invoke(
        app,
        ["auth", "rotate-agent-token", "--backend-url", "http://127.0.0.1:8123"],
        env={"OUTPOST_ADMIN_PASSWORD": "admin-secret"},
    )
    assert result.exit_code == 0, result.output
    # A 48-hex token was generated and printed.
    lines = [l for l in result.output.splitlines() if "New OUTPOST_AGENT_TOKEN:" in l]
    assert lines and len(lines[0].split(":")[-1].strip()) == 48


def test_rotate_fails_when_admin_login_refused(monkeypatch):
    import outpost.commands.auth as auth_mod

    class _Resp:
        status_code = 401
        text = '{"detail":"Invalid password"}'

        def json(self):
            return {"detail": "Invalid password"}

    monkeypatch.setattr(auth_mod.requests, "post", lambda url, json=None, headers=None, timeout=None: _Resp())

    result = runner.invoke(
        app,
        ["auth", "rotate-agent-token", "--backend-url", "http://127.0.0.1:8123", "--token", "x" * 20],
        env={"OUTPOST_ADMIN_PASSWORD": "wrong"},
    )
    assert result.exit_code == 2
    assert "Admin login failed" in result.output
