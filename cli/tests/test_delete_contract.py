"""CLI contract test for DELETE status-code acceptance — the terminal
mirror of `frontend/src/test/apiDeleteContract.test.ts`.

The webapp's `del()` was relaxed to treat 200 and 204 both as success (a
backend that 200s a DELETE with a body used to throw a misleading error).
The CLI's only DELETE path — `watchlist_remove` — already accepts
`(200, 204)`; this test pins that contract so it can't silently regress to
a 204-only check the way the webapp's did.
"""

import pytest
from outpost.lib import api_client


class _FakeResponse:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


def _fake_delete(monkeypatch, status_code: int, text: str = "") -> list:
    """Patch `requests.delete` and return the args the real call received."""
    calls = []

    def fake_delete(url, **kwargs):
        calls.append((url, kwargs))
        return _FakeResponse(status_code, text)

    monkeypatch.setattr(api_client.requests, "delete", fake_delete)
    return calls


def test_watchlist_remove_accepts_204(monkeypatch):
    """REST-canonical no-content DELETE resolves."""
    calls = _fake_delete(monkeypatch, 204)
    api_client.watchlist_remove("203.0.113.88")
    assert len(calls) == 1
    url, kwargs = calls[0]
    assert url == f"{api_client.BASE_URL}/watchlist/203.0.113.88"
    assert kwargs["timeout"] == 15


def test_watchlist_remove_accepts_200_with_body(monkeypatch):
    """A backend that 200s a DELETE with a body must not throw — the exact
    regression the webapp's `del()` used to hit."""
    _fake_delete(monkeypatch, 200, '{"removed": true}')
    api_client.watchlist_remove("evil.example.com")  # must not raise


def test_watchlist_remove_rejects_500_with_clear_error(monkeypatch):
    """A genuine failure raises APIError with the DELETE + status message."""
    _fake_delete(monkeypatch, 500, "internal boom")
    with pytest.raises(api_client.APIError) as exc:
        api_client.watchlist_remove("203.0.113.88")
    assert "DELETE /watchlist/203.0.113.88 → 500" in str(exc.value)
    assert "internal boom" in str(exc.value)
