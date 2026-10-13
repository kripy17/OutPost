"""Automated verification suite for OutPost's SSRF and Outbound Request Guard.

Guarantees:
1. Loopback addresses (127.0.0.0/8, ::1, localhost) are strictly prohibited.
2. Cloud metadata services (169.254.169.254, metadata.google.internal) are blocked.
3. Private RFC 1918 and link-local ranges are blocked by default on operator webhooks.
4. Non-HTTP protocols (file://, gopher://, ftp://) and user-info credential stuffing are blocked.
5. Mutating settings endpoints reject SSRF payloads with 400 Bad Request.
6. Legitimate public endpoints (Slack, Discord, generic HTTPS) pass validation.
"""

import pytest
from fastapi.testclient import TestClient

from ..core.ssrf import validate_outbound_url, is_prohibited_ip
from ..main import app


def test_validate_outbound_url_blocks_loopback():
    for target in [
        "http://127.0.0.1:8000/webhook",
        "http://127.0.0.2:9000",
        "http://localhost:8080/hook",
        "http://[::1]/api",
    ]:
        valid, reason, _ = validate_outbound_url(target)
        assert valid is False, f"Expected {target} to be blocked"
        assert any(term in reason.lower() for term in ["loopback", "localhost", "prohibited"])


def test_validate_outbound_url_blocks_cloud_metadata():
    for target in [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.170.2/v2/metadata",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://instance-data/latest/meta-data/",
    ]:
        valid, reason, _ = validate_outbound_url(target)
        assert valid is False, f"Expected metadata target {target} to be blocked"
        assert any(term in reason.lower() for term in ["metadata", "link-local", "prohibited", "internal"])


def test_validate_outbound_url_blocks_private_networks():
    for target in [
        "http://10.0.0.1/webhook",
        "http://172.16.0.100/alert",
        "http://192.168.1.1/push",
    ]:
        valid, reason, _ = validate_outbound_url(target, allow_private=False)
        assert valid is False, f"Expected private RFC 1918 target {target} to be blocked"
        assert "prohibited" in reason.lower() or "private" in reason.lower()


def test_validate_outbound_url_blocks_non_http_schemes():
    for target in [
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_flushall",
        "ftp://attacker.com/leak",
        "dict://127.0.0.1:11211/stat",
    ]:
        valid, reason, _ = validate_outbound_url(target)
        assert valid is False, f"Expected non-http scheme {target} to be blocked"
        assert "scheme" in reason.lower()


def test_validate_outbound_url_blocks_credential_injection():
    valid, reason, _ = validate_outbound_url("http://admin:secret@api.example.com/webhook")
    assert valid is False
    assert "credential" in reason.lower()


def test_validate_outbound_url_allows_public_https():
    for target in [
        "https://hooks.slack.com/services/T00/B00/X00",
        "https://discord.com/api/webhooks/12345/abcdef",
    ]:
        # Test without live DNS lookup requirement
        valid, reason, _ = validate_outbound_url(target, resolve_dns=False)
        assert valid is True, f"Expected valid public URL {target} to pass, got: {reason}"


def test_settings_api_rejects_ssrf_webhook():
    client = TestClient(app)

    # 1. Loopback attack in webhook_url
    res1 = client.put(
        "/notifications/settings",
        json={"webhook_url": "http://127.0.0.1:9090/internal/admin"},
    )
    assert res1.status_code == 400
    assert "SSRF violation" in res1.json()["detail"]

    # 2. Cloud metadata attack in slack_webhook
    res2 = client.put(
        "/notifications/settings",
        json={"slack_webhook": "http://169.254.169.254/latest/meta-data/"},
    )
    assert res2.status_code == 400
    assert "SSRF violation" in res2.json()["detail"]

    # 3. File protocol attack in discord_webhook
    res3 = client.put(
        "/notifications/settings",
        json={"discord_webhook": "file:///etc/shadow"},
    )
    assert res3.status_code == 400
    assert "SSRF violation" in res3.json()["detail"]
