"""Enrichment internals — the provider HTTP paths, cache freshness, and the
hash-reputation flow.

The API-level intel tests (test_intel) monkeypatch `_query_abuseipdb` /
`_query_virustotal`, so the REAL query, freshness, and caching logic had no
direct coverage. This file pins them: AbuseIPDB/VirusTotal parsing and error
handling, `_cache_fresh` band logic, and `enrich_hash` cache-first / no-key /
with-key paths.
"""

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from ..core.api_keys import set_api_key
from ..models.samples import get_hash_cache
from ..services import enrichment


class FakeResp:
    def __init__(self, status=200, payload=None, exc=None):
        self._status = status
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self._exc = exc

    def raise_for_status(self):
        if self._exc:
            raise self._exc
        if self._status >= 400:
            raise httpx.HTTPStatusError("HTTP error", request=None, response=None)

    def json(self):
        return self._payload


class FakeClient:
    def __init__(self, resp=None, fail=False):
        self._resp = resp
        self._fail = fail
        self.calls: list[tuple[str, dict]] = []

    async def get(self, url, **kwargs):
        if self._fail:
            raise AssertionError("network should not be touched on cache hit")
        self.calls.append((url, kwargs))
        return self._resp


# ---------------------------------------------------------------------------
# _cache_fresh
# ---------------------------------------------------------------------------


def test_cache_fresh_within_ttl_is_fresh():
    cached = {"checked_at": datetime.now(timezone.utc).isoformat()}
    assert enrichment._cache_fresh(cached) is True


def test_cache_fresh_past_ttl_is_stale():
    cached = {"checked_at": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()}
    assert enrichment._cache_fresh(cached) is False


def test_cache_fresh_invalid_or_missing_timestamp_is_stale():
    assert enrichment._cache_fresh({"checked_at": "not-a-date"}) is False
    assert enrichment._cache_fresh({}) is False


# ---------------------------------------------------------------------------
# _query_abuseipdb
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_abuseipdb_no_key_returns_none_without_network():
    client = FakeClient(fail=True)
    assert await enrichment._query_abuseipdb(client, "203.0.113.9", "") is None
    assert client.calls == []


@pytest.mark.asyncio
async def test_abuseipdb_parses_abuse_score():
    client = FakeClient(FakeResp(payload={"data": {"abuseConfidenceScore": 70}}))
    score = await enrichment._query_abuseipdb(client, "203.0.113.9", "key")
    assert score == 70
    url, kwargs = client.calls[0]
    assert "abuseipdb" in url
    assert kwargs["headers"]["Key"] == "key"
    assert kwargs["params"]["ipAddress"] == "203.0.113.9"


@pytest.mark.asyncio
async def test_abuseipdb_http_error_returns_none():
    client = FakeClient(FakeResp(status=429, payload={}))
    assert await enrichment._query_abuseipdb(client, "203.0.113.9", "key") is None


@pytest.mark.asyncio
async def test_abuseipdb_bad_payload_returns_none():
    client = FakeClient(FakeResp(payload={"unexpected": True}))
    assert await enrichment._query_abuseipdb(client, "203.0.113.9", "key") is None


# ---------------------------------------------------------------------------
# _query_virustotal
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_virustotal_no_key_returns_none_without_network():
    client = FakeClient(fail=True)
    assert await enrichment._query_virustotal(client, "203.0.113.9", "") is None


@pytest.mark.asyncio
async def test_virustotal_parses_malicious_count():
    payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 12}}}}
    client = FakeClient(FakeResp(payload=payload))
    assert await enrichment._query_virustotal(client, "203.0.113.9", "key") == 12


@pytest.mark.asyncio
async def test_virustotal_error_returns_none():
    client = FakeClient(FakeResp(status=500, payload={}))
    assert await enrichment._query_virustotal(client, "203.0.113.9", "key") is None


# ---------------------------------------------------------------------------
# enrich_hash
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enrich_hash_cache_hit_skips_network(conn):
    sha = "a" * 64
    # Create the row via the no-key path, then backdate-check freshness by
    # setting checked_at to now (a fresh row must skip the network entirely).
    await enrichment.enrich_hash(FakeClient(fail=True), conn, sha)
    conn.execute("UPDATE hash_cache SET checked_at = ? WHERE sha256 = ?", (datetime.now(timezone.utc).isoformat(), sha))
    conn.commit()

    out = await enrichment.enrich_hash(FakeClient(fail=True), conn, sha)
    assert out["sha256"] == sha
    assert out["vt_detections"] is None


@pytest.mark.asyncio
async def test_enrich_hash_no_key_returns_honest_none_and_caches(conn):
    sha = "b" * 64
    out = await enrichment.enrich_hash(FakeClient(fail=True), conn, sha)
    assert out == {"sha256": sha, "vt_detections": None, "malware_family": None}
    assert get_hash_cache(conn, sha) is not None


@pytest.mark.asyncio
async def test_enrich_hash_with_key_parses_and_caches(conn):
    set_api_key(conn, "virustotal", "vt-key")
    sha = "c" * 64
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 9},
                "meaningful_name": "evil.dll",
                "popular_threat_classification": {"suggested_threat_label": "trojan"},
            }
        }
    }
    out = await enrichment.enrich_hash(FakeClient(FakeResp(payload=payload)), conn, sha)
    assert out["vt_detections"] == 9
    assert out["malware_family"] == "evil.dll"
    cached = get_hash_cache(conn, sha)
    assert cached["vt_detections"] == 9
