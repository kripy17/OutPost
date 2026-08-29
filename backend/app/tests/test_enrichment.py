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
    def __init__(self, resp=None, fail=False, post_resp=None):
        self._resp = resp
        self._fail = fail
        # Default POST answer: ThreatFox "no_results" so hash enrichment's
        # family backfill stays inert unless a test opts in.
        self._post_resp = post_resp if post_resp is not None else FakeResp(payload={"query_status": "no_results"})
        self.calls: list[tuple[str, dict]] = []
        self.posts: list[tuple[str, dict]] = []

    async def get(self, url, **kwargs):
        if self._fail:
            raise AssertionError("network should not be touched on cache hit")
        self.calls.append((url, kwargs))
        return self._resp

    async def post(self, url, **kwargs):
        # `fail` guards GETs only — abuse.ch POSTs are key-less and stay
        # reachable on the no-VT-key paths (default resp: no_results).
        self.posts.append((url, kwargs))
        return self._post_resp


@pytest.fixture(autouse=True)
def _abusech_on(monkeypatch):
    """Unit tests exercise the real abuse.ch query paths — opt the flag in.

    Production defaults to OFF (no keyless third-party egress); these tests
    pin the parsing/caching logic, not the opt-in gate."""
    monkeypatch.setattr(enrichment.config, "ABUSECH_ENABLED", True)


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


# ---------------------------------------------------------------------------
# docs/08 MVP-tier — abuse.ch URLhaus + ThreatFox
# ---------------------------------------------------------------------------


def test_looks_like_domain_accepts_hostnames_rejects_the_rest():
    assert enrichment.looks_like_domain("evil.example.com") is True
    assert enrichment.looks_like_domain("EVIL.Example.COM.") is True
    assert enrichment.looks_like_domain("203.0.113.9") is False  # an IP, not a name
    assert enrichment.looks_like_domain("*") is False
    assert enrichment.looks_like_domain(None) is False
    assert enrichment.looks_like_domain("") is False


def test_strip_family_prefix_removes_platform_tag():
    assert enrichment._strip_family_prefix("win.asyncrat") == "asyncrat"
    assert enrichment._strip_family_prefix("elf.mirai") == "mirai"
    # Long first labels are real family names with dots, not platforms.
    assert enrichment._strip_family_prefix("cobalt.strike.beacon") == "cobalt.strike.beacon"
    assert enrichment._strip_family_prefix(None) is None


@pytest.mark.asyncio
async def test_urlhaus_parses_status_and_tags():
    client = FakeClient(post_resp=FakeResp(payload={"query_status": "ok", "url_status": "online", "tags": ["AsyncRAT"]}))
    out = await enrichment._query_urlhaus(client, "evil.example.com")
    assert out == {"url_status": "online", "tags": ["AsyncRAT"]}
    url, kwargs = client.posts[0]
    assert "urlhaus-api.abuse.ch" in url
    assert kwargs["data"]["host"] == "evil.example.com"


@pytest.mark.asyncio
async def test_urlhaus_no_results_is_none():
    client = FakeClient(post_resp=FakeResp(payload={"query_status": "no_results"}))
    assert await enrichment._query_urlhaus(client, "clean.example.org") is None


@pytest.mark.asyncio
async def test_threatfox_parses_first_match():
    client = FakeClient(post_resp=FakeResp(payload={
        "query_status": "ok",
        "data": [{"malware": "win.asyncrat", "confidence_level": "100", "threat_type": "botnet_cc"}],
    }))
    out = await enrichment._query_threatfox(client, "203.0.113.9")
    assert out["malware"] == "win.asyncrat"
    assert out["confidence_level"] == 100


@pytest.mark.asyncio
async def test_enrich_domain_urlhaus_listed_is_malicious_and_cached(conn):
    client = FakeClient(post_resp=FakeResp(payload={"query_status": "ok", "url_status": "offline", "tags": []}))
    out = await enrichment.enrich_domain(client, conn, "Listed.Example.COM.")
    assert out["domain"] == "listed.example.com"
    assert out["reputation"] == "malicious"
    assert out["urlhaus_status"] == "offline"
    # Cache hit: second call must not touch the network.
    again = await enrichment.enrich_domain(FakeClient(fail=True), conn, "listed.example.com")
    assert again["reputation"] == "malicious"
    assert again["checked_at"] == out["checked_at"]


@pytest.mark.asyncio
async def test_enrich_domain_threatfox_confidence_bands(conn):
    low = FakeClient(post_resp=FakeResp(payload={
        "query_status": "ok", "data": [{"malware": "elf.mirai", "confidence_level": 50, "threat_type": "payload_delivery"}],
    }))
    out = await enrichment.enrich_domain(low, conn, "low.example.org")
    assert out["reputation"] == "suspicious"
    assert out["malware_family"] == "mirai"

    high = FakeClient(post_resp=FakeResp(payload={
        "query_status": "ok", "data": [{"malware": "win.asyncrat", "confidence_level": 100, "threat_type": "botnet_cc"}],
    }))
    out2 = await enrichment.enrich_domain(high, conn, "high.example.org")
    assert out2["reputation"] == "malicious"


@pytest.mark.asyncio
async def test_enrich_run_domains_filters_to_domain_shapes(conn):
    from ..models import event as event_store

    run_id = "domaintest1"
    conn.execute(
        "INSERT INTO runs (run_id, sample_name, platform, session_type, source, started_at) "
        "VALUES (?, ?, 'windows', 'analysis', 'test', ?)",
        (run_id, "x", datetime.now(timezone.utc).isoformat()),
    )
    try:
        base = {"run_id": run_id, "platform": "windows", "event_type": "dns_query", "timestamp": "", "pid": 1, "host_id": "local"}
        event_store.insert_event(conn, {**base, "query": "c2.evil.example.com"})
        event_store.insert_event(conn, {**base, "query": "203.0.113.9"})  # IP — skipped
        event_store.insert_event(conn, {**base, "tls_sni": "sni.example.net"})
        event_store.insert_event(conn, {**base, "dest_ip": "198.51.100.5"})  # no domain fields
        conn.commit()

        called: list[str] = []

        async def fake_enrich_domain(client, c, domain):
            called.append(domain)
            return {"domain": domain, "urlhaus_status": None, "urlhaus_tags": [], "malware_family": None,
                    "threatfox_confidence": None, "reputation": "unknown", "checked_at": ""}

        orig = enrichment.enrich_domain
        enrichment.enrich_domain = fake_enrich_domain
        try:
            out = await enrichment.enrich_run_domains(conn, run_id)
        finally:
            enrichment.enrich_domain = orig
        assert sorted(called) == ["c2.evil.example.com", "sni.example.net"]
        assert set(out) == {"c2.evil.example.com", "sni.example.net"}
    finally:
        conn.execute("DELETE FROM events WHERE run_id = ?", (run_id,))
        conn.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
        conn.commit()


@pytest.mark.asyncio
async def test_enrich_domain_disabled_flag_makes_no_requests(conn, monkeypatch):
    """Default install: abuse.ch is opt-in — disabled must return the honest
    shape without touching the network."""
    monkeypatch.setattr(enrichment.config, "ABUSECH_ENABLED", False)
    client = FakeClient(fail=True)  # any GET/POST would raise
    out = await enrichment.enrich_domain(client, conn, "quiet.example.org")
    assert out["reputation"] == "unknown"
    assert out["checked_at"] is None
    assert "OUTPOST_ABUSECH_ENABLED" in out["note"]
    assert client.posts == [] and client.calls == []
