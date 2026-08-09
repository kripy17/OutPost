"""Threat-intel API keys in Settings (roadmap): DB-backed with env fallback.

- GET /settings/keys never returns a raw key — only set/source/masked suffix.
- PUT stores (DB overrides env), DELETE clears back to env, unknown names 404.
- The effective key drives enrichment: put a key, then check it resolves.
"""


def test_keys_list_never_leaks_raw_values(client):
    resp = client.get("/settings/keys")
    assert resp.status_code == 200
    body = resp.json()
    names = {k["name"] for k in body["keys"]}
    assert names == {"abuseipdb", "virustotal"}
    for k in body["keys"]:
        raw = str(k)
        assert "super-secret" not in raw  # no raw key anywhere in the payload
        assert "suffix" in k and "source" in k


def test_set_clear_and_masked_suffix(client):
    # Start clean: clear any DB row from a previous test run.
    client.delete("/settings/keys/abuseipdb")
    got = client.put("/settings/keys/abuseipdb", json={"value": "abcd1234wxyz"})
    assert got.status_code == 200
    status = got.json()
    assert status["set"] is True and status["source"] == "db"
    assert status["suffix"] == "wxyz"
    assert "abcd1234" not in str(status)

    listed = client.get("/settings/keys").json()["keys"]
    abuse = next(k for k in listed if k["name"] == "abuseipdb")
    assert abuse["set"] is True and abuse["source"] == "db" and abuse["suffix"] == "wxyz"

    client.delete("/settings/keys/abuseipdb")
    cleared = client.get("/settings/keys").json()["keys"]
    assert next(k for k in cleared if k["name"] == "abuseipdb")["set"] is False


def test_set_validation_and_unknown_name(client):
    assert client.put("/settings/keys/notakey", json={"value": "x"}).status_code == 404
    assert client.put("/settings/keys/abuseipdb", json={"value": "  "}).status_code == 422
    assert client.put("/settings/keys/abuseipdb", json={"value": "has space"}).status_code == 422


def test_env_fallback_resolves(client, monkeypatch):
    """An unset DB row resolves to the env key — zero-config path unchanged."""
    from ..core import config

    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "env-secret-zzz")
    client.delete("/settings/keys/abuseipdb")

    status = client.get("/settings/keys").json()["keys"]
    abuse = next(k for k in status if k["name"] == "abuseipdb")
    assert abuse["set"] is True and abuse["source"] == "env" and abuse["suffix"] == "-zzz"
    assert "env-secret" not in str(abuse)

    # A DB row overrides the env fallback.
    client.put("/settings/keys/abuseipdb", json={"value": "db-wins-aaaa"})
    status = client.get("/settings/keys").json()["keys"]
    abuse = next(k for k in status if k["name"] == "abuseipdb")
    assert abuse["source"] == "db" and abuse["suffix"] == "aaaa"
    client.delete("/settings/keys/abuseipdb")


def test_test_endpoint_requires_key(client):
    client.delete("/settings/keys/virustotal")
    resp = client.post("/settings/keys/virustotal/test")
    assert resp.status_code == 422


def test_key_write_is_audited(client):
    client.put("/settings/keys/virustotal", json={"value": "audit-me-1234"})
    entries = client.get("/audit").json()["events"]
    assert any(e["action"] == "keys.set" for e in entries)
    client.delete("/settings/keys/virustotal")


def test_key_rotation_age_tracked(client):
    """A stored key carries its set-at stamp + age so Settings can suggest
    rotation; clearing removes the stamp too."""
    client.delete("/settings/keys/abuseipdb")
    client.put("/settings/keys/abuseipdb", json={"value": "rot-me-9876"})
    st = next(k for k in client.get("/settings/keys").json()["keys"] if k["name"] == "abuseipdb")
    assert st["set"] and st["source"] == "db"
    assert st["set_at"] and st["age_days"] is not None and st["age_days"] >= 0

    client.delete("/settings/keys/abuseipdb")
    st = next(k for k in client.get("/settings/keys").json()["keys"] if k["name"] == "abuseipdb")
    assert st["set_at"] is None and st["age_days"] is None


def _net(run_id: str, ip: str, ts: int) -> dict:
    return {
        "run_id": run_id, "platform": "linux", "event_type": "network_connection",
        "timestamp": f"2026-08-09T10:00:{ts:02d}Z", "pid": 100 + ts,
        "process_name": "curl", "dest_ip": ip, "dest_port": 443, "protocol": "TCP",
    }


def test_re_enrich_clears_cached_intel_then_reruns(client, monkeypatch):
    """POST /runs/{id}/re-enrich deletes the run's cached IP rows before
    re-running enrichment (stub observes an EMPTY cache at call time)."""
    run_id = client.post("/runs", json={"sample_name": "reenrich.bin", "platform": "linux"}).json()["run_id"]
    client.post("/ingest/batch", json=[_net(run_id, "203.0.113.201", 1), _net(run_id, "198.51.100.55", 2)])
    client.get(f"/runs/{run_id}")  # primes enrichment_cache (cache-first upsert)

    from ..services import enrichment

    captured = {}

    async def fake_enrich(conn, rid):
        # Scoped to THIS run's IPs — the shared test DB may hold cached rows
        # for other tests' runs, so the whole-table count isn't meaningful.
        captured["remaining"] = conn.execute(
            "SELECT COUNT(*) AS n FROM enrichment_cache WHERE ip IN ('203.0.113.201', '198.51.100.55')"
        ).fetchone()["n"]
        return {}

    monkeypatch.setattr(enrichment, "enrich_run", fake_enrich)
    resp = client.post(f"/runs/{run_id}/re-enrich")
    assert resp.status_code == 200
    assert resp.json()["ips_cleared"] == 2
    assert captured["remaining"] == 0  # the DELETE happened before re-enrich ran
    entries = client.get("/audit").json()["events"]
    assert any(e["action"] == "run.re-enrich" for e in entries)


def test_re_enrich_unknown_run_404(client):
    assert client.post("/runs/nope/re-enrich").status_code == 404


def test_refresh_ip_bypasses_ttl_once(client, monkeypatch, conn):
    """POST /runs/{id}/enrichment/refresh?ip= drops that IP's cache row and
    re-queries with the current keys — the proof it bypassed the TTL: a
    cache row still within TTL (1 day old, 7-day TTL) would have been served
    untouched, but the refresh re-queries and the verdict changes."""
    from datetime import datetime, timedelta, timezone

    run_id = client.post("/runs", json={"sample_name": "refresh-ip.bin", "platform": "linux"}).json()["run_id"]
    client.post("/ingest/batch", json=[_net(run_id, "203.0.113.202", 1)])
    detail = client.get(f"/runs/{run_id}").json()
    conn_row = next(c for c in detail["network_connections"] if c["dest_ip"] == "203.0.113.202")
    assert conn_row["checked_at"] is not None  # run detail surfaces the cache age

    from ..services import enrichment

    async def fake_abuse(client_, ip, key):
        return 55  # > 50 → malicious

    async def fake_vt(client_, ip, key):
        return None

    monkeypatch.setattr(enrichment, "_query_abuseipdb", fake_abuse)
    monkeypatch.setattr(enrichment, "_query_virustotal", fake_vt)

    # Backdate the row to just WITHIN TTL with a clean verdict — a fresh-cache
    # read would serve abuse=0/clean; only a real re-query yields the new one.
    conn.execute(
        "UPDATE enrichment_cache SET checked_at = ?, abuse_score = 0, vt_malicious_count = NULL, reputation = 'clean' WHERE ip = ?",
        ((datetime.now(timezone.utc) - timedelta(days=1)).isoformat(), "203.0.113.202"),
    )
    conn.commit()

    resp = client.post(f"/runs/{run_id}/enrichment/refresh", params={"ip": "203.0.113.202"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["reputation"] == "malicious" and body["abuse_score"] == 55
    assert body["checked_at"] and body["checked_at"] > (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()

    entries = client.get("/audit").json()["events"]
    assert any(e["action"] == "intel.refresh-ip" for e in entries)


def test_refresh_ip_unknown_run_or_nonmember_404(client):
    assert client.post("/runs/nope/enrichment/refresh", params={"ip": "203.0.113.202"}).status_code == 404
    run_id = client.post("/runs", json={"sample_name": "refresh-404.bin", "platform": "linux"}).json()["run_id"]
    client.post("/ingest/batch", json=[_net(run_id, "203.0.113.203", 1)])
    # Reaching a DIFFERENT run's IP is not a refreshable member of this run.
    assert client.post(f"/runs/{run_id}/enrichment/refresh", params={"ip": "198.51.100.99"}).status_code == 404
