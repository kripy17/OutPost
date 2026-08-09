"""Intel-cache operations tests: freshness aggregate, stale-only sweep,
global per-IP refresh, and the export cache-age columns (JSON report
network_connections + IOC CSV checked_at)."""

from datetime import datetime, timedelta, timezone

from ..services import enrichment


def _net(run_id: str, ip: str, ts: int) -> dict:
    return {
        "run_id": run_id, "platform": "linux", "event_type": "network_connection",
        "timestamp": f"2026-08-09T10:00:{ts:02d}Z", "pid": 100 + ts,
        "process_name": "curl", "dest_ip": ip, "dest_port": 443, "protocol": "TCP",
    }


def _make_run_with_ip(client, sample: str, ip: str, ts: int = 1) -> str:
    run_id = client.post("/runs", json={"sample_name": sample, "platform": "linux"}).json()["run_id"]
    client.post("/ingest/batch", json=[_net(run_id, ip, ts)])
    client.get(f"/runs/{run_id}")  # primes enrichment_cache
    return run_id


def test_freshness_reports_total_stale_and_oldest(client, conn):
    _make_run_with_ip(client, "fresh-a.bin", "203.0.113.210")
    _make_run_with_ip(client, "fresh-b.bin", "198.51.100.60")
    # One row backdated past the TTL.
    conn.execute(
        "UPDATE enrichment_cache SET checked_at = ? WHERE ip = '203.0.113.210'",
        ((datetime.now(timezone.utc) - timedelta(days=20)).isoformat(),),
    )
    conn.commit()

    f = client.get("/intel/freshness").json()
    assert f["total"] >= 2
    assert f["stale_count"] >= 1
    assert f["oldest_checked_at"] and f["oldest_age_hours"] is not None and f["oldest_age_hours"] >= 20 * 24


def test_refresh_stale_only_refreshes_past_ttl_rows(client, monkeypatch, conn):
    """The sweep re-queries ONLY rows older than the TTL — a fresh row keeps
    its verdict untouched, a stale one flips to the re-query result."""
    _make_run_with_ip(client, "stale-a.bin", "203.0.113.211")
    _make_run_with_ip(client, "stale-b.bin", "198.51.100.61")
    conn.execute(
        "UPDATE enrichment_cache SET checked_at = ?, abuse_score = 0, reputation = 'clean' WHERE ip = '203.0.113.211'",
        ((datetime.now(timezone.utc) - timedelta(days=10)).isoformat(),),
    )
    conn.commit()

    async def fake_abuse(client_, ip, key):
        return 60  # > 50 → malicious

    async def fake_vt(client_, ip, key):
        return None

    monkeypatch.setattr(enrichment, "_query_abuseipdb", fake_abuse)
    monkeypatch.setattr(enrichment, "_query_virustotal", fake_vt)

    resp = client.post("/intel/refresh-stale", params={"max": 50})
    assert resp.status_code == 200
    body = resp.json()
    # The sweep is global, so other tests' stale rows may be swept too — the
    # contract we lock: OUR backdated row is among the refreshed ones and
    # came back re-queried, not cache-served.
    assert body["refreshed"] >= 1
    mine = next(r for r in body["rows"] if r["ip"] == "203.0.113.211")
    assert mine["reputation"] == "malicious"

    # The fresh row was left untouched.
    from ..models.event import get_cache

    assert get_cache(conn, "198.51.100.61")["reputation"] in ("unknown", "clean", "suspicious")
    entries = client.get("/audit").json()["events"]
    assert any(e["action"] == "intel.refresh-stale" for e in entries)


def test_refresh_stale_respects_max(client, conn):
    _make_run_with_ip(client, "stale-c.bin", "203.0.113.212")
    _make_run_with_ip(client, "stale-d.bin", "203.0.113.213")
    conn.execute(
        "UPDATE enrichment_cache SET checked_at = ? WHERE ip IN ('203.0.113.212','203.0.113.213')",
        ((datetime.now(timezone.utc) - timedelta(days=10)).isoformat(),),
    )
    conn.commit()
    body = client.post("/intel/refresh-stale", params={"max": 1}).json()
    assert body["refreshed"] == 1


def test_global_ip_refresh_bypasses_ttl_once(client, monkeypatch, conn):
    """POST /enrichment/{ip}/refresh works for ANY ip (no run scoping) — the
    Footprint page's per-seed refresh — and is audited."""
    ip = "203.0.113.214"
    _make_run_with_ip(client, "global-a.bin", ip)
    conn.execute(
        "UPDATE enrichment_cache SET checked_at = ?, abuse_score = 0, reputation = 'clean' WHERE ip = ?",
        ((datetime.now(timezone.utc) - timedelta(days=1)).isoformat(), ip),
    )
    conn.commit()

    async def fake_abuse(client_, ip_, key):
        return 70

    async def fake_vt(client_, ip_, key):
        return None

    monkeypatch.setattr(enrichment, "_query_abuseipdb", fake_abuse)
    monkeypatch.setattr(enrichment, "_query_virustotal", fake_vt)

    resp = client.post(f"/enrichment/{ip}/refresh")
    assert resp.status_code == 200
    body = resp.json()
    assert body["reputation"] == "malicious" and body["abuse_score"] == 70
    assert body["checked_at"]
    entries = client.get("/audit").json()["events"]
    assert any(e["action"] == "intel.refresh-ip" and ip in (e.get("target_id") or "") for e in entries)


def test_json_report_carries_network_connections_with_checked_at(client, conn):
    run_id = _make_run_with_ip(client, "export-a.bin", "203.0.113.215")
    conn.execute(
        "UPDATE enrichment_cache SET checked_at = ? WHERE ip = '203.0.113.215'",
        ((datetime.now(timezone.utc) - timedelta(hours=5)).isoformat(),),
    )
    conn.commit()
    report = client.get(f"/runs/{run_id}/export").json()
    conns = report["network_connections"]
    assert len(conns) == 1 and conns[0]["dest_ip"] == "203.0.113.215"
    assert conns[0]["checked_at"] is not None and conns[0]["reputation"] is not None


def test_ioc_csv_includes_checked_at_column(client, conn):
    run_id = _make_run_with_ip(client, "export-b.bin", "203.0.113.216")
    conn.execute(
        "UPDATE enrichment_cache SET checked_at = ? WHERE ip = '203.0.113.216'",
        ((datetime.now(timezone.utc) - timedelta(hours=3)).isoformat(),),
    )
    conn.commit()
    csv_text = client.get(f"/runs/{run_id}/iocs", params={"format": "csv"}).text
    lines = csv_text.strip().splitlines()
    assert lines[0] == "type,value,first_seen,checked_at"
    ip_row = next(l for l in lines[1:] if l.startswith("ip,"))
    fields = ip_row.split(",")
    assert len(fields) == 4 and fields[3]  # the ip row carries its checked_at stamp
