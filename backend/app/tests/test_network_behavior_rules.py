"""Tests for the network-behavior rules: TLS-SNI tracking, DNS-over-HTTPS to
known resolvers, and same-destination connection fan-out (all T1071 C2)."""

import datetime

from .conftest import make_run


def _ts(offset_seconds: int = 0) -> str:
    return (
        datetime.datetime(2026, 8, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        + datetime.timedelta(seconds=offset_seconds)
    ).isoformat()


def _ingest(client, run_id: str, events: list[dict]) -> None:
    resp = client.post("/ingest/batch", json=events)
    assert resp.status_code == 202, resp.text


def _net(run_id: str, ip: str, port: int, pid: int, proc: str, ts: int = 0, sni: str | None = None) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "network_connection",
        "timestamp": _ts(ts), "pid": pid, "process_name": proc,
        "dest_ip": ip, "dest_port": port, "protocol": "TCP", "tls_sni": sni,
    }


def _alerts(client, run_id: str) -> list[dict]:
    return client.get(f"/runs/{run_id}/alerts").json()


# -- TLS SNI ------------------------------------------------------------------


def test_tls_sni_ip_literal_fires(client):
    run_id = make_run(client, sample_name="raw-tls.exe")
    _ingest(client, run_id, [
        _net(run_id, "198.51.100.80", 443, 100, "evil.exe", ts=1, sni="198.51.100.81"),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "tls-sni-suspicious"]
    assert len(fired) == 1
    assert "IP-literal" in fired[0]["details"]


def test_tls_sni_dga_label_fires(client):
    run_id = make_run(client, sample_name="sni-dga.exe")
    _ingest(client, run_id, [
        _net(run_id, "198.51.100.80", 443, 100, "evil.exe", ts=1, sni="a" * 30 + ".evil.example.com"),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "tls-sni-suspicious"]
    assert len(fired) == 1
    assert "suspicious label" in fired[0]["details"]


def test_tls_sni_normal_hostname_stays_quiet(client):
    run_id = make_run(client, sample_name="normal-tls.exe")
    _ingest(client, run_id, [
        _net(run_id, "198.51.100.80", 443, 100, "chrome.exe", ts=1, sni="www.example.com"),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "tls-sni-suspicious"]
    assert fired == []


# -- DNS over HTTPS -----------------------------------------------------------


def test_doh_resolver_use_script_host_fires(client):
    run_id = make_run(client, sample_name="doh-exfil.ps1")
    _ingest(client, run_id, [
        _net(run_id, "1.1.1.1", 443, 100, "powershell.exe", ts=1, sni="cloudflare-dns.com"),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "doh-resolver-use"]
    assert len(fired) == 1
    assert "Cloudflare" in fired[0]["details"]
    assert "powershell.exe" in fired[0]["details"]


def test_doh_resolver_use_browser_stays_quiet(client):
    run_id = make_run(client, sample_name="normal-browser.exe")
    _ingest(client, run_id, [
        _net(run_id, "1.1.1.1", 443, 100, "chrome.exe", ts=1, sni="cloudflare-dns.com"),
    ])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "doh-resolver-use"]
    assert fired == []


# -- Same-destination fan-out -------------------------------------------------


def test_fanout_contact_many_processes_fires(client):
    run_id = make_run(client, sample_name="coordinated.exe")
    events = [_net(run_id, "198.51.100.82", 443, pid, f"proc{pid}.exe", ts=pid) for pid in range(100, 106)]
    _ingest(client, run_id, events)
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "fanout-contact"]
    assert len(fired) == 1
    assert "198.51.100.82" in fired[0]["details"]
    assert "5 distinct processes" in fired[0]["details"] or "6 distinct processes" in fired[0]["details"]


def test_fanout_contact_flags_every_destination_in_one_batch(client):
    """Multiple fan-out IPs in ONE batch → an alert per destination (the old
    return-on-first-match missed all but the first)."""
    run_id = make_run(client, sample_name="multi-fanout.exe")
    events = []
    for ip in ("198.51.100.83", "198.51.100.84", "198.51.100.85"):
        for pid in range(100, 106):
            events.append(_net(run_id, ip, 443, pid, f"proc{pid}.exe", ts=pid))
    _ingest(client, run_id, events)
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "fanout-contact"]
    assert len(fired) == 3
    ips = {a["related_ip"] for a in fired}
    assert ips == {"198.51.100.83", "198.51.100.84", "198.51.100.85"}


def test_fanout_contact_below_threshold_stays_quiet(client):
    run_id = make_run(client, sample_name="couple-procs.exe")
    events = [_net(run_id, "198.51.100.82", 443, pid, f"proc{pid}.exe", ts=pid) for pid in range(100, 104)]
    _ingest(client, run_id, events)
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "fanout-contact"]
    assert fired == []


# -- Recurring fan-out (same destination across many windows) -----------------


def _fanout_window(run_id: str, ip: str, base_ts: int) -> list[dict]:
    """Five fresh processes fanning out to one IP inside one window."""
    return [
        _net(run_id, ip, 443, 5000 + base_ts + pid, f"proc{base_ts}-{pid}.exe", ts=base_ts + pid)
        for pid in range(5)
    ]


def test_fanout_recurring_fires_after_multiple_windows(client):
    """Same IP fanning out in 3 distinct windows → fanout-recurring fires
    (the long-running-plant signal) alongside the per-window burst alerts."""
    run_id = make_run(client, sample_name="persistent-plant.exe")
    for w in range(3):
        _ingest(client, run_id, _fanout_window(run_id, "198.51.100.90", base_ts=1000 + w * 400))
    recurring = [a for a in _alerts(client, run_id) if a["rule_id"] == "fanout-recurring"]
    assert len(recurring) == 1
    assert recurring[0]["related_ip"] == "198.51.100.90"
    assert "3 distinct" in recurring[0]["details"]
    # The per-window burst alert fired too (deduped to one per IP).
    bursts = [a for a in _alerts(client, run_id) if a["rule_id"] == "fanout-contact"]
    assert len(bursts) == 1


def test_fanout_recurring_single_window_never_fires(client):
    """One window of fan-out is a burst, not a plant — only fanout-contact."""
    run_id = make_run(client, sample_name="one-off.exe")
    _ingest(client, run_id, _fanout_window(run_id, "198.51.100.91", base_ts=1000))
    assert all(a["rule_id"] != "fanout-recurring" for a in _alerts(client, run_id))


def test_fanout_recurring_respects_lowered_tunable(client):
    """FANOUT_RECUR_MIN_WINDOWS=2 makes a two-window plant fire — knobs drive
    the recurrence threshold, no restart."""
    try:
        resp = client.put("/rules/tuning/FANOUT_RECUR_MIN_WINDOWS", json={"value": "2"})
        assert resp.status_code == 200, resp.text
        run_id = make_run(client, sample_name="two-window-plant.exe")
        for w in range(2):
            _ingest(client, run_id, _fanout_window(run_id, "198.51.100.92", base_ts=1000 + w * 400))
        recurring = [a for a in _alerts(client, run_id) if a["rule_id"] == "fanout-recurring"]
        assert len(recurring) == 1
        assert "2 distinct" in recurring[0]["details"]
    finally:
        client.delete("/rules/tuning/FANOUT_RECUR_MIN_WINDOWS")


def test_fanout_recurring_excludes_doh_resolver(client):
    """Known DoH resolvers never trigger the recurring plant signal."""
    run_id = make_run(client, sample_name="doh-recurring.exe")
    for w in range(4):
        _ingest(client, run_id, _fanout_window(run_id, "1.1.1.1", base_ts=1000 + w * 400))
    assert all(a["rule_id"] != "fanout-recurring" for a in _alerts(client, run_id))


def test_fanout_recurring_respects_lookback(client):
    """The scan is bounded: with a 500s lookback the oldest window falls out
    of range (only 2 recent windows qualify), and widening the lookback to
    1000s brings it back (3 windows → fires). Long live sessions re-scan only
    recent history per ingest, not the whole run."""
    try:
        resp = client.put("/rules/tuning/FANOUT_RECUR_LOOKBACK_SECONDS", json={"value": "500"})
        assert resp.status_code == 200, resp.text
        run_id = make_run(client, sample_name="lookback-plant.exe")
        for w in range(3):
            _ingest(client, run_id, _fanout_window(run_id, "198.51.100.93", base_ts=1000 + w * 400))
        assert all(a["rule_id"] != "fanout-recurring" for a in _alerts(client, run_id))

        resp = client.put("/rules/tuning/FANOUT_RECUR_LOOKBACK_SECONDS", json={"value": "1000"})
        assert resp.status_code == 200, resp.text
        # Re-evaluate under the wider lookback: a 4th window makes 3 qualify.
        _ingest(client, run_id, _fanout_window(run_id, "198.51.100.93", base_ts=1000 + 3 * 400))
        recurring = [a for a in _alerts(client, run_id) if a["rule_id"] == "fanout-recurring"]
        assert len(recurring) == 1
        assert recurring[0]["related_ip"] == "198.51.100.93"
    finally:
        client.delete("/rules/tuning/FANOUT_RECUR_LOOKBACK_SECONDS")


def test_events_run_type_index_exists():
    """The composite (run_id, event_type) index is created on every boot —
    the per-run event-type scans (recurrence, process map, dns windows) are
    indexed reads, not table scans."""
    import sqlite3

    from ..core import config

    conn = sqlite3.connect(config.DATABASE_PATH)
    try:
        indexes = {r[1] for r in conn.execute("PRAGMA index_list('events')").fetchall()}
    finally:
        conn.close()
    assert "idx_events_run_type" in indexes


def test_fanout_contact_excludes_known_doh_resolver(client):
    run_id = make_run(client, sample_name="multi-doh.exe")
    events = [_net(run_id, "1.1.1.1", 443, pid, f"proc{pid}.exe", ts=pid) for pid in range(100, 106)]
    _ingest(client, run_id, events)
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "fanout-contact"]
    assert fired == []
