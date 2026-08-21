"""Per-host baseline anomalies (roadmap 4.x) — the anomaly layer.

A host's own telemetry builds the baseline; first-time processes / network
destinations fire `baseline-anomaly` once the baseline is established
(BASELINE_MIN_EVENTS, default 100 — tests drive it by shipping 100+ events).
Each novel observation fires exactly once: the batch that sees it alerts, then
learns it, so the next batch treats it as known. Hosts that never pass the
gate stay quiet (no first-day spam).
"""

from datetime import datetime, timedelta, timezone

from .conftest import make_run


def _ts(i: int) -> str:
    return (datetime(2026, 8, 9, 12, 0, tzinfo=timezone.utc) + timedelta(seconds=i)).isoformat()


def _proc(run_id: str, pid: int, name: str, host: str, i: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "linux", "event_type": "process_create",
        "timestamp": _ts(i), "pid": pid, "ppid": 0, "process_name": name,
        "command_line": f"{name} --x", "host_id": host,
    }


def _net(run_id: str, ip: str, host: str, i: int = 0, port: int = 443) -> dict:
    return {
        "run_id": run_id, "platform": "linux", "event_type": "network_connection",
        "timestamp": _ts(i), "pid": 1, "dest_ip": ip, "dest_port": port, "protocol": "tcp",
        "host_id": host,
    }


def _baseline_alerts(client, run_id):
    return [a for a in client.get(f"/runs/{run_id}/alerts").json() if a["rule_id"] == "baseline-anomaly"]


def _establish(client, run_id: str, host: str) -> None:
    """Ship enough process events to cross the 100-observation gate."""
    client.post(
        "/ingest/batch",
        json=[_proc(run_id, 1000 + i, f"known-bin-{i:03d}", host, i) for i in range(105)],
    )


def test_new_host_is_quiet_until_baseline_established(client):
    run_id = make_run(client, sample_name="bl-quiet.bin", platform="linux")
    _establish(client, run_id, "bl-quiet-host")
    # All 105 were novel, but the baseline wasn't established → nothing fired.
    assert _baseline_alerts(client, run_id) == []

    # Established now — a genuinely new binary fires exactly one anomaly.
    client.post("/ingest/batch", json=[_proc(run_id, 2000, "novel-binary", "bl-quiet-host", 200)])
    hits = _baseline_alerts(client, run_id)
    assert len(hits) == 1
    assert "novel-binary" in hits[0]["details"]
    assert "bl-quiet-host" in hits[0]["details"]


def test_novel_observation_fires_once_then_is_learned(client):
    """Check-then-learn: the first sighting alerts and is then known — the
    same process/IP in the next batch never re-fires."""
    run_id = make_run(client, sample_name="bl-once.bin", platform="linux")
    _establish(client, run_id, "bl-once-host")

    client.post("/ingest/batch", json=[_net(run_id, "203.0.113.220", "bl-once-host", 300)])
    hits = _baseline_alerts(client, run_id)
    assert len(hits) == 1 and hits[0]["related_ip"] == "203.0.113.220"

    # Same IP again → learned, no second alert.
    client.post("/ingest/batch", json=[_net(run_id, "203.0.113.220", "bl-once-host", 301)])
    assert len(_baseline_alerts(client, run_id)) == 1

    # A different novel IP still fires.
    client.post("/ingest/batch", json=[_net(run_id, "198.51.100.66", "bl-once-host", 302)])
    assert len(_baseline_alerts(client, run_id)) == 2


def test_baseline_profile_endpoint_and_reset(client):
    run_id = make_run(client, sample_name="bl-profile.bin", platform="linux")
    _establish(client, run_id, "bl-profile-host")
    client.post("/ingest/batch", json=[_net(run_id, "203.0.113.220", "bl-profile-host", 300)])
    client.post("/ingest/batch", json=[_proc(run_id, 3000, "novel-two", "bl-profile-host", 301)])

    prof = client.get("/baselines/bl-profile-host").json()
    assert prof["host_id"] == "bl-profile-host"
    assert prof["total_observations"] >= 105
    assert prof["anomaly_count"] == 2
    names = {p["value"] for p in prof["processes"]}
    assert "known-bin-000" in names and "novel-two" in names
    ips = {n["value"] for n in prof["networks"]}
    assert "203.0.113.220" in ips

    # Reset forgets everything; the next batch starts learning from zero.
    assert client.delete("/baselines/bl-profile-host").json()["reset"] is True
    prof2 = client.get("/baselines/bl-profile-host").json()
    assert prof2["total_observations"] == 0
    # Unknown host baseline is a valid empty profile (404 is only for… nothing).
    assert client.get("/baselines/never-seen-host").json()["total_observations"] == 0
