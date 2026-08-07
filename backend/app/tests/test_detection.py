"""Detection heuristics — Task 5 acceptance: one test per rule (docs/11)."""

from .conftest import make_run

BASE_TS = "2026-08-01T10:00:00Z"


def _post(client, run_id, events):
    resp = client.post("/ingest/batch", json=events)
    assert resp.status_code == 202
    return resp.json()["alerts"]


def _alerts(client, run_id):
    return client.get(f"/runs/{run_id}/alerts").json()


def test_rule1_masquerading(client):
    """svchost.exe running from an unexpected path."""
    run_id = make_run(client)
    _post(
        client,
        run_id,
        [{
            "run_id": run_id, "platform": "windows", "event_type": "process_create",
            "timestamp": BASE_TS, "pid": 501, "ppid": 4,
            "process_name": "svchost.exe",
            "command_line": r"C:\Users\Public\svchost.exe -k netsvcs",
        }],
    )
    # Rule 7 (first-seen) also fires for a fresh process name — assert per-rule.
    alerts = _alerts(client, run_id)
    masq = [a for a in alerts if a["rule_id"] == "masquerading"]
    assert len(masq) == 1
    alert = masq[0]
    assert alert["severity"] == "malicious"
    assert "expected C:\\Windows\\System32\\svchost.exe" in alert["details"]


def test_rule1_masquerading_legit_path_not_flagged(client):
    run_id = make_run(client)
    _post(
        client,
        run_id,
        [{
            "run_id": run_id, "platform": "windows", "event_type": "process_create",
            "timestamp": BASE_TS, "pid": 502, "ppid": 4,
            "process_name": "svchost.exe",
            "command_line": r"C:\Windows\System32\svchost.exe -k netsvcs",
        }],
    )
    assert all(a["rule_id"] != "masquerading" for a in _alerts(client, run_id))


def test_rule2_suspicious_parent_child(client):
    """winword.exe spawning cmd.exe — macro-malware pattern."""
    run_id = make_run(client)
    events = [
        {
            "run_id": run_id, "platform": "windows", "event_type": "process_create",
            "timestamp": BASE_TS, "pid": 700, "ppid": 4, "process_name": "winword.exe",
            "command_line": r"C:\Program Files\Microsoft Office\winword.exe",
        },
        {
            "run_id": run_id, "platform": "windows", "event_type": "process_create",
            "timestamp": "2026-08-01T10:00:01Z", "pid": 701, "ppid": 700,
            "process_name": "cmd.exe", "command_line": r"C:\Windows\System32\cmd.exe /c whoami",
        },
    ]
    _post(client, run_id, [events[0]])
    _post(client, run_id, [events[1]])
    # Rule 7 (first-seen) also fires for the new cmd.exe — assert per-rule.
    alerts = _alerts(client, run_id)
    pc = [a for a in alerts if a["rule_id"] == "suspicious-parent-child"]
    assert len(pc) == 1
    alert = pc[0]
    assert alert["severity"] == "malicious"
    assert "winword.exe spawned cmd.exe" in alert["details"]


def test_rule3_lolbin_abuse(client):
    """Base64-encoded PowerShell command."""
    run_id = make_run(client)
    _post(
        client,
        run_id,
        [{
            "run_id": run_id, "platform": "windows", "event_type": "process_create",
            "timestamp": BASE_TS, "pid": 800, "ppid": 4,
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgA",
        }],
    )
    # Rule 7 (first-seen) also fires for a fresh process name — assert per-rule.
    alerts = _alerts(client, run_id)
    lb = [a for a in alerts if a["rule_id"] == "lolbin-abuse"]
    assert len(lb) == 1
    alert = lb[0]
    assert alert["severity"] == "malicious"
    assert "base64-encoded" in alert["details"]


def test_rule4_beaconing(client):
    """5+ connections to the same IP at regular ~30s intervals.

    Uses a common port (443) on purpose: 4444 now independently fires the
    `unusual-port` rule, and this test asserts exact alert counts per-rule.
    """
    from datetime import datetime, timedelta, timezone

    run_id = make_run(client)
    base = datetime(2026, 8, 1, 10, 0, 10, tzinfo=timezone.utc)
    events = []
    for i in range(6):
        events.append({
            "run_id": run_id, "platform": "windows", "event_type": "network_connection",
            "timestamp": (base + timedelta(seconds=30 * i)).isoformat(),
            "pid": 900, "dest_ip": "203.0.113.9", "dest_port": 443, "protocol": "TCP",
        })
    # Fires once the 5th regular connection lands; later batches are deduped.
    assert _post(client, run_id, events[:5]) == 1
    assert _post(client, run_id, events[5:]) == 0
    alerts = _alerts(client, run_id)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule_id"] == "beaconing"
    assert alert["severity"] == "suspicious"
    assert "203.0.113.9" in alert["details"]


def test_rule4_irregular_traffic_not_beaconing(client):
    from datetime import datetime, timedelta, timezone

    run_id = make_run(client)
    base = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)
    events = []
    for i, offset in enumerate([1, 5, 40, 100, 250, 400]):
        events.append({
            "run_id": run_id, "platform": "windows", "event_type": "network_connection",
            "timestamp": (base + timedelta(seconds=offset)).isoformat(),
            "pid": 901, "dest_ip": "203.0.113.10", "dest_port": 443, "protocol": "TCP",
        })
    _post(client, run_id, events)
    assert _alerts(client, run_id) == []


def test_rule5_registry_persistence(client):
    """Write to an autorun Run key."""
    run_id = make_run(client)
    n = _post(
        client,
        run_id,
        [{
            "run_id": run_id, "platform": "windows", "event_type": "registry_write",
            "timestamp": BASE_TS, "pid": 950, "ppid": 4,
            "process_name": "reg.exe",
            "registry_key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        }],
    )
    assert n == 1
    alert = _alerts(client, run_id)[0]
    assert alert["rule_id"] == "registry-persistence"
    assert alert["severity"] == "suspicious"
    assert "autorun key" in alert["details"]


def test_rule6_rename_burst(client):
    """11+ file writes from one pid within 10 seconds."""
    from datetime import datetime, timedelta, timezone

    run_id = make_run(client)
    base = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)
    events = []
    for i in range(12):
        events.append({
            "run_id": run_id, "platform": "windows", "event_type": "file_write",
            "timestamp": (base + timedelta(seconds=i % 10)).isoformat(),
            "pid": 980, "ppid": 4, "process_name": "enc.exe",
            "file_path": f"C:\\Users\\victim\\Documents\\file{i}.enc",
        })
    # Fires once the 11th write lands; later batches are deduped.
    assert _post(client, run_id, events[:11]) == 1
    assert _post(client, run_id, events[11:]) == 0
    alerts = _alerts(client, run_id)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule_id"] == "rename-burst"
    assert alert["severity"] == "malicious"
    assert "file writes from pid" in alert["details"]


def test_alerts_endpoint_404(client):
    resp = client.get("/runs/nope/alerts")
    assert resp.status_code == 404
