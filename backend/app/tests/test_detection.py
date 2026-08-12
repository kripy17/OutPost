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


def test_rule1_masquerading_systemd_init_alias_ok(client):
    """pid 1's /sbin/init execve is systemd on Arch/Ubuntu (symlink) — the
    soak FP: real host init fired "systemd from unexpected path" (soak-discovered)."""
    run_id = make_run(client)
    for cmdline in ("/sbin/init", "/usr/sbin/init", "/usr/lib/systemd/systemd --user"):
        _post(
            client,
            run_id,
            [{
                "run_id": run_id, "platform": "linux", "event_type": "process_create",
                "timestamp": BASE_TS, "pid": 1, "ppid": 0,
                "process_name": "systemd", "command_line": cmdline,
            }],
        )
    assert all(a["rule_id"] != "masquerading" for a in _alerts(client, run_id))


def test_rule1_masquerading_systemd_from_tmp_still_fires(client):
    """The alias only whitelists the distro init symlinks — a real
    masquerade (systemd dropped in /tmp) still fires."""
    run_id = make_run(client)
    _post(
        client,
        run_id,
        [{
            "run_id": run_id, "platform": "linux", "event_type": "process_create",
            "timestamp": BASE_TS, "pid": 511, "ppid": 1,
            "process_name": "systemd", "command_line": "/tmp/systemd --user",
        }],
    )
    masq = [a for a in _alerts(client, run_id) if a["rule_id"] == "masquerading"]
    assert len(masq) == 1
    assert "expected /usr/lib/systemd/systemd" in masq[0]["details"]


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


def test_rule4_burst_not_beaconing(client):
    """A rapid burst (intervals ≈ 0s) is traffic, not a beacon — needs a
    minimum positive mean interval. Soak FP: 7 connections to one IP within
    0.2s fired as "regular ~0s intervals"."""
    from datetime import datetime, timedelta, timezone

    run_id = make_run(client)
    base = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)
    events = [{
        "run_id": run_id, "platform": "windows", "event_type": "network_connection",
        "timestamp": (base + timedelta(milliseconds=80 * i)).isoformat(),
        "pid": 902, "dest_ip": "203.0.113.11", "dest_port": 443, "protocol": "TCP",
    } for i in range(6)]
    _post(client, run_id, events)
    assert all(a["rule_id"] != "beaconing" for a in _alerts(client, run_id))


def test_rule4_non_routable_ips_ignored(client):
    """0.0.0.0 and loopback traffic never beacons — even at perfectly regular
    30s intervals. Soak FPs: 6 conns to 0.0.0.0:8001 and 5 to 127.0.0.1:8001
    (our own dev-stack polling) fired as beaconing."""
    from datetime import datetime, timedelta, timezone

    run_id = make_run(client)
    base = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)
    events = []
    for ip in ("0.0.0.0", "127.0.0.1"):
        for i in range(6):
            events.append({
                "run_id": run_id, "platform": "linux", "event_type": "network_connection",
                "timestamp": (base + timedelta(seconds=30 * i)).isoformat(),
                "pid": 903, "dest_ip": ip, "dest_port": 8001, "protocol": "TCP",
            })
    _post(client, run_id, events)
    assert all(a["rule_id"] != "beaconing" for a in _alerts(client, run_id))


def test_rule3_unusual_port_loopback_not_flagged(client):
    """A local listener on a C2-ish port is a dev service, not a plant — the
    unusual-port rule only judges routable destinations. Soak-2 FP: a
    127.0.0.1:9001 connection fired "port commonly used by C2 frameworks"."""
    run_id = make_run(client)
    _post(
        client,
        run_id,
        [{
            "run_id": run_id, "platform": "linux", "event_type": "network_connection",
            "timestamp": BASE_TS, "pid": 904, "dest_ip": "127.0.0.1",
            "dest_port": 9001, "protocol": "TCP",
        }],
    )
    assert all(a["rule_id"] != "unusual-port" for a in _alerts(client, run_id))
    # And the same port on a routable IP still fires.
    _post(
        client,
        run_id,
        [{
            "run_id": run_id, "platform": "linux", "event_type": "network_connection",
            "timestamp": BASE_TS, "pid": 905, "dest_ip": "203.0.113.20",
            "dest_port": 4444, "protocol": "TCP",
        }],
    )
    up = [a for a in _alerts(client, run_id) if a["rule_id"] == "unusual-port"]
    assert len(up) == 1
    assert "203.0.113.20:4444" in up[0]["details"]


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


def test_rule1_masquerading_exe_path_authority_clears_sh_symlink(client):
    """The real-auditd soak FP: bash invoked as /usr/bin/sh (Arch's sh→bash
    symlink) reads as "bash from an unexpected path" to the cmdline check. The
    kernel-resolved exe_path (/usr/bin/bash) is authoritative and clears it."""
    run_id = make_run(client)
    _post(
        client,
        run_id,
        [{
            "run_id": run_id, "platform": "linux", "event_type": "process_create",
            "timestamp": BASE_TS, "pid": 89890, "ppid": 1,
            "process_name": "bash", "command_line": "/usr/bin/sh -c whoami",
            "exe_path": "/usr/bin/bash",
        }],
    )
    assert all(a["rule_id"] != "masquerading" for a in _alerts(client, run_id))


def test_rule1_masquerading_exe_path_authority_still_fires(client):
    """argv[0] cannot spoof the resolved path: bash copied to /tmp fires even
    when the command line claims /usr/bin/bash."""
    run_id = make_run(client)
    _post(
        client,
        run_id,
        [{
            "run_id": run_id, "platform": "linux", "event_type": "process_create",
            "timestamp": BASE_TS, "pid": 89900, "ppid": 1,
            "process_name": "bash", "command_line": "/usr/bin/bash -c 'echo hi'",
            "exe_path": "/tmp/bash",
        }],
    )
    masq = [a for a in _alerts(client, run_id) if a["rule_id"] == "masquerading"]
    assert len(masq) == 1
    assert "resolved /tmp/bash" in masq[0]["details"]


def test_rule1_masquerading_sh_symlink_no_exe_path_ok(client):
    """Legacy events without exe_path still tolerate the sh→bash alias — the
    cmdline fallback must not reintroduce the FP for old rows."""
    run_id = make_run(client)
    _post(
        client,
        run_id,
        [{
            "run_id": run_id, "platform": "linux", "event_type": "process_create",
            "timestamp": BASE_TS, "pid": 89891, "ppid": 1,
            "process_name": "bash", "command_line": "/usr/bin/sh -c whoami",
        }],
    )
    assert all(a["rule_id"] != "masquerading" for a in _alerts(client, run_id))


def test_rule4_dns_resolver_cadence_not_beaconing(client):
    """Real-auditd soak FPs: regular-interval DNS (53) and DoH (443) traffic
    to public resolvers has exactly beacon-like cadence but is background
    noise. Port 53 is DNS (the DNS-tunnel rules' job) and public DoH
    resolvers on 443 are exempt; a resolver beacon on a C2 port still fires."""
    from datetime import datetime, timedelta, timezone

    run_id = make_run(client)
    base = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)
    events = []
    for i in range(6):
        events.append({
            "run_id": run_id, "platform": "linux", "event_type": "network_connection",
            "timestamp": (base + timedelta(seconds=5 * i)).isoformat(),
            "pid": 910, "dest_ip": "8.8.8.8", "dest_port": 53, "protocol": "TCP",
        })
        events.append({
            "run_id": run_id, "platform": "linux", "event_type": "network_connection",
            "timestamp": (base + timedelta(seconds=5 * i + 2)).isoformat(),
            "pid": 911, "dest_ip": "8.8.8.8", "dest_port": 443, "protocol": "TCP",
        })
    _post(client, run_id, events)
    assert all(a["rule_id"] != "beaconing" for a in _alerts(client, run_id))


def test_rule4_v6_doh_resolver_cadence_not_beaconing(client):
    """The real-feed re-measurement FP: the v6 Google resolver's regular 443
    cadence (2001:4860:4860::8888) fired beaconing because only the v4 forms
    were exempted. The compressed v6 DoH resolvers are exempt too — and a
    v6 beacon on a C2 port still fires."""
    from datetime import datetime, timedelta, timezone

    run_id = make_run(client)
    base = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)
    events = [{
        "run_id": run_id, "platform": "linux", "event_type": "network_connection",
        "timestamp": (base + timedelta(seconds=5 * i)).isoformat(),
        "pid": 915, "dest_ip": "2001:4860:4860::8888", "dest_port": 443, "protocol": "TCP",
    } for i in range(6)]
    _post(client, run_id, events)
    assert all(a["rule_id"] != "beaconing" for a in _alerts(client, run_id))
    # A v6 destination on a C2 port still beacons (fan-out style, one pid).
    base2 = datetime(2026, 8, 1, 11, 0, 0, tzinfo=timezone.utc)
    run2 = make_run(client)
    events2 = [{
        "run_id": run2, "platform": "linux", "event_type": "network_connection",
        "timestamp": (base2 + timedelta(seconds=5 * i)).isoformat(),
        "pid": 916, "dest_ip": "2606:4700:4700::1111", "dest_port": 4444, "protocol": "TCP",
    } for i in range(5)]
    _post(client, run2, events2)
    beac = [a for a in _alerts(client, run2) if a["rule_id"] == "beaconing"]
    assert len(beac) == 1


def test_rule4_resolver_beacon_on_non_dns_port_still_fires(client):
    """The exemptions only cover the resolver protocols — a beacon to a known
    resolver on a C2 port fires (the demo/soak 1.1.1.1:4444 beacon must not
    be silently exempted by the DoH list)."""
    from datetime import datetime, timedelta, timezone

    run_id = make_run(client)
    base = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)
    events = [{
        "run_id": run_id, "platform": "linux", "event_type": "network_connection",
        "timestamp": (base + timedelta(seconds=5 * i)).isoformat(),
        "pid": 912, "dest_ip": "1.1.1.1", "dest_port": 4444, "protocol": "TCP",
    } for i in range(5)]
    assert _post(client, run_id, events) >= 1
    beac = [a for a in _alerts(client, run_id) if a["rule_id"] == "beaconing"]
    assert len(beac) == 1
    assert "1.1.1.1:4444" in beac[0]["details"]


def test_rule4_same_ip_different_ports_not_aggregated(client):
    """A C2 channel is one ip:port tuple. 3 regular conns on each of two
    ports to the same IP must NOT aggregate into a 6-conn beacon — the
    real-auditd soak summed DNS-53 + DoH-443 into "12 connections to
    8.8.8.8". Neither channel alone crosses the 5-conn threshold."""
    from datetime import datetime, timedelta, timezone

    run_id = make_run(client)
    base = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)
    events = []
    for i in range(3):
        events.append({
            "run_id": run_id, "platform": "linux", "event_type": "network_connection",
            "timestamp": (base + timedelta(seconds=5 * i)).isoformat(),
            "pid": 913, "dest_ip": "203.0.113.21", "dest_port": 8080, "protocol": "TCP",
        })
        events.append({
            "run_id": run_id, "platform": "linux", "event_type": "network_connection",
            "timestamp": (base + timedelta(seconds=5 * i + 2)).isoformat(),
            "pid": 914, "dest_ip": "203.0.113.21", "dest_port": 9090, "protocol": "TCP",
        })
    _post(client, run_id, events)
    assert all(a["rule_id"] != "beaconing" for a in _alerts(client, run_id))
