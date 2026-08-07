"""Tests for Phase 6 standout features (docs/10):

- Task 23: IOC extraction/export
- Task 24: cross-run IOC search + Rule 7 (first-seen process)
- Task 25: run comparison/diff
- Task 26: personal watchlist (API + enrichment override)
- Task 27: Suricata/Sigma rule generator
"""

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


def _proc(run_id: str, pid: int, ppid: int, name: str, cmd: str = "", ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "process_create",
        "timestamp": _ts(ts), "pid": pid, "ppid": ppid, "process_name": name,
        "command_line": cmd,
    }


def _net(run_id: str, ip: str, port: int = 4444, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "network_connection",
        "timestamp": _ts(ts), "pid": 1, "dest_ip": ip, "dest_port": port,
        "protocol": "TCP",
    }


# ---------------------------------------------------------------------------
# Task 23 — IOC extraction/export
# ---------------------------------------------------------------------------
def test_iocs_extraction(client):
    run_id = make_run(client)
    _ingest(client, run_id, [
        _net(run_id, "1.2.3.4", ts=1),
        _net(run_id, "1.2.3.4", ts=5),  # duplicate — must be deduplicated
        _net(run_id, "5.6.7.8", ts=9),
        {**_proc(run_id, 10, 1, "evil.exe"), **{"event_type": "process_create"}},
        {**_proc(run_id, 10, 1, "evil.exe")},
        {"run_id": run_id, "platform": "windows", "event_type": "file_write",
         "timestamp": _ts(3), "pid": 10, "file_path": r"C:\temp\payload.dll"},
        {"run_id": run_id, "platform": "windows", "event_type": "registry_write",
         "timestamp": _ts(4), "pid": 10,
         "registry_key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Bad"},
    ])

    resp = client.get(f"/runs/{run_id}/iocs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["run_id"] == run_id
    types = {ioc["type"] for ioc in data["iocs"]}
    assert types == {"ip", "file_path", "registry_key", "process"}
    values = [ioc["value"] for ioc in data["iocs"]]
    assert values.count("1.2.3.4") == 1  # deduplicated
    assert "5.6.7.8" in values and r"C:\temp\payload.dll" in values


def test_iocs_csv_export(client):
    run_id = make_run(client)
    _ingest(client, run_id, [_net(run_id, "1.2.3.4", ts=1)])
    resp = client.get(f"/runs/{run_id}/iocs?format=csv")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    body = resp.text
    assert body.startswith("type,value,first_seen")
    assert "1.2.3.4" in body


def test_iocs_unknown_run_404(client):
    resp = client.get("/runs/doesnotexist/iocs")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Task 24 — cross-run IOC search + Rule 7 (first-seen)
# ---------------------------------------------------------------------------
def test_cross_run_ioc_search(client):
    # Distinct IPs: the session DB is shared across tests, so avoid values
    # used by other tests (e.g. rule4's 203.0.113.9) to keep counts exact.
    a = make_run(client, sample_name="sample-a.bin")
    b = make_run(client, sample_name="sample-b.bin")
    _ingest(client, a, [_net(a, "203.0.113.55", ts=1)])
    _ingest(client, b, [_net(b, "203.0.113.55", ts=1), _net(b, "198.51.100.7", ts=2)])

    resp = client.get("/ioc/search", params={"value": "203.0.113.55"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 2
    run_ids = {m["run_id"] for m in data["matches"]}
    assert run_ids == {a, b}

    resp = client.get("/ioc/search", params={"value": "198.51.100.7"})
    assert resp.json()["count"] == 1
    assert resp.json()["matches"][0]["run_id"] == b


def test_ioc_search_matches_process_names(client):
    a = make_run(client)
    _ingest(client, a, [_proc(a, 1, 0, "totally-new-tool.exe", ts=1)])
    resp = client.get("/ioc/search", params={"value": "totally-new-tool.exe"})
    assert resp.json()["count"] == 1


def test_rule7_first_seen_process(client):
    """Rule 7 fires only for processes never seen in a *prior* run."""
    first = make_run(client, sample_name="run-one.bin")
    _ingest(client, first, [_proc(first, 1, 0, "known.exe", ts=1)])

    second = make_run(client, sample_name="run-two.bin")
    _ingest(client, second, [
        _proc(second, 2, 0, "known.exe", ts=1),  # seen before — no alert
        _proc(second, 3, 0, "novel.exe", ts=2),  # never seen — alert
    ])

    alerts = client.get(f"/runs/{second}/alerts").json()
    first_seen = [a for a in alerts if a["rule_id"] == "first-seen-process"]
    assert len(first_seen) == 1
    assert first_seen[0]["severity"] == "suspicious"
    assert "novel.exe" in first_seen[0]["details"]


# ---------------------------------------------------------------------------
# Task 25 — run comparison/diff
# ---------------------------------------------------------------------------
def test_compare_runs(client):
    a = make_run(client, sample_name="variant-a.bin")
    b = make_run(client, sample_name="variant-b.bin")
    _ingest(client, a, [
        _proc(a, 1, 0, "launcher.exe", ts=1),
        _proc(a, 2, 1, "core-a.exe", ts=2),
        _net(a, "203.0.113.1", ts=3),
    ])
    _ingest(client, b, [
        _proc(b, 1, 0, "launcher.exe", ts=1),
        _proc(b, 2, 1, "core-b.exe", ts=2),
        _net(b, "203.0.113.2", ts=3),
    ])

    resp = client.get(f"/runs/{a}/compare/{b}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["processes"]["shared"] == ["launcher.exe"]
    assert data["processes"]["only_a"] == ["core-a.exe"]
    assert data["processes"]["only_b"] == ["core-b.exe"]
    assert data["ips"]["only_a"] == ["203.0.113.1"]
    assert data["ips"]["only_b"] == ["203.0.113.2"]


def test_compare_unknown_run_404(client):
    a = make_run(client)
    resp = client.get(f"/runs/{a}/compare/nope")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Task 26 — personal watchlist
# ---------------------------------------------------------------------------
def test_watchlist_crud(client):
    resp = client.post("/watchlist", json={"value": "203.0.113.66", "label": "C2 from sample X"})
    assert resp.status_code == 201
    assert resp.json()["value"] == "203.0.113.66"

    entries = client.get("/watchlist").json()
    assert any(e["value"] == "203.0.113.66" for e in entries)

    assert client.delete("/watchlist/203.0.113.66").status_code == 204
    assert client.delete("/watchlist/203.0.113.66").status_code == 404


def test_watchlist_flags_enrichment(client):
    client.post("/watchlist", json={"value": "203.0.113.77", "label": "tracked infra"})

    run_id = make_run(client)
    _ingest(client, run_id, [_net(run_id, "203.0.113.77", ts=1)])

    detail = client.get(f"/runs/{run_id}").json()
    conns = detail["network_connections"]
    assert len(conns) == 1
    assert conns[0]["dest_ip"] == "203.0.113.77"
    assert conns[0]["watchlist"] is True
    assert conns[0]["watchlist_label"] == "tracked infra"
    # No API keys configured → neutral verdict overridden to suspicious.
    assert conns[0]["reputation"] == "suspicious"


# ---------------------------------------------------------------------------
# Task 27 — Suricata/Sigma rule generator
# ---------------------------------------------------------------------------
def test_suricata_rules_generation():
    from ..services.rule_generator import generate_suricata_rules

    conns = [
        {"dest_ip": "203.0.113.9", "dest_port": 4444, "protocol": "TCP", "reputation": "malicious"},
        {"dest_ip": "8.8.8.8", "dest_port": 443, "protocol": "TCP", "reputation": "clean"},
    ]
    rules = generate_suricata_rules("abc123", conns)
    assert len(rules) == 1  # only the malicious one
    assert "alert tcp any any -> 203.0.113.9 4444" in rules[0]
    assert "abc123" in rules[0]
    # Deterministic sid (stable across processes, unlike builtin hash()).
    assert generate_suricata_rules("abc123", conns) == rules


def test_sigma_rules_generation():
    from ..services.rule_generator import generate_sigma_rules

    alerts = [
        {"rule_id": "lolbin-abuse"},
        {"rule_id": "lolbin-abuse"},  # duplicate — deduplicated
        {"rule_id": "registry-persistence"},
    ]
    rules = generate_sigma_rules("abc123", alerts)
    assert len(rules) == 2
    assert all("title:" in r and "detection:" in r for r in rules)
    # Literal substring patterns — Sigma |contains is NOT regex, so the
    # generated YAML must not contain regex escapes like `\.*`.
    assert "CommandLine|contains: '-enc'" in rules[0]
    assert r"TargetObject|contains: '\CurrentVersion\Run'" in rules[1]


def test_rules_endpoint(client):
    run_id = make_run(client)
    _ingest(client, run_id, [_net(run_id, "203.0.113.9", ts=1)])

    suricata = client.get(f"/runs/{run_id}/rules")
    assert suricata.status_code == 200
    assert "No malicious connections observed in this run." in suricata.text

    sigma = client.get(f"/runs/{run_id}/rules?format=sigma")
    assert sigma.status_code == 200
    assert "# No Sigma-generatable findings" in sigma.text
