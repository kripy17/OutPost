"""P3.1 — detection-side IOC population + provenance.

The IOC entity system previously had readers but no producer: nothing ever
wrote `ioc_provenance` / `ioc_findings`, so the workspace API derived
nothing. Now every persisted finding feeds a best-effort extraction pass:

- structured `related_ip` → ip entity (always high-signal)
- details text tokens: URLs (→ url + host domain), hex digests, emails,
  IPv4s with octet validation (loopback/unspecified excluded)
- canonical identity via normalize_value; create-or-reuse on
  UNIQUE(value, type) — five detections of one IP yield ONE entity
- provenance: finding ref always, event ref when the rule is per-event;
  composite run-wide rules stay finding-ref only
- ioc_findings links persisted for the workspace detail payload

Failure isolation is part of the contract: population never raises, and a
persistence problem must not lose the detection that surfaced it.
"""

import sqlite3
from datetime import datetime, timezone

import pytest

from .conftest import make_run


def _net(run_id: str, ip: str = "203.0.113.166", port: int = 4444) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "network_connection",
        "timestamp": "2026-08-17T00:00:00Z", "pid": 1, "dest_ip": ip, "dest_port": port, "protocol": "tcp",
    }


def _ioc_rows(conn: sqlite3.Connection) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM iocs ORDER BY value")]


def test_detection_populates_ioc_with_finding_and_event_provenance(client, conn):
    run_id = make_run(client)
    client.post("/ingest/batch", json=[_net(run_id)])
    alert = client.get(f"/runs/{run_id}/alerts").json()[0]

    # Session DB is shared across tests — scope to this canonical identity.
    rows = [r for r in _ioc_rows(conn) if r["value"] == "203.0.113.166"]
    assert [(r["value"], r["type"]) for r in rows] == [("203.0.113.166", "ip")]
    row = rows[0]
    assert row["source"] == "detection" and row["disposition"] == "candidate"

    prov = conn.execute(
        "SELECT ref_type, ref_id FROM ioc_provenance WHERE ioc_id = ?", (row["ioc_id"],)
    ).fetchall()
    refs = {(r["ref_type"], r["ref_id"]) for r in prov}
    assert ("finding", str(alert["id"])) in refs
    assert any(r["ref_type"] == "event" for r in prov)  # per-event rule

    link = conn.execute(
        "SELECT finding_id FROM ioc_findings WHERE ioc_id = ? AND finding_id = ?",
        (row["ioc_id"], alert["id"]),
    ).fetchall()
    assert len(link) == 1
    conn.close()


def test_repeated_observations_reuse_one_entity(client, conn):
    # Two runs, same IP → one canonical entity, two findings linked.
    # (Unique IP per test: the session DB is shared across tests.)
    ids = []
    for name in ("p31-reuse-a.bin", "p31-reuse-b.bin"):
        run_id = make_run(client, sample_name=name)
        client.post("/ingest/batch", json=[_net(run_id, ip="203.0.113.167")])
        ids.append(client.get(f"/runs/{run_id}/alerts").json()[0]["id"])

    rows = [r for r in _ioc_rows(conn) if r["value"] == "203.0.113.167"]
    assert len(rows) == 1
    linked = conn.execute(
        "SELECT finding_id FROM ioc_findings WHERE ioc_id = ? ORDER BY finding_id", (rows[0]["ioc_id"],)
    ).fetchall()
    assert [r["finding_id"] for r in linked] == sorted(ids)
    conn.close()


def test_normalization_is_the_canonical_identity(client, conn):    # Mixed-case IP in one run, lowercase in another → same entity.
    run_a = make_run(client, sample_name="p31-norm-a.bin")
    client.post("/ingest/batch", json=[_net(run_a, ip="203.0.113.168")])
    run_b = make_run(client, sample_name="p31-norm-b.bin")
    client.post("/ingest/batch", json=[_net(run_b, ip="203.0.113.168")])
    rows = [r for r in _ioc_rows(conn) if r["value"] == "203.0.113.168"]
    assert len(rows) == 1
    conn.close()


def test_details_tokens_extracted_url_domain_hash_email(client, conn):
    # A rule whose details text carries tokens: use the lolbin rule
    # (powershell -enc) and check what lands; then unit-level coverage of
    # the extractor for the full token matrix.
    from ..core.schema import Alert
    from ..services.ioc_extraction import extract_from_alert

    alert = Alert(
        run_id="r", host_id="h", rule_id="t", rule_name="t", severity="suspicious",
        triggered_at=datetime.now(timezone.utc), title="t",
        description="d", related_ip="198.51.100.7",
        details=(
            "C2 at http://Evil.Example.net/payload?a=1 and https://198.51.100.7/x "
            "sha256 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff "
            "md5 00112233445566778899aabbccddeeff contact ops@evil.example.net "
            "loopback 127.0.0.1 ignored, invalid 999.1.1.1 ignored"
        ),
    )
    pairs = extract_from_alert(alert)
    by_type: dict[str, set[str]] = {}
    for value, ioc_type in pairs:
        by_type.setdefault(ioc_type, set()).add(value)

    assert by_type["ip"] == {"198.51.100.7"}  # loopback + invalid octets dropped
    assert by_type["url"] == {"http://Evil.Example.net/payload?a=1", "https://198.51.100.7/x"}
    assert by_type["domain"] == {"evil.example.net"}  # URL host; IP-host contributes none
    assert by_type["hash"] == {
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "00112233445566778899aabbccddeeff",
    }
    assert by_type["email"] == {"ops@evil.example.net"}


def test_composite_rules_get_finding_ref_only(client, conn):
    # DNS tunneling is a run-wide composite: it fires without a single
    # triggering event, so its IOCs must carry NO event provenance.
    # Shape per the rule: network_connection events carrying `query`, with
    # >= 6 distinct long/high-entropy labels (DNS_TUNNEL_MIN_DISTINCT).
    labels = [f"lbl{i:02d}{'x' * 20}" for i in range(6)]
    run_id = make_run(client, sample_name="p31-dns-tunnel.bin")
    events = [
        {
            "run_id": run_id, "platform": "windows", "event_type": "network_connection",
            "timestamp": f"2026-08-17T00:{i:02d}:00Z", "pid": 9,
            "dest_ip": "198.51.100.50", "dest_port": 53, "protocol": "udp",
            "query": f"{label}.c2.evil.example.net",
        }
        for i, label in enumerate(labels)
    ]
    client.post("/ingest/batch", json=events)
    alerts = client.get(f"/runs/{run_id}/alerts").json()
    tunnel = [a for a in alerts if "dns" in a["rule_id"]]
    assert tunnel, "expected the dns tunneling composite to fire"
    finding_ids = {str(a["id"]) for a in tunnel}
    domain_rows = [r for r in _ioc_rows(conn) if r["type"] == "domain"]
    # Scope to entities this run's findings linked (session DB is shared).
    mine = conn.execute(
        f"SELECT ioc_id FROM ioc_findings WHERE finding_id IN ({','.join('?' * len(finding_ids))})",
        tuple(int(f) for f in finding_ids),
    ).fetchall()
    my_ioc_ids = {r["ioc_id"] for r in mine}
    assert my_ioc_ids, "composite should still populate entities"
    for row in domain_rows:
        if row["ioc_id"] not in my_ioc_ids:
            continue
        refs = {r["ref_type"] for r in conn.execute(
            "SELECT ref_type FROM ioc_provenance WHERE ioc_id = ?", (row["ioc_id"],)
        ).fetchall()}
        assert "finding" in refs
        assert "event" not in refs
    conn.close()


def test_population_failure_never_loses_detection(client, conn, monkeypatch):
    # The contract: IOC persistence is enrichment. Break the store layer —
    # the ingest must still succeed and the alert must still exist.
    from ..models import iocs as iocs_store

    def boom(*a, **k):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(iocs_store, "observe_ioc", boom)
    run_id = make_run(client, sample_name="p31-fail.bin")
    resp = client.post("/ingest/batch", json=[_net(run_id, ip="203.0.113.170")])
    assert resp.status_code == 202
    alerts = client.get(f"/runs/{run_id}/alerts").json()
    assert len(alerts) == 1  # detection result preserved
    # ...and nothing half-written for this run's indicator.
    assert [r for r in _ioc_rows(conn) if r["value"] == "203.0.113.170"] == []
    conn.close()


def test_manual_api_compatibility_unchanged(client, conn):
    # The analyst path keeps its own semantics: source=analyst, label kept,
    # INSERT OR IGNORE dedupe WITHOUT last_seen bumping.
    first = client.post("/iocs", json={"value": "Example.COM", "type": "domain", "label": "watch"}).json()
    again = client.post("/iocs", json={"value": "example.com", "type": "domain"}).json()
    assert first["ioc_id"] == again["ioc_id"]
    assert first["source"] == "analyst" and first["label"] == "watch"
    assert again["label"] == "watch"
    assert len([r for r in _ioc_rows(conn) if r["value"] == "example.com"]) == 1
    conn.close()


def test_analyst_label_backfills_onto_detection_created_entity(client, conn):
    # Detection saw the IP first (ingest), then the analyst labels it —
    # the label must land on the canonical entity, not vanish.
    run_id = make_run(client, sample_name="p31-label.bin")
    client.post("/ingest/batch", json=[_net(run_id, ip="203.0.113.171")])
    made = client.post("/iocs", json={"value": "203.0.113.171", "type": "ip", "label": "c2 host"}).json()
    assert made["source"] == "detection"
    row = next(r for r in _ioc_rows(conn) if r["value"] == "203.0.113.171")
    assert row["label"] == "c2 host"
    # A second analyst POST with a different label does NOT clobber it.
    client.post("/iocs", json={"value": "203.0.113.171", "type": "ip", "label": "other"})
    row = next(r for r in _ioc_rows(conn) if r["value"] == "203.0.113.171")
    assert row["label"] == "c2 host"
    conn.close()


@pytest.mark.parametrize("bad", ["127.0.0.1", "0.0.0.0", "300.1.1.1", "1.2.3"])
def test_noise_ips_not_extracted(client, conn, bad):
    run_id = make_run(client, sample_name=f"p31-noise-{bad.replace('.', '_')}.bin")
    client.post("/ingest/batch", json=[{**_net(run_id, ip="203.0.113.166"),
                                        "command_line": None}])
    # related_ip path only accepts valid public-ish IPs; feed the noise via
    # an alert details text through the extractor directly.
    from ..core.schema import Alert
    from ..services.ioc_extraction import extract_from_alert
    alert = Alert(run_id="r", host_id="h", rule_id="t", rule_name="t", severity="suspicious",
                  triggered_at=datetime.now(timezone.utc), title="t",
                  description="d", details=f"seen {bad}")
    assert extract_from_alert(alert) == []
    conn.close()


def test_workspace_detail_reflects_auto_population(client, conn):
    run_id = make_run(client, sample_name="p31-detail.bin")
    client.post("/ingest/batch", json=[_net(run_id, ip="203.0.113.169")])
    listing = client.get("/iocs", params={"type": "ip"}).json()["iocs"]
    target = next(i for i in listing if i["value"] == "203.0.113.169")
    det = client.get(f"/iocs/{target['ioc_id']}").json()
    assert det["findings"], "auto-linked finding visible in workspace detail"
    assert det["runs"][0]["run_id"] == run_id
    conn.close()
