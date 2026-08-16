"""Tests for the alert-triage lifecycle (analyst workflow): per-alert status
(open → acknowledged → resolved with a comment), per-run IOC allowlists
(future suppression + retroactive ack), and per-rule suppressions (global and
per-run scope). Suppressions are global state on the shared test DB, so every
test cleans up after itself in a finally block.
"""

from datetime import datetime, timedelta, timezone

from .conftest import make_run


def _ts(offset_seconds: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)).isoformat()


def _conn(run_id: str, ip: str, pid: int = 1) -> dict:
    """A network connection to an uncommon C2 port — fires unusual-port."""
    return {
        "run_id": run_id, "platform": "windows", "event_type": "network_connection",
        "timestamp": _ts(5), "pid": pid, "dest_ip": ip, "dest_port": 4444, "protocol": "tcp",
    }


def _lolbin(run_id: str, pid: int = 1000) -> dict:
    """powershell -enc — fires lolbin-abuse (malicious)."""
    return {
        "run_id": run_id, "platform": "windows", "event_type": "process_create",
        "timestamp": _ts(5), "pid": pid, "ppid": 1, "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc SQBFAFgA",
    }


# -- Alert status lifecycle ----------------------------------------------------


def test_alert_status_patch_roundtrip(client):
    run_id = make_run(client, sample_name="triage-status.bin")
    client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.77")])
    alerts = client.get(f"/runs/{run_id}/alerts").json()
    assert alerts, "unusual-port should have fired"
    aid = alerts[0]["id"]
    assert alerts[0]["status"] == "open"
    assert alerts[0]["status_comment"] is None

    resp = client.patch(f"/alerts/{aid}", json={"status": "acknowledged", "comment": "  FP — our scanner  "})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "acknowledged"
    assert body["status_comment"] == "FP — our scanner"
    assert body["status_at"]

    # Reflected on the run's alert list, and resolve works from there.
    got = client.get(f"/runs/{run_id}/alerts").json()
    assert got[0]["status"] == "acknowledged"
    assert client.patch(f"/alerts/{aid}", json={"status": "resolved"}).json()["status"] == "resolved"

    # Validation: bad status 422, unknown alert 404.
    assert client.patch(f"/alerts/{aid}", json={"status": "banana"}).status_code == 422
    assert client.patch("/alerts/999999", json={"status": "resolved"}).status_code == 404


def test_alert_status_comment_semantics(client):
    """The transition-comment contract both clients mirror (webapp
    triageLifecycle, CLI test_triage_lifecycle), pinned at its source: a
    non-empty comment is recorded whitespace-trimmed, while an empty /
    whitespace-only / omitted comment stores NULL — so a bare transition
    CLEARS a prior comment rather than accumulating it on the alert."""
    run_id = make_run(client, sample_name="comment-contract.bin")
    client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.77")])
    aid = client.get(f"/runs/{run_id}/alerts").json()[0]["id"]
    assert client.get(f"/runs/{run_id}/alerts").json()[0]["status_comment"] is None

    # Non-empty (padded) comment → recorded, trimmed.
    resp = client.patch(f"/alerts/{aid}", json={"status": "acknowledged", "comment": "  seen, will resolve  "}).json()
    assert resp["status"] == "acknowledged"
    assert resp["status_comment"] == "seen, will resolve"

    # A bare resolve (no comment key) → NULL, clearing the prior comment —
    # the exact case the webapp + CLI lifecycle tests pin.
    resp = client.patch(f"/alerts/{aid}", json={"status": "resolved"}).json()
    assert resp["status"] == "resolved"
    assert resp["status_comment"] is None

    # Empty string → NULL.
    resp = client.patch(f"/alerts/{aid}", json={"status": "open", "comment": ""}).json()
    assert resp["status"] == "open"
    assert resp["status_comment"] is None

    # Whitespace-only → NULL (stripped first).
    resp = client.patch(f"/alerts/{aid}", json={"status": "acknowledged", "comment": "   "}).json()
    assert resp["status_comment"] is None

    # And a fresh non-empty comment after the clears is recorded again.
    resp = client.patch(f"/alerts/{aid}", json={"status": "resolved", "comment": "FP, our scanner"}).json()
    assert resp["status_comment"] == "FP, our scanner"


# -- Bulk triage (select many alerts → one transition) ------------------------


def test_bulk_status_acks_multiple_alerts(client):
    run_id = make_run(client, sample_name="bulk-ack.bin")
    client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.77"), _conn(run_id, "198.51.100.9", pid=2), _lolbin(run_id)])
    alerts = client.get(f"/runs/{run_id}/alerts").json()
    assert len(alerts) >= 2, "multiple rules should have fired"
    ids = [a["id"] for a in alerts if a["status"] == "open"]
    assert len(ids) >= 2

    resp = client.post("/alerts/bulk", json={"ids": ids, "status": "acknowledged", "comment": "bulk sweep"})
    assert resp.status_code == 200
    assert resp.json()["updated"] == len(ids)

    got = client.get(f"/runs/{run_id}/alerts").json()
    assert all(a["status"] == "acknowledged" and a["status_comment"] == "bulk sweep" for a in got)


def test_bulk_status_resolve_and_validation(client):
    run_id = make_run(client, sample_name="bulk-resolve.bin")
    client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.77"), _lolbin(run_id)])
    ids = [a["id"] for a in client.get(f"/runs/{run_id}/alerts").json()]

    assert client.post("/alerts/bulk", json={"ids": ids, "status": "resolved"}).json()["updated"] == len(ids)
    # Same comment contract as PATCH: an omitted comment stores NULL.
    assert all(a["status"] == "resolved" and a["status_comment"] is None for a in client.get(f"/runs/{run_id}/alerts").json())

    # Validation: bad status 422, empty ids → 0 without touching the DB.
    assert client.post("/alerts/bulk", json={"ids": ids, "status": "banana"}).status_code == 422
    assert client.post("/alerts/bulk", json={"ids": [], "status": "resolved"}).json() == {"updated": 0}


def test_alerts_csv_export(client):
    run_id = make_run(client, sample_name="export-alerts.bin")
    client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.77"), _lolbin(run_id)])
    resp = client.get("/alerts/export")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    body = resp.text
    assert "rule_id" in body and "lolbin-abuse" in body


def test_events_csv_export(client):
    run_id = make_run(client, sample_name="export-events.bin")
    client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.77"), _lolbin(run_id)])
    resp = client.get("/events/export")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    body = resp.text
    assert "event_type" in body and "network_connection" in body
    # Filters carry through: q narrows the export.
    resp2 = client.get("/events/export", params={"q": "203.0.113.77"})
    assert "203.0.113.77" in resp2.text
    resp3 = client.get("/events/export", params={"q": "no-such-ip-anywhere"})
    assert "network_connection" not in resp3.text


# -- Per-run IOC allowlists ----------------------------------------------------


def test_allowlist_blocks_future_alerts(client):
    run_id = make_run(client, sample_name="allow-block.bin")
    resp = client.post(f"/runs/{run_id}/allowlist", json={"kind": "ip", "value": "203.0.113.77", "note": "scanner"})
    assert resp.status_code == 201
    assert resp.json()["acked"] == 0  # nothing open yet

    # The allowlisted IP never fires unusual-port…
    client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.77")])
    assert client.get(f"/runs/{run_id}/alerts").json() == []

    # …but a different IP on the same port still does.
    client.post("/ingest/batch", json=[_conn(run_id, "198.51.100.9", pid=2)])
    alerts = client.get(f"/runs/{run_id}/alerts").json()
    assert any(a["rule_id"] == "unusual-port" and a["related_ip"] == "198.51.100.9" for a in alerts)


def test_allowlist_acks_existing_matching_alerts(client):
    run_id = make_run(client, sample_name="allow-ack.bin")
    client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.77")])
    client.post("/ingest/batch", json=[_conn(run_id, "198.51.100.9", pid=2)])

    resp = client.post(f"/runs/{run_id}/allowlist", json={"kind": "ip", "value": "203.0.113.77"})
    assert resp.status_code == 201
    assert resp.json()["acked"] == 1

    alerts = client.get(f"/runs/{run_id}/alerts").json()
    by_ip = {a["related_ip"]: a for a in alerts}
    assert by_ip["203.0.113.77"]["status"] == "acknowledged"
    assert "Allowlisted" in by_ip["203.0.113.77"]["status_comment"]
    # Unrelated alert stays open.
    assert by_ip["198.51.100.9"]["status"] == "open"


def test_allowlist_file_kind_matches_details(client):
    run_id = make_run(client, sample_name="allow-file.bin", platform="linux")
    client.post(f"/runs/{run_id}/allowlist", json={"kind": "file", "value": ".bashrc", "note": "known dev box"})
    client.post(
        "/ingest/batch",
        json=[{
            "run_id": run_id, "platform": "linux", "event_type": "file_write",
            "timestamp": _ts(5), "pid": 1, "file_path": "/home/u/.bashrc",
        }],
    )
    # autostart-persistence would have fired; the file allowlist blocks it.
    assert client.get(f"/runs/{run_id}/alerts").json() == []


def test_allowlist_hash_kind_matches_run_sample(client, conn):
    """A hash-kind entry matches the run's uploaded-sample SHA-256 — alerts
    themselves never carry a hash, so this is the only hash in scope."""
    sha = "ab" * 32  # 64 hex chars
    conn.execute(
        "INSERT INTO samples (sample_id, original_name, sha256, detected_platform, size, created_at) "
        "VALUES ('s-1', 'hash-demo.bin', ?, 'windows', 4, '2026-08-01T00:00:00Z')",
        (sha,),
    )
    conn.commit()  # release the write lock so the client can write runs
    run_id = make_run(client, sample_name="hash-demo.bin")

    # Mismatching hash → the rule still fires.
    client.post(f"/runs/{run_id}/allowlist", json={"kind": "hash", "value": "cd" * 32})
    client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.77")])
    alerts = client.get(f"/runs/{run_id}/alerts").json()
    assert any(a["rule_id"] == "unusual-port" and a["status"] == "open" for a in alerts)

    # The run's actual sample hash → matching alerts stop firing.
    resp = client.post(f"/runs/{run_id}/allowlist", json={"kind": "hash", "value": sha})
    assert resp.status_code == 201
    assert resp.json()["acked"] == 1  # the open unusual-port alert gets acked
    client.post("/ingest/batch", json=[_conn(run_id, "198.51.100.9", pid=2)])
    alerts = client.get(f"/runs/{run_id}/alerts").json()
    assert all(a["status"] == "acknowledged" for a in alerts)
    assert not any(a["related_ip"] == "198.51.100.9" for a in alerts)  # blocked, never inserted


def test_allowlist_list_and_delete(client):
    run_id = make_run(client, sample_name="allow-crud.bin")
    entry = client.post(f"/runs/{run_id}/allowlist", json={"kind": "ip", "value": "1.2.3.4", "note": "x"}).json()
    assert [x["value"] for x in client.get(f"/runs/{run_id}/allowlist").json()] == ["1.2.3.4"]

    assert client.delete(f"/runs/{run_id}/allowlist/{entry['id']}").status_code == 204
    assert client.get(f"/runs/{run_id}/allowlist").json() == []
    # Unknown run / unknown entry 404.
    assert client.get("/runs/nope/allowlist").status_code == 404
    assert client.delete(f"/runs/{run_id}/allowlist/999").status_code == 404


# -- Rule suppressions ---------------------------------------------------------


def test_suppression_global_stops_rule(client):
    created = client.post("/rules/suppressions", json={"rule_id": "lolbin-abuse", "reason": "noisy in demo"})
    assert created.status_code == 201
    sid = created.json()["id"]
    try:
        run_id = make_run(client, sample_name="supp-global.bin")
        client.post("/ingest/batch", json=[_lolbin(run_id)])
        assert client.get(f"/runs/{run_id}/alerts").json() == []
    finally:
        assert client.delete(f"/rules/suppressions/{sid}").status_code == 204
    # Removal restores the rule — a fresh run fires again.
    run2 = make_run(client, sample_name="supp-global-2.bin")
    client.post("/ingest/batch", json=[_lolbin(run2)])
    assert any(a["rule_id"] == "lolbin-abuse" for a in client.get(f"/runs/{run2}/alerts").json())


def test_suppression_scoped_to_run(client):
    run_id = make_run(client, sample_name="supp-a.bin")
    other = make_run(client, sample_name="supp-b.bin")
    resp = client.post("/rules/suppressions", json={"rule_id": "lolbin-abuse", "run_id": run_id, "reason": "campaign FP"})
    sid = resp.json()["id"]
    try:
        client.post("/ingest/batch", json=[_lolbin(run_id)])
        assert client.get(f"/runs/{run_id}/alerts").json() == []
        # The same rule still fires in an unsuppressed run.
        client.post("/ingest/batch", json=[_lolbin(other)])
        assert any(a["rule_id"] == "lolbin-abuse" for a in client.get(f"/runs/{other}/alerts").json())
    finally:
        client.delete(f"/rules/suppressions/{sid}")


def test_suppression_scoped_to_sample_value(client):
    """Value scope = sample name (the queue sweep's suppress-for-this-sample
    action): a suppression for `lolbin-abuse → supp-sample.bin` silences that
    sample's future runs but leaves other samples firing — the exact shape
    that keeps detonate-demo.sh from regenerating 48 open alerts per C2."""
    run_id = make_run(client, sample_name="supp-sample.bin")
    other = make_run(client, sample_name="supp-other.bin")
    resp = client.post(
        "/rules/suppressions",
        json={"rule_id": "lolbin-abuse", "value": "supp-sample.bin", "reason": "demo sample noise"},
    )
    assert resp.status_code == 201
    assert resp.json()["value"] == "supp-sample.bin"
    sid = resp.json()["id"]
    try:
        client.post("/ingest/batch", json=[_lolbin(run_id)])
        client.post("/ingest/batch", json=[_lolbin(other)])
        assert client.get(f"/runs/{run_id}/alerts").json() == []
        assert any(a["rule_id"] == "lolbin-abuse" for a in client.get(f"/runs/{other}/alerts").json())
    finally:
        client.delete(f"/rules/suppressions/{sid}")


def test_suppression_scoped_to_ip_value(client):
    """Value scope = related IP (the queue sweep's suppress-for-this-C2
    action): that destination's alerts stop firing while other destinations
    of the same rule still surface."""
    run_id = make_run(client, sample_name="supp-ip.bin")
    resp = client.post(
        "/rules/suppressions",
        json={"rule_id": "unusual-port", "value": "203.0.113.77", "reason": "known C2 under watch"},
    )
    sid = resp.json()["id"]
    try:
        client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.77"), _conn(run_id, "198.51.100.9", pid=2)])
        alerts = client.get(f"/runs/{run_id}/alerts").json()
        assert not any(a["rule_id"] == "unusual-port" and a["related_ip"] == "203.0.113.77" for a in alerts)
        assert any(a["rule_id"] == "unusual-port" and a["related_ip"] == "198.51.100.9" for a in alerts)
    finally:
        client.delete(f"/rules/suppressions/{sid}")


# -- Triage queue (the analyst work list) -------------------------------------


def test_queue_lists_open_alerts_with_run_context(client):
    run_id = make_run(client, sample_name="queue-a.bin", platform="linux")
    client.post(
        "/ingest/batch",
        json=[
            {**_conn(run_id, "203.0.113.77"), "host_id": "queue-host"},
            _lolbin(run_id),
        ],
    )
    # Scope by the run's sample name — the shared seeded DB holds other
    # alerts, and the default aging sort + limit would cut off the newest.
    data = client.get("/alerts/queue", params={"status": "all", "q": "queue-a.bin"}).json()
    mine = data["alerts"]
    assert len(mine) == 2
    for a in mine:
        assert a["sample_name"] == "queue-a.bin"
        assert a["status"] == "open"
    # Run context: the run's hosts ride along.
    unusual = next(a for a in mine if a["rule_id"] == "unusual-port")
    assert "queue-host" in unusual["host_ids"]
    assert data["open"] >= 2


def test_queue_filters_by_status_rule_host_and_text(client):
    run_id = make_run(client, sample_name="queue-b.bin", platform="linux")
    client.post(
        "/ingest/batch",
        json=[
            {**_conn(run_id, "203.0.113.77"), "host_id": "filter-host"},
            _lolbin(run_id),
        ],
    )
    # Status filter isolates the malicious lolbin.
    mal = client.get("/alerts/queue", params={"status": "all", "severity": "malicious"}).json()
    assert all(a["severity"] == "malicious" for a in mal["alerts"])
    # Rule filter.
    by_rule = client.get("/alerts/queue", params={"status": "all", "rule_id": "unusual-port"}).json()
    assert all(a["rule_id"] == "unusual-port" for a in by_rule["alerts"])
    # Host filter.
    by_host = client.get("/alerts/queue", params={"status": "all", "host_id": "filter-host"}).json()
    assert all("filter-host" in a["host_ids"] for a in by_host["alerts"])
    # Free text matches sample / rule / details.
    by_q = client.get("/alerts/queue", params={"status": "all", "q": "queue-b.bin"}).json()
    assert all(a["run_id"] == run_id for a in by_q["alerts"])
    assert client.get("/alerts/queue", params={"status": "all", "q": "zzz-no-match"}).json()["total"] == 0


def test_queue_tab_badges_stay_live_under_status_filter(client):
    """The Open view's tab badges (Acknowledged / Resolved counts) are live
    totals across the active non-status filters — a status-filtered query must
    NOT zero out the other buckets (regression: the counts query inherited the
    status WHERE clause, so the Open view always showed Acknowledged 0)."""
    run_id = make_run(client, sample_name="queue-tabs.bin")
    client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.88"), _lolbin(run_id)])
    alerts = client.get(f"/runs/{run_id}/alerts").json()
    assert len(alerts) == 2
    # Ack one, resolve the other — a mixed-status run.
    client.patch(f"/alerts/{alerts[0]['id']}", json={"status": "acknowledged"})
    client.patch(f"/alerts/{alerts[1]['id']}", json={"status": "resolved"})

    # Viewing the OPEN tab must still report the acknowledged + resolved
    # totals (1 each) while pagination stays scoped to open (total 0 here).
    q = client.get("/alerts/queue", params={"status": "open", "q": "queue-tabs.bin"}).json()
    assert q["acknowledged"] >= 1
    assert q["resolved"] >= 1
    assert q["total"] == 0  # no open alerts in this run — pagination scoped
    # And the ALL view reports both buckets too.
    allv = client.get("/alerts/queue", params={"status": "all", "q": "queue-tabs.bin"}).json()
    assert allv["open"] == 0 and allv["acknowledged"] >= 1 and allv["resolved"] >= 1
    assert allv["total"] == allv["open"] + allv["acknowledged"] + allv["resolved"]


def test_queue_provenance_filter_splits_real_from_synthetic(client):
    """provenance=real excludes seed/webapp-demo runs; provenance=synthetic
    isolates them — the queue-side mirror of the History archive's default
    hide-synthetic split, so demo noise can be acked in bulk without
    hand-picking sample names."""
    real = make_run(client, sample_name="prov-real.bin", source="cli")
    synth = make_run(client, sample_name="prov-synth.bin", source="webapp-demo")
    client.post("/ingest/batch", json=[_conn(real, "203.0.113.79")])
    client.post("/ingest/batch", json=[_conn(synth, "203.0.113.80")])

    real_only = client.get("/alerts/queue", params={"status": "all", "provenance": "real", "q": "prov-"}).json()
    assert {a["run_id"] for a in real_only["alerts"]} == {real}
    synth_only = client.get("/alerts/queue", params={"status": "all", "provenance": "synthetic", "q": "prov-"}).json()
    assert {a["run_id"] for a in synth_only["alerts"]} == {synth}
    # No filter → both (the default triage view is unfiltered).
    both = client.get("/alerts/queue", params={"status": "all", "q": "prov-"}).json()
    assert {a["run_id"] for a in both["alerts"]} == {real, synth}
    assert client.get("/alerts/queue", params={"provenance": "banana"}).status_code == 422


def test_queue_aging_sort_surfaces_oldest_open_first(client):
    """sort=aging (the default) puts the longest-open alert first — the SLA
    pressure the queue exists to surface."""
    a = make_run(client, sample_name="sla-old.bin")
    b = make_run(client, sample_name="sla-new.bin")
    old_ts = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
    new_ts = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
    client.post("/ingest/batch", json=[{**_conn(a, "203.0.113.90"), "timestamp": old_ts}])
    client.post("/ingest/batch", json=[{**_conn(b, "203.0.113.91"), "timestamp": new_ts}])

    # Scope to this test's own runs — the shared seeded DB holds demo alerts
    # with older timestamps that would otherwise sort first.
    q = client.get("/alerts/queue", params={"status": "all", "rule_id": "unusual-port", "q": "sla-"}).json()
    assert len(q["alerts"]) == 2
    assert q["alerts"][0]["run_id"] == a  # oldest open first
    newest = client.get("/alerts/queue", params={"status": "all", "rule_id": "unusual-port", "q": "sla-", "sort": "newest"}).json()
    assert newest["alerts"][0]["run_id"] == b
    assert client.get("/alerts/queue", params={"sort": "banana"}).status_code == 422


def test_assign_claims_alert_and_audits(client):
    run_id = make_run(client, sample_name="queue-assign.bin")
    client.post("/ingest/batch", json=[_conn(run_id, "203.0.113.77")])
    aid = client.get(f"/runs/{run_id}/alerts").json()[0]["id"]

    resp = client.post(f"/alerts/{aid}/assign", json={"assignee": "sofi"})
    assert resp.status_code == 200
    assert resp.json()["assignee"] == "sofi"

    by_assignee = client.get("/alerts/queue", params={"status": "all", "assignee": "sofi"}).json()
    assert any(a["id"] == aid for a in by_assignee["alerts"])
    # Unassign clears it; unknown alert 404.
    assert client.post(f"/alerts/{aid}/assign", json={"assignee": ""}).json()["assignee"] is None
    assert client.post("/alerts/999999/assign", json={"assignee": "x"}).status_code == 404


def test_suppression_validation_and_dedupe(client):
    assert client.post("/rules/suppressions", json={"rule_id": "not-a-rule"}).status_code == 422
    assert client.post("/rules/suppressions", json={"rule_id": "lolbin-abuse", "run_id": "   "}).status_code == 422

    # Same (rule, scope) twice → one active row (the later replaces the earlier).
    a = client.post("/rules/suppressions", json={"rule_id": "beaconing"}).json()
    b = client.post("/rules/suppressions", json={"rule_id": "beaconing", "reason": "replaced"}).json()
    # A value-scoped entry is a DIFFERENT scope — it coexists with the global one.
    c = client.post("/rules/suppressions", json={"rule_id": "beaconing", "value": "detonate-demo.sh"}).json()
    assert c["value"] == "detonate-demo.sh"
    try:
        rows = client.get("/rules/suppressions").json()
        mine = [r for r in rows if r["rule_id"] == "beaconing" and r["run_id"] is None]
        assert len(mine) == 2, "the value scope is a distinct suppression row"
        global_row = next(r for r in mine if not r.get("value"))
        assert global_row["reason"] == "replaced"
        assert any(r.get("value") == "detonate-demo.sh" for r in mine)
    finally:
        client.delete(f"/rules/suppressions/{a['id']}")
        client.delete(f"/rules/suppressions/{b['id']}")
        client.delete(f"/rules/suppressions/{c['id']}")
    assert client.delete("/rules/suppressions/999").status_code == 404
