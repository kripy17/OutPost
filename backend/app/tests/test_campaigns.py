"""Tests for the webapp "Campaigns" view (runs clustered by shared IP)."""

import datetime

from .conftest import make_run


def _ts(offset: int = 0) -> str:
    # The ingest route serializes via pydantic model_dump(mode="json"), which
    # emits UTC as the "Z" form — match that contract in both payload and
    # assertion so span_start/span_end compare equal.
    return (
        datetime.datetime(2026, 8, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        + datetime.timedelta(seconds=offset)
    ).isoformat().replace("+00:00", "Z")


def _net(run_id: str, ip: str, ts: int = 0) -> dict:
    return {
        "run_id": run_id, "platform": "windows", "event_type": "network_connection",
        "timestamp": _ts(ts), "pid": 1, "dest_ip": ip, "dest_port": 4444, "protocol": "TCP",
    }


def _ingest(client, run_id: str, events: list[dict]) -> None:
    resp = client.post("/ingest/batch", json=events)
    assert resp.status_code == 202, resp.text


def test_campaign_groups_runs_sharing_ip(client):
    a = make_run(client, sample_name="campa-a.bin")
    b = make_run(client, sample_name="campa-b.bin")
    for rid in (a, b):
        _ingest(client, rid, [_net(rid, "203.0.113.201", ts=1)])

    solo = make_run(client, sample_name="campa-solo.bin")
    _ingest(client, solo, [_net(solo, "203.0.113.202", ts=1)])  # one run — not a campaign

    camps = client.get("/campaigns").json()
    hit = [c for c in camps if c["key"] == "203.0.113.201"]
    assert len(hit) == 1
    assert {r["run_id"] for r in hit[0]["runs"]} == {a, b}
    # A single-run IP never anchors a campaign.
    assert all(c["key"] != "203.0.113.202" for c in camps)


def test_campaigns_hide_synthetic_members_by_default(client):
    """Archive parity on the campaigns view: seed / webapp-demo members are
    excluded by default, a campaign reduced below two real members is dropped,
    and the timeline is recomputed from the real members only.
    include_synthetic=true restores the full cluster."""
    a = make_run(client, sample_name="campmix-real-a.bin", source="cli")
    b = make_run(client, sample_name="campmix-real-b.bin", source="cli")
    s = make_run(client, sample_name="campmix-seed.bin", source="webapp-demo")
    for rid in (a, b, s):
        _ingest(client, rid, [_net(rid, "203.0.113.230", ts=1)])

    # A seed-only pair: both members synthetic — dropped entirely by default.
    s1 = make_run(client, sample_name="camponly-s1.bin", source="seed")
    s2 = make_run(client, sample_name="camponly-s2.bin", source="seed")
    for rid in (s1, s2):
        _ingest(client, rid, [_net(rid, "203.0.113.231", ts=1)])

    bare = client.get("/campaigns").json()
    mix = [c for c in bare if c["key"] == "203.0.113.230"]
    assert len(mix) == 1
    assert {r["run_id"] for r in mix[0]["runs"]} == {a, b}
    # Timeline/evidence recomputed from the real members only.
    assert all(t["sample_name"] != "campmix-seed.bin" for t in mix[0]["timeline"])
    # The seed-only cluster is not a campaign once synthetic members are out.
    assert all(c["key"] != "203.0.113.231" for c in bare)

    full = client.get("/campaigns", params={"include_synthetic": "true"}).json()
    mix_full = [c for c in full if c["key"] == "203.0.113.230"][0]
    assert {r["run_id"] for r in mix_full["runs"]} == {a, b, s}
    assert any(c["key"] == "203.0.113.231" for c in full)


def test_clean_shared_ip_not_a_campaign(client, conn):
    from ..models.event import upsert_cache

    upsert_cache(conn, "198.51.100.201", 0, 0, "clean")
    conn.commit()

    a = make_run(client, sample_name="clean-a.bin")
    b = make_run(client, sample_name="clean-b.bin")
    for rid in (a, b):
        _ingest(client, rid, [_net(rid, "198.51.100.201", ts=1)])

    camps = client.get("/campaigns").json()
    assert all(c["key"] != "198.51.100.201" for c in camps)


def test_campaign_reflects_watchlist(client):
    client.post("/watchlist", json={"value": "203.0.113.203", "label": "tracked C2"})

    a = make_run(client, sample_name="wl-a.bin")
    b = make_run(client, sample_name="wl-b.bin")
    for rid in (a, b):
        _ingest(client, rid, [_net(rid, "203.0.113.203", ts=1)])

    camps = client.get("/campaigns").json()
    hit = [c for c in camps if c["key"] == "203.0.113.203"]
    assert len(hit) == 1
    assert hit[0]["watchlist"] is True
    assert hit[0]["watchlist_label"] == "tracked C2"


def test_json_export_references_campaigns(client):
    """Exported reports link back to the campaign(s) their run belongs to."""
    a = make_run(client, sample_name="exp-a.bin")
    b = make_run(client, sample_name="exp-b.bin")
    for rid in (a, b):
        _ingest(client, rid, [_net(rid, "203.0.113.205", ts=1)])

    report = client.get(f"/runs/{a}/export").json()
    assert "campaigns" in report
    keys = [c["key"] for c in report["campaigns"]]
    assert "203.0.113.205" in keys

    # A run that shares no IP exports an empty list.
    solo = make_run(client, sample_name="exp-solo.bin")
    _ingest(client, solo, [_net(solo, "203.0.113.206", ts=1)])
    assert client.get(f"/runs/{solo}/export").json()["campaigns"] == []


def test_campaign_timeline_and_ioc_evidence(client):
    a = make_run(client, sample_name="ev-a.bin")
    b = make_run(client, sample_name="ev-b.bin")
    _ingest(client, a, [
        _net(a, "203.0.113.204", ts=1),
        {"run_id": a, "platform": "windows", "event_type": "registry_write",
         "timestamp": _ts(2), "pid": 1,
         "registry_key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Bad"},
    ])
    _ingest(client, b, [_net(b, "203.0.113.204", ts=5)])

    camps = client.get("/campaigns").json()
    hit = [c for c in camps if c["key"] == "203.0.113.204"][0]

    assert len(hit["timeline"]) == 3  # combined, chronological
    assert all("sample_name" in t for t in hit["timeline"])
    assert hit["span_start"] == _ts(1) and hit["span_end"] == _ts(5)

    keys = {r["value"] for r in hit["iocs"]["registry_keys"]}
    assert any("CurrentVersion\\Run" in k for k in keys)
