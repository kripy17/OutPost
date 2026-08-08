"""Tests for the shareable-intelligence exports: the MITRE Navigator layer
(coverage matrix) and campaign-level STIX bundles (cluster → MISP/OpenCTI)."""

import datetime

from .conftest import make_run


def _ts(offset: int = 0) -> str:
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


# -- MITRE Navigator layer -----------------------------------------------------


def test_navigator_layer_shape_and_tactic_slugs(client):
    from ..services.risk import RULE_META

    layer = client.get("/coverage/navigator").json()

    assert layer["version"] == "4.3"
    assert layer["domain"] == "enterprise-attack"
    assert layer["name"] == "OutPost detection coverage"

    # Every rule is represented in exactly one merged cell (by technique+tactic).
    cells = {
        (t["techniqueID"], t["tactic"]): t
        for t in layer["techniques"]
    }
    assert len(cells) == len(layer["techniques"])  # one cell per technique+tactic

    # first-seen-process and attack-chain both map to T1204/Execution — the
    # merge must keep both rule ids and take the heaviest weight.
    t1204 = cells[("T1204", "execution")]
    assert "first-seen-process" in t1204["comment"] and "attack-chain" in t1204["comment"]
    assert t1204["score"] == max(RULE_META["first-seen-process"]["weight"], RULE_META["attack-chain"]["weight"])

    for rid, meta in RULE_META.items():
        cell = cells[(meta["technique"], meta["tactic"].lower().replace(" ", "-"))]
        assert rid in cell["comment"]  # every rule exported, none invented
        assert cell["score"] >= meta["weight"]
        # Severity tone matches the webapp chips; malicious wins the merge.
        if meta["severity"] == "malicious":
            assert cell["color"] == "#c4453b"
        else:
            assert cell["color"] in ("#c4453b", "#d9a441")
        # Slug form: lowercase-hyphen — never a display name like "Command and Control".
        assert cell["tactic"] == meta["tactic"].lower().replace(" ", "-")

    # The gradient max is the heaviest rule weight — Navigator scales cells by it.
    assert layer["gradient"]["max"] == max(m["weight"] for m in RULE_META.values())


def test_navigator_layer_technique_ids_are_canonical(client):
    layer = client.get("/coverage/navigator").json()
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert all(i.startswith("T") for i in ids)
    # No duplicate (techniqueID, tactic) pairs — the merge guarantees it.
    pairs = [(t["techniqueID"], t["tactic"]) for t in layer["techniques"]]
    assert len(pairs) == len(set(pairs))


def test_navigator_covers_all_14_enterprise_tactics(client):
    """The verify.sh coverage gate — the layer must cover exactly the 14
    canonical Enterprise tactics. Uncovered tactic: add a rule + RULE_META
    entry. *Unknown* tactic (a typo, or a display name that maps to no
    canonical slug): fix the RULE_META tactic — otherwise it would render as a
    silent "unknown tactic" column on the Coverage page while the gate passes."""
    from ..services.navigator import ENTERPRISE_TACTICS_14

    layer = client.get("/coverage/navigator").json()
    covered = {t["tactic"] for t in layer["techniques"]}
    missing = [t for t in ENTERPRISE_TACTICS_14 if t not in covered]
    assert missing == [], (
        "Uncovered ATT&CK tactics (add a detection rule + RULE_META entry): "
        + ", ".join(missing)
    )
    extra = sorted(covered - set(ENTERPRISE_TACTICS_14))
    assert extra == [], (
        "Unknown ATT&CK tactics (fix the RULE_META tactic label): " + ", ".join(extra)
    )


# -- Campaign STIX bundle ------------------------------------------------------


def test_campaign_stix_bundle_shape(client):
    a = make_run(client, sample_name="stix-camp-a.bin")
    b = make_run(client, sample_name="stix-camp-b.bin")
    for rid in (a, b):
        _ingest(client, rid, [_net(rid, "203.0.113.210", ts=1)])
    _ingest(client, a, [{
        "run_id": a, "platform": "windows", "event_type": "registry_write",
        "timestamp": _ts(2), "pid": 1,
        "registry_key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
    }])

    key = "203.0.113.210"
    bundle = client.get(f"/campaigns/{key}/export?format=stix").json()

    assert bundle["type"] == "bundle" and bundle["spec_version"] == "2.1"
    types = {o["type"] for o in bundle["objects"]}
    assert {"x-outpost-campaign", "indicator", "x-outpost-run", "relationship"} <= types

    # Cluster object carries the key + member count.
    camp = next(o for o in bundle["objects"] if o["type"] == "x-outpost-campaign")
    assert camp["key"] == key and camp["member_count"] == 2

    # The signature IP is an indicator with an ipv4-addr pattern.
    ip_inds = [o for o in bundle["objects"] if o["type"] == "indicator" and "ipv4-addr" in o["pattern"]]
    assert any(key in o["name"] for o in ip_inds)

    # The registry IOC rides along as a windows-registry-key indicator.
    reg_inds = [
        o for o in bundle["objects"]
        if o["type"] == "indicator" and "windows-registry-key" in o["pattern"]
    ]
    assert len(reg_inds) == 1

    # Both members are present as x-outpost-run objects with relationships to
    # the campaign, and every indicator indicates the campaign.
    run_refs = {o["id"] for o in bundle["objects"] if o["type"] == "x-outpost-run"}
    assert len(run_refs) == 2
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    related = [r for r in rels if r["relationship_type"] == "related-to"]
    indicates = [r for r in rels if r["relationship_type"] == "indicates"]
    assert len(related) == 2 and all(r["target_ref"] == camp["id"] for r in related)
    assert len(indicates) == len(ip_inds) + len(reg_inds)

    # Deterministic ids (same seed → same bundle ids) and valid STIX shape.
    again = client.get(f"/campaigns/{key}/export?format=stix").json()
    assert [o["id"] for o in bundle["objects"]] == [o["id"] for o in again["objects"]]
    for o in bundle["objects"]:
        assert "--" in o["id"]


def test_campaign_stix_unknown_key_404(client):
    resp = client.get("/campaigns/nope/export?format=stix")
    assert resp.status_code == 404


def test_campaign_stix_rejects_other_formats(client):
    a = make_run(client, sample_name="fmt-a.bin")
    b = make_run(client, sample_name="fmt-b.bin")
    for rid in (a, b):
        _ingest(client, rid, [_net(rid, "203.0.113.211", ts=1)])
    resp = client.get("/campaigns/203.0.113.211/export?format=json")
    assert resp.status_code == 422
