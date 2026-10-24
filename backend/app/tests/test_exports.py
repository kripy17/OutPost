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



