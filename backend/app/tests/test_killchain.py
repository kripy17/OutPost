"""Roadmap 2.4 — kill-chain sequence correlation (services/killchain.py)."""

from ..services.killchain import chain_label, correlate_chain

# Chronological alert fixtures (rule_id only matters; triggered_at order is
# given by list position since correlate_chain consumes them in order).
DROPPER = {"rule_id": "suspicious-parent-child"}  # Execution
LOLBIN = {"rule_id": "lolbin-abuse"}  # Execution
BEACON = {"rule_id": "beaconing"}  # Command and Control
PERSIST = {"rule_id": "registry-persistence"}  # Persistence
BURST = {"rule_id": "rename-burst"}  # Impact


def test_no_chain_below_two_stages():
    assert correlate_chain([LOLBIN]) == []
    assert correlate_chain([]) == []


def test_full_arc_correlates_execution_c2_persistence_impact():
    links = correlate_chain([DROPPER, LOLBIN, BEACON, PERSIST, BURST])
    stages = [(l["from"], l["to"]) for l in links]
    assert stages == [
        ("Execution", "Command and Control"),
        ("Command and Control", "Persistence"),
        ("Persistence", "Impact"),
    ]
    assert chain_label(links) == "Execution → Command and Control → Persistence → Impact"


def test_partial_chain_reports_only_observed_links():
    links = correlate_chain([BEACON, PERSIST])
    assert [(l["from"], l["to"]) for l in links] == [("Command and Control", "Persistence")]
    assert chain_label(links) == "Command and Control → Persistence"


def test_out_of_order_stages_skip_backward_jump():
    # Persistence fired BEFORE C2 — the greedy walk must not report a link.
    links = correlate_chain([PERSIST, BEACON])
    assert links == []


def test_duplicate_stages_do_not_duplicate_links():
    links = correlate_chain([LOLBIN, LOLBIN, BEACON, BEACON])
    assert len(links) == 1
    assert links[0] == {"from": "Execution", "to": "Command and Control", "count": 1}


def test_unknown_rule_ids_ignored():
    links = correlate_chain([{"rule_id": "future-rule-x"}, BEACON, PERSIST])
    assert [(l["from"], l["to"]) for l in links] == [("Command and Control", "Persistence")]
