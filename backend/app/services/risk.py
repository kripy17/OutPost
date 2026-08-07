"""Run risk scoring + MITRE ATT&CK metadata (roadmap 1.3).

Every detection rule carries an ATT&CK technique/tactic (analyst context) and
a weight. A run's risk score is the sum of the weights of the *distinct* rules
that fired, capped at 100 — distinct, so five beacon alerts don't stack into a
higher score than one beacon plus one persistence write.

`RULE_META` is the single source of truth; the `GET /rules/meta` endpoint and
the webapp's ATT&CK chips both read it.
"""

from typing import TypedDict


class RuleMeta(TypedDict):
    technique: str
    tactic: str
    weight: int


RULE_META: dict[str, RuleMeta] = {
    "masquerading": {
        "technique": "T1036.005",
        "tactic": "Defense Evasion",
        "weight": 20,
    },
    "suspicious-parent-child": {
        "technique": "T1204.002",
        "tactic": "Execution",
        "weight": 18,
    },
    "lolbin-abuse": {
        "technique": "T1059",
        "tactic": "Execution",
        "weight": 14,
    },
    "beaconing": {
        "technique": "T1071.001",
        "tactic": "Command and Control",
        "weight": 15,
    },
    "registry-persistence": {
        "technique": "T1547.001",
        "tactic": "Persistence",
        "weight": 16,
    },
    "autostart-persistence": {
        "technique": "T1547",
        "tactic": "Persistence",
        "weight": 16,
    },
    "rename-burst": {
        "technique": "T1486",
        "tactic": "Impact",
        "weight": 22,
    },
    "first-seen-process": {
        "technique": "T1204",
        "tactic": "Execution",
        "weight": 6,
    },
    "unusual-port": {
        "technique": "T1571",
        "tactic": "Command and Control",
        "weight": 10,
    },
    "attack-chain": {
        "technique": "T1204",
        "tactic": "Execution",
        "weight": 30,
    },
}


def compute_risk_score(rule_ids: list[str]) -> int:
    """Sum weights of distinct fired rules, capped at 100 (roadmap 1.3).

    Unknown rule_ids (e.g. future/legacy) contribute 0 so the score never
    crashes on data this build doesn't know about.
    """
    total = sum(RULE_META.get(rid, {}).get("weight", 0) for rid in set(rule_ids))
    return min(100, total)
