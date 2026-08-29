"""Kill-chain sequence correlation (roadmap 2.4).

The detection engine already tags every alert with a kill-chain stage (see
detection._KILL_CHAIN_STAGE). This service goes one step further: it looks
for *ordered sequences* of stages — the classic malware arc
dropper → execution → C2 → persistence → impact — and reports which links of
that chain a run actually exhibited, in time order.

`correlate_chain(alerts)` returns the observed chain links, e.g.:

    [
        {"from": "Execution", "to": "Command and Control", "count": 1},
        {"from": "Command and Control", "to": "Persistence", "count": 1},
    ]

Chains are built greedily along the canonical stage order (below); a run that
only touched, say, Persistence and Impact reports the single jump between
them. Runs touching fewer than 2 mapped stages report no chain. The result
feeds the run-detail page ("chain diagram") and campaign clustering, which
now prefers members with correlated chains.
"""


# Canonical attack progression — the order analysts read a chain in. Stages
# that don't map to a rule (e.g. initial-access-only rule sets) are absent;
# the correlation simply skips them. Reconnaissance / Resource Development
# are first: detection's stage map emits them (recon sweeps, infra staging),
# and leaving them unmapped made their index -1 sort them ahead of time.
_CANONICAL_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Defense Evasion",
    "Command and Control",
    "Persistence",
    "Privilege Escalation",
    "Credential Access",
    "Discovery",
    "Exfiltration",
    "Impact",
]

# rule_id → stage (single source, imported from detection to stay in lockstep).
from ..services.detection import _KILL_CHAIN_STAGE


def _stage_of(rule_id: str) -> str | None:
    return _KILL_CHAIN_STAGE.get(rule_id)


def _stage_index(stage: str) -> int:
    return _CANONICAL_ORDER.index(stage) if stage in _CANONICAL_ORDER else -1


def correlate_chain(alerts: list[dict]) -> list[dict]:
    """Return observed stage-to-stage links for a run's alerts, time-ordered.

    Alerts must be chronological (oldest first — the detail route supplies
    them ordered by triggered_at). Each fired alert contributes its stage; the
    greedy walk advances through the canonical order and records a link each
    time the run reaches a *later* stage after an earlier one.

    Returns [] when fewer than 2 distinct mapped stages fired.
    """
    # First alert per stage, in time order (a stage may fire many times).
    seen: dict[str, int] = {}
    for alert in alerts:
        stage = _stage_of(alert.get("rule_id", ""))
        if stage is None or stage in seen:
            continue
        seen[stage] = len(seen)

    if len(seen) < 2:
        return []

    # Sort stages by canonical position; walk adjacent pairs, recording a link
    # only when the later stage genuinely came after the earlier one.
    ordered = sorted(seen, key=_stage_index)
    links: list[dict] = []
    for a, b in zip(ordered, ordered[1:]):
        if seen[b] > seen[a]:
            links.append({"from": a, "to": b, "count": 1})
    return links


def chain_label(links: list[dict]) -> str | None:
    """Human label for a chain, e.g. \"dropper → C2 → persistence\".

    Returns None for no chain. Used by the webapp chain card and campaign
    summaries so analysts get the arc at a glance.
    """
    if not links:
        return None
    stages = [links[0]["from"]] + [link["to"] for link in links]
    return " → ".join(stages)
