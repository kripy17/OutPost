"""Run risk scoring + MITRE ATT&CK metadata (roadmap 1.3).

Every detection rule carries an ATT&CK technique/tactic (analyst context) and
a weight. A run's risk score is the sum of the weights of the *distinct* rules
that fired, capped at 100 — distinct, so five beacon alerts don't stack into a
higher score than one beacon plus one persistence write.

`RULE_META` is the single source of truth; the `GET /rules/meta` endpoint and
the webapp's ATT&CK chips both read it.

NOTE: `severity` here must stay in sync with the severity passed to
`_make_alert` in services/detection.py — the coverage matrix tones its chips
by this field, so a drift would miscolor a rule (e.g. lolbin-abuse is
malicious at weight 14; suid-set is suspicious at weight 18).
"""

from typing import TypedDict


class RuleMeta(TypedDict):
    technique: str
    tactic: str
    weight: int
    severity: str  # the alert severity the rule actually fires with


RULE_META: dict[str, RuleMeta] = {
    "network-scan": {
        "technique": "T1595",
        "tactic": "Reconnaissance",
        "weight": 8,
        "severity": "suspicious",
    },
    "toolchain-build": {
        "technique": "T1587.001",
        "tactic": "Resource Development",
        "weight": 8,
        "severity": "suspicious",
    },
    "document-dropper": {
        "technique": "T1566.002",
        "tactic": "Initial Access",
        "weight": 18,
        "severity": "malicious",
    },
    "lateral-rdp-smb": {
        "technique": "T1021.001",
        "tactic": "Lateral Movement",
        "weight": 10,
        "severity": "suspicious",
    },
    "screen-capture": {
        "technique": "T1113",
        "tactic": "Collection",
        "weight": 12,
        "severity": "suspicious",
    },
    "masquerading": {
        "technique": "T1036.005",
        "tactic": "Defense Evasion",
        "weight": 20,
        "severity": "malicious",
    },
    "suspicious-parent-child": {
        "technique": "T1204.002",
        "tactic": "Execution",
        "weight": 18,
        "severity": "malicious",
    },
    "lolbin-abuse": {
        "technique": "T1059",
        "tactic": "Execution",
        "weight": 14,
        "severity": "malicious",
    },
    "beaconing": {
        "technique": "T1071.001",
        "tactic": "Command and Control",
        "weight": 15,
        "severity": "suspicious",
    },
    "registry-persistence": {
        "technique": "T1547.001",
        "tactic": "Persistence",
        "weight": 16,
        "severity": "suspicious",
    },
    "autostart-persistence": {
        "technique": "T1547",
        "tactic": "Persistence",
        "weight": 16,
        "severity": "suspicious",
    },
    "ssh-authorized-keys": {
        "technique": "T1098.004",
        "tactic": "Persistence",
        "weight": 16,
        "severity": "suspicious",
    },
    "scheduled-task": {
        "technique": "T1053.005",
        "tactic": "Persistence",
        "weight": 16,
        "severity": "suspicious",
    },
    "suid-set": {
        "technique": "T1548.001",
        "tactic": "Privilege Escalation",
        "weight": 18,
        "severity": "suspicious",
    },
    "credential-dump": {
        "technique": "T1003.001",
        "tactic": "Credential Access",
        "weight": 20,
        "severity": "malicious",
    },
    "suspicious-extension": {
        "technique": "T1036.003",
        "tactic": "Defense Evasion",
        "weight": 16,
        "severity": "malicious",
    },
    "shell-history-wipe": {
        "technique": "T1070.003",
        "tactic": "Defense Evasion",
        "weight": 12,
        "severity": "suspicious",
    },
    "enumeration-burst": {
        "technique": "T1082",
        "tactic": "Discovery",
        "weight": 14,
        "severity": "suspicious",
    },
    "data-staging": {
        "technique": "T1048",
        "tactic": "Exfiltration",
        "weight": 18,
        "severity": "malicious",
    },
    "rename-burst": {
        "technique": "T1486",
        "tactic": "Impact",
        "weight": 22,
        "severity": "malicious",
    },
    "first-seen-process": {
        "technique": "T1204",
        "tactic": "Execution",
        "weight": 6,
        "severity": "suspicious",
    },
    "unusual-port": {
        "technique": "T1571",
        "tactic": "Command and Control",
        "weight": 10,
        "severity": "suspicious",
    },
    "attack-chain": {
        "technique": "T1204",
        "tactic": "Execution",
        "weight": 30,
        "severity": "malicious",
    },
    "baseline-anomaly": {
        "technique": "T1071.001",
        "tactic": "Command and Control",
        "weight": 12,
        "severity": "suspicious",
    },
}


def compute_risk_score(rule_ids: list[str]) -> int:
    """Sum weights of distinct fired rules, capped at 100 (roadmap 1.3).

    Unknown rule_ids (e.g. future/legacy) contribute 0 so the score never
    crashes on data this build doesn't know about.
    """
    total = sum(RULE_META.get(rid, {}).get("weight", 0) for rid in set(rule_ids))
    return min(100, total)


# Human rule names mirror detection.py's alert titles (single source of truth
# for the /rules/meta endpoint, the webapp chips, and the Navigator layer).
RULE_NAMES: dict[str, str] = {
    "network-scan": "Active scanning (network reconnaissance)",
    "toolchain-build": "Tool compiled from a writable location (capability development)",
    "document-dropper": "Document viewer spawned a script interpreter (spearphishing)",
    "lateral-rdp-smb": "Outbound RDP/SMB connection (lateral movement)",
    "screen-capture": "Screen capture / clipboard theft tool",
    "masquerading": "Process masquerading as system binary",
    "suspicious-parent-child": "Suspicious parent-child process relationship",
    "lolbin-abuse": "Living-off-the-land binary abuse",
    "beaconing": "C2-style beaconing",
    "registry-persistence": "Persistence via registry Run key",
    "autostart-persistence": "Persistence via shell/autostart file",
    "rename-burst": "Rapid file write burst (possible ransomware)",
    "first-seen-process": "First-seen process (novelty)",
    "unusual-port": "Connection to uncommon C2-style port",
    "attack-chain": "Coordinated attack chain",
    "baseline-anomaly": "Baseline anomaly",
    "ssh-authorized-keys": "SSH authorized_keys tampering",
    "suid-set": "SUID/SGID bit set (privilege escalation)",
    "scheduled-task": "Scheduled task created (persistence)",
    "credential-dump": "Credential dumping",
    "suspicious-extension": "Suspicious double-extension executable",
    "shell-history-wipe": "Shell history wiped (anti-forensics)",
    "enumeration-burst": "Discovery enumeration burst",
    "data-staging": "Data staging: archive then exfil",
}


def rule_name(rule_id: str) -> str:
    """Human display name for a rule id (falls back to the id itself)."""
    return RULE_NAMES.get(rule_id, rule_id)
