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
    "lateral-psexec-smb": {
        "technique": "T1021.002",
        "tactic": "Lateral Movement",
        "weight": 12,
        "severity": "suspicious",
    },
    "lateral-winrm-wmi": {
        "technique": "T1021.006",
        "tactic": "Lateral Movement",
        "weight": 12,
        "severity": "suspicious",
    },
    "lateral-smb-share": {
        "technique": "T1021.001",
        "tactic": "Lateral Movement",
        "weight": 8,
        "severity": "suspicious",
    },
    "rdp-brute-force": {
        "technique": "T1021.001",
        "tactic": "Lateral Movement",
        "weight": 14,
        "severity": "suspicious",
    },
    "log-service-stop": {
        "technique": "T1070.001",
        "tactic": "Defense Evasion",
        "weight": 14,
        "severity": "malicious",
    },
    "log-clearing": {
        "technique": "T1070.001",
        "tactic": "Defense Evasion",
        "weight": 16,
        "severity": "malicious",
    },
    "dns-tunneling": {
        "technique": "T1071.004",
        "tactic": "Command and Control",
        "weight": 16,
        "severity": "suspicious",
    },
    "dns-long-label": {
        "technique": "T1568.002",
        "tactic": "Command and Control",
        "weight": 10,
        "severity": "suspicious",
    },
    "dns-unusual-port": {
        "technique": "T1071.004",
        "tactic": "Command and Control",
        "weight": 8,
        "severity": "suspicious",
    },
    "tls-sni-suspicious": {
        "technique": "T1071.001",
        "tactic": "Command and Control",
        "weight": 12,
        "severity": "suspicious",
    },
    "tls-ja3-c2": {
        "technique": "T1071.001",
        "tactic": "Command and Control",
        "weight": 20,
        "severity": "malicious",
    },
    "doh-resolver-use": {
        "technique": "T1071.004",
        "tactic": "Command and Control",
        "weight": 10,
        "severity": "suspicious",
    },
    "fanout-contact": {
        "technique": "T1071.001",
        "tactic": "Command and Control",
        "weight": 14,
        "severity": "suspicious",
    },
    "fanout-recurring": {
        "technique": "T1071.001",
        "tactic": "Command and Control",
        "weight": 18,
        "severity": "suspicious",
    },
    "shadow-copy-deletion": {
        "technique": "T1490",
        "tactic": "Impact",
        "weight": 22,
        "severity": "malicious",
    },
    "remote-thread-injection": {
        "technique": "T1055.002",
        "tactic": "Privilege Escalation",
        "weight": 20,
        "severity": "malicious",
    },
    "ifeo-persistence": {
        "technique": "T1546.012",
        "tactic": "Persistence",
        "weight": 18,
        "severity": "malicious",
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
    "lateral-psexec-smb": "PsExec / SMB-admin remote execution",
    "lateral-winrm-wmi": "WinRM / WMI remote execution",
    "lateral-smb-share": "SMB share enumeration (lateral movement)",
    "rdp-brute-force": "RDP connection burst (brute-force / spray)",
    "log-service-stop": "Logging service stopped/disabled (anti-forensics)",
    "log-clearing": "Event/journal logs purged (anti-forensics)",
    "dns-tunneling": "DNS tunneling (suspicious label burst)",
    "dns-long-label": "Long / high-entropy DNS query (DGA or tunneling)",
    "dns-unusual-port": "DNS query on a non-standard port",
    "tls-sni-suspicious": "TLS handshake with IP-literal or DGA-style SNI",
    "tls-ja3-c2": "Known C2 TLS client handshake (JA3 fingerprint)",
    "doh-resolver-use": "DNS-over-HTTPS from a script host",
    "fanout-contact": "Coordinated contact with one destination",
    "fanout-recurring": "Recurring coordinated fan-out",
    "shadow-copy-deletion": "Volume Shadow Copy & backup deletion (ransomware inhibitor)",
    "remote-thread-injection": "Remote thread injection into system process",
    "ifeo-persistence": "IFEO debugger registry persistence",
}


def rule_name(rule_id: str) -> str:
    """Human display name for a rule id (falls back to the id itself)."""
    return RULE_NAMES.get(rule_id, rule_id)


# Per-alert remediation guidance — every finding carries a short "what to do"
# checklist, turning detection into action (kill the PID, remove the
# persistence point, revoke the credential). Served by GET /rules/meta and
# rendered on the run detail alert list.
RULE_REMEDIATION: dict[str, list[str]] = {
    "network-scan": ["Identify the scanning PID and the target scope", "Block outbound to the scanned ranges at the firewall"],
    "toolchain-build": ["Remove the compiled artifact from the writable location", "Review what was compiled and why"],
    "document-dropper": ["Isolate the document and its parent application", "Scan the document with the YARA lab / AV", "Treat the spawned script host as compromised"],
    "lateral-rdp-smb": ["Verify the connection was intentional", "Segment RDP/SMB exposure at the network layer"],
    "screen-capture": ["Kill the capture process", "Check for exfil of the captured data"],
    "masquerading": ["Kill the masquerading process", "Inspect the binary path and hash in the sample vault"],
    "suspicious-parent-child": ["Terminate the child process chain", "Quarantine the parent sample"],
    "lolbin-abuse": ["Terminate the LOLBin invocation", "Decode/analyze the payload it fetched"],
    "beaconing": ["Block the beacon destination IP", "Inspect the beaconing process for persistence"],
    "registry-persistence": ["Delete the Run key value", "Kill the process registered to run"],
    "autostart-persistence": ["Remove the autostart file/symlink", "Kill the process it launches"],
    "rename-burst": ["Isolate the machine from the network immediately", "Preserve the encrypted files for recovery research"],
    "first-seen-process": ["Verify the process is expected on this host", "Quarantine if unknown"],
    "unusual-port": ["Block the C2 port at the firewall", "Inspect the connecting process"],
    "attack-chain": ["Treat the host as fully compromised", "Collect memory + disk images before cleanup"],
    "baseline-anomaly": ["Review the anomalous item against the host baseline", "Escalate if unexplained"],
    "ssh-authorized-keys": ["Remove the rogue key from authorized_keys", "Rotate the account's credentials"],
    "suid-set": ["Clear the SUID/SGID bit", "Review how the binary was replaced"],
    "scheduled-task": ["Delete the scheduled task", "Inspect the task payload"],
    "credential-dump": ["Reset the affected credentials", "Rotate service accounts the dump touched"],
    "suspicious-extension": ["Quarantine the double-extension file", "Block the file hash in the vault"],
    "shell-history-wipe": ["Preserve the shell session logs if possible", "Note the wipe as a deliberate anti-forensics act"],
    "enumeration-burst": ["Identify the enumerating PID (recon actors panel)", "Assume the host is being surveyed — hunt for the follow-on"],
    "data-staging": ["Block the exfil destination", "Find and secure the staged archive"],
    "lateral-psexec-smb": ["Revoke the account that mounted admin$", "Disable the remote-admin path used"],
    "lateral-winrm-wmi": ["Revoke WinRM/WMI access for the abused account", "Review remote-execution allowlists"],
    "lateral-smb-share": ["Identify what the enumerator accessed", "Restrict share permissions"],
    "rdp-brute-force": ["Block the source IP at the firewall", "Check for successful logons after the burst"],
    "log-service-stop": ["Re-enable the logging service", "Restore forwarding to the collector"],
    "log-clearing": ["Preserve any remaining log copies", "Treat the cleared window as unknown activity"],
    "dns-tunneling": ["Block the tunneled base domain at the DNS layer", "Inspect the resolving process"],
    "dns-long-label": ["Block the DGA domain", "Hunt for sibling DGA domains"],
    "dns-unusual-port": ["Block the non-standard DNS port", "Inspect the process doing covert DNS"],
    "tls-sni-suspicious": ["Block the SNI/destination at the egress proxy", "Inspect the TLS client process and its cert chain"],
    "tls-ja3-c2": ["Block the remote C2 IP and JA3 signature on firewall / proxy", "Isolate endpoint and inspect process memory for injected C2 beacon"],
    "doh-resolver-use": ["Review the script host's intent — DoH hides DNS from inspection", "Block the resolver at the firewall if unauthorized"],
    "fanout-contact": ["Block the shared destination IP", "Treat every contacting process as potentially compromised"],
    "fanout-recurring": [
        "Block the shared destination IP at the firewall/EDR",
        "Treat every contacting process as potentially compromised",
        "Hunt the run's timeline for what changed between each fan-out window — the plant keeps spawning new processes",
    ],
    "shadow-copy-deletion": [
        "Isolate the host immediately from the network to stop ransomware encryption",
        "Verify shadow storage and preserve uncorrupted volume backups",
        "Terminate the ransomware parent process tree",
    ],
    "remote-thread-injection": [
        "Terminate the target process or freeze its execution",
        "Extract process memory dump for injected shellcode or DLL payloads",
        "Inspect the source process lineage and persistent triggers",
    ],
    "ifeo-persistence": [
        "Remove the malicious Debugger / SilentProcessExit key under Image File Execution Options",
        "Kill any resident processes launched by the hook",
        "Audit registry permissions on HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    ],
}
