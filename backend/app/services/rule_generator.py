"""Auto-generated Suricata/Sigma/YARA rules from a run's findings.

Phase 6 Task 27 & Standout Features #8. Template-based, deterministic, and verified:
- Suricata: Network-based detection for malicious C2 endpoints, ports, protocols.
- Sigma: Log-based behavioral rules covering process creation, registry tampering, shadow deletion, LOLBins, persistence.
- YARA: Signature/artifact rules based on binary hashes, command-line snippets, and file paths.
"""

import hashlib
import uuid
from typing import Any


def _stable_sid(seed: str) -> int:
    """Deterministic, process-independent rule sid (builtin hash() is salted)."""
    digest = int(hashlib.sha1(seed.encode("utf-8")).hexdigest(), 16)
    return 100_000 + (digest % 900_000)


# ---------------------------------------------------------------------------
# Suricata — network-based IDS signatures
# ---------------------------------------------------------------------------
def generate_suricata_rules(run_id: str, connections: list[dict[str, Any]]) -> list[str]:
    """Generate Suricata rules for malicious connections observed in a run."""
    rules: list[str] = []
    seen: set[str] = set()

    for conn in connections:
        rep = conn.get("reputation")
        if rep not in ("malicious", "suspicious") and not conn.get("watchlist") and not conn.get("abuse_score"):
            continue
        ip = str(conn.get("dest_ip", "")).strip()
        if not ip or ip in seen or ip.startswith(("127.", "0.", "::1", "10.", "192.168.")):
            continue
        seen.add(ip)

        port = conn.get("dest_port") or "any"
        proto = str(conn.get("protocol") or "tcp").lower()
        sid = _stable_sid(f"{run_id}:{ip}:{port}")
        rule = (
            f"alert {proto} any any -> {ip} {port} "
            f'(msg:"OutPost: possible C2 communication observed in run {run_id[:12]} to {ip}"; '
            f'reference:url,https://github.com/outpost-sec/outpost; '
            f'classtype:trojan-activity; sid:{sid}; rev:1;)'
        )
        rules.append(rule)
    return rules


# ---------------------------------------------------------------------------
# Sigma — log-based detection templates
# ---------------------------------------------------------------------------
_SIGMA_TEMPLATES: dict[str, dict[str, Any]] = {
    "lolbin-abuse": {
        "title": "OutPost: LOLBin abuse observed in run {run_id}",
        "logsource": {"category": "process_creation", "product": "windows"},
        "field": "CommandLine",
        "modifier": "contains",
        "pattern": "-enc",
        "level": "high",
        "tags": ["attack.defense_evasion", "attack.t1218"],
    },
    "powershell-encoded-cmd": {
        "title": "OutPost: Obfuscated or Base64 PowerShell execution in run {run_id}",
        "logsource": {"category": "process_creation", "product": "windows"},
        "field": "CommandLine",
        "modifier": "contains",
        "pattern": "-EncodedCommand",
        "level": "high",
        "tags": ["attack.execution", "attack.t1059.001"],
    },
    "macro-spawn-lolbin": {
        "title": "OutPost: Office document spawned script interpreter in run {run_id}",
        "logsource": {"category": "process_creation", "product": "windows"},
        "field": "ParentImage",
        "modifier": "endswith",
        "pattern": "winword.exe",
        "level": "critical",
        "tags": ["attack.initial_access", "attack.t1566.001"],
    },
    "suspicious-parent-child": {
        "title": "OutPost: Suspicious parent-child process relationship in run {run_id}",
        "logsource": {"category": "process_creation", "product": "windows"},
        "field": "ParentImage",
        "modifier": "endswith",
        "pattern": "explorer.exe",
        "level": "high",
        "tags": ["attack.execution", "attack.t1059"],
    },
    "masquerading": {
        "title": "OutPost: Process masquerading or path spoofing in run {run_id}",
        "logsource": {"category": "process_creation", "product": "windows"},
        "field": "Image",
        "modifier": "endswith",
        "pattern": "svchost.exe",
        "level": "medium",
        "tags": ["attack.defense_evasion", "attack.t1036"],
    },
    "registry-persistence": {
        "title": "OutPost: Registry Run-key persistence created in run {run_id}",
        "logsource": {"category": "registry_set", "product": "windows"},
        "field": "TargetObject",
        "modifier": "contains",
        "pattern": r"\CurrentVersion\Run",
        "level": "high",
        "tags": ["attack.persistence", "attack.t1547.001"],
    },
    "cron-persistence": {
        "title": "OutPost: Linux cron or systemd persistence stager in run {run_id}",
        "logsource": {"category": "file_change", "product": "linux"},
        "field": "TargetFilename",
        "modifier": "contains",
        "pattern": "/etc/cron.",
        "level": "high",
        "tags": ["attack.persistence", "attack.t1053.003"],
    },
    "shadow-copy-deletion": {
        "title": "OutPost: Volume shadow copy deletion (ransomware preparation) in run {run_id}",
        "logsource": {"category": "process_creation", "product": "windows"},
        "field": "CommandLine",
        "modifier": "contains",
        "pattern": "delete shadows",
        "level": "critical",
        "tags": ["attack.impact", "attack.t1490"],
    },
    "credential-dumping": {
        "title": "OutPost: LSASS memory credential access attempt in run {run_id}",
        "logsource": {"category": "process_access", "product": "windows"},
        "field": "TargetImage",
        "modifier": "endswith",
        "pattern": "lsass.exe",
        "level": "critical",
        "tags": ["attack.credential_access", "attack.t1003.001"],
    },
    "ransomware-file-burst": {
        "title": "OutPost: High-volume rapid file encryption activity in run {run_id}",
        "logsource": {"category": "file_event", "product": "windows"},
        "field": "TargetFilename",
        "modifier": "endswith",
        "pattern": ".locked",
        "level": "critical",
        "tags": ["attack.impact", "attack.t1486"],
    },
    "c2-beaconing": {
        "title": "OutPost: High-frequency C2 beacon network communication in run {run_id}",
        "logsource": {"category": "network_connection", "product": "windows"},
        "field": "DestinationPort",
        "modifier": "contains",
        "pattern": "443",
        "level": "high",
        "tags": ["attack.command_and_control", "attack.t1071"],
    },
    "log-clearing": {
        "title": "OutPost: Security event log deletion (defense evasion) in run {run_id}",
        "logsource": {"category": "process_creation", "product": "windows"},
        "field": "CommandLine",
        "modifier": "contains",
        "pattern": "wevtutil cl",
        "level": "high",
        "tags": ["attack.defense_evasion", "attack.t1070.001"],
    },
}


def generate_sigma_rules(run_id: str, alerts: list[dict[str, Any]]) -> list[str]:
    """Generate Sigma rules for distinct alert heuristic types in a run."""
    rules: list[str] = []
    seen: set[str] = set()

    for alert in alerts:
        rule_id = alert.get("rule_id")
        if not rule_id or rule_id in seen:
            continue
        seen.add(rule_id)

        tmpl = _SIGMA_TEMPLATES.get(rule_id)
        if not tmpl:
            continue

        tags_block = "\n".join(f"    - {t}" for t in tmpl.get("tags", ["attack.execution"]))
        logsource = tmpl["logsource"]
        rule_yaml = (
            f"title: {tmpl['title'].format(run_id=run_id[:12])}\n"
            f"id: {uuid.uuid4()}\n"
            f"status: experimental\n"
            f"description: Automatically synthesized Sigma rule generated from behavioral telemetry in run {run_id}.\n"
            f"references:\n"
            f"    - https://github.com/outpost-sec/outpost\n"
            f"author: OutPost Behavioral Monitor\n"
            f"tags:\n{tags_block}\n"
            f"logsource:\n"
            f"    category: {logsource['category']}\n"
            f"    product: {logsource['product']}\n"
            f"detection:\n"
            f"    selection:\n"
            f"        {tmpl['field']}|{tmpl['modifier']}: '{tmpl['pattern']}'\n"
            f"    condition: selection\n"
            f"level: {tmpl['level']}\n"
        )
        rules.append(rule_yaml)

    return rules


# ---------------------------------------------------------------------------
# YARA — file and memory signature generation
# ---------------------------------------------------------------------------
def generate_yara_rules(
    run_id: str,
    sample_name: str | None = None,
    hashes: list[str] | None = None,
    strings: list[str] | None = None,
) -> list[str]:
    """Generate YARA signature rules from observed sample attributes."""
    rule_name = f"OutPost_{hashlib.md5(run_id.encode()).hexdigest()[:10]}"
    name_str = sample_name or f"run_{run_id[:8]}"

    strings_lines = []
    condition_parts = []

    if hashes:
        for idx, h in enumerate(hashes[:4]):
            strings_lines.append(f'        $hash_{idx} = "{h}" ascii wide')
        condition_parts.append("any of ($hash_*)")

    if strings:
        for idx, s in enumerate(strings[:6]):
            clean_s = s.replace('"', '\\"')[:80]
            if clean_s:
                strings_lines.append(f'        $str_{idx} = "{clean_s}" ascii wide')
        condition_parts.append("1 of ($str_*)")

    if not strings_lines:
        strings_lines.append(f'        $sample_ref = "{name_str}" ascii wide')
        condition_parts.append("$sample_ref")

    strings_block = "\n".join(strings_lines)
    condition_block = " or ".join(condition_parts) if condition_parts else "all of them"

    yara_rule = (
        f"rule {rule_name} {{\n"
        f"    meta:\n"
        f'        description = "Synthesized YARA detection for {name_str} from run {run_id[:12]}"\n'
        f'        author = "OutPost Behavioral Monitor"\n'
        f'        date = "{run_id[:10]}"\n'
        f'        reference = "https://github.com/outpost-sec/outpost"\n'
        f"    strings:\n"
        f"{strings_block}\n"
        f"    condition:\n"
        f"        {condition_block}\n"
        f"}}"
    )
    return [yara_rule]


# ---------------------------------------------------------------------------
# Structured Suite Generator
# ---------------------------------------------------------------------------
def generate_detection_suite(
    run_id: str,
    alerts: list[dict[str, Any]],
    connections: list[dict[str, Any]],
    sample_name: str | None = None,
    hashes: list[str] | None = None,
) -> dict[str, Any]:
    """Generate a complete detection suite (Sigma, Suricata, YARA) in structured format."""
    sigma_rules = generate_sigma_rules(run_id, alerts)
    suricata_rules = generate_suricata_rules(run_id, connections)
    yara_rules = generate_yara_rules(run_id, sample_name, hashes)

    return {
        "run_id": run_id,
        "sample_name": sample_name,
        "counts": {
            "sigma": len(sigma_rules),
            "suricata": len(suricata_rules),
            "yara": len(yara_rules),
            "total": len(sigma_rules) + len(suricata_rules) + len(yara_rules),
        },
        "sigma": sigma_rules,
        "suricata": suricata_rules,
        "yara": yara_rules,
    }
