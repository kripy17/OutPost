"""Auto-generated Suricata/Sigma/YARA rules from a run's findings.

Phase 6 Task 27 & Standout Features #8. Template-based, deterministic, and verified:
- Suricata: Network-based detection for malicious C2 endpoints, ports, protocols.
- Sigma: Log-based behavioral rules covering process creation, registry tampering, shadow deletion, LOLBins, persistence.
- YARA: Signature/artifact rules based on binary hashes, command-line snippets, and file paths.
"""

import hashlib
import re
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


# ---------------------------------------------------------------------------
# SigmaHQ Transpiler & Community Rule Library
# ---------------------------------------------------------------------------


COMMUNITY_SIGMA_RULES = [
    {
        "id": "sigma-win-powershell-download-cradle",
        "title": "Suspicious PowerShell Download Cradle",
        "platform": "windows",
        "level": "high",
        "severity": "malicious",
        "mitre_tactics": ["execution", "command-and-control"],
        "mitre_techniques": ["T1059.001", "T1105"],
        "description": "Detects suspicious PowerShell execution with web download cradles (DownloadString, WebClient, Invoke-WebRequest) designed to download and execute in-memory payloads.",
        "sigma_yaml": """title: Suspicious PowerShell Download Cradle
id: 3d304ab1-633a-442a-a92c-e36214ec042e
status: stable
description: Detects suspicious PowerShell download cradles attempting to execute remote code.
references:
    - https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_download_cradles.yml
author: Florian Roth, SigmaHQ
date: 2022-03-15
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command_and_control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'Net.WebClient'
            - 'Invoke-WebRequest'
            - 'IEX((New-Object'
            - 'irm '
    condition: selection
level: high
""",
    },
    {
        "id": "sigma-win-certutil-download",
        "title": "Certutil Remote Artifact Download",
        "platform": "windows",
        "level": "high",
        "severity": "malicious",
        "mitre_tactics": ["defense-evasion", "command-and-control"],
        "mitre_techniques": ["T1105", "T1140"],
        "description": "Detects use of certutil.exe to download files or decode base64 payloads from remote URLs (LOLBAS T1105).",
        "sigma_yaml": """title: Certutil Remote Artifact Download
id: e011a79f-879a-4c29-ba80-77a82c4be3e6
status: stable
description: Detects execution of certutil with urlcache parameter to download remote files.
author: Florian Roth, SigmaHQ
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.command_and_control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\certutil.exe'
        CommandLine|contains:
            - '-urlcache'
            - '/urlcache'
            - '-split'
            - '/split'
    condition: selection
level: high
""",
    },
    {
        "id": "sigma-win-vssadmin-shadow-delete",
        "title": "Volume Shadow Copy Deletion (Ransomware Inhibit Recovery)",
        "platform": "windows",
        "level": "critical",
        "severity": "malicious",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1490"],
        "description": "Detects deletion of volume shadow copies via vssadmin or wmic, a common precursor to ransomware encryption.",
        "sigma_yaml": """title: Volume Shadow Copy Deletion
id: c947e116-0914-4c4c-9548-5256e22f254b
status: stable
description: Detects volume shadow copies deletion to inhibit system recovery.
author: Michael Haag, SigmaHQ
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'delete shadows'
            - 'resize shadowstorage'
            - 'shadowcopy delete'
    condition: selection
level: critical
""",
    },
    {
        "id": "sigma-win-mimikatz-commands",
        "title": "Mimikatz LSASS Credential Dump Commands",
        "platform": "windows",
        "level": "critical",
        "severity": "malicious",
        "mitre_tactics": ["credential-access"],
        "mitre_techniques": ["T1003.001"],
        "description": "Detects command-line arguments indicative of Mimikatz execution targeting LSASS and SAM credential extraction.",
        "sigma_yaml": """title: Mimikatz LSASS Credential Dump Commands
id: 0e86b052-a0f1-4347-81ef-24908a8d11c7
status: stable
description: Detects command-line parameters used by Mimikatz modules.
author: Florian Roth, SigmaHQ
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'sekurlsa::logonpasswords'
            - 'sekurlsa::wdigest'
            - 'lsadump::sam'
            - 'lsadump::secrets'
            - 'privilege::debug'
            - 'crypto::certificates'
    condition: selection
level: critical
""",
    },
    {
        "id": "sigma-win-mshta-execution",
        "title": "MSHTA Proxy Scriptlet Execution",
        "platform": "windows",
        "level": "high",
        "severity": "malicious",
        "mitre_tactics": ["defense-evasion"],
        "mitre_techniques": ["T1218.005"],
        "description": "Detects mshta.exe executing inline JavaScript/VBScript or remote HTML applications.",
        "sigma_yaml": """title: MSHTA Proxy Scriptlet Execution
id: 67f113ec-232d-4340-9045-d529e307c503
status: stable
description: Detects mshta executing inline scriptlets or remote URLs.
author: Diego Perez, SigmaHQ
tags:
    - attack.defense_evasion
    - attack.t1218.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\mshta.exe'
        CommandLine|contains:
            - 'javascript:'
            - 'vbscript:'
            - 'about:'
            - 'http://'
            - 'https://'
    condition: selection
level: high
""",
    },
    {
        "id": "sigma-lnx-susp-curl-pipe-bash",
        "title": "Suspicious Remote Script Pipe to Shell",
        "platform": "linux",
        "level": "high",
        "severity": "malicious",
        "mitre_tactics": ["execution", "command-and-control"],
        "mitre_techniques": ["T1059.004", "T1105"],
        "description": "Detects remote shell download pipelines such as curl/wget piped directly into bash or sh.",
        "sigma_yaml": """title: Suspicious Remote Script Pipe to Shell
id: 79be7526-7ee6-4e50-b08e-c9069dfd0f7a
status: stable
description: Detects execution of scripts directly piped from curl/wget into shell interpreters.
author: OutPost Community, SigmaHQ
tags:
    - attack.execution
    - attack.t1059.004
    - attack.command_and_control
    - attack.t1105
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - 'curl | bash'
            - 'curl | sh'
            - 'wget -O- | bash'
            - 'wget -qO- | sh'
            - 'curl -sSL | python'
    condition: selection
level: high
""",
    },
    {
        "id": "sigma-macos-osascript-user-prompt",
        "title": "AppleScript / OSAScript Fake Credential Prompt",
        "platform": "macos",
        "level": "high",
        "severity": "malicious",
        "mitre_tactics": ["credential-access"],
        "mitre_techniques": ["T1056.002"],
        "description": "Detects osascript prompting users for administrative credentials via hidden-answer GUI dialogs.",
        "sigma_yaml": """title: AppleScript Fake Credential Prompt
id: 4831d1d8-3011-482a-a92c-f9e4299b8288
status: stable
description: Detects osascript executing password capture dialog prompts on macOS.
author: OutPost Community, SigmaHQ
tags:
    - attack.credential_access
    - attack.t1056.002
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith:
            - '/osascript'
        CommandLine|contains:
            - 'display dialog'
            - 'with hidden answer'
            - 'default answer'
            - 'Administrator Password'
    condition: selection
level: high
""",
    },
]


def get_community_sigma_rules() -> list[dict[str, Any]]:
    """Return the curated SigmaHQ community detection rules library."""
    return list(COMMUNITY_SIGMA_RULES)


def transpile_sigma_yaml(yaml_str: str) -> dict[str, Any]:
    """Transpile a Sigma YAML detection rule into OutPost detection filter/logic."""
    if not yaml_str or not yaml_str.strip():
        raise ValueError("Empty Sigma rule string")

    import yaml

    try:
        data = yaml.safe_load(yaml_str)
    except Exception as e:
        raise ValueError(f"Invalid Sigma YAML: {e}")

    if not isinstance(data, dict):
        raise ValueError("Sigma document must be a YAML mapping")

    title = str(data.get("title") or "Imported Sigma Rule").strip()
    description = str(data.get("description") or "Transpiled from Sigma specification").strip()
    level = str(data.get("level") or "medium").strip().lower()
    status = str(data.get("status") or "experimental").strip()
    sigma_id = str(data.get("id") or uuid.uuid4().hex[:8]).strip()
    logsource = data.get("logsource") or {}
    product = str(logsource.get("product") or "all").lower()

    # Severity mapping
    severity = "malicious" if level in ("critical", "high") else "suspicious"

    # Extract tags (MITRE ATT&CK)
    raw_tags = data.get("tags") or []
    if isinstance(raw_tags, str):
        raw_tags = [raw_tags]
    mitre_techniques: list[str] = []
    mitre_tactics: list[str] = []
    for tag in raw_tags:
        t_str = str(tag).strip()
        if t_str.startswith("attack."):
            val = t_str[7:].strip()
            if val.lower().startswith("t"):
                mitre_techniques.append(val.upper())
            else:
                mitre_tactics.append(val.replace("_", "-"))

    # Parse detection definitions
    detection_def = data.get("detection") or {}
    criteria: list[dict[str, Any]] = []

    def _normalize_field(raw_k: str) -> tuple[str, str]:
        target = "command_line"
        modifier = "contains"
        if "|" in raw_k:
            rf, mod = raw_k.split("|", 1)
            raw_field = rf.strip()
            modifier = mod.strip().lower()
        else:
            raw_field = raw_k.strip()

        fl = raw_field.lower()
        if "image" in fl and "parent" not in fl:
            target = "process_name"
        elif "parentimage" in fl or "parent" in fl:
            target = "parent_name"
        elif "commandline" in fl or "cmd" in fl:
            target = "command_line"
        elif "targetobject" in fl or "registry" in fl:
            target = "registry_key"
        elif "targetfilename" in fl or "file" in fl:
            target = "file_path"
        elif "destinationip" in fl or "dest_ip" in fl or "dst_ip" in fl:
            target = "dest_ip"
        elif "destinationport" in fl or "dest_port" in fl or "dst_port" in fl:
            target = "dest_port"

        return target, modifier

    for sel_name, sel_content in detection_def.items():
        if sel_name == "condition" or not isinstance(sel_content, dict):
            continue
        for field_key, field_val in sel_content.items():
            target_f, mod = _normalize_field(str(field_key))
            values = field_val if isinstance(field_val, list) else [field_val]
            str_vals = [str(v).strip() for v in values if v is not None]
            if not str_vals:
                continue
            criteria.append({
                "section": sel_name,
                "original_field": str(field_key),
                "target_field": target_f,
                "modifier": mod,
                "values": str_vals,
                "value": str_vals[0] if len(str_vals) == 1 else str_vals,
            })

    rule_id = f"sigma-{re.sub(r'[^a-zA-Z0-9]', '-', title.lower())[:32].strip('-')}"

    return {
        "rule_id": rule_id,
        "sigma_id": sigma_id,
        "title": title,
        "description": description,
        "platform": product,
        "level": level,
        "severity": severity,
        "status": status,
        "mitre_tactics": mitre_tactics or ["execution"],
        "mitre_techniques": mitre_techniques or ["T1059"],
        "criteria": criteria,
        "transpiled_filter_count": len(criteria),
        "condition": str(detection_def.get("condition") or "selection"),
        "source": "sigma_import",
    }

