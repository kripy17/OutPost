"""Enterprise Incident Response Playbook Catalog & Engine.

Provides standardized, battle-tested incident response playbooks for enterprise SOC
and DFIR teams. Each playbook provides phase-structured containment and remediation
task checklists, recommended endpoint forensic hunts, and threat hunting queries.
"""

from typing import Any, Dict, List
import sqlite3
from datetime import datetime, timezone

from ..models import investigation as inv_model


IR_PLAYBOOKS: List[Dict[str, Any]] = [
    {
        "id": "ransomware_containment",
        "name": "Ransomware & Destructive Locker Protocol",
        "severity": "critical",
        "tactic": "Impact",
        "description": "Structured containment, evidence preservation, blast radius scoping, and clean recovery workflow for ransomware or wiper infections.",
        "mitre_attack": ["T1486", "T1485", "T1490"],
        "recommended_probes": ["deleted_binaries", "crontab_persistence", "suspicious_sockets"],
        "hunt_queries": [
            "vssadmin delete shadows",
            "wbadmin delete catalog",
            "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
            ".locked",
        ],
        "tasks": [
            {
                "title": "Network isolate all affected and adjacent endpoints immediately",
                "category": "containment",
                "priority": "critical",
                "description": "Trigger network containment via OutPost quarantine to sever lateral spreading and active C2 encryption commands.",
            },
            {
                "title": "Halt suspected ransomware processes and child lineages",
                "category": "containment",
                "priority": "critical",
                "description": "Identify parent-child process tree under suspicious locker and terminate execution while preserving volatile process dumps.",
            },
            {
                "title": "Acquire live volatile process memory dumps from affected hosts",
                "category": "investigation",
                "priority": "high",
                "description": "Extract unbacked RWX memory mappings to preserve encryption keys and ransomware configuration before reboot.",
            },
            {
                "title": "Audit shadow copies and backup storage immutability",
                "category": "investigation",
                "priority": "high",
                "description": "Verify whether volume shadow copies, offline storage repositories, or cloud snapshots were tampered with or deleted.",
            },
            {
                "title": "Preserve dropped ransom notes, locker binary, and encrypted sample files",
                "category": "investigation",
                "priority": "medium",
                "description": "Hash locker executables, collect ransom note templates, and identify specific ransomware family indicators.",
            },
            {
                "title": "Revoke compromised domain/service accounts and session tokens",
                "category": "eradication",
                "priority": "high",
                "description": "Reset credentials for all service accounts and privileged operators active on compromised systems.",
            },
            {
                "title": "Block ransomware C2 payment and communications infrastructure",
                "category": "eradication",
                "priority": "high",
                "description": "Add identified onion relays, payment domains, and staging IPs to corporate edge firewalls and DNS sinkholes.",
            },
            {
                "title": "Restore filesystems and databases from verified clean immutable backups",
                "category": "recovery",
                "priority": "high",
                "description": "Re-image affected operating systems and restore mission-critical data from validated offline backups.",
            },
            {
                "title": "Implement OutPost canary file monitoring on sensitive file shares",
                "category": "recovery",
                "priority": "medium",
                "description": "Deploy bait/canary documents with high-priority file-write detection rules to catch re-infection attempts.",
            },
        ],
    },
    {
        "id": "credential_dumping",
        "name": "Credential Harvesting & Memory Scraping Incident",
        "severity": "high",
        "tactic": "Credential Access",
        "description": "Triage and containment workflow for LSASS memory dumping, shadow copy extraction, or credential scraping.",
        "mitre_attack": ["T1003.001", "T1003.008", "T1552.001"],
        "recommended_probes": ["ssh_authorized_keys", "suid_lotl_binaries", "deleted_binaries"],
        "hunt_queries": [
            "lsass.exe",
            "procdump",
            "mimikatz",
            "/etc/shadow",
            "comsvcs.dll",
        ],
        "tasks": [
            {
                "title": "Isolate host running memory harvesting utilities",
                "category": "containment",
                "priority": "critical",
                "description": "Quarantine host immediately to block threat actor from using scraped credentials across the domain.",
            },
            {
                "title": "Inspect memory access handles and dump file targets",
                "category": "investigation",
                "priority": "high",
                "description": "Examine process command lines, mini-dump file locations in /tmp or %TEMP%, and handle access rights.",
            },
            {
                "title": "Audit all accounts logged onto the compromised endpoint",
                "category": "investigation",
                "priority": "high",
                "description": "Identify all Domain Admins, service accounts, and local users whose hashes or plaintext passwords were exposed.",
            },
            {
                "title": "Force immediate enterprise password reset and revoke Kerberos tickets",
                "category": "eradication",
                "priority": "critical",
                "description": "Rotate passwords for all exposed accounts and reset KRBTGT encryption key twice if Domain Controller was compromised.",
            },
            {
                "title": "Scan enterprise logs for lateral authentication using compromised credentials",
                "category": "eradication",
                "priority": "high",
                "description": "Hunt for anomalous RDP, SSH, WinRM, or SMB logons initiated during or after the dumping timestamp.",
            },
            {
                "title": "Enable Credential Guard and restricted administrative mode",
                "category": "recovery",
                "priority": "medium",
                "description": "Harden host endpoint configuration to prevent non-privileged debug access and LSASS process reading.",
            },
        ],
    },
    {
        "id": "c2_intrusion",
        "name": "Command & Control / Reverse Shell Intrusion",
        "severity": "critical",
        "tactic": "Command and Control",
        "description": "Response protocol for persistent interactive reverse shells, C2 beaconing, and remote access implants.",
        "mitre_attack": ["T1071.001", "T1059.004", "T1105"],
        "recommended_probes": ["suspicious_sockets", "crontab_persistence", "deleted_binaries"],
        "hunt_queries": [
            "nc -e",
            "/dev/tcp/",
            "bash -i",
            "python -c 'import socket'",
        ],
        "tasks": [
            {
                "title": "Terminate interactive shell sessions and malicious socket connections",
                "category": "containment",
                "priority": "critical",
                "description": "Kill suspicious shell processes (bash/sh/powershell) connected to external IP addresses.",
            },
            {
                "title": "Quarantine compromised endpoint from internal network",
                "category": "containment",
                "priority": "high",
                "description": "Prevent interactive adversary hands-on-keyboard reconnaissance or internal staging.",
            },
            {
                "title": "Analyze socket connection flows and beacon regularity intervals",
                "category": "investigation",
                "priority": "high",
                "description": "Run OutPost Network Protocol Analyzer on affected run to determine C2 beaconing period and jitter.",
            },
            {
                "title": "Extract stage-2 payloads and temporary scripts from disk and memory",
                "category": "investigation",
                "priority": "high",
                "description": "Carve memory regions and collect dropped files from /tmp, /dev/shm, or user AppData directories.",
            },
            {
                "title": "Check all persistence locations for scheduled callbacks",
                "category": "eradication",
                "priority": "high",
                "description": "Execute OutPost Forensic Probes across crontab, systemd services, shell RC profiles, and registry Run keys.",
            },
            {
                "title": "Block C2 IP addresses and DNS domains at enterprise firewall",
                "category": "eradication",
                "priority": "high",
                "description": "Push remote endpoints identified in beacon analysis to perimeter blocklists.",
            },
            {
                "title": "Validate endpoint clean state with live memory YARA inspection",
                "category": "recovery",
                "priority": "medium",
                "description": "Execute full YARA memory sweep on host to verify no dormant implants remain active in process memory.",
            },
        ],
    },
    {
        "id": "data_exfiltration",
        "name": "Sensitive Data Staging & Exfiltration",
        "severity": "high",
        "tactic": "Exfiltration",
        "description": "Procedure for detecting, interrupting, and assessing unauthorized packaging and outbound transfer of corporate data.",
        "mitre_attack": ["T1560.001", "T1048.003", "T1020"],
        "recommended_probes": ["suspicious_sockets", "deleted_binaries"],
        "hunt_queries": [
            "tar -czf",
            "zip -r -P",
            "7z a",
            "rclone copy",
            "curl -F",
        ],
        "tasks": [
            {
                "title": "Block destination exfiltration endpoints and terminate transfer streams",
                "category": "containment",
                "priority": "critical",
                "description": "Sever outbound data flows immediately and block cloud storage / mega / pastebin upload endpoints.",
            },
            {
                "title": "Identify staged archive files and staging directory contents",
                "category": "investigation",
                "priority": "high",
                "description": "Locate password-protected or compressed archives created prior to transfer and catalog file listings.",
            },
            {
                "title": "Determine scope of sensitive files and customer data exposed",
                "category": "investigation",
                "priority": "high",
                "description": "Perform data classification audit on staged files to determine regulatory and breach notification requirements.",
            },
            {
                "title": "Audit access logs to source database and file repository",
                "category": "investigation",
                "priority": "medium",
                "description": "Determine initial read source and identity used to harvest the sensitive records.",
            },
            {
                "title": "Secure staging paths and delete encrypted archive artifacts",
                "category": "eradication",
                "priority": "medium",
                "description": "Safely scrub unencrypted or passworded staging archives from local disks.",
            },
            {
                "title": "Enable outbound data loss prevention (DLP) and large upload alerts",
                "category": "recovery",
                "priority": "low",
                "description": "Tune OutPost volume and network heuristics for high-byte-count outbound transfers.",
            },
        ],
    },
]


def list_playbooks() -> List[Dict[str, Any]]:
    """Retrieve all available Incident Response Playbook templates."""
    return IR_PLAYBOOKS


def get_playbook(playbook_id: str) -> Dict[str, Any] | None:
    """Retrieve a specific playbook template by identifier."""
    p_id = playbook_id.strip().lower()
    for p in IR_PLAYBOOKS:
        if p["id"] == p_id:
            return p
    return None


def apply_playbook_to_investigation(
    conn: sqlite3.Connection,
    investigation_id: str,
    playbook_id: str,
    assignee: str | None = None,
) -> Dict[str, Any]:
    """Instantiate an IR Playbook into an active investigation.

    Creates all structured tasks, adds an audit note, and returns the applied
    playbook summary with created task IDs.
    """
    pb = get_playbook(playbook_id)
    if not pb:
        raise ValueError(f"Playbook '{playbook_id}' not found")

    # Verify investigation exists
    inv = inv_model.get(conn, investigation_id)
    if not inv:
        raise ValueError(f"Investigation '{investigation_id}' not found")

    cat_map = {
        "containment": "containment",
        "investigation": "evidence_collection",
        "evidence_collection": "evidence_collection",
        "eradication": "eradication",
        "recovery": "remediation",
        "remediation": "remediation",
        "triage": "triage",
    }

    created_tasks = []
    for t_spec in pb.get("tasks", []):
        cat = cat_map.get(t_spec.get("category", "triage"), "triage")
        t = inv_model.create_task(
            conn,
            investigation_id=investigation_id,
            title=t_spec["title"],
            category=cat,
            priority=t_spec.get("priority", "medium"),
            assignee=assignee,
        )
        created_tasks.append(t)

    # Append case audit note
    note_content = (
        f"Applied Incident Response Playbook: **{pb['name']}**\n\n"
        f"- **Tactic:** {pb['tactic']}\n"
        f"- **Severity:** {pb['severity'].upper()}\n"
        f"- **Tasks Instantiated:** {len(created_tasks)}\n"
        f"- **Recommended Forensic Probes:** {', '.join(pb.get('recommended_probes', []))}\n"
        f"- **Threat Hunting Queries:** {', '.join(pb.get('hunt_queries', []))}"
    )
    inv_model.add_note(conn, investigation_id, note=note_content, actor="OutPost Automation")

    return {
        "investigation_id": investigation_id,
        "playbook_id": pb["id"],
        "playbook_name": pb["name"],
        "tasks_created_count": len(created_tasks),
        "tasks": created_tasks,
        "recommended_probes": pb.get("recommended_probes", []),
        "hunt_queries": pb.get("hunt_queries", []),
    }
