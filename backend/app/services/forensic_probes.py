"""Live Host Forensic Hunting Probes.

Provides targeted on-demand forensic inspection queries against live endpoints:
- Crontab persistence hunting
- SSH authorized_keys audit
- In-memory deleted binary discovery (fileless / unlinked executables)
- Suspicious listening socket analysis
- SUID executable audit
"""

import os
import re
import socket
from pathlib import Path
from typing import Any, Dict, List


def hunt_crontab() -> List[Dict[str, Any]]:
    """Hunt for suspicious crontab and scheduled task persistence."""
    results = []
    cron_locations = [
        Path("/etc/crontab"),
        Path("/etc/cron.d"),
        Path("/etc/cron.daily"),
        Path("/etc/cron.hourly"),
        Path("/var/spool/cron/crontabs"),
    ]
    # Also check user crontab
    user_cron = Path(f"/var/spool/cron/{os.getlogin() if hasattr(os, 'getlogin') else 'root'}")
    if user_cron.exists():
        cron_locations.append(user_cron)

    sus_patterns = ["curl", "wget", "sh", "bash", "python", "/tmp/", "nc ", "base64", "chmod +x"]

    for loc in cron_locations:
        if loc.is_file():
            try:
                content = loc.read_text(errors="ignore")
                for line in content.splitlines():
                    clean = line.strip()
                    if clean and not clean.startswith("#"):
                        is_sus = any(p in clean for p in sus_patterns)
                        results.append({
                            "location": str(loc),
                            "entry": clean,
                            "is_suspicious": is_sus,
                            "severity": "suspicious" if is_sus else "info",
                            "details": "Executes scripting interpreter or /tmp payload" if is_sus else "Standard scheduled job",
                        })
            except Exception:
                pass
        elif loc.is_dir():
            try:
                for f in loc.iterdir():
                    if f.is_file():
                        try:
                            content = f.read_text(errors="ignore")
                            for line in content.splitlines()[:5]:
                                clean = line.strip()
                                if clean and not clean.startswith("#"):
                                    is_sus = any(p in clean for p in sus_patterns)
                                    results.append({
                                        "location": str(f),
                                        "entry": clean[:120],
                                        "is_suspicious": is_sus,
                                        "severity": "suspicious" if is_sus else "info",
                                        "details": "Script or binary staged in cron directory",
                                    })
                        except Exception:
                            pass
            except Exception:
                pass
    return results


def hunt_ssh_keys() -> List[Dict[str, Any]]:
    """Hunt for unauthorized or backdoor SSH keys in authorized_keys files."""
    results = []
    ssh_files = [
        Path.home() / ".ssh" / "authorized_keys",
        Path("/root/.ssh/authorized_keys"),
    ]
    # Check /home/*/.ssh/authorized_keys
    home_dir = Path("/home")
    if home_dir.exists():
        try:
            for u in home_dir.iterdir():
                ak = u / ".ssh" / "authorized_keys"
                if ak.is_file() and ak not in ssh_files:
                    ssh_files.append(ak)
        except Exception:
            pass

    for ak in ssh_files:
        if not ak.is_file():
            continue
        try:
            content = ak.read_text(errors="ignore")
            for line in content.splitlines():
                clean = line.strip()
                if clean and not clean.startswith("#"):
                    parts = clean.split()
                    key_type = parts[0] if parts else "unknown"
                    comment = parts[2] if len(parts) > 2 else "(no comment)"
                    is_sus = any(b in comment.lower() for b in ("test", "backdoor", "root", "temp", "tmp", "anon"))
                    results.append({
                        "file": str(ak),
                        "key_type": key_type,
                        "comment": comment,
                        "is_suspicious": is_sus,
                        "severity": "suspicious" if is_sus else "info",
                        "preview": clean[:40] + "..." + clean[-20:],
                    })
        except Exception:
            pass
    return results


def hunt_deleted_binaries() -> List[Dict[str, Any]]:
    """Hunt for running processes whose executable on disk has been unlinked (fileless stealth malware)."""
    results = []
    proc_root = Path("/proc")
    if not proc_root.exists():
        return results

    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        exe_link = entry / "exe"
        try:
            target = os.readlink(exe_link)
            if "(deleted)" in target:
                comm = (entry / "comm").read_text().strip() if (entry / "comm").exists() else "unknown"
                cmdline = (
                    (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="ignore").strip()
                    if (entry / "cmdline").exists()
                    else comm
                )
                results.append({
                    "pid": pid,
                    "process_name": comm,
                    "target": target,
                    "command_line": cmdline[:160],
                    "is_suspicious": True,
                    "severity": "malicious",
                    "details": f"Process {comm} (PID {pid}) executing unlinked binary '{target}'",
                })
        except Exception:
            pass
    return results


def hunt_suspicious_sockets() -> List[Dict[str, Any]]:
    """Hunt for listening sockets on non-standard ports or unusual network daemons."""
    results = []
    known_safe_ports = {22, 53, 80, 443, 8000, 8001, 5173, 5174, 3000, 5432, 3306, 6379}
    
    # Parse /proc/net/tcp and /proc/net/tcp6
    for tcp_path in [Path("/proc/net/tcp"), Path("/proc/net/tcp6")]:
        if not tcp_path.exists():
            continue
        try:
            lines = tcp_path.read_text().splitlines()[1:]
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 4:
                    state = parts[3]
                    # 0A is TCP_LISTEN
                    if state == "0A":
                        local_addr_hex = parts[1]
                        ip_hex, port_hex = local_addr_hex.split(":")
                        port = int(port_hex, 16)
                        inode = parts[9]
                        is_unusual = port not in known_safe_ports and port > 1024
                        results.append({
                            "port": port,
                            "inode": inode,
                            "protocol": "TCP",
                            "state": "LISTEN",
                            "is_suspicious": is_unusual,
                            "severity": "suspicious" if is_unusual else "info",
                            "details": f"Listening TCP port {port}" + (" (Unusual non-standard service port)" if is_unusual else ""),
                        })
        except Exception:
            pass
    return results[:25]


def hunt_suid_binaries() -> List[Dict[str, Any]]:
    """Audit SUID executables for Living-off-the-Land (LotL) privilege escalation candidates."""
    results = []
    known_gtfo_bins = {
        "find", "vim", "nano", "cp", "mv", "nmap", "bash", "sh", "python",
        "perl", "ruby", "tar", "zip", "awk", "gawk", "sed", "less", "more", "env"
    }

    search_dirs = [Path("/usr/bin"), Path("/bin"), Path("/tmp"), Path("/usr/local/bin")]
    for d in search_dirs:
        if not d.exists():
            continue
        try:
            for p in d.iterdir():
                if p.is_file() and not p.is_symlink():
                    try:
                        st = p.stat()
                        # SUID is 0o4000
                        if st.st_mode & 0o4000:
                            is_gtfo = p.name.lower() in known_gtfo_bins
                            results.append({
                                "path": str(p),
                                "filename": p.name,
                                "size_bytes": st.st_size,
                                "is_gtfobins_candidate": is_gtfo,
                                "is_suspicious": is_gtfo or "/tmp" in str(p),
                                "severity": "malicious" if "/tmp" in str(p) else "suspicious" if is_gtfo else "info",
                                "details": f"SUID bit set on known LotL binary ({p.name})" if is_gtfo else "SUID binary",
                            })
                    except Exception:
                        pass
        except Exception:
            pass
    return results[:30]


PROBE_REGISTRY = {
    "crontab_persistence": {
        "id": "crontab_persistence",
        "name": "Crontab & Scheduled Job Persistence",
        "tactic": "Persistence",
        "technique": "T1053.003",
        "description": "Scans /etc/crontab, /etc/cron.*, and user crontabs for suspicious scheduled tasks and reverse shells.",
        "handler": hunt_crontab,
    },
    "ssh_authorized_keys": {
        "id": "ssh_authorized_keys",
        "name": "SSH Authorized Keys Backdoor Audit",
        "tactic": "Persistence",
        "technique": "T1098.004",
        "description": "Audits authorized_keys files across root and user home directories for unauthorized access keys.",
        "handler": hunt_ssh_keys,
    },
    "deleted_binaries": {
        "id": "deleted_binaries",
        "name": "Memory-Resident Deleted Inodes (Fileless Execution)",
        "tactic": "Defense Evasion",
        "technique": "T1070.004",
        "description": "Identifies active processes running from executables that have been deleted from disk.",
        "handler": hunt_deleted_binaries,
    },
    "suspicious_sockets": {
        "id": "suspicious_sockets",
        "name": "Suspicious Listening Sockets & Ports",
        "tactic": "Command and Control",
        "technique": "T1571",
        "description": "Audits open TCP listeners across the host for non-standard ports and unauthorized services.",
        "handler": hunt_suspicious_sockets,
    },
    "suid_lotl_binaries": {
        "id": "suid_lotl_binaries",
        "name": "SUID Executables & GTFOBins Privilege Escalation",
        "tactic": "Privilege Escalation",
        "technique": "T1548.001",
        "description": "Scans system directories for SUID binaries known to permit privilege escalation (GTFOBins).",
        "handler": hunt_suid_binaries,
    },
}


def list_forensic_probes() -> List[Dict[str, Any]]:
    """List all available forensic hunting probes."""
    return [
        {
            "id": p["id"],
            "name": p["name"],
            "tactic": p["tactic"],
            "technique": p["technique"],
            "description": p["description"],
        }
        for p in PROBE_REGISTRY.values()
    ]


def run_forensic_probe(probe_id: str) -> Dict[str, Any]:
    """Execute a specific forensic probe and return structured findings."""
    probe = PROBE_REGISTRY.get(probe_id)
    if not probe:
        raise ValueError(f"Probe '{probe_id}' not found")

    findings = probe["handler"]()
    anomalies = [f for f in findings if f.get("is_suspicious")]

    return {
        "probe_id": probe["id"],
        "name": probe["name"],
        "tactic": probe["tactic"],
        "technique": probe["technique"],
        "total_items": len(findings),
        "anomalies_count": len(anomalies),
        "findings": findings,
    }
