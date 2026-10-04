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
import sys
import uuid
from datetime import datetime, timezone
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


def hunt_systemd_units() -> List[Dict[str, Any]]:
    """Hunt for suspicious systemd services and timer persistence (T1543.002 / T1053.006)."""
    results: List[Dict[str, Any]] = []
    systemd_dirs = [
        Path("/etc/systemd/system"),
        Path("/run/systemd/system"),
        Path("/usr/lib/systemd/system"),
        Path.home() / ".config/systemd/user",
    ]
    home_dir = Path("/home")
    if home_dir.exists():
        try:
            for u in home_dir.iterdir():
                u_sys = u / ".config/systemd/user"
                if u_sys.is_dir() and u_sys not in systemd_dirs:
                    systemd_dirs.append(u_sys)
        except Exception:
            pass

    sus_patterns = [
        "curl ", "wget ", "python", "perl", "sh -i", "bash -i", "/dev/tcp",
        "/tmp/", "/dev/shm/", "base64", "nc ", "ncat ", "socat ", "chmod +x",
    ]

    for d in systemd_dirs:
        if not d.exists() or not d.is_dir():
            continue
        try:
            for unit_file in d.iterdir():
                if not unit_file.is_file() or unit_file.is_symlink():
                    continue
                if not any(unit_file.name.endswith(ext) for ext in (".service", ".timer", ".path")):
                    continue
                try:
                    content = unit_file.read_text(errors="ignore")
                    is_hidden = unit_file.name.startswith(".")
                    for line in content.splitlines():
                        clean = line.strip()
                        if any(clean.startswith(prefix) for prefix in ("ExecStart=", "ExecStartPre=", "ExecStartPost=")):
                            cmd = clean.split("=", 1)[1].strip()
                            is_sus = any(p in cmd.lower() for p in sus_patterns) or is_hidden
                            if is_sus or "/etc/systemd/system" in str(d):
                                results.append({
                                    "location": str(unit_file),
                                    "entry": f"[{unit_file.name}] {cmd[:100]}",
                                    "unit_name": unit_file.name,
                                    "command": cmd[:140],
                                    "is_suspicious": is_sus,
                                    "severity": "malicious" if ("/tmp/" in cmd or "/dev/shm/" in cmd or "/dev/tcp" in cmd) else ("suspicious" if is_sus else "info"),
                                    "details": "Executes scripting interpreter or staging payload" if is_sus else "Configured systemd service unit",
                                })
                except Exception:
                    pass
        except Exception:
            pass
    return results[:35]


def hunt_shell_profiles() -> List[Dict[str, Any]]:
    """Hunt for unauthorized environment hooks and shell profile backdoors (T1546.004)."""
    results: List[Dict[str, Any]] = []
    profile_targets = [
        Path("/etc/profile"),
        Path("/etc/bash.bashrc"),
        Path("/etc/environment"),
        Path.home() / ".bashrc",
        Path.home() / ".bash_profile",
        Path.home() / ".profile",
        Path.home() / ".zshrc",
    ]
    prof_d = Path("/etc/profile.d")
    if prof_d.is_dir():
        try:
            for f in prof_d.iterdir():
                if f.is_file() and f not in profile_targets:
                    profile_targets.append(f)
        except Exception:
            pass

    home_dir = Path("/home")
    if home_dir.exists():
        try:
            for u in home_dir.iterdir():
                for name in (".bashrc", ".bash_profile", ".profile", ".zshrc"):
                    sh_f = u / name
                    if sh_f.is_file() and sh_f not in profile_targets:
                        profile_targets.append(sh_f)
        except Exception:
            pass

    sus_patterns = [
        "alias sudo=", "alias su=", "alias ssh=", "/dev/tcp/", "nohup ",
        "disown", "nc -e", "mkfifo", "curl ", "wget ", "base64", "LD_PRELOAD",
        "PROMPT_COMMAND", "/tmp/", "/dev/shm/",
    ]

    for p in profile_targets:
        if not p.is_file():
            continue
        try:
            content = p.read_text(errors="ignore")
            for line in content.splitlines():
                clean = line.strip()
                if clean and not clean.startswith("#"):
                    is_sus = any(pat.lower() in clean.lower() for pat in sus_patterns)
                    if is_sus:
                        results.append({
                            "location": str(p),
                            "entry": clean[:120],
                            "file": str(p),
                            "line": clean[:120],
                            "is_suspicious": True,
                            "severity": "malicious" if ("alias sudo" in clean or "/dev/tcp" in clean or "LD_PRELOAD" in clean) else "suspicious",
                            "details": "Suspicious shell startup hook or hijacked command alias",
                        })
        except Exception:
            pass
    return results[:25]


def hunt_ld_preload() -> List[Dict[str, Any]]:
    """Hunt for shared library hijacking via /etc/ld.so.preload and process environments (T1574.006)."""
    results: List[Dict[str, Any]] = []

    # 1. Global /etc/ld.so.preload check
    preload_file = Path("/etc/ld.so.preload")
    if preload_file.is_file():
        try:
            content = preload_file.read_text(errors="ignore")
            entries = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]
            for entry in entries:
                results.append({
                    "location": "/etc/ld.so.preload",
                    "entry": entry,
                    "source": "/etc/ld.so.preload",
                    "library": entry,
                    "is_suspicious": True,
                    "severity": "malicious",
                    "details": f"Global rootkit hook in /etc/ld.so.preload: '{entry}'",
                })
        except Exception:
            pass

    # 2. Inspect active process environments in /proc/*/environ for LD_PRELOAD
    proc_dir = Path("/proc")
    if proc_dir.exists():
        try:
            for entry in proc_dir.iterdir():
                if not entry.name.isdigit():
                    continue
                pid = int(entry.name)
                environ_path = entry / "environ"
                try:
                    env_bytes = environ_path.read_bytes()
                    for env_var in env_bytes.split(b"\x00"):
                        if env_var.startswith(b"LD_PRELOAD="):
                            val = env_var.decode(errors="ignore").split("=", 1)[1]
                            if val.strip():
                                comm = (entry / "comm").read_text().strip() if (entry / "comm").exists() else "unknown"
                                results.append({
                                    "location": f"/proc/{pid}/environ",
                                    "entry": f"PID {pid} ({comm}) -> LD_PRELOAD={val}",
                                    "source": f"/proc/{pid}/environ",
                                    "pid": pid,
                                    "process_name": comm,
                                    "library": val,
                                    "is_suspicious": True,
                                    "severity": "malicious",
                                    "details": f"Process {comm} (PID {pid}) executed with LD_PRELOAD={val}",
                                })
                except Exception:
                    pass
        except Exception:
            pass

    return results[:20]


def hunt_kernel_modules() -> List[Dict[str, Any]]:
    """Hunt for suspicious loadable kernel modules and kernel rootkits (T1547.006)."""
    results: List[Dict[str, Any]] = []

    # 1. Audit /proc/sys/kernel/tainted
    taint_file = Path("/proc/sys/kernel/tainted")
    if taint_file.is_file():
        try:
            val_str = taint_file.read_text(errors="ignore").strip()
            if val_str.isdigit():
                taint_val = int(val_str)
                if taint_val > 0:
                    flags = []
                    if taint_val & (1 << 0):
                        flags.append("Proprietary module (P)")
                    if taint_val & (1 << 1):
                        flags.append("Force loaded (F)")
                    if taint_val & (1 << 12):
                        flags.append("Out-of-tree module (O)")
                    if taint_val & (1 << 13):
                        flags.append("Unsigned module (E)")
                    flag_str = ", ".join(flags) if flags else f"Taint mask {taint_val}"
                    is_sus = bool(taint_val & (1 << 12) or taint_val & (1 << 13))
                    results.append({
                        "location": "/proc/sys/kernel/tainted",
                        "entry": f"Kernel Tainted: {taint_val} ({flag_str})",
                        "module": "kernel",
                        "taint_val": taint_val,
                        "is_suspicious": is_sus,
                        "severity": "suspicious" if is_sus else "info",
                        "details": f"Kernel execution tainted by {flag_str}",
                    })
        except Exception:
            pass

    # 2. Audit loaded modules in /proc/modules
    known_rootkit_names = {
        "diamorphine", "reptile", "suterusu", "adore", "kbeast", "moodnt",
        "hide_proc", "rootkit", "kernel_hook", "syscall_hook", "backdoor",
    }
    proc_modules = Path("/proc/modules")
    if proc_modules.is_file():
        try:
            content = proc_modules.read_text(errors="ignore")
            for line in content.splitlines():
                parts = line.split()
                if not parts:
                    continue
                mod_name = parts[0]
                size_bytes = parts[1] if len(parts) > 1 else "0"
                state = parts[4] if len(parts) > 4 else "Live"
                is_rootkit = mod_name.lower() in known_rootkit_names or any(rk in mod_name.lower() for rk in ("rootkit", "diamorph"))
                if is_rootkit:
                    results.append({
                        "location": "/proc/modules",
                        "entry": f"{mod_name} ({size_bytes} B, state={state})",
                        "module": mod_name,
                        "size": size_bytes,
                        "state": state,
                        "is_suspicious": True,
                        "severity": "critical",
                        "details": f"Identified signature of known kernel rootkit LKM: '{mod_name}'",
                    })
        except Exception:
            pass

    return results[:25]


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
    "systemd_services": {
        "id": "systemd_services",
        "name": "Systemd Services & Timers Persistence",
        "tactic": "Persistence",
        "technique": "T1543.002",
        "description": "Scans system and user systemd service and timer unit files for backdoors and unauthorized execution.",
        "handler": hunt_systemd_units,
    },
    "shell_profiles": {
        "id": "shell_profiles",
        "name": "Shell Profile & Environment Backdoor Audit",
        "tactic": "Persistence",
        "technique": "T1546.004",
        "description": "Audits /etc/profile, bashrc, and user startup dotfiles for command interception and stealth payloads.",
        "handler": hunt_shell_profiles,
    },
    "ld_preload_hijack": {
        "id": "ld_preload_hijack",
        "name": "LD_PRELOAD & Shared Library Hijack Inspection",
        "tactic": "Defense Evasion",
        "technique": "T1574.006",
        "description": "Detects user-space rootkits in /etc/ld.so.preload and processes injected with custom preloaded libraries.",
        "handler": hunt_ld_preload,
    },
    "kernel_rootkits": {
        "id": "kernel_rootkits",
        "name": "Kernel Modules & LKM Rootkit Inspection",
        "tactic": "Persistence",
        "technique": "T1547.006",
        "description": "Audits /proc/modules and kernel taint flags for malicious out-of-tree loadable kernel modules and rootkits.",
        "handler": hunt_kernel_modules,
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


def collect_host_triage_pack(include_yara: bool = True, host_id: str = "local") -> Dict[str, Any]:
    """Collect a comprehensive live endpoint forensic triage pack.

    Compiles:
    - Host metrics and kernel state
    - All registered targeted forensic hunt probes
    - Active process listing and execution causality
    - Open sockets and network listening endpoints
    - Memory-resident YARA signature sweep (optional)
    """
    from . import host_forensics

    ts_now = datetime.now(timezone.utc)
    triage_id = f"triage_{ts_now.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

    # 1. Host Metrics & Pulse
    try:
        metrics = host_forensics.get_current_system_metrics()
    except Exception:
        metrics = {"error": "metrics_unavailable"}

    # 2. Live Process and Network Snapshot
    try:
        processes = host_forensics.get_live_processes()
    except Exception:
        processes = []

    try:
        sockets = host_forensics.get_live_sockets()
    except Exception:
        sockets = []

    # 3. Execute all registered forensic hunt probes
    probe_results: Dict[str, Any] = {}
    total_anomalies = 0
    for p_id in PROBE_REGISTRY:
        try:
            res = run_forensic_probe(p_id)
            probe_results[p_id] = res
            total_anomalies += res.get("anomalies_count", 0)
        except Exception as e:
            probe_results[p_id] = {"error": str(e), "anomalies_count": 0, "findings": []}

    # 4. Volatile memory / executable binary YARA inspection
    yara_results: Dict[str, Any] = {"scanned": False, "threat_count": 0, "threats": []}
    if include_yara:
        try:
            yara_results = host_forensics.scan_live_memory_yara(limit_pids=50)
            yara_results["scanned"] = True
        except Exception as e:
            yara_results = {"scanned": False, "error": str(e), "threat_count": 0, "threats": []}

    threat_count = yara_results.get("threat_count", 0)
    severity = "critical" if (threat_count > 0 or total_anomalies >= 3) else ("suspicious" if total_anomalies > 0 else "clean")

    return {
        "triage_id": triage_id,
        "collected_at": ts_now.isoformat(),
        "host_id": host_id,
        "hostname": socket.gethostname(),
        "platform": sys.platform,
        "metrics": metrics,
        "summary": {
            "severity": severity,
            "total_processes": len(processes),
            "total_sockets": len(sockets),
            "total_probes_executed": len(PROBE_REGISTRY),
            "probe_anomalies_count": total_anomalies,
            "yara_threats_count": threat_count,
        },
        "probe_results": probe_results,
        "active_processes": processes[:100],
        "active_sockets": sockets[:100],
        "memory_yara": yara_results,
    }
