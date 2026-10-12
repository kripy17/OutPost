"""Live Host Forensic Hunting Probes.

Provides targeted on-demand forensic inspection queries against live endpoints:
- Crontab persistence hunting
- SSH authorized_keys audit
- In-memory deleted binary discovery (fileless / unlinked executables)
- Suspicious listening socket analysis
- SUID executable audit
"""

import hashlib
import json
import os
import platform
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


def hunt_rwx_memory_injection() -> List[Dict[str, Any]]:
    """Hunt for processes harboring executable and writable (RWX) memory pages or fileless injection (T1055)."""
    results: List[Dict[str, Any]] = []
    proc_root = Path("/proc")
    if not proc_root.exists():
        return results

    # Binaries where JIT compilers legitimately map RWX pages
    jit_known_processes = {"node", "js", "chrome", "firefox", "java", "qemu-system"}

    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        maps_file = entry / "maps"
        if not maps_file.is_file():
            continue
        try:
            comm = (entry / "comm").read_text(errors="ignore").strip() if (entry / "comm").exists() else "unknown"
            content = maps_file.read_text(errors="ignore")
            for line in content.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    addr_range = parts[0]
                    perms = parts[1]
                    pathname = parts[5] if len(parts) >= 6 else ""

                    is_rwx = perms.startswith("rwx")
                    is_exec_stack_heap = "x" in perms and pathname in ("[stack]", "[heap]")
                    is_memfd_exec = "x" in perms and ("memfd:" in pathname or "/memfd:" in pathname)

                    if is_rwx or is_exec_stack_heap or is_memfd_exec:
                        is_jit = any(j in comm.lower() for j in jit_known_processes)
                        severity = "info" if is_jit else ("critical" if (is_exec_stack_heap or is_memfd_exec) else "suspicious")
                        details = (
                            f"Process {comm} (PID {pid}) contains anonymous RWX memory ({addr_range})"
                            if is_rwx else
                            f"Process {comm} (PID {pid}) contains executable {pathname} memory region ({addr_range})"
                        )
                        results.append({
                            "location": f"/proc/{pid}/maps",
                            "entry": f"PID {pid} ({comm}) [{perms}] {addr_range} {pathname}".strip(),
                            "pid": pid,
                            "process_name": comm,
                            "permissions": perms,
                            "address_range": addr_range,
                            "mapping": pathname or "anonymous",
                            "is_suspicious": not is_jit,
                            "severity": severity,
                            "details": details,
                        })
                        if len(results) >= 25:
                            return results
        except Exception:
            pass

    return results[:25]


def hunt_dns_hosts_hijack() -> List[Dict[str, Any]]:
    """Hunt for local DNS redirection, /etc/hosts poisoning, and name resolution hijacking (T1565.001 / T1556)."""
    results: List[Dict[str, Any]] = []

    # 1. Inspect /etc/hosts for redirection of public/critical domains
    hosts_path = Path("/etc/hosts")
    critical_domains = {
        "microsoft.com", "google.com", "github.com", "virustotal.com",
        "update.microsoft.com", "security.ubuntu.com", "archive.ubuntu.com",
        "cloudflare.com", "aws.amazon.com", "azure.com",
    }
    if hosts_path.is_file():
        try:
            content = hosts_path.read_text(errors="ignore")
            for line in content.splitlines():
                clean = line.strip()
                if not clean or clean.startswith("#"):
                    continue
                parts = clean.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    domains = parts[1:]
                    for d in domains:
                        d_lower = d.lower()
                        if any(c in d_lower for c in critical_domains):
                            results.append({
                                "location": "/etc/hosts",
                                "entry": f"{ip} -> {d}",
                                "type": "hosts_poisoning",
                                "ip": ip,
                                "domain": d,
                                "is_suspicious": True,
                                "severity": "critical",
                                "details": f"/etc/hosts redirects critical domain '{d}' to '{ip}'",
                            })
                        elif not (ip.startswith("127.") or ip == "::1" or ip.startswith("fe00:") or ip.startswith("ff0")):
                            results.append({
                                "location": "/etc/hosts",
                                "entry": f"{ip} -> {d}",
                                "type": "static_host_mapping",
                                "ip": ip,
                                "domain": d,
                                "is_suspicious": False,
                                "severity": "info",
                                "details": f"Static host definition for {d}",
                            })
        except Exception:
            pass

    # 2. Inspect /etc/resolv.conf for rogue nameservers
    resolv_path = Path("/etc/resolv.conf")
    known_public_resolvers = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "127.0.0.53", "127.0.0.1"}
    if resolv_path.is_file():
        try:
            content = resolv_path.read_text(errors="ignore")
            for line in content.splitlines():
                clean = line.strip()
                if clean.startswith("nameserver "):
                    ns = clean.split()[1].strip()
                    is_unusual = ns not in known_public_resolvers and not (ns.startswith("10.") or ns.startswith("192.168.") or ns.startswith("172."))
                    results.append({
                        "location": "/etc/resolv.conf",
                        "entry": f"nameserver {ns}",
                        "type": "dns_nameserver",
                        "nameserver": ns,
                        "is_suspicious": is_unusual,
                        "severity": "suspicious" if is_unusual else "info",
                        "details": f"Configured recursive DNS nameserver ({ns})" + (" [Unrecognized public resolver]" if is_unusual else ""),
                    })
        except Exception:
            pass

    # 3. Inspect /etc/nsswitch.conf for hijacked hosts resolver
    nsswitch_path = Path("/etc/nsswitch.conf")
    if nsswitch_path.is_file():
        try:
            content = nsswitch_path.read_text(errors="ignore")
            for line in content.splitlines():
                clean = line.strip()
                if clean.startswith("hosts:"):
                    directives = clean.split(":", 1)[1].strip()
                    standard_modules = {"files", "dns", "myhostname", "mymachines", "resolve", "mdns4_minimal", "[notfound=return]"}
                    unknown_mods = [m for m in directives.split() if m.lower() not in standard_modules]
                    if unknown_mods:
                        results.append({
                            "location": "/etc/nsswitch.conf",
                            "entry": clean,
                            "type": "nsswitch_hijack",
                            "unknown_modules": unknown_mods,
                            "is_suspicious": True,
                            "severity": "critical",
                            "details": f"Unrecognized NSS host resolution module(s) detected: {', '.join(unknown_mods)}",
                        })
        except Exception:
            pass

    return results[:25]


def hunt_pam_backdoors() -> List[Dict[str, Any]]:
    """Hunt for PAM (Pluggable Authentication Modules) backdoors and auth bypasses (T1556).

    Audits:
    1. /etc/pam.d/* service files for permissive auth bypasses (e.g. pam_permit.so in auth stack,
       unauthorized pam_exec.so executing external scripts/payloads).
    2. Unusual file paths referenced in PAM configurations (/tmp, /dev/shm, /opt, hidden paths).
    3. Staged PAM module hooks designed to grant unconditional root access.
    """
    results: List[Dict[str, Any]] = []
    pam_dir = Path("/etc/pam.d")

    sus_module_patterns = ["/tmp/", "/dev/shm/", "/opt/", "/var/tmp/", "/root/"]
    sensitive_services = {"sudo", "su", "sshd", "login", "passwd", "common-auth", "system-auth"}

    if pam_dir.is_dir():
        try:
            for p_file in sorted(pam_dir.iterdir()):
                if not p_file.is_file():
                    continue
                service_name = p_file.name
                try:
                    content = p_file.read_text(errors="ignore")
                    for line in content.splitlines():
                        clean = line.strip()
                        if not clean or clean.startswith("#"):
                            continue
                        tokens = clean.split()
                        if len(tokens) >= 3:
                            mod_type = tokens[0].lower()
                            mod_path = tokens[2]

                            # Check for auth sufficient pam_permit.so in sensitive services (instant root bypass)
                            if service_name in sensitive_services and mod_type == "auth" and "pam_permit.so" in mod_path:
                                results.append({
                                    "location": str(p_file),
                                    "entry": clean,
                                    "service": service_name,
                                    "module": mod_path,
                                    "is_suspicious": True,
                                    "severity": "critical",
                                    "details": f"Authentication bypass: 'pam_permit.so' configured in {service_name} auth stack permits any credential",
                                })
                            # Check for pam_exec executing scripts from suspicious directories
                            elif "pam_exec.so" in mod_path or (len(tokens) > 3 and "pam_exec" in clean):
                                is_sus_exec = any(p in clean for p in sus_module_patterns) or "sh " in clean or "bash " in clean or "python" in clean
                                results.append({
                                    "location": str(p_file),
                                    "entry": clean,
                                    "service": service_name,
                                    "module": "pam_exec.so",
                                    "is_suspicious": True,
                                    "severity": "critical" if is_sus_exec else "suspicious",
                                    "details": f"PAM execution hook in {service_name}: triggers external command on authentication",
                                })
                            # Check for non-standard path loading
                            elif any(pat in mod_path for pat in sus_module_patterns) or mod_path.startswith("."):
                                results.append({
                                    "location": str(p_file),
                                    "entry": clean,
                                    "service": service_name,
                                    "module": mod_path,
                                    "is_suspicious": True,
                                    "severity": "critical",
                                    "details": f"Staged PAM module loaded from non-standard directory: {mod_path}",
                                })
                except Exception:
                    pass
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
    "rwx_memory_injection": {
        "id": "rwx_memory_injection",
        "name": "RWX Memory Mappings & Fileless Injection",
        "tactic": "Defense Evasion",
        "technique": "T1055",
        "description": "Scans /proc/*/maps across active processes for executable & writable (RWX) memory pages and fileless injection.",
        "handler": hunt_rwx_memory_injection,
    },
    "dns_hosts_hijack": {
        "id": "dns_hosts_hijack",
        "name": "DNS Nameservers & /etc/hosts Hijacking",
        "tactic": "Impact",
        "technique": "T1565.001",
        "description": "Audits /etc/hosts, /etc/resolv.conf, and /etc/nsswitch.conf for domain redirection and rogue resolver injection.",
        "handler": hunt_dns_hosts_hijack,
    },
    "pam_backdoors": {
        "id": "pam_backdoors",
        "name": "PAM Authentication Backdoors & Bypasses",
        "tactic": "Credential Access",
        "technique": "T1556",
        "description": "Audits /etc/pam.d/ for rogue PAM modules, password bypasses (pam_permit), and unauthorized pam_exec hooks.",
        "handler": hunt_pam_backdoors,
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

    # Cryptographic section digests and manifest for chain-of-custody (NIST SP 800-86)
    def _hash_section(obj: Any) -> str:
        try:
            serialized = json.dumps(obj, sort_keys=True, default=str).encode("utf-8")
            return hashlib.sha256(serialized).hexdigest()
        except Exception:
            return hashlib.sha256(str(obj).encode("utf-8")).hexdigest()

    section_hashes = {
        "metrics": _hash_section(metrics),
        "probe_results": _hash_section(probe_results),
        "active_processes": _hash_section(processes[:100]),
        "active_sockets": _hash_section(sockets[:100]),
        "memory_yara": _hash_section(yara_results),
    }
    manifest_raw = "|".join(f"{k}:{v}" for k, v in sorted(section_hashes.items()))
    manifest_sha256 = hashlib.sha256(manifest_raw.encode("utf-8")).hexdigest()

    # Read machine-id if available
    machine_id = "unknown"
    for m_path in [Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")]:
        if m_path.is_file():
            try:
                machine_id = m_path.read_text().strip()
                if machine_id:
                    break
            except Exception:
                pass

    manifest = {
        "collector": "OutPost Sovereign DFIR Engine 1.0",
        "schema_version": "1.0.0",
        "standard": "NIST SP 800-86 Cryptographic Evidence Integrity",
        "manifest_sha256": manifest_sha256,
        "section_hashes": section_hashes,
        "chain_of_custody": {
            "acquired_by": "OutPost Sovereign Workstation",
            "hostname": socket.gethostname(),
            "machine_id": machine_id,
            "kernel_release": platform.release(),
            "platform": sys.platform,
            "acquisition_timestamp": ts_now.isoformat(),
        },
    }

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
        "manifest": manifest,
    }

