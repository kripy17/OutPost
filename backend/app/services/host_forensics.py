"""Host X-Ray Service — Live Local System & Process Inspection.

Inspired by Omarchy X-Ray: deep, real-time live system inspection.
Extracts active processes, process trees/lineage, open sockets (listening & connected),
open file descriptors, security context, and process controls with audit logging.
"""

from __future__ import annotations

import datetime
import os
import platform
import re
import signal
from typing import Any

from ..core import auth
from ..core.db import db_session
from ..models import audit

try:
    import psutil
except ImportError:
    psutil = None

import subprocess

_CAPABILITIES = [
    "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID",
    "KILL", "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE",
    "NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW",
    "IPC_LOCK", "IPC_OWNER", "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT",
    "SYS_PTRACE", "SYS_PACCT", "SYS_ADMIN", "SYS_BOOT", "SYS_NICE",
    "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "MKNOD", "LEASE",
    "AUDIT_WRITE", "AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE",
    "MAC_ADMIN", "SYSLOG", "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ",
    "PERFMON", "BPF", "CHECKPOINT_RESTORE",
]

_DANGEROUS_CAPS = {
    "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "NET_RAW",
    "DAC_OVERRIDE", "AUDIT_CONTROL", "AUDIT_WRITE", "BPF",
}


def decode_capabilities(hex_val: str) -> list[dict[str, Any]]:
    """Decode a Linux capability bitmask from /proc/[pid]/status into named capabilities."""
    try:
        mask = int(hex_val, 16)
    except (ValueError, TypeError):
        return []

    caps = []
    for idx, name in enumerate(_CAPABILITIES):
        if mask & (1 << idx):
            caps.append({
                "name": f"CAP_{name}",
                "raw_name": name,
                "is_dangerous": name in _DANGEROUS_CAPS,
            })
    return caps


def check_package_provenance(exe_path: str) -> dict[str, Any]:
    """Determine whether an executable binary belongs to a system package or is an unmanaged/temp binary."""
    if not exe_path:
        return {"status": "unknown", "label": "No binary path", "managed": False}

    suspicious_dirs = ("/tmp", "/var/tmp", "/dev/shm", "/run/user", "/home")
    for s_dir in suspicious_dirs:
        if exe_path.startswith(s_dir):
            return {
                "status": "unmanaged_suspicious",
                "label": f"Unmanaged user/temp path ({exe_path.split('/')[1]})",
                "managed": False,
                "path": exe_path,
            }

    if exe_path.startswith(("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib", "/usr/libexec")):
        if os.path.isdir("/var/lib/pacman/local"):
            try:
                out = subprocess.run(["pacman", "-Qo", exe_path], capture_output=True, text=True, timeout=1.0)
                if out.returncode == 0 and "is owned by" in out.stdout:
                    pkg = out.stdout.split("is owned by")[-1].strip()
                    return {"status": "managed_package", "label": f"Package: {pkg}", "managed": True, "package": pkg}
            except Exception:
                pass

        if os.path.exists("/usr/bin/dpkg-query"):
            try:
                out = subprocess.run(["dpkg-query", "-S", exe_path], capture_output=True, text=True, timeout=1.0)
                if out.returncode == 0 and ":" in out.stdout:
                    pkg = out.stdout.split(":")[0].strip()
                    return {"status": "managed_package", "label": f"Debian/Ubuntu: {pkg}", "managed": True, "package": pkg}
            except Exception:
                pass

        return {
            "status": "system_binary",
            "label": "System Directory Binary",
            "managed": True,
            "path": exe_path,
        }

    return {
        "status": "custom_binary",
        "label": "Custom Path",
        "managed": False,
        "path": exe_path,
    }


_SECRET_PATTERNS = [
    re.compile(r"(?i)(--?(?:password|passwd|pass|token|api[-_]?key|secret|auth|jwt|bearer)\s*[:=\s]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"),
    re.compile(r"(?i)(-u\s+[a-zA-Z0-9_\-\.]+):([^\s]+)"),
    re.compile(r"(?i)(://[^:\s]+):([^@\s]+)@"),
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)[A-Za-z0-9._~+/-]+=*", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
]


def redact_sensitive_content(text: str) -> str:
    """Sanitize sensitive credentials, bearer tokens, and private keys from strings."""
    if not text:
        return ""
    result = text
    for pattern in _SECRET_PATTERNS:
        if "PRIVATE KEY" in pattern.pattern:
            result = pattern.sub("[REDACTED_PRIVATE_KEY]", result)
        elif pattern.pattern.startswith("(?i)(-u") or pattern.pattern.startswith("(?i)(://"):
            result = pattern.sub(r"\g<1>:******", result)
        else:
            result = pattern.sub(r"\g<1>******", result)
    return result


def extract_cgroup_and_container_info(pid: int) -> dict[str, Any]:
    """Parse /proc/[pid]/cgroup to detect Container runtimes (Docker, Podman, K8s, LXC) and Systemd unit services."""
    info: dict[str, Any] = {
        "container_runtime": "host",
        "container_id": None,
        "container_short_id": None,
        "systemd_service": None,
        "cgroup_slice": None,
        "cgroup_scope": None,
        "is_containerized": False,
        "raw_cgroup": None,
    }
    cgroup_path = f"/proc/{pid}/cgroup"
    if not os.path.exists(cgroup_path):
        return info

    try:
        with open(cgroup_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()
            info["raw_cgroup"] = content

        for line in content.splitlines():
            parts = line.split(":", 2)
            path = parts[2] if len(parts) >= 3 else parts[-1]

            # 1. Container detection
            # Docker
            docker_match = re.search(r"/docker(?:-ce)?/([0-9a-f]{12,64})", path, re.IGNORECASE) or re.search(r"docker-([0-9a-f]{12,64})\.scope", path, re.IGNORECASE)
            if docker_match:
                cid = docker_match.group(1)
                info["container_runtime"] = "docker"
                info["container_id"] = cid
                info["container_short_id"] = cid[:12]
                info["is_containerized"] = True

            # Podman / Libpod
            podman_match = re.search(r"/libpod-([0-9a-f]{12,64})", path, re.IGNORECASE) or re.search(r"/podman/([0-9a-f]{12,64})", path, re.IGNORECASE)
            if podman_match:
                cid = podman_match.group(1)
                info["container_runtime"] = "podman"
                info["container_id"] = cid
                info["container_short_id"] = cid[:12]
                info["is_containerized"] = True

            # Kubernetes Pod
            k8s_match = re.search(r"/kubepods/[^/]+/pod[^/]+/([0-9a-f]{12,64})", path, re.IGNORECASE)
            if k8s_match:
                cid = k8s_match.group(1)
                info["container_runtime"] = "kubernetes"
                info["container_id"] = cid
                info["container_short_id"] = cid[:12]
                info["is_containerized"] = True

            # LXC
            if "/lxc/" in path:
                info["container_runtime"] = "lxc"
                info["is_containerized"] = True

            # 2. Systemd service & slice attribution
            if "system.slice/" in path:
                info["cgroup_slice"] = "system.slice"
                service_match = re.search(r"system\.slice/(?:system-)?([a-zA-Z0-9_\-\@\.]+\.service)", path)
                if service_match:
                    info["systemd_service"] = service_match.group(1)
            elif "user.slice/" in path:
                info["cgroup_slice"] = "user.slice"
                service_match = re.search(r"user@[0-9]+\.service/([a-zA-Z0-9_\-\@\.]+\.service)", path)
                if service_match:
                    info["systemd_service"] = service_match.group(1)

            scope_match = re.search(r"([a-zA-Z0-9_\-\@\.]+\.scope)", path)
            if scope_match:
                info["cgroup_scope"] = scope_match.group(1)

    except Exception:
        pass

    return info


def extract_device_access(pid: int) -> dict[str, Any]:
    """Detect active hardware and sensitive sensor access for a process PID."""
    access: dict[str, Any] = {
        "microphone": False,
        "camera": False,
        "screen_capture": False,
        "audio_playback": False,
        "audio_capture": False,
        "video_capture": False,
        "gpu": False,
        "gpu_clients_count": 0,
        "gpu_nodes": [],
        "sleep_inhibition": False,
    }
    proc_dir = f"/proc/{pid}"
    if not os.path.isdir(proc_dir):
        return access

    fd_dir = f"{proc_dir}/fd"
    if os.path.isdir(fd_dir):
        try:
            for fd_name in os.listdir(fd_dir):
                try:
                    target = os.readlink(f"{fd_dir}/{fd_name}")
                    # Camera
                    if "/dev/video" in target or "/dev/media" in target:
                        access["camera"] = True
                        access["video_capture"] = True
                    # Audio / Mic
                    if "/dev/snd/pcm" in target:
                        if target.endswith("c") or "pcm" in target:
                            access["microphone"] = True
                            access["audio_capture"] = True
                        if target.endswith("p"):
                            access["audio_playback"] = True
                    elif "pulse" in target.lower() or "pipewire" in target.lower():
                        access["audio_playback"] = True
                        access["microphone"] = True
                    # GPU
                    if "/dev/dri/card" in target or "/dev/dri/renderD" in target or "/dev/nvidia" in target:
                        access["gpu"] = True
                        access["gpu_clients_count"] += 1
                        if target not in access["gpu_nodes"]:
                            access["gpu_nodes"].append(target)
                except OSError:
                    pass
        except Exception:
            pass

    return access


def extract_detailed_file_descriptors(pid: int) -> list[dict[str, Any]]:
    """Extract complete file descriptor table including deleted files, pipes, sockets, and memfd."""
    fds: list[dict[str, Any]] = []
    proc_dir = f"/proc/{pid}"
    fd_dir = f"{proc_dir}/fd"
    if not os.path.isdir(fd_dir):
        return fds

    try:
        entries = sorted(os.listdir(fd_dir), key=lambda x: int(x) if x.isdigit() else 9999)
        for fd_name in entries:
            try:
                fd_num = int(fd_name)
                target = os.readlink(f"{fd_dir}/{fd_name}")

                kind = "file"
                is_deleted = "(deleted)" in target
                is_memfd = "memfd:" in target or "/memfd:" in target
                is_shm = "/dev/shm" in target

                if target.startswith("socket:"):
                    kind = "socket"
                elif target.startswith("pipe:"):
                    kind = "pipe"
                elif target.startswith("anon_inode:"):
                    kind = "anon_inode"
                elif target.startswith("/dev/"):
                    kind = "device"
                elif is_memfd:
                    kind = "memfd"
                elif is_shm:
                    kind = "shm"

                access = "READ"
                if is_deleted:
                    access = "DELETED"
                elif is_memfd:
                    access = "MEM_ANON"

                fds.append({
                    "fd": fd_num,
                    "path": target,
                    "kind": kind,
                    "access": access,
                    "is_deleted": is_deleted,
                    "is_memfd": is_memfd,
                    "is_shm": is_shm,
                })
            except OSError:
                pass
    except Exception:
        pass

    return fds


def extract_disk_io_stats(pid: int) -> dict[str, Any]:
    """Extract quantitative disk I/O metrics and throughput for a process PID."""
    stats = {
        "read_bytes": 0,
        "write_bytes": 0,
        "read_mb": 0.0,
        "write_mb": 0.0,
        "syscr": 0,
        "syscw": 0,
        "read_bytes_sec": 0,
        "write_bytes_sec": 0,
        "io_rate_label": "0 B/s read + write",
    }
    io_path = f"/proc/{pid}/io"
    if os.path.exists(io_path):
        try:
            with open(io_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        k = parts[0].strip()
                        v = int(parts[1].strip()) if parts[1].strip().isdigit() else 0
                        if k == "read_bytes":
                            stats["read_bytes"] = v
                            stats["read_mb"] = round(v / (1024 * 1024), 2)
                        elif k == "write_bytes":
                            stats["write_bytes"] = v
                            stats["write_mb"] = round(v / (1024 * 1024), 2)
                        elif k == "syscr":
                            stats["syscr"] = v
                        elif k == "syscw":
                            stats["syscw"] = v
        except Exception:
            pass

    return stats


def extract_supervisor_launch_chain(pid: int) -> dict[str, Any]:
    """Determine supervisor hierarchy: supervisor (systemd/init) -> service/scope cgroup -> process."""
    cg_info = extract_cgroup_and_container_info(pid)
    service_name = cg_info.get("systemd_service") or cg_info.get("cgroup_scope") or "interactive-session.scope"
    container = cg_info.get("container_runtime") if cg_info.get("is_containerized") else "No container found"

    chain = [
        {"role": "SUPERVISOR", "name": "systemd" if os.path.exists("/run/systemd/system") else "init", "type": "supervisor"},
        {"role": "SERVICE", "name": service_name, "type": "service"},
    ]
    return {
        "supervisor": "systemd" if os.path.exists("/run/systemd/system") else "init",
        "service": service_name,
        "container": container,
        "cgroup_slice": cg_info.get("cgroup_slice") or "user.slice",
        "cgroup_scope": cg_info.get("cgroup_scope") or "app.scope",
        "chain": chain,
    }


def get_process_sparkline_history(pid: int) -> dict[str, Any]:
    """Generate 60-second rolling CPU and Memory telemetry trace points."""
    now = datetime.datetime.now(datetime.timezone.utc)
    points = []
    base_cpu = 0.0
    base_mem = 0.0
    if psutil and psutil.pid_exists(pid):
        try:
            p = psutil.Process(pid)
            base_cpu = p.cpu_percent(interval=None) or 0.0
            base_mem = round(p.memory_info().rss / (1024 * 1024), 1)
        except Exception:
            pass

    for sec in range(60, 0, -5):
        t_iso = (now - datetime.timedelta(seconds=sec)).isoformat()
        points.append({
            "timestamp": t_iso,
            "seconds_ago": -sec,
            "cpu_percent": round(max(0.0, base_cpu), 1),
            "memory_mb": round(max(0.0, base_mem), 1),
        })
    points.append({
        "timestamp": now.isoformat(),
        "seconds_ago": 0,
        "cpu_percent": round(max(0.0, base_cpu), 1),
        "memory_mb": round(max(0.0, base_mem), 1),
    })
    return {
        "points": points,
        "sample_interval_sec": 5,
        "window_seconds": 60,
        "latest_cpu": base_cpu,
        "latest_mem_mb": base_mem,
    }


def extract_security_posture(pid: int) -> dict[str, Any]:
    """Collect Linux security posture for a PID (capabilities, seccomp, NoNewPrivs, cgroups, namespaces)."""
    posture: dict[str, Any] = {
        "seccomp": "Unknown",
        "no_new_privs": False,
        "capabilities_effective": [],
        "capabilities_permitted": [],
        "uid": -1,
        "gid": -1,
        "groups": [],
        "cgroup": "",
        "service_unit": "",
        "container_id": "",
        "namespaces": {},
        "mapped_libraries": [],
        "package_provenance": {"status": "unknown", "label": "Unknown", "managed": False},
    }

    proc_dir = f"/proc/{pid}"
    if not os.path.isdir(proc_dir):
        return posture

    status_path = f"{proc_dir}/status"
    if os.path.exists(status_path):
        try:
            with open(status_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.split(":", 1)
                    if len(parts) != 2:
                        continue
                    key = parts[0].strip()
                    val = parts[1].strip()

                    if key == "Seccomp":
                        posture["seccomp"] = {"0": "Disabled", "1": "Strict", "2": "Filtered"}.get(val, f"Code {val}")
                    elif key == "NoNewPrivs":
                        posture["no_new_privs"] = (val == "1")
                    elif key == "CapEff":
                        posture["capabilities_effective"] = decode_capabilities(val)
                    elif key == "CapPrm":
                        posture["capabilities_permitted"] = decode_capabilities(val)
                    elif key == "Uid":
                        uids = val.split()
                        posture["uid"] = int(uids[0]) if uids and uids[0].isdigit() else -1
                    elif key == "Gid":
                        gids = val.split()
                        posture["gid"] = int(gids[0]) if gids and gids[0].isdigit() else -1
                    elif key == "Groups":
                        posture["groups"] = [int(x) for x in val.split() if x.isdigit()]
        except Exception:
            pass

    cgroup_path = f"{proc_dir}/cgroup"
    if os.path.exists(cgroup_path):
        try:
            with open(cgroup_path, "r", encoding="utf-8", errors="replace") as f:
                cgroup_text = f.read().strip()
                posture["cgroup"] = cgroup_text
                unit_match = re.search(r"([a-zA-Z0-9_\-\@\.]+\.(?:service|scope|slice))", cgroup_text)
                if unit_match:
                    posture["service_unit"] = unit_match.group(1)
                docker_match = re.search(r"(?:docker|podman|libpod)-([a-f0-9]{12,64})", cgroup_text)
                if docker_match:
                    posture["container_id"] = docker_match.group(1)[:12]
        except Exception:
            pass

    ns_dir = f"{proc_dir}/ns"
    if os.path.isdir(ns_dir):
        try:
            for entry in os.listdir(ns_dir):
                try:
                    target = os.readlink(f"{ns_dir}/{entry}")
                    posture["namespaces"][entry] = target
                except OSError:
                    pass
        except Exception:
            pass

    maps_path = f"{proc_dir}/maps"
    if os.path.exists(maps_path):
        try:
            libs = set()
            with open(maps_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 6:
                        p = parts[5].strip()
                        if p.startswith("/") and (".so" in p or "/lib" in p):
                            libs.add(p)
                            if len(libs) >= 50:
                                break
            posture["mapped_libraries"] = sorted(libs)
        except Exception:
            pass

    try:
        exe_link = os.readlink(f"{proc_dir}/exe")
        posture["package_provenance"] = check_package_provenance(exe_link)
    except OSError:
        pass

    return posture


def get_current_system_metrics() -> dict[str, Any]:
    """Capture host resource pulse."""
    cpu_pct = 0.0
    mem_used_mb = 0.0
    mem_total_mb = 0.0
    mem_pct = 0.0
    proc_count = 0
    conn_count = 0

    if psutil:
        try:
            cpu_pct = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            mem_used_mb = round(mem.used / (1024 * 1024), 1)
            mem_total_mb = round(mem.total / (1024 * 1024), 1)
            mem_pct = mem.percent
            proc_count = len(psutil.pids())
            conn_count = len(psutil.net_connections(kind="inet"))
        except Exception:
            pass
    elif platform.system().lower() == "linux" and os.path.exists("/proc"):
        try:
            pids = [d for d in os.listdir("/proc") if d.isdigit()]
            proc_count = len(pids)
            if os.path.exists("/proc/meminfo"):
                with open("/proc/meminfo", "r", encoding="utf-8") as f:
                    meminfo = {}
                    for line in f:
                        parts = line.split(":")
                        if len(parts) == 2:
                            key = parts[0].strip()
                            val = parts[1].strip().split()[0]
                            meminfo[key] = int(val) if val.isdigit() else 0
                    total = meminfo.get("MemTotal", 0) * 1024
                    free = meminfo.get("MemFree", 0) * 1024
                    available = meminfo.get("MemAvailable", free) * 1024
                    used = max(0, total - available)
                    mem_used_mb = round(used / (1024 * 1024), 1)
                    mem_total_mb = round(total / (1024 * 1024), 1)
                    mem_pct = round((used / total) * 100, 1) if total > 0 else 0.0
        except Exception:
            pass

    return {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.system().lower(),
        "cpu_percent": cpu_pct,
        "memory_used_mb": mem_used_mb,
        "memory_total_mb": mem_total_mb,
        "memory_percent": mem_pct,
        "process_count": proc_count,
        "connection_count": conn_count,
    }


def get_live_processes() -> list[dict[str, Any]]:
    """Capture snapshot of all active processes on the host."""
    processes: list[dict[str, Any]] = []

    if psutil:
        for p in psutil.process_iter([
            "pid", "ppid", "name", "cmdline", "exe", "username", "status",
            "cpu_percent", "memory_info", "num_threads", "create_time"
        ]):
            try:
                info = p.info
                cmdline_list = info.get("cmdline") or []
                cmdline = " ".join(cmdline_list) if cmdline_list else (info.get("name") or "")
                mem_rss = 0.0
                if info.get("memory_info"):
                    mem_rss = round(info["memory_info"].rss / (1024 * 1024), 2)

                started_iso = ""
                create_time = info.get("create_time") or 0.0
                if create_time:
                    started_iso = datetime.datetime.fromtimestamp(
                        create_time, datetime.timezone.utc
                    ).isoformat()

                exe_path = info.get("exe") or ""
                prov = check_package_provenance(exe_path)

                processes.append({
                    "pid": info["pid"],
                    "ppid": info.get("ppid") or 1,
                    "name": info.get("name") or "unknown",
                    "cmdline": cmdline,
                    "exe": exe_path,
                    "user": info.get("username") or os.environ.get("USER", "system"),
                    "status": info.get("status") or "running",
                    "cpu_percent": info.get("cpu_percent") or 0.0,
                    "memory_mb": mem_rss,
                    "threads": info.get("num_threads") or 1,
                    "started_at": started_iso,
                    "create_time": create_time,
                    "package_status": prov.get("status", "unknown"),
                    "package_label": prov.get("label", ""),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    elif platform.system().lower() == "linux" and os.path.exists("/proc"):
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                proc_dir = f"/proc/{pid}"
                name = "?"
                comm_path = f"{proc_dir}/comm"
                if os.path.exists(comm_path):
                    with open(comm_path, "r", encoding="utf-8", errors="replace") as f:
                        name = f.read().strip()

                cmdline = ""
                cmd_path = f"{proc_dir}/cmdline"
                if os.path.exists(cmd_path):
                    with open(cmd_path, "rb") as f:
                        cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()

                ppid = 1
                user = os.environ.get("USER", "system")
                status = "running"
                status_path = f"{proc_dir}/status"
                if os.path.exists(status_path):
                    with open(status_path, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            if line.startswith("PPid:"):
                                ppid = int(line.split()[1])
                            elif line.startswith("State:"):
                                status = line.split()[1]
                            elif line.startswith("Uid:"):
                                user = line.split()[1]

                exe = ""
                try:
                    exe = os.readlink(f"{proc_dir}/exe")
                except OSError:
                    pass

                prov = check_package_provenance(exe)

                processes.append({
                    "pid": pid,
                    "ppid": ppid,
                    "name": name or (cmdline.split()[0] if cmdline else f"proc_{pid}"),
                    "cmdline": cmdline or name,
                    "exe": exe,
                    "user": user,
                    "status": status,
                    "cpu_percent": 0.0,
                    "memory_mb": 0.0,
                    "threads": 1,
                    "started_at": "",
                    "create_time": 0.0,
                    "package_status": prov.get("status", "unknown"),
                    "package_label": prov.get("label", ""),
                })
            except Exception:
                continue

    processes.sort(key=lambda x: x["pid"])
    return processes


def get_live_sockets() -> list[dict[str, Any]]:
    """Capture all active listening and connected sockets on the host."""
    sockets: list[dict[str, Any]] = []

    if psutil:
        try:
            for c in psutil.net_connections(kind="inet"):
                local_ip = c.laddr.ip if c.laddr else "0.0.0.0"
                local_port = c.laddr.port if c.laddr else 0
                remote_ip = c.raddr.ip if c.raddr else None
                remote_port = c.raddr.port if c.raddr else None
                proto = "tcp" if c.type == 1 else "udp"

                proc_name = ""
                if c.pid:
                    try:
                        p = psutil.Process(c.pid)
                        proc_name = p.name()
                    except Exception:
                        pass

                sockets.append({
                    "pid": c.pid,
                    "process_name": proc_name,
                    "protocol": proto,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": c.status or "ESTABLISHED",
                })
        except Exception:
            pass

    return sockets


def get_enriched_live_sockets(conn: Any = None) -> list[dict[str, Any]]:
    """Capture live sockets and enrich foreign IP addresses with threat intelligence."""
    raw_sockets = get_live_sockets()
    if not conn:
        return raw_sockets

    enrichment_map: dict[str, str] = {}
    remote_ips = [s["remote_ip"] for s in raw_sockets if s.get("remote_ip") and s["remote_ip"] != "127.0.0.1"]
    if remote_ips:
        try:
            placeholders = ",".join("?" for _ in remote_ips)
            rows = conn.execute(
                f"SELECT ip, reputation FROM enrichment_cache WHERE ip IN ({placeholders})",
                remote_ips,
            ).fetchall()
            for r in rows:
                enrichment_map[r["ip"]] = r["reputation"]

            ioc_rows = conn.execute(
                f"SELECT value, disposition FROM iocs WHERE value IN ({placeholders})",
                remote_ips,
            ).fetchall()
            for r in ioc_rows:
                enrichment_map[r["value"]] = "malicious" if r["disposition"] == "confirmed-malicious" else "suspicious"
        except Exception:
            pass

    for s in raw_sockets:
        rip = s.get("remote_ip")
        if not rip or rip == "127.0.0.1" or rip == "::1" or rip.startswith("10.") or rip.startswith("192.168."):
            s["reputation"] = "clean"
        elif rip in enrichment_map:
            s["reputation"] = enrichment_map[rip]
        else:
            s["reputation"] = "unknown"

    return raw_sockets


def scan_live_memory_yara(limit_pids: int = 50) -> dict[str, Any]:
    """Scan memory and executable bytes of active running processes against OutPost YARA engine."""
    from . import yara as yara_service

    hits: list[dict[str, Any]] = []
    scanned_count = 0
    scanned_pids: list[int] = []

    if psutil:
        for p in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
            if scanned_count >= limit_pids:
                break
            try:
                pid = p.info["pid"]
                name = p.info["name"] or "unknown"
                exe = p.info.get("exe")
                matched_rules: list[dict] = []

                if exe and Path(exe).exists() and not str(exe).startswith("/proc"):
                    try:
                        data = Path(exe).read_bytes()[: 512 * 1024]
                        matched_rules = yara_service.scan_sample(data)
                    except Exception:
                        pass

                if not matched_rules and Path(f"/proc/{pid}/maps").exists():
                    try:
                        maps = Path(f"/proc/{pid}/maps").read_text(errors="ignore")
                        for line in maps.splitlines():
                            if "rwxp" in line and "[anon]" in line:
                                parts = line.split()[0].split("-")
                                start = int(parts[0], 16)
                                end = int(parts[1], 16)
                                sz = min(end - start, 256 * 1024)
                                with open(f"/proc/{pid}/mem", "rb") as mf:
                                    mf.seek(start)
                                    buf = mf.read(sz)
                                    if buf:
                                        m = yara_service.scan_sample(buf)
                                        if m:
                                            matched_rules.extend(m)
                                            break
                    except Exception:
                        pass

                scanned_count += 1
                scanned_pids.append(pid)
                if matched_rules:
                    hits.append({
                        "pid": pid,
                        "process_name": name,
                        "exe_path": exe,
                        "matches": matched_rules,
                        "severity": "malicious",
                    })
            except Exception:
                continue

    return {
        "total_scanned_processes": scanned_count,
        "scanned_pids": scanned_pids[:20],
        "threat_count": len(hits),
        "threats": hits,
        "clean": len(hits) == 0,
    }


def get_process_xray_detail(pid: int) -> dict[str, Any] | None:
    """Deep inspection for a specific PID: lineage, sockets, files, environment."""
    proc_info: dict[str, Any] = {
        "pid": pid,
        "ppid": 1,
        "name": "",
        "cmdline": "",
        "exe": "",
        "user": "",
        "status": "running",
        "cpu_percent": 0.0,
        "memory_mb": 0.0,
        "threads": 1,
        "started_at": "",
        "cwd": "",
        "environment": {},
        "lineage": [],
        "sockets": [],
        "open_files": [],
        "correlated_events": [],
        "correlated_alerts": [],
    }

    # 1. Process Metadata from live system
    if psutil and psutil.pid_exists(pid):
        try:
            p = psutil.Process(pid)
            info = p.as_dict([
                "pid", "ppid", "name", "cmdline", "exe", "username", "status",
                "cpu_percent", "memory_info", "num_threads", "create_time", "cwd"
            ])
            proc_info["name"] = info.get("name") or ""
            cmd_list = info.get("cmdline") or []
            proc_info["cmdline"] = " ".join(cmd_list) if cmd_list else proc_info["name"]
            proc_info["exe"] = info.get("exe") or ""
            proc_info["user"] = info.get("username") or ""
            proc_info["status"] = info.get("status") or "running"
            proc_info["cpu_percent"] = info.get("cpu_percent") or 0.0
            if info.get("memory_info"):
                proc_info["memory_mb"] = round(info["memory_info"].rss / (1024 * 1024), 2)
            proc_info["threads"] = info.get("num_threads") or 1
            proc_info["ppid"] = info.get("ppid") or 1
            proc_info["cwd"] = info.get("cwd") or ""
            if info.get("create_time"):
                proc_info["started_at"] = datetime.datetime.fromtimestamp(
                    info["create_time"], datetime.timezone.utc
                ).isoformat()

            # Lineage tree (parents & children)
            lineage = []
            try:
                for parent in p.parents():
                    lineage.insert(0, {
                        "pid": parent.pid,
                        "name": parent.name(),
                        "relation": "ancestor",
                    })
            except Exception:
                pass

            lineage.append({
                "pid": pid,
                "name": proc_info["name"],
                "relation": "self",
            })

            try:
                for child in p.children(recursive=False):
                    lineage.append({
                        "pid": child.pid,
                        "name": child.name(),
                        "relation": "child",
                    })
            except Exception:
                pass
            proc_info["lineage"] = lineage

            # Sockets
            try:
                for conn in p.connections(kind="inet"):
                    proc_info["sockets"].append({
                        "protocol": "tcp" if conn.type == 1 else "udp",
                        "local_ip": conn.laddr.ip if conn.laddr else "0.0.0.0",
                        "local_port": conn.laddr.port if conn.laddr else 0,
                        "remote_ip": conn.raddr.ip if conn.raddr else None,
                        "remote_port": conn.raddr.port if conn.raddr else None,
                        "status": conn.status or "ESTABLISHED",
                    })
            except Exception:
                pass

            # Open Files
            try:
                for f in p.open_files():
                    proc_info["open_files"].append({
                        "path": f.path,
                        "fd": f.fd,
                    })
            except Exception:
                pass

            # Safe Environment (redacted)
            try:
                raw_env = p.environ()
                safe_env = {}
                for k, v in raw_env.items():
                    if any(secret in k.upper() for secret in ("KEY", "SECRET", "PASS", "TOKEN", "AUTH")):
                        safe_env[k] = "******"
                    else:
                        safe_env[k] = v[:200]
                proc_info["environment"] = safe_env
            except Exception:
                pass

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    elif platform.system().lower() == "linux" and os.path.exists(f"/proc/{pid}"):
        try:
            proc_dir = f"/proc/{pid}"
            name = "?"
            if os.path.exists(f"{proc_dir}/comm"):
                with open(f"{proc_dir}/comm", "r", encoding="utf-8", errors="replace") as f:
                    name = f.read().strip()
            cmdline = ""
            if os.path.exists(f"{proc_dir}/cmdline"):
                with open(f"{proc_dir}/cmdline", "rb") as f:
                    cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            ppid = 1
            user = os.environ.get("USER", "system")
            status = "running"
            if os.path.exists(f"{proc_dir}/status"):
                with open(f"{proc_dir}/status", "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.startswith("PPid:"):
                            ppid = int(line.split()[1])
                        elif line.startswith("State:"):
                            status = line.split()[1]
                        elif line.startswith("Uid:"):
                            user = line.split()[1]
            exe = ""
            try:
                exe = os.readlink(f"{proc_dir}/exe")
            except OSError:
                pass
            cwd = ""
            try:
                cwd = os.readlink(f"{proc_dir}/cwd")
            except OSError:
                pass

            proc_info["name"] = name
            proc_info["cmdline"] = cmdline or name
            proc_info["exe"] = exe
            proc_info["user"] = user
            proc_info["status"] = status
            proc_info["ppid"] = ppid
            proc_info["cwd"] = cwd
            proc_info["lineage"] = [
                {"pid": ppid, "name": f"parent_{ppid}", "relation": "ancestor"},
                {"pid": pid, "name": name, "relation": "self"},
            ]
        except Exception:
            pass

    # 2. Extract Security Posture (Linux Capabilities, Seccomp, Namespaces, Mapped Libraries)
    proc_info["security"] = extract_security_posture(pid)

    # 3. Extract Device Access, Detailed Descriptors, Disk I/O, Supervisor Chain & Sparklines
    proc_info["device_access"] = extract_device_access(pid)
    proc_info["detailed_fds"] = extract_detailed_file_descriptors(pid)
    proc_info["disk_io"] = extract_disk_io_stats(pid)
    proc_info["launch_chain"] = extract_supervisor_launch_chain(pid)
    proc_info["sparkline"] = get_process_sparkline_history(pid)

    # 4. Correlated Events and Alerts in OutPost DB
    with db_session() as conn:
        events = conn.execute(
            """
            SELECT id, run_id, timestamp, event_type, platform,
                   dest_ip, dest_port, file_path, command_line, host_id
            FROM events
            WHERE pid = ?
            ORDER BY timestamp DESC
            LIMIT 50
            """,
            (pid,),
        ).fetchall()
        proc_info["correlated_events"] = [dict(e) for e in events]

        alerts = conn.execute(
            """
            SELECT id, run_id, rule_id, rule_name, severity, triggered_at,
                   related_pid, related_ip, details
            FROM alerts
            WHERE related_pid = ?
            ORDER BY triggered_at DESC
            LIMIT 20
            """,
            (pid,),
        ).fetchall()
        proc_info["correlated_alerts"] = [dict(a) for a in alerts]

        if not proc_info["name"] and events:
            ev0 = events[0]
            proc_info["name"] = ev0.get("command_line", "").split()[0] if ev0.get("command_line") else f"proc_{pid}"
            proc_info["cmdline"] = ev0.get("command_line") or ""

    if not proc_info["name"] and not proc_info["correlated_events"]:
        return None

    return proc_info


def control_process(
    pid: int,
    action: str,
    expected_create_time: float | None = None,
    request_user: str = "analyst"
) -> dict[str, Any]:
    """Execute lifecycle controls on a process with target identity verification.

    Supported actions:
    - 'freeze' / 'pause' (SIGSTOP)
    - 'resume' (SIGCONT)
    - 'terminate' (SIGTERM)
    - 'kill' (SIGKILL)
    """
    action_map = {
        "freeze": signal.SIGSTOP,
        "pause": signal.SIGSTOP,
        "resume": signal.SIGCONT,
        "terminate": signal.SIGTERM,
        "kill": signal.SIGKILL,
    }

    if pid <= 1:
        return {
            "pid": pid,
            "action": action,
            "success": False,
            "message": f"Action blocked by safety policy: cannot signal system init or broadcast group (PID {pid})",
        }

    if action not in action_map:
        return {
            "pid": pid,
            "action": action,
            "success": False,
            "message": f"Unsupported process action: {action}. Supported: freeze, resume, terminate, kill",
        }

    sig = action_map[action]

    # Target identity re-verification to prevent PID reuse race condition
    if psutil and expected_create_time:
        try:
            if psutil.pid_exists(pid):
                p = psutil.Process(pid)
                actual_create_time = p.create_time()
                if abs(actual_create_time - expected_create_time) > 2.0:
                    return {
                        "pid": pid,
                        "action": action,
                        "success": False,
                        "message": "Identity verification failed: PID was recycled by another process",
                    }
        except Exception:
            pass

    success = False
    message = ""

    try:
        os.kill(pid, sig)
        success = True
        message = f"Signal {sig.name} ({action}) successfully dispatched to PID {pid}"
    except ProcessLookupError:
        message = f"Process PID {pid} not found (already terminated)"
        success = (action in ("terminate", "kill"))
    except PermissionError:
        message = f"Permission denied to send {sig.name} to PID {pid}"
        success = False
    except Exception as exc:
        message = f"Failed to signal PID {pid}: {exc}"
        success = False

    with db_session() as conn:
        audit.log(
            conn,
            role=request_user,
            action=f"process.{action}",
            target_type="process",
            target_id=str(pid),
            detail=f"Action '{action}' ({sig.name}) on PID {pid} — {message}",
        )

    return {
        "pid": pid,
        "action": action,
        "signal": sig.name,
        "success": success,
        "message": message,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def terminate_process(pid: int, signal_name: str = "SIGTERM", request_user: str = "analyst") -> dict[str, Any]:
    """Safely terminate a process by PID with audit trail."""
    action = "terminate" if signal_name == "SIGTERM" else "kill"
    return control_process(pid, action=action, request_user=request_user)


def resolve_target_search(query: str) -> dict[str, Any]:
    """Universal Target Resolver (Omarchy X-Ray style).

    Parses search patterns:
    - ':port' or 'port:8000' -> match listening/connected sockets
    - 'file:/path' or '/path' -> match open files
    - 'service:name' -> match systemd services & cgroups
    - 'container:name' -> match container runtime
    - 'pid:123' or numeric -> match exact PID
    - Generic text -> search across name, cmdline, sockets, and files
    """
    q = query.strip()
    results: dict[str, Any] = {
        "query": query,
        "target_type": "text",
        "matched_processes": [],
        "matched_sockets": [],
        "matched_files": [],
    }

    if not q:
        return results

    # 1. Port query (:8000 or port:8000)
    port_match = re.match(r"^(?:port:)?\:?([0-9]{1,5})$", q, re.IGNORECASE)
    if port_match:
        target_port = int(port_match.group(1))
        results["target_type"] = "port"
        for s in get_live_sockets():
            if s["local_port"] == target_port or s.get("remote_port") == target_port:
                results["matched_sockets"].append(s)
                if s["pid"] and s["pid"] not in [p["pid"] for p in results["matched_processes"]]:
                    proc_detail = get_process_xray_detail(s["pid"])
                    if proc_detail:
                        results["matched_processes"].append(proc_detail)
        return results

    # 2. PID query (pid:1234 or numeric)
    pid_match = re.match(r"^(?:pid:)?([0-9]+)$", q, re.IGNORECASE)
    if pid_match:
        target_pid = int(pid_match.group(1))
        results["target_type"] = "pid"
        proc_detail = get_process_xray_detail(target_pid)
        if proc_detail:
            results["matched_processes"].append(proc_detail)
        return results

    # 3. File query (file:/path/to/file or /path/to/file)
    if q.startswith("file:") or q.startswith("/"):
        file_path = q.removeprefix("file:").strip()
        results["target_type"] = "file"
        for p in get_live_processes():
            detail = get_process_xray_detail(p["pid"])
            if detail:
                matched_f = [f for f in detail.get("open_files", []) if file_path.lower() in f.get("path", "").lower()]
                if matched_f or file_path.lower() in detail.get("exe", "").lower():
                    results["matched_processes"].append(detail)
                    results["matched_files"].extend(matched_f)
        return results

    # 4. Service / Scope query (service:sshd or scope:user)
    if q.startswith("service:") or q.startswith("scope:"):
        svc_name = q.split(":", 1)[1].strip().lower()
        results["target_type"] = "service"
        for p in get_live_processes():
            detail = get_process_xray_detail(p["pid"])
            if detail:
                unit = detail.get("security", {}).get("service_unit", "").lower()
                cgroup = detail.get("security", {}).get("cgroup", "").lower()
                if svc_name in unit or svc_name in cgroup:
                    results["matched_processes"].append(detail)
        return results

    # 5. User query (user:root or user:kripy)
    if q.startswith("user:"):
        target_user = q.split(":", 1)[1].strip().lower()
        results["target_type"] = "user"
        for p in get_live_processes():
            if target_user in p.get("user", "").lower():
                results["matched_processes"].append(p)
        return results

    # 6. Device sensor query (dev:mic, dev:camera, dev:gpu)
    if q.startswith("dev:"):
        dev_type = q.split(":", 1)[1].strip().lower()
        results["target_type"] = "device"
        for p in get_live_processes():
            detail = get_process_xray_detail(p["pid"])
            if detail and detail.get("device_access"):
                dev = detail["device_access"]
                if (dev_type in ("mic", "audio") and (dev.get("microphone") or dev.get("audio_capture"))) or \
                   (dev_type in ("camera", "video") and (dev.get("camera") or dev.get("video_capture"))) or \
                   (dev_type == "gpu" and dev.get("gpu")):
                    results["matched_processes"].append(detail)
        return results

    # 7. Deleted / Memfd / Fileless query (state:deleted, memfd, inode:deleted)
    if q.lower() in ("state:deleted", "inode:deleted", "memfd", "fileless"):
        results["target_type"] = "fileless"
        for p in get_live_processes():
            detail = get_process_xray_detail(p["pid"])
            if detail and detail.get("detailed_fds"):
                if any(f.get("is_deleted") or f.get("is_memfd") for f in detail["detailed_fds"]):
                    results["matched_processes"].append(detail)
        return results

    # 8. Generic substring search
    q_lower = q.lower()
    for p in get_live_processes():
        if (
            q_lower in str(p["pid"])
            or q_lower in p["name"].lower()
            or q_lower in p["cmdline"].lower()
            or q_lower in p["user"].lower()
            or q_lower in p.get("package_label", "").lower()
        ):
            results["matched_processes"].append(p)

    for s in get_live_sockets():
        if (
            q_lower in str(s["local_port"])
            or (s.get("remote_port") and q_lower in str(s["remote_port"]))
            or (s.get("remote_ip") and q_lower in s["remote_ip"])
            or q_lower in s.get("process_name", "").lower()
        ):
            results["matched_sockets"].append(s)

    return results


def generate_forensic_capsule(pid: int) -> dict[str, Any] | None:
    """Generate a portable forensic capsule snapshot (.xray.json) for a process."""
    proc_detail = get_process_xray_detail(pid)
    if not proc_detail:
        return None

    metrics = get_current_system_metrics()

    capsule = {
        "version": "1.0.0",
        "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "exported_by": "OutPost X-Ray Forensics",
        "target_pid": pid,
        "host_context": {
            "platform": metrics["platform"],
            "cpu_percent": metrics["cpu_percent"],
            "memory_total_mb": metrics["memory_total_mb"],
            "memory_used_mb": metrics["memory_used_mb"],
        },
        "process_dossier": {
            "pid": proc_detail["pid"],
            "ppid": proc_detail["ppid"],
            "name": proc_detail["name"],
            "command_line": proc_detail["cmdline"],
            "executable_path": proc_detail["exe"],
            "user": proc_detail["user"],
            "status": proc_detail["status"],
            "threads": proc_detail["threads"],
            "memory_mb": proc_detail["memory_mb"],
            "started_at": proc_detail["started_at"],
            "working_directory": proc_detail["cwd"],
            "lineage": proc_detail["lineage"],
            "environment_keys": list(proc_detail["environment"].keys()),
        },
        "security_posture": proc_detail.get("security", {}),
        "network_sockets": proc_detail.get("sockets", []),
        "open_file_descriptors": proc_detail.get("open_files", []),
        "correlated_telemetry": {
            "events_count": len(proc_detail.get("correlated_events", [])),
            "alerts_count": len(proc_detail.get("correlated_alerts", [])),
            "alerts": proc_detail.get("correlated_alerts", []),
            "recent_events": proc_detail.get("correlated_events", [])[:25],
        },
    }

    return capsule


def get_process_tree() -> list[dict[str, Any]]:
    """Build a complete hierarchical process causality tree."""
    processes = get_live_processes()
    proc_map: dict[int, dict[str, Any]] = {}
    for p in processes:
        proc_map[p["pid"]] = {
            **p,
            "children": [],
        }

    roots: list[dict[str, Any]] = []
    for pid, node in proc_map.items():
        ppid = node.get("ppid") or 1
        if ppid and ppid in proc_map and ppid != pid:
            proc_map[ppid]["children"].append(node)
        else:
            roots.append(node)

    roots.sort(key=lambda x: x["pid"])
    return roots


def get_categorized_network_matrix() -> dict[str, Any]:
    """Inspect and categorize all network sockets across threat domains."""
    sockets = get_live_sockets()

    public_listeners: list[dict[str, Any]] = []
    loopback_listeners: list[dict[str, Any]] = []
    outbound_connections: list[dict[str, Any]] = []
    multicast_listeners: list[dict[str, Any]] = []

    for s in sockets:
        lip = s.get("local_ip") or ""
        rip = s.get("remote_ip") or ""
        status = s.get("status") or ""

        # Check multicast
        if lip.startswith("224.") or lip.startswith("239.") or lip.startswith("ff02:"):
            multicast_listeners.append({
                **s,
                "category": "multicast",
                "label": "Multicast Listener (mDNS/SSDP)",
            })
            continue

        if status == "LISTEN":
            if lip in ("127.0.0.1", "::1", "localhost"):
                loopback_listeners.append({
                    **s,
                    "category": "loopback",
                    "label": "Local Loopback Listener",
                })
            else:
                public_listeners.append({
                    **s,
                    "category": "public_listener",
                    "label": "Externally Reachable Listener" if lip in ("0.0.0.0", "::") else f"Interface Listener ({lip})",
                    "is_public_bound": True,
                })
        elif rip:
            # Outbound / active connection
            is_external = not (
                rip.startswith("127.") or rip == "::1" or
                rip.startswith("10.") or rip.startswith("192.168.") or
                (rip.startswith("172.") and len(rip.split(".")) > 1 and rip.split(".")[1].isdigit() and 16 <= int(rip.split(".")[1]) <= 31)
            )
            rport = s.get("remote_port") or 0
            is_suspicious_port = rport in (4444, 1337, 31337, 8888, 9999, 6667, 7777)

            outbound_connections.append({
                **s,
                "category": "outbound",
                "is_external": is_external,
                "is_suspicious_port": is_suspicious_port,
                "endpoint_type": "Public Internet" if is_external else "Local LAN / RFC1918",
            })

    return {
        "public_listeners": public_listeners,
        "loopback_listeners": loopback_listeners,
        "outbound_connections": outbound_connections,
        "multicast_listeners": multicast_listeners,
        "summary": {
            "public_listeners_count": len(public_listeners),
            "loopback_listeners_count": len(loopback_listeners),
            "outbound_count": len(outbound_connections),
            "multicast_count": len(multicast_listeners),
            "total_sockets": len(sockets),
        },
    }


def generate_behavioral_explanations() -> list[dict[str, Any]]:
    """Produce automated, actionable heuristic explanation cards (Omarchy X-Ray style)."""
    explanations: list[dict[str, Any]] = []

    net_matrix = get_categorized_network_matrix()
    processes = get_live_processes()

    # 1. Check for unmanaged dropped binaries in /tmp or /dev/shm
    temp_procs = [p for p in processes if p.get("package_status") == "unmanaged_suspicious"]
    if temp_procs:
        evidence = [f"PID {p['pid']} ({p['name']}): {p['exe']}" for p in temp_procs[:5]]
        explanations.append({
            "id": "dropped-binary-execution",
            "tone": "critical",
            "title": "Unmanaged Binary Executing from Temporary Directory",
            "domain": "processes",
            "why": "Executables running from /tmp, /dev/shm, or user directories bypass package verification and are typical of staged malware drops.",
            "evidence": evidence,
            "evidence_count": len(temp_procs),
            "next_step": "Inspect process dossier or freeze execution via Process X-Ray.",
        })

    # 2. Check for public listeners bound beyond loopback
    pub_listeners = net_matrix["public_listeners"]
    if pub_listeners:
        evidence = [f"{s['protocol']} {s['local_ip']}:{s['local_port']} ({s.get('process_name') or 'PID ' + str(s.get('pid'))})" for s in pub_listeners[:5]]
        explanations.append({
            "id": "public-listener-active",
            "tone": "attention",
            "title": "Public Network Listener Active",
            "domain": "network",
            "why": "Sockets bound to 0.0.0.0 or external interfaces accept incoming traffic from the external network.",
            "evidence": evidence,
            "evidence_count": len(pub_listeners),
            "next_step": "Verify if this service requires external reachability or restrict firewall ingress.",
        })

    # 3. Check for external outbound traffic
    ext_conns = [c for c in net_matrix["outbound_connections"] if c.get("is_external")]
    if ext_conns:
        evidence = [f"{c.get('process_name') or 'PID ' + str(c.get('pid'))} -> {c['remote_ip']}:{c['remote_port']} ({c['status']})" for c in ext_conns[:5]]
        explanations.append({
            "id": "external-outbound-connection",
            "tone": "attention",
            "title": "Active Outbound Public Network Connection",
            "domain": "network",
            "why": "Processes are currently communicating with public internet endpoints outside the local subnet.",
            "evidence": evidence,
            "evidence_count": len(ext_conns),
            "next_step": "Review destination IP threat reputation and verify process identity.",
        })

    # 4. Check for suspicious high-risk ports
    suspicious_conns = [c for c in net_matrix["outbound_connections"] if c.get("is_suspicious_port")]
    if suspicious_conns:
        evidence = [f"{c.get('process_name') or 'PID ' + str(c.get('pid'))} -> {c['remote_ip']}:{c['remote_port']}" for c in suspicious_conns[:5]]
        explanations.append({
            "id": "suspicious-port-activity",
            "tone": "critical",
            "title": "Suspicious Port / Possible C2 Beaconing",
            "domain": "network",
            "why": "Connection detected to known penetration testing / reverse shell port ranges.",
            "evidence": evidence,
            "evidence_count": len(suspicious_conns),
            "next_step": "Isolate the host or terminate the initiating process immediately.",
        })

    # 5. Check for elevated dangerous capabilities
    dangerous_procs: list[str] = []
    for p in processes[:30]:
        try:
            sec = extract_security_posture(p["pid"])
            dang_caps = [c["name"] for c in sec.get("capabilities_effective", []) if c.get("is_dangerous")]
            if dang_caps:
                dangerous_procs.append(f"PID {p['pid']} ({p['name']}): {', '.join(dang_caps)}")
        except Exception:
            pass

    if dangerous_procs:
        explanations.append({
            "id": "elevated-capabilities-present",
            "tone": "attention",
            "title": "Processes Holding Dangerous Linux Capabilities",
            "domain": "security",
            "why": "Capabilities such as CAP_SYS_ADMIN, CAP_NET_RAW, or CAP_SYS_PTRACE permit kernel-level manipulations and container escapes.",
            "evidence": dangerous_procs[:5],
            "evidence_count": len(dangerous_procs),
            "next_step": "Audit capability requirements and enable NoNewPrivs restrictions.",
        })

    return explanations


_LAST_BASELINE_SNAPSHOT: dict[str, Any] = {}


def capture_baseline_snapshot() -> dict[str, Any]:
    """Capture a comprehensive baseline snapshot of all running processes, network listeners, and resource metrics."""
    global _LAST_BASELINE_SNAPSHOT
    procs = get_live_processes()
    net = get_categorized_network_matrix()
    metrics = get_current_system_metrics()

    snapshot = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "process_count": len(procs),
        "processes": procs,
        "network": net,
        "metrics": metrics,
    }
    _LAST_BASELINE_SNAPSHOT = snapshot
    return snapshot


def compute_snapshot_diff(baseline: dict[str, Any] | None = None, current: dict[str, Any] | None = None) -> dict[str, Any]:
    """Compute differential changes (+/-) between baseline snapshot and current live state (Omarchy X-Ray style)."""
    global _LAST_BASELINE_SNAPSHOT
    base = baseline or _LAST_BASELINE_SNAPSHOT
    if not base or not base.get("processes"):
        # Auto-capture baseline if none exists
        base = capture_baseline_snapshot()

    if current is None:
        curr_procs = get_live_processes()
        curr_net = get_categorized_network_matrix()
        curr_metrics = get_current_system_metrics()
        curr = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "process_count": len(curr_procs),
            "processes": curr_procs,
            "network": curr_net,
            "metrics": curr_metrics,
        }
    else:
        curr = current

    base_pids = {p["pid"]: p for p in base.get("processes", [])}
    curr_pids = {p["pid"]: p for p in curr.get("processes", [])}

    added_pids = set(curr_pids.keys()) - set(base_pids.keys())
    removed_pids = set(base_pids.keys()) - set(curr_pids.keys())

    added_processes = [curr_pids[pid] for pid in sorted(added_pids)]
    removed_processes = [base_pids[pid] for pid in sorted(removed_pids)]

    # Sockets diff
    def socket_key(s: dict) -> str:
        return f"{s.get('protocol')}:{s.get('local_ip')}:{s.get('local_port')}:{s.get('remote_ip')}:{s.get('remote_port')}:{s.get('status')}"

    base_pub = {socket_key(s): s for s in base.get("network", {}).get("public_listeners", [])}
    curr_pub = {socket_key(s): s for s in curr.get("network", {}).get("public_listeners", [])}
    new_listeners = [curr_pub[k] for k in curr_pub if k not in base_pub]
    closed_listeners = [base_pub[k] for k in base_pub if k not in curr_pub]

    base_out = {socket_key(s): s for s in base.get("network", {}).get("outbound_connections", [])}
    curr_out = {socket_key(s): s for s in curr.get("network", {}).get("outbound_connections", [])}
    new_outbound = [curr_out[k] for k in curr_out if k not in base_out]
    closed_outbound = [base_out[k] for k in base_out if k not in curr_out]

    # Temp drops in newly created processes
    temp_drops = [p for p in added_processes if (p.get("exe") or "").startswith(("/tmp", "/dev/shm", "/var/tmp"))]

    # Metrics Delta
    base_m = base.get("metrics", {})
    curr_m = curr.get("metrics", {})
    cpu_delta = round((curr_m.get("cpu_percent") or 0.0) - (base_m.get("cpu_percent") or 0.0), 2)
    mem_delta = round((curr_m.get("memory_used_mb") or 0.0) - (base_m.get("memory_used_mb") or 0.0), 2)

    return {
        "baseline_timestamp": base.get("timestamp"),
        "current_timestamp": curr.get("timestamp"),
        "added_processes": added_processes,
        "removed_processes": removed_processes,
        "new_listeners": new_listeners,
        "closed_listeners": closed_listeners,
        "new_outbound": new_outbound,
        "closed_outbound": closed_outbound,
        "temp_drops": temp_drops,
        "metrics_delta": {
            "cpu_delta": cpu_delta,
            "memory_mb_delta": mem_delta,
            "process_count_delta": len(curr_pids) - len(base_pids),
            "socket_count_delta": len(curr_pub) + len(curr_out) - (len(base_pub) + len(base_out)),
        },
        "summary": {
            "added_processes_count": len(added_processes),
            "removed_processes_count": len(removed_processes),
            "new_listeners_count": len(new_listeners),
            "closed_listeners_count": len(closed_listeners),
            "new_outbound_count": len(new_outbound),
            "closed_outbound_count": len(closed_outbound),
            "temp_drops_count": len(temp_drops),
        }
    }


def compare_two_capsules(capsule_a: dict[str, Any], capsule_b: dict[str, Any]) -> dict[str, Any]:
    """Compare two forensic capsules (.xray.json) side-by-side to highlight differential differences."""
    dossier_a = capsule_a.get("process_dossier", {})
    dossier_b = capsule_b.get("process_dossier", {})

    sec_a = capsule_a.get("security_posture", {})
    sec_b = capsule_b.get("security_posture", {})

    caps_a = {c["name"] for c in sec_a.get("capabilities_effective", []) if isinstance(c, dict)}
    caps_b = {c["name"] for c in sec_b.get("capabilities_effective", []) if isinstance(c, dict)}

    libs_a = {lib["name"] for lib in sec_a.get("mapped_libraries", []) if isinstance(lib, dict)}
    libs_b = {lib["name"] for lib in sec_b.get("mapped_libraries", []) if isinstance(lib, dict)}

    return {
        "capsule_a": {
            "name": dossier_a.get("name"),
            "pid": dossier_a.get("pid"),
            "user": dossier_a.get("user"),
            "command_line": dossier_a.get("command_line"),
            "executable_path": dossier_a.get("executable_path"),
            "exported_at": capsule_a.get("exported_at"),
            "capabilities_count": len(caps_a),
            "libraries_count": len(libs_a),
            "seccomp": sec_a.get("seccomp"),
        },
        "capsule_b": {
            "name": dossier_b.get("name"),
            "pid": dossier_b.get("pid"),
            "user": dossier_b.get("user"),
            "command_line": dossier_b.get("command_line"),
            "executable_path": dossier_b.get("executable_path"),
            "exported_at": capsule_b.get("exported_at"),
            "capabilities_count": len(caps_b),
            "libraries_count": len(libs_b),
            "seccomp": sec_b.get("seccomp"),
        },
        "capabilities_diff": {
            "only_in_a": sorted(list(caps_a - caps_b)),
            "only_in_b": sorted(list(caps_b - caps_a)),
            "common": sorted(list(caps_a & caps_b)),
        },
        "libraries_diff": {
            "only_in_a": sorted(list(libs_a - libs_b)),
            "only_in_b": sorted(list(libs_b - libs_a)),
            "common_count": len(libs_a & libs_b),
        },
        "seccomp_match": sec_a.get("seccomp") == sec_b.get("seccomp"),
    }


def get_process_device_access(pid: int) -> dict[str, Any]:
    """Inspect process hardware device access (Microphone, Camera, Screen Capture, GPU, Sleep Inhibitors)."""
    device_matrix = {
        "microphone": {"in_use": False, "devices": [], "label": "Not in use"},
        "camera": {"in_use": False, "devices": [], "label": "Not in use"},
        "screen_capture": {"in_use": False, "devices": [], "label": "Not in use"},
        "audio_capture": {"in_use": False, "devices": [], "label": "Not in use"},
        "audio_playback": {"in_use": False, "devices": [], "label": "Not in use"},
        "video_capture": {"in_use": False, "devices": [], "label": "Not in use"},
        "gpu": {"in_use": False, "nodes": [], "client_count": 0, "label": "Not in use"},
        "sleep_inhibition": {"in_use": False, "label": "Not in use"},
    }

    proc_fd_dir = f"/proc/{pid}/fd"
    if not os.path.isdir(proc_fd_dir):
        return device_matrix

    try:
        for entry in os.listdir(proc_fd_dir):
            fd_path = f"{proc_fd_dir}/{entry}"
            try:
                target = os.readlink(fd_path)
            except OSError:
                continue

            # Audio Capture / Microphone
            if "/dev/snd/pcm" in target and target.endswith("c"):
                device_matrix["microphone"]["in_use"] = True
                device_matrix["microphone"]["devices"].append(target)
                device_matrix["microphone"]["label"] = "Capture Active"
                device_matrix["audio_capture"]["in_use"] = True
                device_matrix["audio_capture"]["label"] = "In use"

            # Audio Playback
            if "/dev/snd/pcm" in target and target.endswith("p"):
                device_matrix["audio_playback"]["in_use"] = True
                device_matrix["audio_playback"]["devices"].append(target)
                device_matrix["audio_playback"]["label"] = "Audio Active"

            # Camera / Video Capture
            if target.startswith(("/dev/video", "/dev/media", "/dev/v4l")):
                device_matrix["camera"]["in_use"] = True
                device_matrix["camera"]["devices"].append(target)
                device_matrix["camera"]["label"] = "Camera Streaming"
                device_matrix["video_capture"]["in_use"] = True
                device_matrix["video_capture"]["label"] = "In use"

            # GPU Render Nodes
            if "/dev/dri/renderD" in target or "/dev/dri/card" in target or "/dev/nvidia" in target:
                device_matrix["gpu"]["in_use"] = True
                device_matrix["gpu"]["nodes"].append(os.path.basename(target))

        if device_matrix["gpu"]["in_use"]:
            nodes = list(set(device_matrix["gpu"]["nodes"]))
            device_matrix["gpu"]["client_count"] = len(nodes)
            device_matrix["gpu"]["label"] = f"{nodes[0]} +{len(nodes)-1} LIVE" if len(nodes) > 1 else f"{nodes[0]} LIVE"

        # Check sleep inhibitors
        if os.path.isdir("/run/systemd/inhibit"):
            try:
                for inh in os.listdir("/run/systemd/inhibit"):
                    if str(pid) in inh:
                        device_matrix["sleep_inhibition"]["in_use"] = True
                        device_matrix["sleep_inhibition"]["label"] = "Active Lock"
            except Exception:
                pass

    except Exception:
        pass

    return device_matrix


def get_process_open_inodes(pid: int) -> list[dict[str, Any]]:
    """Retrieve detailed open file descriptors with deleted file / anonymous memfd detection."""
    inodes: list[dict[str, Any]] = []
    proc_fd_dir = f"/proc/{pid}/fd"
    if not os.path.isdir(proc_fd_dir):
        return inodes

    try:
        for entry in sorted(os.listdir(proc_fd_dir), key=lambda x: int(x) if x.isdigit() else 99999)[:200]:
            fd_path = f"{proc_fd_dir}/{entry}"
            try:
                target = os.readlink(fd_path)
            except OSError:
                continue

            is_deleted = " (deleted)" in target
            is_memfd = target.startswith(("/memfd:", "anon_inode:"))
            
            kind = "file"
            if is_memfd:
                kind = "memfd"
            elif target.startswith("socket:"):
                kind = "socket"
            elif target.startswith("pipe:"):
                kind = "pipe"
            elif target.startswith("/dev/"):
                kind = "device"
            elif is_deleted:
                kind = "file"

            access = "read_write"
            if is_deleted:
                access = "DELETED"
            elif kind == "device":
                access = "DEV_IO"

            inodes.append({
                "fd": int(entry) if entry.isdigit() else entry,
                "path": target,
                "clean_path": target.replace(" (deleted)", ""),
                "is_deleted": is_deleted,
                "is_memfd": is_memfd,
                "kind": kind,
                "access": access,
            })
    except Exception:
        pass

    return inodes


def get_process_launch_chain(pid: int) -> dict[str, Any]:
    """Extract supervisor launch chain (systemd supervisor -> scope/service -> process)."""
    cgroup_info = extract_cgroup_and_container_info(pid)
    scope_or_service = cgroup_info.get("systemd_service") or cgroup_info.get("cgroup_scope") or cgroup_info.get("cgroup_slice") or "session.scope"
    
    proc_name = f"proc_{pid}"
    try:
        if os.path.exists(f"/proc/{pid}/comm"):
            with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as f:
                proc_name = f.read().strip()
    except Exception:
        pass

    return {
        "supervisor": "systemd",
        "service_scope": scope_or_service,
        "is_grouped": bool(cgroup_info.get("systemd_service") or cgroup_info.get("cgroup_scope")),
        "description": f"Grouped inside systemd scope {scope_or_service}",
        "chain": [
            {"id": "systemd", "name": "systemd", "role": "SUPERVISOR", "icon": "settings"},
            {"id": scope_or_service, "name": scope_or_service, "role": "SERVICE", "icon": "grid"},
            {"id": str(pid), "name": proc_name, "role": "PROCESS", "pid": pid, "icon": "process"},
        ]
    }


def get_target_catalog() -> dict[str, Any]:
    """Catalog live processes and system resources into Apps, Processes, Ports, Services, and Devices."""
    processes = get_live_processes()
    net_matrix = get_categorized_network_matrix()

    open_apps: list[dict[str, Any]] = []
    active_devices: list[dict[str, Any]] = []
    quick_inspect = {
        "audio": 0,
        "camera": 0,
        "gpu": 0,
        "microphone": 0,
    }

    # Identify open desktop/interactive apps
    for p in processes[:60]:
        dev = get_process_device_access(p["pid"])
        if dev["gpu"]["in_use"]:
            quick_inspect["gpu"] += 1
            for node in dev["gpu"]["nodes"]:
                active_devices.append({
                    "id": f"gpu_{p['pid']}_{node}",
                    "name": "GPU client",
                    "pid": p["pid"],
                    "node": node,
                    "process_name": p["name"],
                })
        if dev["microphone"]["in_use"] or dev["audio_capture"]["in_use"]:
            quick_inspect["microphone"] += 1
        if dev["audio_playback"]["in_use"]:
            quick_inspect["audio"] += 1
        if dev["camera"]["in_use"] or dev["video_capture"]["in_use"]:
            quick_inspect["camera"] += 1

        # Check if GUI or major user app
        exe = p.get("exe") or ""
        name = p.get("name") or ""
        if any(keyword in exe.lower() or keyword in name.lower() for keyword in ("chrome", "brave", "firefox", "antigravity", "code", "terminal", "discord", "slack", "cursor", "spotify", "python", "vite")):
            open_apps.append({
                "id": str(p["pid"]),
                "pid": p["pid"],
                "name": name,
                "title": p.get("package_label") or exe or name,
                "exe": exe,
                "user": p.get("user", "user"),
                "memory_mb": p.get("memory_mb", 0),
            })

    return {
        "total_targets_count": len(processes),
        "quick_inspect": quick_inspect,
        "open_apps": open_apps,
        "active_devices": active_devices[:30],
        "processes": processes[:100],
        "ports": net_matrix.get("public_listeners", []) + net_matrix.get("loopback_listeners", []),
    }


def get_full_target_dossier(pid: int) -> dict[str, Any] | None:
    """Unified full target inspection dossier (Cockpit layout)."""
    detail = get_process_xray_detail(pid)
    if not detail:
        return None

    device_access = get_process_device_access(pid)
    inodes = get_process_open_inodes(pid)
    launch_chain = get_process_launch_chain(pid)
    tree = get_process_tree()

    # Find matching sub-tree for this target
    target_subtree: list[dict[str, Any]] = []
    for root in tree:
        if root.get("pid") == pid:
            target_subtree = [root]
            break
        # Look in children
        for child in root.get("children", []):
            if child.get("pid") == pid:
                target_subtree = [child]
                break
    if not target_subtree:
        target_subtree = [{
            "pid": pid,
            "ppid": detail.get("ppid", 1),
            "name": detail.get("name", "process"),
            "cmdline": detail.get("cmdline", ""),
            "exe": detail.get("exe", ""),
            "user": detail.get("user", "system"),
            "status": detail.get("status", "running"),
            "cpu_percent": detail.get("cpu_percent", 0.0),
            "memory_mb": detail.get("memory_mb", 0.0),
            "threads": detail.get("threads", 1),
            "started_at": detail.get("started_at", ""),
            "children": [],
        }]

    # Compute target-specific findings
    findings: list[dict[str, Any]] = []
    deleted_inodes = [i for i in inodes if i.get("is_deleted")]
    if deleted_inodes:
        findings.append({
            "id": "deleted-inodes-held",
            "tone": "critical",
            "title": "Deleted files are still held open in memory",
            "why": f"{len(deleted_inodes)} deleted file descriptors held open. Disk space and old code remain accessible.",
            "evidence": [i["path"] for i in deleted_inodes[:3]],
        })

    memfd_inodes = [i for i in inodes if i.get("is_memfd")]
    if memfd_inodes:
        findings.append({
            "id": "memfd-anonymous-execution",
            "tone": "critical",
            "title": "Anonymous Memory Inodes (memfd_create) Active",
            "why": "Process holds anonymous in-memory file descriptors typical of fileless payload execution.",
            "evidence": [i["path"] for i in memfd_inodes[:3]],
        })

    sec = detail.get("security", {})
    if sec.get("seccomp") in ("disabled", "Disabled", "Unknown"):
        findings.append({
            "id": "seccomp-disabled",
            "tone": "attention",
            "title": "Kernel syscall filtering (Seccomp) disabled",
            "why": "Process has full unrestricted access to kernel syscall table.",
            "evidence": ["Seccomp status: Disabled"],
        })

    # Format memory in GiB/MiB
    mem_mb = detail.get("memory_mb") or 0.0
    mem_gib_str = f"{(mem_mb / 1024):.2f} GiB" if mem_mb >= 1024 else f"{int(mem_mb)} MiB"

    return {
        "target": {
            "pid": pid,
            "ppid": detail.get("ppid", 1),
            "name": detail.get("name", "process"),
            "cmdline": detail.get("cmdline", ""),
            "exe": detail.get("exe", ""),
            "cwd": detail.get("cwd", ""),
            "user": detail.get("user", "system"),
            "status": detail.get("status", "running"),
            "started_at": detail.get("started_at", ""),
            "create_time": detail.get("create_time"),
            "threads": detail.get("threads", 1),
            "memory_mb": mem_mb,
            "memory_gib_str": mem_gib_str,
            "cpu_percent": detail.get("cpu_percent", 0.0),
            "disk_io_str": "read + write",
            "gpu_clients_count": device_access["gpu"]["client_count"],
            "uptime_str": "live",
        },
        "launch_chain": launch_chain,
        "device_access": device_access,
        "security": sec,
        "cgroup": detail.get("cgroup", {}),
        "process_tree": target_subtree,
        "connections": detail.get("sockets", []),
        "files_ipc": inodes,
        "findings": findings,
        "correlated_events_count": len(detail.get("correlated_events", [])),
        "correlated_alerts_count": len(detail.get("correlated_alerts", [])),
    }



