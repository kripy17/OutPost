"""Live system snapshot — processes + listening ports, stdlib only.

The collector ships this on an interval while an agent is running, so the
webapp's Agents page and Live Monitor can show "what's running NOW" on each
host — the Event-Viewer parity view, not just the event stream.

Cross-platform, best-effort by design: a snapshot failure (permission,
missing tool, odd format) degrades to an empty-but-valid payload and never
crashes the collector. Linux reads /proc directly; Windows shells out to
`tasklist` + `netstat -ano`; macOS to `ps` + `netstat -anv`.
"""

import datetime
import json
import os
import re
import subprocess
import sys


def utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _base(host_id: str, platform: str) -> dict:
    return {"host_id": host_id, "platform": platform, "collected_at": utcnow(), "processes": [], "listening": []}


# -- Linux: /proc ---------------------------------------------------------------


def _linux(host_id: str) -> dict:
    out = _base(host_id, "linux")

    # Listening sockets: inode -> (proto, addr, port). /proc/net/tcp[6] rows are
    # `sl local rem st ... inode`; state 0A is LISTEN.
    listen = {}
    for path, proto in (("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6"), ("/proc/net/udp", "udp"), ("/proc/net/udp6", "udp6")):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                next(fh, None)  # header
                for line in fh:
                    parts = line.split()
                    if len(parts) < 10 or parts[3] != "0A":
                        continue
                    local = parts[1]
                    if ":" in local:
                        hex_ip, hex_port = local.rsplit(":", 1)
                    else:
                        continue
                    port = int(hex_port, 16)
                    ip = _hex_ipv4(hex_ip) if proto.endswith(("tcp", "udp")) and len(hex_ip) <= 8 else _hex_ipv6(hex_ip)
                    listen[parts[9]] = (proto, ip, port)  # inode -> endpoint
        except (OSError, IndexError, ValueError):
            continue

    # Processes: pid -> name (+ user). /proc/<pid>/fd/* symlinks map inodes back
    # to the owning pid for listening ports.
    pids = []
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except OSError:
        pass

    fd_inode_to_pid = {}
    for pid in pids:
        fd_dir = f"/proc/{pid}/fd"
        try:
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(f"{fd_dir}/{fd}")
                except OSError:
                    continue
                m = re.match(r"socket:\[(\d+)\]", target)
                if m:
                    fd_inode_to_pid.setdefault(m.group(1), pid)
        except OSError:
            continue

    for pid in sorted(pids, key=int):
        try:
            with open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace") as fh:
                name = fh.read().strip()[:64] or "?"
        except OSError:
            continue
        cmdline = ""
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmdline = fh.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()[:200]
        except OSError:
            pass
        user = ""
        try:
            with open(f"/proc/{pid}/status", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("Uid:"):
                        user = line.split()[1]
                        break
        except OSError:
            pass
        out["processes"].append({"pid": int(pid), "name": name, "user": user, "cmdline": cmdline})

    for inode, (proto, ip, port) in listen.items():
        out["listening"].append({
            "proto": proto, "addr": ip, "port": port,
            "pid": int(fd_inode_to_pid[inode]) if inode in fd_inode_to_pid else None,
        })
    return out


def _hex_ipv4(hex_ip: str) -> str:
    try:
        raw = bytes.fromhex(hex_ip)
        if len(raw) == 4:
            return ".".join(str(b) for b in raw)
    except ValueError:
        pass
    return "0.0.0.0"


def _hex_ipv6(hex_ip: str) -> str:
    try:
        raw = bytes.fromhex(hex_ip)
        if len(raw) == 16:
            import ipaddress

            return str(ipaddress.IPv6Address(raw))
    except (ValueError, ImportError):
        pass
    return "::"


# -- Windows / macOS: shell out -------------------------------------------------


def _windows(host_id: str) -> dict:
    out = _base(host_id, "windows")
    try:
        procs = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=15, check=False
        ).stdout
        for line in procs.splitlines():
            m = re.match(r'"([^"]*)","(\d+)"', line.strip())
            if m:
                out["processes"].append({"pid": int(m.group(2)), "name": m.group(1), "user": "", "cmdline": ""})
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        net = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=15, check=False).stdout
        for line in net.splitlines():
            parts = line.split()
            if len(parts) >= 5 and "LISTENING" in parts:
                proto = parts[0].lower()
                addr, port = parts[1].rsplit(":", 1)
                out["listening"].append({"proto": proto, "addr": addr, "port": int(port), "pid": int(parts[-1])})
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return out


def _macos(host_id: str) -> dict:
    out = _base(host_id, "macos")
    try:
        ps = subprocess.run(["ps", "-axo", "pid=,comm="], capture_output=True, text=True, timeout=15, check=False).stdout
        for line in ps.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                out["processes"].append({"pid": int(parts[0]), "name": parts[1][:64], "user": "", "cmdline": ""})
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    try:
        net = subprocess.run(["netstat", "-anv", "-p", "tcp"], capture_output=True, text=True, timeout=15, check=False).stdout
        for line in net.splitlines():
            if "LISTEN" not in line:
                continue
            parts = line.split()
            if len(parts) >= 4:
                addr, port = parts[3].rsplit(".", 1)
                out["listening"].append({"proto": "tcp", "addr": addr, "port": int(port), "pid": None})
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return out


# -- Public entry ---------------------------------------------------------------


def collect_snapshot(host_id: str, platform: str | None = None) -> dict:
    """Collect a live snapshot for the host. `platform` defaults to the current
    OS; the agent's host is the machine it runs on, so platform is derived from
    sys.platform unless the caller knows better."""
    platform = (platform or sys.platform).lower()
    if platform in ("win32", "windows", "win"):
        snap = _windows(host_id)
    elif platform in ("darwin", "macos"):
        snap = _macos(host_id)
    else:
        snap = _linux(host_id)
    # Never ship a partially-shaped payload: the schema fields are fixed.
    snap.setdefault("processes", [])
    snap.setdefault("listening", [])
    return snap


def dumps(host_id: str, platform: str | None = None) -> str:
    return json.dumps(collect_snapshot(host_id, platform))
