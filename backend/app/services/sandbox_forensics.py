"""Dynamic Sandbox Forensics, Process Tree Poller & Artifact Extractor.

Provides deep execution introspection for OutPost's dynamic malware analysis:
- Kernel /proc polling for child process discovery, open sockets, and memory maps
- Shannon entropy analysis for dropped and encrypted artifacts
- Persistent artifact capture and preview generation
- Chronological behavioral timeline assembly
- C2 network and DNS sinkholing telemetry
"""

import asyncio
import datetime
import hashlib
import ipaddress
import math
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from ..core import config
from ..core.db import db_session
from ..models import event as event_store
from . import yara as yara_service


def calculate_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of raw binary data (0.0 to 8.0)."""
    if not data:
        return 0.0
    occ = [0] * 256
    for b in data:
        occ[b] += 1
    ent = 0.0
    total = len(data)
    for count in occ:
        if count > 0:
            p = count / total
            ent -= p * math.log2(p)
    return round(ent, 3)


def resolve_socket_endpoints(pid: int, inode: int) -> dict[str, Any] | None:
    """Inspect Linux /proc tables for the given socket inode to determine protocol,
    local/remote IP addresses, ports, and connection state.
    """
    for proto in ("tcp", "udp", "tcp6", "udp6"):
        for net_dir in (Path(f"/proc/{pid}/net"), Path("/proc/net")):
            table_path = net_dir / proto
            if not table_path.exists():
                continue
            try:
                lines = table_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                # Inode is at column index 9 in /proc/net/tcp, udp, tcp6, udp6
                if parts[9] == str(inode):
                    is_v6 = "6" in proto
                    base_proto = "tcp" if "tcp" in proto else "udp"
                    try:
                        loc_ip_hex, loc_port_hex = parts[1].split(":")
                        rem_ip_hex, rem_port_hex = parts[2].split(":")
                        loc_port = int(loc_port_hex, 16)
                        rem_port = int(rem_port_hex, 16)
                        if is_v6:
                            loc_bytes = b"".join([bytes.fromhex(loc_ip_hex)[i:i+4][::-1] for i in range(0, 16, 4)])
                            loc_ip = str(ipaddress.IPv6Address(loc_bytes))
                            rem_bytes = b"".join([bytes.fromhex(rem_ip_hex)[i:i+4][::-1] for i in range(0, 16, 4)])
                            rem_ip = str(ipaddress.IPv6Address(rem_bytes))
                        else:
                            loc_ip = str(ipaddress.IPv4Address(bytes.fromhex(loc_ip_hex)[::-1]))
                            rem_ip = str(ipaddress.IPv4Address(bytes.fromhex(rem_ip_hex)[::-1]))
                        state = parts[3]
                        # 0A is TCP_LISTEN; for UDP, rem_port == 0 is listening/unconnected
                        is_listen = (state == "0A") or (rem_port == 0 and rem_ip in ("0.0.0.0", "::"))
                        return {
                            "protocol": base_proto,
                            "state": state,
                            "is_listen": is_listen,
                            "local_ip": loc_ip,
                            "local_port": loc_port,
                            "dest_ip": rem_ip,
                            "dest_port": rem_port,
                        }
                    except Exception:
                        continue
    return None


async def poll_sandbox_process_tree(
    main_pid: int,
    run_id: str,
    platform_name: str,
    sandbox_dir: Path,
    events_batch: list[dict[str, Any]],
    timeline_events: list[dict[str, Any]],
    stop_event: asyncio.Event,
    start_time_mono: float,
) -> None:
    """Actively monitor Linux /proc during sandbox execution to discover
    forked child processes, in-memory deleted inodes, open sockets, and RWX memory pages.
    """
    seen_pids = {main_pid}
    seen_fds: set[tuple[int, str]] = set()

    while not stop_event.is_set():
        try:
            # 1. Discover child processes from /proc
            proc_root = Path("/proc")
            if proc_root.exists():
                for entry in proc_root.iterdir():
                    if not entry.name.isdigit():
                        continue
                    pid = int(entry.name)
                    if pid in seen_pids:
                        continue
                    try:
                        stat_file = entry / "stat"
                        if stat_file.exists():
                            parts = stat_file.read_text().split()
                            ppid = int(parts[3])
                            if ppid in seen_pids:
                                seen_pids.add(pid)
                                cmd_raw = (
                                    (entry / "cmdline")
                                    .read_bytes()
                                    .replace(b"\x00", b" ")
                                    .decode(errors="ignore")
                                    .strip()
                                )
                                comm = (
                                    (entry / "comm").read_text().strip()
                                    if (entry / "comm").exists()
                                    else parts[1].strip("()")
                                )
                                now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                                elapsed_ms = int((time.monotonic() - start_time_mono) * 1000)

                                resolved_exe = ""
                                try:
                                    resolved_exe = os.readlink(entry / "exe")
                                except OSError:
                                    if cmd_raw:
                                        first = cmd_raw.split()[0]
                                        if first.startswith("/"):
                                            resolved_exe = first

                                ev = {
                                    "run_id": run_id,
                                    "platform": platform_name,
                                    "event_type": "process_create",
                                    "timestamp": now_iso,
                                    "pid": pid,
                                    "ppid": ppid,
                                    "process_name": comm,
                                    "command_line": cmd_raw or comm,
                                    "exe_path": resolved_exe,
                                    "host_id": "local",
                                }
                                events_batch.append(ev)
                                with db_session() as conn:
                                    ev["id"] = event_store.insert_event(conn, ev)

                                is_sus = any(
                                    b in comm.lower()
                                    for b in ("sh", "bash", "curl", "wget", "cmd", "powershell", "python", "nc")
                                )
                                timeline_events.append({
                                    "timestamp": now_iso,
                                    "elapsed_ms": elapsed_ms,
                                    "category": "process",
                                    "title": f"Spawned Child Process: {comm} (PID {pid})",
                                    "details": f"Command: {cmd_raw or comm} | Parent PID: {ppid}",
                                    "severity": "suspicious" if is_sus else "info",
                                })
                    except Exception:
                        pass

            # 2. Inspect FDs of all tracked PIDs for deleted inodes & sockets
            for p in list(seen_pids):
                fd_dir = Path(f"/proc/{p}/fd")
                if not fd_dir.exists():
                    continue
                try:
                    for fd_link in fd_dir.iterdir():
                        try:
                            target = os.readlink(fd_link)
                        except OSError:
                            continue
                        key = (p, target)
                        if key in seen_fds:
                            continue
                        seen_fds.add(key)
                        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                        elapsed_ms = int((time.monotonic() - start_time_mono) * 1000)

                        if "(deleted)" in target:
                            # Genuine fileless malware unlinks payloads in volatile temp directories (/tmp, /dev/shm, /var/tmp, memfd:)
                            # Exclude inherited system/editor/library caches and desktop IPC
                            is_volatile_drop = any(target.startswith(v) for v in ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/", "memfd:"))
                            if not is_volatile_drop or any(ignored in target for ignored in (
                                "/dev/shm/.org.chromium", "/dev/shm/pulse", "/dev/shm/wayland",
                                "/dev/dri", "/tmp/#", "/opt/", "/usr/", "/lib", ".cache", "node_modules"
                            )):
                                continue
                            # Fileless in-memory execution / unlinked binary
                            ev = {
                                "run_id": run_id,
                                "platform": platform_name,
                                "event_type": "file_delete",
                                "timestamp": now_iso,
                                "pid": p,
                                "file_path": target,
                                "host_id": "local",
                            }
                            events_batch.append(ev)
                            with db_session() as conn:
                                ev["id"] = event_store.insert_event(conn, ev)
                            timeline_events.append({
                                "timestamp": now_iso,
                                "elapsed_ms": elapsed_ms,
                                "category": "memory",
                                "title": "Fileless Inode Execution (Unlinked Payload in Memory)",
                                "details": f"PID {p} holds open descriptor to unlinked file: {target}",
                                "severity": "malicious",
                            })
                        elif target.startswith("socket:["):
                            inode_str = target[len("socket:[") : -1]
                            sock_info = None
                            if inode_str.isdigit():
                                sock_info = resolve_socket_endpoints(p, int(inode_str))

                            if sock_info:
                                is_listen = sock_info["is_listen"]
                                if is_listen:
                                    ev = {
                                        "run_id": run_id,
                                        "platform": platform_name,
                                        "event_type": "socket_listen",
                                        "timestamp": now_iso,
                                        "pid": p,
                                        "src_ip": sock_info["local_ip"],
                                        "src_port": sock_info["local_port"],
                                        "protocol": sock_info["protocol"],
                                        "host_id": "local",
                                    }
                                    events_batch.append(ev)
                                    with db_session() as conn:
                                        ev["id"] = event_store.insert_event(conn, ev)
                                    timeline_events.append({
                                        "timestamp": now_iso,
                                        "elapsed_ms": elapsed_ms,
                                        "category": "network",
                                        "title": f"Local Socket Listening: {sock_info['protocol'].upper()} :{sock_info['local_port']}",
                                        "details": f"PID {p} bound listening socket on {sock_info['local_ip']}:{sock_info['local_port']}",
                                        "severity": "suspicious" if sock_info["local_port"] in (4444, 1337, 8888, 6667) else "info",
                                    })
                                else:
                                    ev = {
                                        "run_id": run_id,
                                        "platform": platform_name,
                                        "event_type": "network_connection",
                                        "timestamp": now_iso,
                                        "pid": p,
                                        "src_ip": sock_info["local_ip"],
                                        "src_port": sock_info["local_port"],
                                        "dest_ip": sock_info["dest_ip"],
                                        "dest_port": sock_info["dest_port"],
                                        "protocol": sock_info["protocol"],
                                        "host_id": "local",
                                    }
                                    events_batch.append(ev)
                                    with db_session() as conn:
                                        ev["id"] = event_store.insert_event(conn, ev)
                                    timeline_events.append({
                                        "timestamp": now_iso,
                                        "elapsed_ms": elapsed_ms,
                                        "category": "network",
                                        "title": f"Network Egress Connection: {sock_info['dest_ip']}:{sock_info['dest_port']}",
                                        "details": f"PID {p} connected to {sock_info['dest_ip']}:{sock_info['dest_port']} ({sock_info['protocol'].upper()})",
                                        "severity": "malicious" if sock_info["dest_port"] in (4444, 1337, 6667, 8888) else "suspicious",
                                    })
                            else:
                                timeline_events.append({
                                    "timestamp": now_iso,
                                    "elapsed_ms": elapsed_ms,
                                    "category": "network",
                                    "title": f"Socket Allocated: {target}",
                                    "details": f"PID {p} opened active network socket {target}",
                                    "severity": "info",
                                })
                except Exception:
                    pass

            # 3. Check memory maps for RWX pages & carve in-memory payloads
            for p in list(seen_pids):
                maps_file = Path(f"/proc/{p}/maps")
                if maps_file.exists():
                    try:
                        content = maps_file.read_text(errors="ignore")
                        for line in content.splitlines():
                            if "rwxp" in line and (line.endswith("[anon]") or " " not in line.strip().split()[-1]):
                                key = (p, "rwxp")
                                if key not in seen_fds:
                                    seen_fds.add(key)
                                    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                                    elapsed_ms = int((time.monotonic() - start_time_mono) * 1000)
                                    timeline_events.append({
                                        "timestamp": now_iso,
                                        "elapsed_ms": elapsed_ms,
                                        "category": "memory",
                                        "title": "Suspicious Memory Allocation (RWX Anonymous Page)",
                                        "details": f"PID {p} mapped RWX memory page without backing file: {line.strip()}",
                                        "severity": "malicious",
                                    })

                                    # Attempt in-memory carving from /proc/[pid]/mem
                                    try:
                                        addr_parts = line.split()[0].split("-")
                                        start_addr = int(addr_parts[0], 16)
                                        end_addr = int(addr_parts[1], 16)
                                        carve_size = min(end_addr - start_addr, 512 * 1024)
                                        mem_path = Path(f"/proc/{p}/mem")
                                        if mem_path.exists() and carve_size > 0:
                                            with open(mem_path, "rb") as mf:
                                                mf.seek(start_addr)
                                                carved = mf.read(carve_size)
                                                if carved and any(b != 0 for b in carved[:256]):
                                                    c_ent = calculate_entropy(carved)
                                                    yara_hits = yara_service.scan_sample(carved)
                                                    yara_desc = f" | YARA: {', '.join(h['name'] for h in yara_hits)}" if yara_hits else ""
                                                    c_name = f"memdump_pid_{p}_{hex(start_addr)}.bin"
                                                    art_dir = config.DATA_DIR / "sandbox_artifacts" / run_id
                                                    art_dir.mkdir(parents=True, exist_ok=True)
                                                    (art_dir / c_name).write_bytes(carved)
                                                    timeline_events.append({
                                                        "timestamp": now_iso,
                                                        "elapsed_ms": elapsed_ms,
                                                        "category": "memory",
                                                        "title": f"In-Memory Carved Payload ({c_name})",
                                                        "details": f"Extracted {len(carved)} bytes from PID {p} memory space. Shannon Entropy: {c_ent}/8.0{yara_desc}",
                                                        "severity": "malicious" if (yara_hits or c_ent > 6.8) else "suspicious",
                                                    })
                                    except Exception:
                                        pass
                    except Exception:
                        pass
        except Exception:
            pass

        await asyncio.sleep(0.05)


def extract_malware_config(sample_bytes: bytes, text_content: str = "") -> dict[str, Any]:
    """Automated Malware Config & Threat Score Extractor.
    Extracts embedded C2 IP endpoints, URLs, crypto ransom wallets, and behavioral tags.
    """
    decoded = text_content
    if not decoded and sample_bytes:
        decoded = sample_bytes.decode("latin1", errors="ignore")

    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    all_ips = set(ip_pattern.findall(decoded))
    c2_ips = [
        ip for ip in all_ips
        if not (ip.startswith("127.") or ip.startswith("0.") or ip.startswith("255.") or ip == "8.8.8.8" or ip == "1.1.1.1")
    ]

    url_pattern = re.compile(r"https?://[a-zA-Z0-9_\-\.:]+(?:/[a-zA-Z0-9_\-\./\?=&%]*)?")
    urls = list(set(url_pattern.findall(decoded)))[:8]

    btc_pattern = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
    monero_pattern = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
    wallets = list(set(btc_pattern.findall(decoded) + monero_pattern.findall(decoded)))[:5]

    ransom_keywords = ["ransom", "bitcoin", "decrypt", "restore your files", "encrypted", ".lockbit", "shadows delete"]
    found_ransom = [kw for kw in ransom_keywords if kw in decoded.lower()]

    score = 0
    indicators = []
    if c2_ips:
        score += min(len(c2_ips) * 15, 30)
        indicators.append(f"Contains {len(c2_ips)} external C2 network endpoint(s)")
    if urls:
        score += min(len(urls) * 10, 20)
        indicators.append(f"Embedded URLs identified ({len(urls)})")
    if wallets:
        score += 35
        indicators.append(f"Cryptocurrency extortion wallet address identified")
    if found_ransom:
        score += 25
        indicators.append(f"Ransomware terminology identified: {', '.join(found_ransom[:3])}")

    ent = calculate_entropy(sample_bytes) if sample_bytes else 0.0
    if ent > 7.1:
        score += 25
        indicators.append(f"High Shannon entropy ({ent:.2f}/8.0) indicating packed/encrypted payload")
    elif ent > 6.4:
        score += 15
        indicators.append(f"Elevated Shannon entropy ({ent:.2f}/8.0)")

    score = min(score, 100)
    verdict = "MALICIOUS" if score >= 60 else "SUSPICIOUS" if score >= 30 else "BENIGN"

    return {
        "threat_score": score,
        "verdict": verdict,
        "entropy": ent,
        "c2_ips": c2_ips[:8],
        "urls": urls,
        "crypto_wallets": wallets,
        "ransom_indicators": found_ransom,
        "behavioral_indicators": indicators,
    }


def extract_dropped_artifacts(
    sandbox_dir: Path,
    original_target: Path,
    run_id: str,
) -> list[dict[str, Any]]:
    """Scan sandbox workspace for any created or modified files,
    compute hashes, Shannon entropy, and persist artifacts for UI review.
    """
    artifacts_dir = config.DATA_DIR / "sandbox_artifacts" / run_id
    try:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    artifacts: list[dict[str, Any]] = []

    EXCLUDED_DIRS = {".wine", ".cache", ".local", "__pycache__", ".git", "windows", "system32", "syswow64"}
    try:
        for path in sandbox_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.resolve() == original_target.resolve():
                continue
            rel = path.relative_to(sandbox_dir)
            if any(part.lower() in EXCLUDED_DIRS for part in rel.parts):
                continue
            if len(artifacts) >= 50:
                break
            try:
                raw = path.read_bytes()
                sha256 = hashlib.sha256(raw).hexdigest()
                md5 = hashlib.md5(raw).hexdigest()
                ent = calculate_entropy(raw)

                # Persist artifact
                artifact_filename = f"{sha256[:12]}_{path.name}"
                dest = artifacts_dir / artifact_filename
                try:
                    dest.write_bytes(raw)
                except Exception:
                    pass

                # Extract preview strings
                text_preview = []
                for s in re.findall(r"[\x20-\x7e]{4,}", raw.decode("latin1", errors="ignore")):
                    clean = s.strip()
                    if clean and clean not in text_preview:
                        text_preview.append(clean)
                    if len(text_preview) >= 8:
                        break

                parsed_config = extract_malware_config(raw, " ".join(text_preview))
                yara_hits = yara_service.scan_sample(raw)

                artifacts.append({
                    "name": str(rel),
                    "filename": path.name,
                    "size_bytes": len(raw),
                    "sha256": sha256,
                    "md5": md5,
                    "entropy": ent,
                    "is_high_entropy": ent > 7.0,
                    "preview": text_preview,
                    "config": parsed_config,
                    "yara_hits": yara_hits,
                    "artifact_id": f"{run_id}_{sha256[:12]}",
                    "download_url": f"/api/sandbox/artifacts/{run_id}/{artifact_filename}",
                })
            except Exception:
                pass
    except Exception:
        pass

    # Also harvest any in-memory carved buffers from execution
    try:
        if artifacts_dir.exists():
            for mem_file in artifacts_dir.glob("memdump_*.bin"):
                try:
                    m_raw = mem_file.read_bytes()
                    m_sha256 = hashlib.sha256(m_raw).hexdigest()
                    m_md5 = hashlib.md5(m_raw).hexdigest()
                    m_ent = calculate_entropy(m_raw)
                    m_yara = yara_service.scan_sample(m_raw)
                    m_preview = []
                    for s in re.findall(r"[\x20-\x7e]{4,}", m_raw.decode("latin1", errors="ignore")):
                        clean = s.strip()
                        if clean and clean not in m_preview:
                            m_preview.append(clean)
                        if len(m_preview) >= 8:
                            break
                    m_config = extract_malware_config(m_raw, " ".join(m_preview))
                    artifacts.append({
                        "name": f"[In-Memory Carved] {mem_file.name}",
                        "filename": mem_file.name,
                        "size_bytes": len(m_raw),
                        "sha256": m_sha256,
                        "md5": m_md5,
                        "entropy": m_ent,
                        "is_high_entropy": m_ent > 7.0,
                        "preview": m_preview,
                        "config": m_config,
                        "yara_hits": m_yara,
                        "artifact_id": f"{run_id}_{m_sha256[:12]}",
                        "download_url": f"/api/sandbox/artifacts/{run_id}/{mem_file.name}",
                    })
                except Exception:
                    pass
    except Exception:
        pass

    return artifacts

