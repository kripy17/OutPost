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

                                ev = {
                                    "run_id": run_id,
                                    "platform": platform_name,
                                    "event_type": "process_create",
                                    "timestamp": now_iso,
                                    "pid": pid,
                                    "ppid": ppid,
                                    "process_name": comm,
                                    "command_line": cmd_raw or comm,
                                    "exe_path": str(entry / "exe"),
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

            # 3. Check memory maps for RWX pages (shellcode / unpacked payloads)
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
                    except Exception:
                        pass
        except Exception:
            pass

        await asyncio.sleep(0.05)


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

    try:
        for path in sandbox_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.resolve() == original_target.resolve():
                continue
            try:
                rel = path.relative_to(sandbox_dir)
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

                artifacts.append({
                    "name": str(rel),
                    "filename": path.name,
                    "size_bytes": len(raw),
                    "sha256": sha256,
                    "md5": md5,
                    "entropy": ent,
                    "is_high_entropy": ent > 7.0,
                    "preview": text_preview,
                    "artifact_id": f"{run_id}_{sha256[:12]}",
                    "download_url": f"/api/sandbox/artifacts/{run_id}/{artifact_filename}",
                })
            except Exception:
                pass
    except Exception:
        pass

    return artifacts
