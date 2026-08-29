"""Volatility3 memory-forensics integration (docs/08-INTEGRATIONS.md #7).

Runs the `vol` CLI against a hypervisor memory dump captured at the end of a
bounded detonation window and cross-references the observed process list
against the run's own telemetry: a process Volatility sees that the collector
never logged is itself an interesting finding (hidden / direct-syscall /
kernel-assisted execution worth an analyst's eyes).

Honest-degradation rules mirror static_analysis.run_capa: without the tool on
PATH nothing fakes results — callers get {"available": false, ...}.
"""

import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ..core import config
from ..models import event as event_store

_ADDR_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?")


def _vol_binary() -> str | None:
    """Explicit OUTPOST_VOLATILITY_PATH first, then `vol`/`volatility3` on PATH."""
    explicit = config.VOLATILITY_PATH.strip()
    if explicit:
        return explicit if Path(explicit).exists() else None
    for name in ("vol", "volatility3"):
        found = shutil.which(name)
        if found:
            return found
    return None


def vol_status() -> dict[str, Any]:
    """Honest tool report — configured vs actually runnable, never faked."""
    explicit = config.VOLATILITY_PATH.strip()
    binary = _vol_binary()
    report: dict[str, Any] = {
        "configured": bool(explicit),
        "available": binary is not None,
        "binary": binary,
        "timeout_seconds": config.VOLATILITY_TIMEOUT,
    }
    if binary is None:
        if explicit:
            report["error"] = f"OUTPOST_VOLATILITY_PATH does not exist: {explicit}"
        else:
            report["error"] = "volatility3 not installed (set OUTPOST_VOLATILITY_PATH or install volatility3)"
    return report


def _iter_rows(payload: Any) -> list[dict[str, Any]]:
    """Harvest candidate row dicts from a vol3 `-r json` payload.

    Modern shape: {"sections": [{"name": ..., "rows": [...]}, ...]}. Some
    plugin/render versions emit a top-level "rows" or a bare list instead.
    Anything unexpected degrades to no rows rather than raising.
    """
    rows: list[dict[str, Any]] = []
    if isinstance(payload, list):
        rows.extend(r for r in payload if isinstance(r, dict))
        return rows
    sections = payload.get("sections") if isinstance(payload, dict) else None
    if isinstance(sections, list):
        for section in sections:
            section_rows = section.get("rows") if isinstance(section, dict) else None
            if isinstance(section_rows, list):
                rows.extend(r for r in section_rows if isinstance(r, dict))
    top_rows = payload.get("rows") if isinstance(payload, dict) else None
    if isinstance(top_rows, list):
        rows.extend(r for r in top_rows if isinstance(r, dict))
    return rows


def _pick(row: dict[str, Any], *keys: str) -> Any:
    """First present key among naming variants across vol3 versions."""
    for key in keys:
        if key in row and row[key] is not None:
            return row[key]
    return None


def parse_vol_processes(payload: Any) -> list[dict[str, Any]]:
    """Normalize pslist rows to {pid, ppid, name, create_time} entries."""
    processes: list[dict[str, Any]] = []
    for row in _iter_rows(payload):
        name = _pick(row, "ImageFileName", "ProcessName", "image_file_name", "process_name")
        if name is None:
            continue
        pid = _pick(row, "PID", "pid")
        ppid = _pick(row, "PPID", "ppid")
        create_time = _pick(row, "CreateTime", "create_time", "CreateTime (UTC)")
        try:
            pid = int(pid) if pid is not None else None
        except (TypeError, ValueError):
            pid = None
        try:
            ppid = int(ppid) if ppid is not None else None
        except (TypeError, ValueError):
            ppid = None
        processes.append(
            {
                "pid": pid,
                "ppid": ppid,
                "name": str(name),
                "create_time": str(create_time) if create_time is not None else None,
            }
        )
    return processes


def parse_vol_connections(payload: Any) -> list[dict[str, Any]]:
    """Normalize netscan rows; address columns may arrive pre-split or as
    rendered 'TCPv4 10.0.2.15:138' composite strings depending on version."""
    connections: list[dict[str, Any]] = []
    for row in _iter_rows(payload):
        proto = str(_pick(row, "Proto", "proto") or "")
        state = _pick(row, "State", "state")
        pid = _pick(row, "PID", "pid")
        owner = _pick(row, "Owner", "owner")

        def _addr(*keys: str, _row=row) -> str | None:
            raw = _pick(_row, *keys)
            if raw is None:
                return None
            text = str(raw).strip()
            if not text or text == "-":
                return None
            match = _ADDR_RE.search(text)
            return f"{match.group(1)}:{match.group(2)}" if match else text

        local = _addr("LocalAddr", "local_addr")
        foreign = _addr("ForeignAddr", "foreign_addr")
        if local is None and foreign is None and not proto:
            continue
        try:
            pid = int(pid) if pid is not None else None
        except (TypeError, ValueError):
            pid = None
        entry: dict[str, Any] = {
            "proto": proto,
            "local_addr": local,
            "foreign_addr": foreign,
            "state": str(state) if state is not None else None,
            "pid": pid,
        }
        if owner is not None:
            entry["owner"] = str(owner)
        connections.append(entry)
    return connections


def cross_reference(processes: list[dict[str, Any]], events: list[dict]) -> dict[str, Any]:
    """Diff Volatility's process list against the run's collected telemetry.

    A memory-resident process whose name never appeared in any process_create
    event is flagged as hidden — direct syscalls, unlogged parents, or
    kernel-assisted execution. Name comparison is case-insensitive (Sysmon
    reports 'MIMIKATZ.EXE', pslist says 'mimikatz.exe').
    """
    telemetry = {
        (e.get("process_name") or "").strip().lower()
        for e in events
        if e.get("event_type") == "process_create"
    }
    telemetry.discard("")
    hidden: list[dict[str, Any]] = []
    matched = 0
    for proc in processes:
        name = (proc.get("name") or "").strip().lower()
        if not name:
            continue
        if name in telemetry:
            matched += 1
        else:
            hidden.append({"pid": proc.get("pid"), "name": proc.get("name")})
    hidden.sort(key=lambda h: ((h.get("name") or "").lower(), h.get("pid") if h.get("pid") is not None else -1))
    return {
        "telemetry_processes": sorted(telemetry),
        "matched_count": matched,
        "hidden_processes": hidden,
    }


def read_dump_bytes(sample_id: str) -> bytes | None:
    """Dump bytes live in the sample vault like any other uploaded artifact."""
    path = config.SAMPLES_DIR / f"{sample_id}.bin"
    if not path.is_file():
        return None
    return path.read_bytes()


def run_memory_scan(dump_bytes: bytes) -> dict[str, Any]:
    """Run windows.pslist (+ best-effort windows.netscan) via the vol CLI.

    Never raises — every failure mode degrades to an honest error field so
    triage still completes. netscan failure alone doesn't sink the scan.
    """
    binary = _vol_binary()
    if not binary:
        status = vol_status()
        return {"available": False, "error": status["error"], "processes": [], "connections": []}

    result: dict[str, Any] = {"available": True}
    tmp_path = ""
    try:
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".dmp") as tmp:
                tmp.write(dump_bytes)
                tmp_path = tmp.name
            proc = subprocess.run(
                [binary, "-r", "json", "-f", tmp_path, "windows.pslist"],
                capture_output=True,
                text=True,
                timeout=config.VOLATILITY_TIMEOUT,
                check=False,
            )
        except FileNotFoundError:
            return {
                "available": False,
                "error": "volatility3 binary vanished mid-scan",
                "processes": [],
                "connections": [],
            }
        except subprocess.TimeoutExpired:
            return {
                "available": True,
                "error": f"volatility3 timed out after {config.VOLATILITY_TIMEOUT}s",
                "processes": [],
                "connections": [],
            }

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()[:200]
            result["error"] = f"windows.pslist exited {proc.returncode}" + (f": {detail}" if detail else "")
            result["processes"] = []
        else:
            try:
                result["processes"] = parse_vol_processes(json.loads(proc.stdout))
            except json.JSONDecodeError:
                result["error"] = "pslist output was not valid JSON"
                result["processes"] = []

        # Best-effort network artifacts — older dumps / non-Windows images fail it.
        try:
            net = subprocess.run(
                [binary, "-r", "json", "-f", tmp_path, "windows.netscan"],
                capture_output=True,
                text=True,
                timeout=config.VOLATILITY_TIMEOUT,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            result["netscan_error"] = "windows.netscan did not complete"
        else:
            if net.returncode != 0:
                result["netscan_error"] = f"windows.netscan exited {net.returncode}"
            else:
                try:
                    result["connections"] = parse_vol_connections(json.loads(net.stdout))
                except json.JSONDecodeError:
                    result["netscan_error"] = "netscan output was not valid JSON"
        result.setdefault("connections", [])
        return result
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def scan_run(conn: sqlite3.Connection, run_id: str, dump_sample_id: str) -> dict[str, Any]:
    """Full pipeline: dump bytes → vol scan → cross-reference this run's
    process_create telemetry. Caller has already validated run + sample."""
    dump_bytes = read_dump_bytes(dump_sample_id)
    if dump_bytes is None:
        return {
            "run_id": run_id,
            "dump_sample_id": dump_sample_id,
            "available": False,
            "error": "dump bytes missing from the sample vault",
            "cross_reference": None,
        }
    scan = run_memory_scan(dump_bytes)
    result: dict[str, Any] = {
        "run_id": run_id,
        "dump_sample_id": dump_sample_id,
        "tools": vol_status(),
        **scan,
    }
    if scan.get("available") and scan.get("processes") is not None:
        result["cross_reference"] = cross_reference(scan["processes"], event_store.list_events_for_run(conn, run_id))
    else:
        result.setdefault("cross_reference", None)
    return result
