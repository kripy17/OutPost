"""Strace Telemetry Parser, Process Lifecycle Attributor, and Timeline Sequencer.

Parses raw strace output captured outside bubblewrap (strace 7.2 with
--decode-pids=pidns, -f, -ttt, -yy).

Key Responsibilities:
1. Reassembles split (<unfinished ...> / <... resumed>) syscall lines per host PID.
2. Identifies the sample execution seam (discarding supervisor setup).
3. Filters supervisor processes using process ancestry (tracking all descendants
   of the sample root, including reparented orphans).
4. Normalizes process lifecycles into analysis_processes.
5. Emits normalized events for process, file, network, DNS, and module activity.
6. Enforces event quotas and suppressed read accounting.
7. Assigns contiguous 0-indexed monotonic `seq` values sorted by timestamp.
8. Writes to analysis_processes, analysis_events, and run_analysis_stats.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("outpost.strace_parser")

# Quota limits per docs/analysis-event-model.md Section 5.3
MAX_FILE_EVENTS = 2500
MAX_MODULE_EVENTS = 5000
MAX_TOTAL_EVENTS = 10000

# Suppressed path prefixes for file_read
SUPPRESSED_READ_PREFIXES = (
    "/usr/lib",
    "/lib",
    "/etc/ld.so",
    "/usr/share",
    "/etc/locale",
    "/proc/sys/vm",
    "/proc/self/maps",
    "/proc/filesystems",
    "/proc/version",
)


def _is_suppressed_system_read(path: str) -> bool:
    """Identify system runtime, loader, and interpreter initialization reads."""
    if any(path.startswith(prefix) for prefix in SUPPRESSED_READ_PREFIXES):
        return True
    # Python virtualenv and standard interpreter libraries
    if "/.venv/" in path or "/site-packages/" in path or path.endswith("/site-packages"):
        return True
    if path.endswith((".pyc", ".pth", "pyvenv.cfg")):
        return True
    # Initial interpreter script reads
    if path.endswith(("/probe.py", "/probe.sh")):
        return True
    return False


@dataclass
class ProcessEntity:
    process_pk: str
    run_id: str
    host_pid: int
    ns_pid: int | None
    host_ppid: int | None
    ns_ppid: int | None
    start_time_us: int
    end_time_us: int | None
    initial_ppid: int
    current_ppid: int
    exe_path: str
    command_line: str
    process_name: str
    host_id: str = "local"
    uid: int | None = None
    gid: int | None = None
    exit_code: int | None = None
    status: str = "running"


@dataclass
class ParsedEvent:
    category: str
    event_type: str
    action: str
    start_time_us: int
    timestamp_iso: str
    host_pid: int
    process_pk: str | None
    target_path: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    source: str = "traced"
    origin: str = "observed"


class StraceParser:
    """State machine parser for Linux strace logs."""

    # 11431 1793087029.468321 execve(...)
    LINE_RE = re.compile(r"^(\d+)\s+(\d+\.\d{6})\s+(.*)$")
    RESUMED_RE = re.compile(r"^<\.\.\.\s+([a-zA-Z0-9_]+)\s+resumed>\s*(.*)$")
    UNFINISHED_RE = re.compile(r"^(.*?)\s*<unfinished \.\.\.>$")
    EXITED_RE = re.compile(r"^\+\+\+\s+exited with (\d+)\s+\+\+\+$")
    KILLED_RE = re.compile(r"^\+\+\+\s+killed by ([a-zA-Z0-9_]+)\s+\+\+\+$")
    SIGNAL_RE = re.compile(r"^---\s+([a-zA-Z0-9_]+)\s+\{(.*)\}\s+---$")

    # clone(...) = 3 /* 11434 in strace's PID NS */
    PIDNS_COMMENT_RE = re.compile(r"^(\d+)\s+/\*\s*(\d+)\s+in strace's PID NS\s*\*/")

    def __init__(
        self,
        run_id: str,
        default_origin: str = "observed",
        expected_cmd: list[str] | str | None = None,
        sandbox_dir: str | Path | None = None,
    ) -> None:
        self.run_id = run_id
        self.default_origin = default_origin
        self.expected_cmd = expected_cmd
        self.sandbox_dir = str(sandbox_dir) if sandbox_dir else None

        # In-flight syscall buffer: host_pid -> (syscall_name, partial_args, start_time_us)
        self.in_flight: dict[int, tuple[str, str, int]] = {}

        # Retained pre-seam clones from supervisor: child_host_pid -> (child_ns_pid, parent_host_pid)
        self.pre_seam_clones: dict[int, tuple[int, int]] = {}

        # Supervisor / sample boundary state
        self.sample_root_host_pid: int | None = None
        self.sample_processes: set[int] = set()

        # Tracked entities
        self.processes: dict[int, ProcessEntity] = {}  # host_pid -> entity
        self.all_processes: list[ProcessEntity] = []

        # Open file descriptors and sockets per host_pid: host_pid -> {fd: target_or_metadata}
        self.fd_table: dict[int, dict[int, str]] = {}
        self.socket_table: dict[int, dict[int, dict[str, Any]]] = {}

        # Events collected before sequence assignment
        self.raw_events: list[ParsedEvent] = []

        # Statistics
        self.suppressed_system_reads = 0
        self.dns_events_count = 0
        self.file_events_count = 0
        self.network_events_count = 0
        self.module_events_count = 0
        self.is_truncated = False
        self.truncation_reason: str | None = None

    def _parse_timestamp(self, ts_str: str) -> tuple[int, str]:
        parts = ts_str.split(".")
        sec = int(parts[0])
        usec = int(parts[1]) if len(parts) > 1 else 0
        total_us = sec * 1_000_000 + usec
        dt = datetime.fromtimestamp(sec + usec / 1_000_000, tz=timezone.utc)
        iso = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return total_us, iso

    def _clean_path(self, raw_path: str) -> str:
        """Strip strace fd annotations like /tmp/file<char 1:3> or </path>."""
        s = raw_path.strip().strip('"').strip("'")
        if "<" in s and s.endswith(">"):
            inner = s[s.find("<") + 1 : -1]
            return inner
        return s.rstrip(")").rstrip(",").strip('"').strip("'")

    def _relativize_path(self, path: str) -> str:
        """Strip internal sandbox directories (/tmp/outpost_sandbox_.../) to maintain clean relative paths."""
        if not path:
            return ""
        m = re.match(r"^/tmp/outpost_sandbox_[^/]+/(.*)$", path)
        if m:
            return m.group(1)
        if self.sandbox_dir and path.startswith(self.sandbox_dir):
            rel = os.path.relpath(path, self.sandbox_dir)
            if not rel.startswith(".."):
                return rel
        return path

    def parse_file(self, file_path: str | Path) -> None:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                self.parse_line(line.rstrip("\r\n"), line_no=line_no)
        if self.sample_root_host_pid is None:
            raise RuntimeError(
                f"Sample start seam not found in trace for run '{self.run_id}': execution never reached target sample"
            )

    def parse_line(self, line: str, line_no: int = 0) -> None:
        if not line:
            return

        m = self.LINE_RE.match(line)
        if not m:
            return

        host_pid = int(m.group(1))
        ts_str = m.group(2)
        rest = m.group(3).strip()

        ts_us, ts_iso = self._parse_timestamp(ts_str)

        # 1. Check for process termination markers
        m_exit = self.EXITED_RE.match(rest)
        if m_exit:
            exit_code = int(m_exit.group(1))
            self._handle_process_exit(host_pid, exit_code, ts_us, ts_iso)
            return

        m_kill = self.KILLED_RE.match(rest)
        if m_kill:
            sig = m_kill.group(1)
            self._handle_process_exit(host_pid, -1, ts_us, ts_iso, signal_name=sig)
            return

        m_sig = self.SIGNAL_RE.match(rest)
        if m_sig:
            return

        # 2. Check for resumed syscall
        m_res = self.RESUMED_RE.match(rest)
        if m_res:
            syscall_name = m_res.group(1)
            tail = m_res.group(2).strip()
            if host_pid in self.in_flight:
                in_name, partial_args, start_us = self.in_flight.pop(host_pid)
                partial_args = partial_args.strip()
                if tail.startswith(","):
                    full_body = f"{partial_args}{tail}"
                elif tail.startswith(")") or tail.startswith("="):
                    full_body = f"{partial_args}{tail}"
                else:
                    full_body = f"{partial_args} {tail}"
                self._dispatch_syscall(host_pid, syscall_name, full_body.strip(), start_us, ts_iso, line_no)
            return

        # 3. Check for unfinished syscall
        m_unf = self.UNFINISHED_RE.match(rest)
        if m_unf:
            unf_body = m_unf.group(1)
            # Find syscall name: name(args...
            p_idx = unf_body.find("(")
            if p_idx != -1:
                syscall_name = unf_body[:p_idx].strip()
                partial_args = unf_body[p_idx + 1 :].strip()
                self.in_flight[host_pid] = (syscall_name, partial_args, ts_us)
            return

        # 4. Standard single-line syscall: name(args) = retval
        p_idx = rest.find("(")
        if p_idx != -1:
            syscall_name = rest[:p_idx].strip()
            rest_args = rest[p_idx + 1 :]
            self._dispatch_syscall(host_pid, syscall_name, rest_args, ts_us, ts_iso, line_no)

    def _split_args_and_return(self, body: str) -> tuple[str, str]:
        """Split 'arg1, arg2) = return_value' into (args, return_value)."""
        # Look for last ') ='
        eq_idx = body.rfind(") = ")
        if eq_idx != -1:
            args = body[:eq_idx]
            ret = body[eq_idx + 4 :].strip()
            return args, ret
        eq_alt = body.rfind(" = ")
        if eq_alt != -1:
            args = body[:eq_alt].rstrip(")")
            ret = body[eq_alt + 3 :].strip()
            return args, ret
        return body, ""

    def _dispatch_syscall(
        self,
        host_pid: int,
        syscall_name: str,
        body: str,
        ts_us: int,
        ts_iso: str,
        line_no: int,
    ) -> None:
        args_str, ret_str = self._split_args_and_return(body)

        # Record pre-seam clones (e.g. bwrap supervisor cloning the sample root into new PID ns)
        if self.sample_root_host_pid is None:
            if syscall_name in ("clone", "clone3", "fork", "vfork"):
                m_pidns = self.PIDNS_COMMENT_RE.match(ret_str)
                if m_pidns:
                    child_ns = int(m_pidns.group(1))
                    child_host = int(m_pidns.group(2))
                    self.pre_seam_clones[child_host] = (child_ns, host_pid)
                return

            if syscall_name == "execve" and (ret_str.startswith("0") or ret_str == "0"):
                exe_path, cmdline = self._parse_execve_args(args_str)
                is_sample = False
                if self.expected_cmd:
                    exp = self.expected_cmd
                    exp_str = " ".join(exp) if isinstance(exp, list) else exp
                    exp_tokens = [t.strip().strip('"').strip("'") for t in exp_str.split()]
                    exp_target = Path(exp_tokens[-1]).name if exp_tokens else ""
                    if exp_target and (exp_target in exe_path or exp_target in cmdline):
                        is_sample = True
                    elif exe_path and not exe_path.endswith("/bwrap") and exe_path != "bwrap":
                        is_sample = True
                else:
                    if exe_path and not exe_path.endswith("/bwrap") and exe_path != "bwrap" and "bwrap" not in args_str[:64]:
                        is_sample = True

                if is_sample:
                    ns_pid, host_ppid = self.pre_seam_clones.get(host_pid, (None, None))
                    ns_ppid = 1 if host_ppid is not None else None
                    self._mark_sample_start(
                        host_pid, args_str, ts_us, ts_iso,
                        ns_pid=ns_pid, host_ppid=host_ppid, ns_ppid=ns_ppid,
                    )
            return

        # 2. Filter processes by ancestry
        if host_pid not in self.sample_processes:
            # Check if this is an execve of a sample process that was cloned
            return

        proc = self.processes.get(host_pid)
        proc_pk = proc.process_pk if proc else None

        # 3. Route specific syscalls
        if syscall_name in ("clone", "clone3", "fork", "vfork"):
            self._handle_clone(host_pid, syscall_name, args_str, ret_str, ts_us, ts_iso)
        elif syscall_name == "execve":
            self._handle_execve(host_pid, args_str, ret_str, ts_us, ts_iso)
        elif syscall_name in ("open", "openat"):
            self._handle_openat(host_pid, proc_pk, args_str, ret_str, ts_us, ts_iso)
        elif syscall_name in ("write", "writev", "pwrite64"):
            self._handle_write(host_pid, proc_pk, args_str, ret_str, ts_us, ts_iso)
        elif syscall_name in ("chmod", "fchmod", "fchmodat"):
            self._handle_chmod(host_pid, proc_pk, args_str, ret_str, ts_us, ts_iso)
        elif syscall_name in ("rename", "renameat", "renameat2"):
            self._handle_rename(host_pid, proc_pk, args_str, ret_str, ts_us, ts_iso)
        elif syscall_name in ("unlink", "unlinkat"):
            self._handle_unlink(host_pid, proc_pk, args_str, ret_str, ts_us, ts_iso)
        elif syscall_name == "socket":
            self._handle_socket(host_pid, args_str, ret_str, ts_us)
        elif syscall_name == "connect":
            self._handle_connect(host_pid, proc_pk, args_str, ret_str, ts_us, ts_iso)
        elif syscall_name in ("sendto", "send", "sendmmsg"):
            self._handle_send(host_pid, proc_pk, syscall_name, args_str, ret_str, ts_us, ts_iso)
        elif syscall_name in ("poll", "ppoll", "select", "pselect6"):
            self._handle_poll(host_pid, proc_pk, args_str, ret_str, ts_us, ts_iso)
        elif syscall_name in ("close",):
            self._handle_close(host_pid, args_str, ret_str)
        elif syscall_name in ("dup", "dup2", "dup3"):
            self._handle_dup(host_pid, args_str, ret_str)

    def _parse_execve_args(self, args_str: str) -> tuple[str, str]:
        """Extract executable path and full argv array from execve args string."""
        p_start = args_str.find("[")
        p_end = args_str.rfind("]")
        if p_start != -1 and p_end != -1 and p_end > p_start:
            cmdline = args_str[p_start : p_end + 1].strip()
            prefix = args_str[:p_start].strip().rstrip(",")
            exe_path = self._clean_path(prefix)
            return exe_path, cmdline
        parts = args_str.split(",", 1)
        exe_path = self._clean_path(parts[0]) if parts else ""
        return exe_path, exe_path

    def _mark_sample_start(
        self,
        host_pid: int,
        args_str: str,
        ts_us: int,
        ts_iso: str,
        ns_pid: int | None = None,
        host_ppid: int | None = None,
        ns_ppid: int | None = None,
    ) -> None:
        self.sample_root_host_pid = host_pid
        self.sample_processes.add(host_pid)

        exe_path, cmdline = self._parse_execve_args(args_str)
        proc_name = Path(exe_path).name if exe_path else "sample"
        proc_pk = f"{self.run_id}:{host_pid}:{ts_us}"

        eff_ns_pid = ns_pid if ns_pid is not None else 2
        eff_host_ppid = host_ppid if host_ppid is not None else (host_pid - 1)
        eff_ns_ppid = ns_ppid if ns_ppid is not None else 1

        proc = ProcessEntity(
            process_pk=proc_pk,
            run_id=self.run_id,
            host_pid=host_pid,
            ns_pid=eff_ns_pid,
            host_ppid=eff_host_ppid,
            ns_ppid=eff_ns_ppid,
            start_time_us=ts_us,
            end_time_us=None,
            initial_ppid=eff_host_ppid,
            current_ppid=eff_host_ppid,
            exe_path=exe_path,
            command_line=cmdline or exe_path,
            process_name=proc_name,
            status="running",
        )
        self.processes[host_pid] = proc
        self.all_processes.append(proc)
        self.fd_table[host_pid] = {}
        self.socket_table[host_pid] = {}

        self.raw_events.append(
            ParsedEvent(
                category="process",
                event_type="process_create",
                action="create",
                start_time_us=ts_us,
                timestamp_iso=ts_iso,
                host_pid=host_pid,
                process_pk=proc_pk,
                target_path=exe_path,
                details={
                    "host_pid": host_pid,
                    "ns_pid": eff_ns_pid,
                    "host_ppid": eff_host_ppid,
                    "ns_ppid": eff_ns_ppid,
                    "exe_path": exe_path,
                    "command_line": cmdline or exe_path,
                    "initial_ppid": eff_host_ppid,
                },
                origin=self.default_origin,
            )
        )

    def _handle_clone(
        self,
        host_pid: int,
        syscall_name: str,
        args_str: str,
        ret_str: str,
        ts_us: int,
        ts_iso: str,
    ) -> None:
        # ret_str: 3 /* 11434 in strace's PID NS */
        m_pidns = self.PIDNS_COMMENT_RE.match(ret_str)
        if m_pidns:
            child_ns_pid = int(m_pidns.group(1))
            child_host_pid = int(m_pidns.group(2))
        else:
            try:
                val = int(ret_str.split()[0])
                if val <= 0:
                    return
                child_host_pid = val
                child_ns_pid = None
            except (ValueError, IndexError):
                return

        # Add child to ancestry-tracked processes
        self.sample_processes.add(child_host_pid)

        parent_proc = self.processes.get(host_pid)
        parent_pk = parent_proc.process_pk if parent_proc else None
        exe_path = parent_proc.exe_path if parent_proc else ""
        proc_name = parent_proc.process_name if parent_proc else "child"

        child_pk = f"{self.run_id}:{child_host_pid}:{ts_us}"
        child_proc = ProcessEntity(
            process_pk=child_pk,
            run_id=self.run_id,
            host_pid=child_host_pid,
            ns_pid=child_ns_pid,
            host_ppid=host_pid,
            ns_ppid=parent_proc.ns_pid if parent_proc else None,
            start_time_us=ts_us,
            end_time_us=None,
            initial_ppid=host_pid,
            current_ppid=host_pid,
            exe_path=exe_path,
            command_line=parent_proc.command_line if parent_proc else "",
            process_name=proc_name,
            status="running",
        )
        self.processes[child_host_pid] = child_proc
        self.all_processes.append(child_proc)
        self.fd_table[child_host_pid] = dict(self.fd_table.get(host_pid, {}))
        self.socket_table[child_host_pid] = dict(self.socket_table.get(host_pid, {}))

        self.raw_events.append(
            ParsedEvent(
                category="process",
                event_type="process_create",
                action="fork",
                start_time_us=ts_us,
                timestamp_iso=ts_iso,
                host_pid=host_pid,
                process_pk=parent_pk,
                target_path=exe_path,
                details={
                    "parent_host_pid": host_pid,
                    "child_host_pid": child_host_pid,
                    "child_ns_pid": child_ns_pid,
                    "child_process_pk": child_pk,
                    "syscall": syscall_name,
                },
                origin=self.default_origin,
            )
        )

    def _handle_execve(
        self,
        host_pid: int,
        args_str: str,
        ret_str: str,
        ts_us: int,
        ts_iso: str,
    ) -> None:
        if not (ret_str.startswith("0") or ret_str == "0"):
            return

        exe_path, cmdline = self._parse_execve_args(args_str)
        proc_name = Path(exe_path).name if exe_path else "exec"

        proc = self.processes.get(host_pid)
        if proc:
            proc.exe_path = exe_path
            proc.command_line = cmdline
            proc.process_name = proc_name
            proc_pk = proc.process_pk
        else:
            proc_pk = f"{self.run_id}:{host_pid}:{ts_us}"
            proc = ProcessEntity(
                process_pk=proc_pk,
                run_id=self.run_id,
                host_pid=host_pid,
                ns_pid=None,
                start_time_us=ts_us,
                end_time_us=None,
                initial_ppid=1,
                current_ppid=1,
                exe_path=exe_path,
                command_line=cmdline,
                process_name=proc_name,
            )
            self.processes[host_pid] = proc
            self.all_processes.append(proc)

        self.raw_events.append(
            ParsedEvent(
                category="process",
                event_type="process_exec",
                action="exec",
                start_time_us=ts_us,
                timestamp_iso=ts_iso,
                host_pid=host_pid,
                process_pk=proc_pk,
                target_path=exe_path,
                details={
                    "host_pid": host_pid,
                    "exe_path": exe_path,
                    "command_line": cmdline,
                },
                origin=self.default_origin,
            )
        )

    def _handle_process_exit(
        self,
        host_pid: int,
        exit_code: int,
        ts_us: int,
        ts_iso: str,
        signal_name: str | None = None,
    ) -> None:
        if host_pid not in self.sample_processes:
            return

        proc = self.processes.get(host_pid)
        if proc:
            proc.status = "terminated"
            proc.exit_code = exit_code
            proc.end_time_us = ts_us
            proc_pk = proc.process_pk
        else:
            proc_pk = None

        self.raw_events.append(
            ParsedEvent(
                category="process",
                event_type="process_terminate",
                action="exit",
                start_time_us=ts_us,
                timestamp_iso=ts_iso,
                host_pid=host_pid,
                process_pk=proc_pk,
                details={
                    "host_pid": host_pid,
                    "exit_code": exit_code,
                    "signal": signal_name,
                },
                origin=self.default_origin,
            )
        )

    def _handle_openat(
        self,
        host_pid: int,
        proc_pk: str | None,
        args_str: str,
        ret_str: str,
        ts_us: int,
        ts_iso: str,
    ) -> None:
        # openat(AT_FDCWD, "probe_c.tmp", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 10
        try:
            fd_val = int(ret_str.split()[0].split("<")[0])
        except (ValueError, IndexError):
            return
        if fd_val < 0:
            return

        parts = [p.strip() for p in args_str.split(",")]
        # For openat: parts[0] is dirfd, parts[1] is path, parts[2] is flags
        # For open: parts[0] is path, parts[1] is flags
        if len(parts) >= 3 and "openat" in parts[0] or "AT_FDCWD" in parts[0] or parts[0].isdigit():
            raw_path = parts[1]
            flags = parts[2] if len(parts) > 2 else ""
        else:
            raw_path = parts[0] if parts else ""
            flags = parts[1] if len(parts) > 1 else ""

        path = self._clean_path(raw_path)
        rel_path = self._relativize_path(path)
        if host_pid not in self.fd_table:
            self.fd_table[host_pid] = {}
        self.fd_table[host_pid][fd_val] = rel_path

        # Check suppression ONLY for system reads (never creates, writes, or mutations)
        is_write_intent = any(flag in flags for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"))
        if not is_write_intent and _is_suppressed_system_read(path):
            self.suppressed_system_reads += 1
            return

        if "O_DIRECTORY" in flags or path in ("/dev/null", "/dev/zero", "/dev/urandom"):
            return

        if "O_CREAT" in flags:
            self.file_events_count += 1
            self.raw_events.append(
                ParsedEvent(
                    category="file",
                    event_type="file_create",
                    action="create",
                    start_time_us=ts_us,
                    timestamp_iso=ts_iso,
                    host_pid=host_pid,
                    process_pk=proc_pk,
                    target_path=rel_path,
                    details={"path": rel_path, "flags": flags, "fd": fd_val},
                    origin=self.default_origin,
                )
            )
        elif "O_RDONLY" in flags:
            self.file_events_count += 1
            self.raw_events.append(
                ParsedEvent(
                    category="file",
                    event_type="file_read",
                    action="read",
                    start_time_us=ts_us,
                    timestamp_iso=ts_iso,
                    host_pid=host_pid,
                    process_pk=proc_pk,
                    target_path=rel_path,
                    details={"path": rel_path, "flags": flags, "fd": fd_val},
                    origin=self.default_origin,
                )
            )

    def _handle_dup(self, host_pid: int, args_str: str, ret_str: str) -> None:
        try:
            new_fd = int(ret_str.split()[0].split("<")[0])
        except (ValueError, IndexError):
            return
        if new_fd < 0:
            return
        parts = [p.strip() for p in args_str.split(",")]
        old_fd_str = parts[0].split("<")[0]
        try:
            old_fd = int(old_fd_str)
            target = self.fd_table.get(host_pid, {}).get(old_fd)
            if target:
                if host_pid not in self.fd_table:
                    self.fd_table[host_pid] = {}
                self.fd_table[host_pid][new_fd] = target
        except ValueError:
            pass

    def _handle_write(
        self,
        host_pid: int,
        proc_pk: str | None,
        args_str: str,
        ret_str: str,
        ts_us: int,
        ts_iso: str,
    ) -> None:
        try:
            bytes_written = int(ret_str.split()[0])
        except (ValueError, IndexError):
            return
        if bytes_written <= 0:
            return

        parts = args_str.split(",", 2)
        raw_fd = parts[0].strip() if parts else ""
        try:
            fd_num = int(raw_fd.split("<")[0])
        except ValueError:
            return

        path = self.fd_table.get(host_pid, {}).get(fd_num, "")
        if "<" in raw_fd and ">" in raw_fd:
            path = self._clean_path(raw_fd)

        rel_path = self._relativize_path(path)

        # Skip terminal/console/pseudo-device writes
        if path.startswith(("/dev/pts", "/dev/tty", "/dev/null", "/dev/zero", "pipe:", "socket:")):
            return
        if fd_num in (1, 2) and not path:
            return

        self.file_events_count += 1
        self.raw_events.append(
            ParsedEvent(
                category="file",
                event_type="file_modify",
                action="write",
                start_time_us=ts_us,
                timestamp_iso=ts_iso,
                host_pid=host_pid,
                process_pk=proc_pk,
                target_path=rel_path or f"fd:{fd_num}",
                details={
                    "fd": fd_num,
                    "path": rel_path,
                    "bytes_written": bytes_written,
                },
                origin=self.default_origin,
            )
        )

    def _handle_chmod(
        self,
        host_pid: int,
        proc_pk: str | None,
        args_str: str,
        ret_str: str,
        ts_us: int,
        ts_iso: str,
    ) -> None:
        if not (ret_str.startswith("0") or ret_str == "0"):
            return
        parts = [p.strip() for p in args_str.split(",") if p.strip()]
        if len(parts) >= 3 and ("AT_FDCWD" in parts[0] or parts[0].isdigit()):
            path = self._clean_path(parts[1])
            mode = parts[2]
        elif len(parts) >= 2:
            path = self._clean_path(parts[0])
            mode = parts[1]
        else:
            return

        rel_path = self._relativize_path(path)
        self.file_events_count += 1
        self.raw_events.append(
            ParsedEvent(
                category="file",
                event_type="file_perm_change",
                action="chmod",
                start_time_us=ts_us,
                timestamp_iso=ts_iso,
                host_pid=host_pid,
                process_pk=proc_pk,
                target_path=rel_path,
                details={"path": rel_path, "mode": mode},
                origin=self.default_origin,
            )
        )

    def _handle_rename(
        self,
        host_pid: int,
        proc_pk: str | None,
        args_str: str,
        ret_str: str,
        ts_us: int,
        ts_iso: str,
    ) -> None:
        if not (ret_str.startswith("0") or ret_str == "0"):
            return
        parts = [p.strip() for p in args_str.split(",") if p.strip()]
        # rename("old", "new") or renameat2(AT_FDCWD, "old", AT_FDCWD, "new", flags)
        if len(parts) >= 4 and ("AT_FDCWD" in parts[0] or parts[0].isdigit()):
            old_path = self._clean_path(parts[1])
            new_path = self._clean_path(parts[3])
        elif len(parts) >= 2:
            old_path = self._clean_path(parts[0])
            new_path = self._clean_path(parts[1])
        else:
            return

        rel_old = self._relativize_path(old_path)
        rel_new = self._relativize_path(new_path)
        self.file_events_count += 1
        self.raw_events.append(
            ParsedEvent(
                category="file",
                event_type="file_rename",
                action="rename",
                start_time_us=ts_us,
                timestamp_iso=ts_iso,
                host_pid=host_pid,
                process_pk=proc_pk,
                target_path=rel_new,
                details={"old_path": rel_old, "new_path": rel_new},
                origin=self.default_origin,
            )
        )

    def _handle_unlink(
        self,
        host_pid: int,
        proc_pk: str | None,
        args_str: str,
        ret_str: str,
        ts_us: int,
        ts_iso: str,
    ) -> None:
        if not (ret_str.startswith("0") or ret_str == "0"):
            return
        parts = [p.strip() for p in args_str.split(",") if p.strip()]
        # unlink("file") or unlinkat(AT_FDCWD, "file", 0)
        if len(parts) >= 2 and ("AT_FDCWD" in parts[0] or parts[0].isdigit()):
            path = self._clean_path(parts[1])
        elif len(parts) >= 1:
            path = self._clean_path(parts[0])
        else:
            return

        rel_path = self._relativize_path(path)
        self.file_events_count += 1
        self.raw_events.append(
            ParsedEvent(
                category="file",
                event_type="file_delete",
                action="delete",
                start_time_us=ts_us,
                timestamp_iso=ts_iso,
                host_pid=host_pid,
                process_pk=proc_pk,
                target_path=rel_path,
                details={"path": rel_path},
                origin=self.default_origin,
            )
        )

    def _handle_socket(self, host_pid: int, args_str: str, ret_str: str, ts_us: int) -> None:
        try:
            fd_val = int(ret_str.split()[0].split("<")[0])
        except (ValueError, IndexError):
            return
        if fd_val < 0:
            return

        parts = [p.strip() for p in args_str.split(",")]
        family = parts[0] if parts else ""
        sock_type = parts[1] if len(parts) > 1 else ""

        if host_pid not in self.socket_table:
            self.socket_table[host_pid] = {}
        self.socket_table[host_pid][fd_val] = {
            "family": family,
            "type": sock_type,
            "created_us": ts_us,
        }

    def _handle_connect(
        self,
        host_pid: int,
        proc_pk: str | None,
        args_str: str,
        ret_str: str,
        ts_us: int,
        ts_iso: str,
    ) -> None:
        # connect(10<TCP:[40508]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.1")}, 16) = -1 ENETUNREACH
        parts = args_str.split(",", 1)
        raw_fd = parts[0].strip() if parts else ""
        try:
            fd_num = int(raw_fd.split("<")[0])
        except ValueError:
            return

        # Extract port and ip from sockaddr string
        port = None
        ip = None
        m_port = re.search(r"sin_port=htons\((\d+)\)", args_str)
        if m_port:
            port = int(m_port.group(1))
        m_ip = re.search(r'sin_addr=inet_addr\("([^"]+)"\)', args_str)
        if m_ip:
            ip = m_ip.group(1)

        # Record destination in socket table for subsequent sendto / poll
        if fd_num in self.socket_table.get(host_pid, {}):
            self.socket_table[host_pid][fd_num]["dest_ip"] = ip
            self.socket_table[host_pid][fd_num]["dest_port"] = port

        # DNS Check: connect on port 53 to loopback is destination binding, NOT network success
        if port == 53:
            # Mark this socket as a DNS client socket
            if fd_num in self.socket_table.get(host_pid, {}):
                self.socket_table[host_pid][fd_num]["is_dns"] = True
            return

        # General TCP/UDP connect
        is_success = ret_str.startswith("0") or ret_str == "0"
        status = "connected" if is_success else "failed"
        error_code = None
        if not is_success:
            err_parts = ret_str.split()
            error_code = err_parts[1] if len(err_parts) > 1 else ret_str

        self.network_events_count += 1
        self.raw_events.append(
            ParsedEvent(
                category="network",
                event_type="network_connect",
                action="connect",
                start_time_us=ts_us,
                timestamp_iso=ts_iso,
                host_pid=host_pid,
                process_pk=proc_pk,
                target_path=f"{ip}:{port}" if ip and port else None,
                details={
                    "fd": fd_num,
                    "dest_ip": ip,
                    "dest_port": port,
                    "status": status,
                    "error_code": error_code,
                    "raw_return": ret_str,
                },
                origin=self.default_origin,
            )
        )

    def _handle_send(
        self,
        host_pid: int,
        proc_pk: str | None,
        syscall_name: str,
        args_str: str,
        ret_str: str,
        ts_us: int,
        ts_iso: str,
    ) -> None:
        # Check if sending on a DNS socket
        parts = args_str.split(",", 2)
        raw_fd = parts[0].strip() if parts else ""
        try:
            fd_num = int(raw_fd.split("<")[0])
        except ValueError:
            return

        sock_info = self.socket_table.get(host_pid, {}).get(fd_num, {})
        dest_port = sock_info.get("dest_port")
        is_dns = dest_port == 53 or sock_info.get("is_dns") or ("UDP" in raw_fd and "53" in str(dest_port))
        if is_dns:
            queries = self._extract_dns_queries_from_call(syscall_name, args_str, ret_str)
            for domain, qtype in queries:
                self.dns_events_count += 1
                ev = ParsedEvent(
                    category="dns",
                    event_type="dns_query",
                    action="query",
                    start_time_us=ts_us,
                    timestamp_iso=ts_iso,
                    host_pid=host_pid,
                    process_pk=proc_pk,
                    target_path=domain,
                    details={
                        "domain": domain,
                        "qtype": qtype,
                        "nameserver": "127.0.0.1:53",
                        "status": "attempted",
                        "note": f"DNS query wire payload transmitted to local resolver fallback ({qtype} record)",
                    },
                    origin=self.default_origin,
                )
                self.raw_events.append(ev)
                sock_info.setdefault("in_flight_queries", []).append((domain, qtype, ts_us))
                sock_info["last_query"] = (domain, qtype)

    def _handle_poll(
        self,
        host_pid: int,
        proc_pk: str | None,
        args_str: str,
        ret_str: str,
        ts_us: int,
        ts_iso: str,
    ) -> None:
        # poll([{fd=10, revents=POLLERR}], 1, 5000) = 1
        if "POLLERR" in ret_str or "POLLERR" in args_str:
            # Find which fd had POLLERR
            m_fd = re.search(r"fd=(\d+)", args_str)
            fd_num = int(m_fd.group(1)) if m_fd else None
            sock_info = self.socket_table.get(host_pid, {}).get(fd_num, {}) if fd_num else {}
            if sock_info.get("is_dns") or sock_info.get("dest_port") == 53:
                domain = "probe.test.invalid"
                qtype = "A"
                in_flight = sock_info.get("in_flight_queries", [])
                if in_flight:
                    domain, qtype, _ = in_flight.pop(0)
                elif "last_query" in sock_info:
                    domain, qtype = sock_info["last_query"]

                self.dns_events_count += 1
                self.raw_events.append(
                    ParsedEvent(
                        category="dns",
                        event_type="dns_query",
                        action="query_failed",
                        start_time_us=ts_us,
                        timestamp_iso=ts_iso,
                        host_pid=host_pid,
                        process_pk=proc_pk,
                        target_path=domain,
                        details={
                            "domain": domain,
                            "qtype": qtype,
                            "nameserver": "127.0.0.1:53",
                            "status": "failed",
                            "error": "POLLERR (ICMP port unreachable from local loopback)",
                        },
                        origin=self.default_origin,
                    )
                )

    def _handle_close(self, host_pid: int, args_str: str, ret_str: str) -> None:
        try:
            fd_num = int(args_str.split()[0].split("<")[0])
        except (ValueError, IndexError):
            return
        if host_pid in self.fd_table:
            self.fd_table[host_pid].pop(fd_num, None)
        if host_pid in self.socket_table:
            self.socket_table[host_pid].pop(fd_num, None)

    def _decode_dns_wire(self, buf: str) -> tuple[str, str] | None:
        """Decode RFC 1035 QNAME and QTYPE from escaped strace wire buffer."""
        try:
            raw_bytes = buf.encode("latin1").decode("unicode_escape").encode("latin1")
        except Exception:
            return None
        if len(raw_bytes) < 12:
            return None
        idx = 12
        labels = []
        while idx < len(raw_bytes):
            length = raw_bytes[idx]
            idx += 1
            if length == 0:
                break
            if idx + length > len(raw_bytes):
                break
            label = raw_bytes[idx : idx + length].decode("ascii", errors="replace")
            labels.append(label)
            idx += length
        domain = ".".join(labels)
        if not domain:
            return None
        qtype = "A"
        if idx + 2 <= len(raw_bytes):
            qtype_num = int.from_bytes(raw_bytes[idx : idx + 2], "big")
            if qtype_num == 1:
                qtype = "A"
            elif qtype_num == 28:
                qtype = "AAAA"
            else:
                qtype = str(qtype_num)
        return domain, qtype

    def _extract_dns_queries_from_call(
        self, syscall_name: str, args_str: str, ret_str: str
    ) -> list[tuple[str, str]]:
        results: list[tuple[str, str]] = []
        if syscall_name == "sendmmsg":
            try:
                num_sent = int(ret_str.split()[0])
            except (ValueError, IndexError):
                num_sent = 1
            iov_bases = re.findall(r'iov_base="([^"]*)"', args_str)
            for iov in iov_bases[:num_sent]:
                res = self._decode_dns_wire(iov)
                if res:
                    results.append(res)
        else:
            m = re.search(r'"([^"]*)"', args_str)
            if m:
                res = self._decode_dns_wire(m.group(1))
                if res:
                    results.append(res)
        return results

    def commit_to_db(self, conn: sqlite3.Connection) -> dict[str, Any]:
        """Assign monotonic sequence numbers, enforce quotas, and persist to database."""
        # 1. Sort all raw events by time
        sorted_events = sorted(self.raw_events, key=lambda e: e.start_time_us)
        run_start_us = sorted_events[0].start_time_us if sorted_events else 0

        # 2. Enforce intelligent quotas
        final_events: list[ParsedEvent] = []
        file_count = 0
        mod_count = 0

        for ev in sorted_events:
            if len(final_events) >= MAX_TOTAL_EVENTS:
                if not self.is_truncated:
                    self.is_truncated = True
                    self.truncation_reason = f"total_quota_exceeded ({MAX_TOTAL_EVENTS})"
                    final_events.append(
                        ParsedEvent(
                            category="process",
                            event_type="trace_truncated",
                            action="truncate",
                            start_time_us=ev.start_time_us,
                            timestamp_iso=ev.timestamp_iso,
                            host_pid=ev.host_pid,
                            process_pk=ev.process_pk,
                            details={"reason": self.truncation_reason, "limit": MAX_TOTAL_EVENTS},
                            origin=self.default_origin,
                        )
                    )
                break

            if ev.category == "file":
                if file_count >= MAX_FILE_EVENTS:
                    if not self.is_truncated:
                        self.is_truncated = True
                        self.truncation_reason = f"file_quota_exceeded ({MAX_FILE_EVENTS})"
                    continue
                file_count += 1
            elif ev.category == "module":
                if mod_count >= MAX_MODULE_EVENTS:
                    continue
                mod_count += 1

            final_events.append(ev)

        # 3. Persist entities into analysis_processes
        with conn:
            for p in self.all_processes:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO analysis_processes (
                        process_pk, run_id, host_pid, ns_pid, host_ppid, ns_ppid, start_time_us, end_time_us,
                        initial_ppid, current_ppid, exe_path, command_line, process_name,
                        host_id, uid, gid, exit_code, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        p.process_pk,
                        p.run_id,
                        p.host_pid,
                        p.ns_pid,
                        p.host_ppid,
                        p.ns_ppid,
                        p.start_time_us,
                        p.end_time_us,
                        p.initial_ppid,
                        p.current_ppid,
                        p.exe_path,
                        p.command_line,
                        p.process_name,
                        p.host_id,
                        p.uid,
                        p.gid,
                        p.exit_code,
                        p.status,
                    ),
                )

            # 4. Persist analysis_events with contiguous 0-indexed monotonic seq
            for seq_idx, ev in enumerate(final_events):
                event_pk = f"{self.run_id}:{seq_idx}"
                mono_us = max(0, ev.start_time_us - run_start_us)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO analysis_events (
                        event_pk, run_id, seq, timestamp, start_time_us, mono_us,
                        process_pk, category, event_type, action, source, origin,
                        target_path, details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_pk,
                        self.run_id,
                        seq_idx,
                        ev.timestamp_iso,
                        ev.start_time_us,
                        mono_us,
                        ev.process_pk,
                        ev.category,
                        ev.event_type,
                        ev.action,
                        ev.source,
                        ev.origin,
                        ev.target_path,
                        json.dumps(ev.details),
                    ),
                )

            # 5. Persist run_analysis_stats
            conn.execute(
                """
                INSERT OR REPLACE INTO run_analysis_stats (
                    run_id, total_events, process_count, file_events_count,
                    network_events_count, module_events_count, dns_events_count,
                    suppressed_system_reads, is_truncated, truncation_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.run_id,
                    len(final_events),
                    len(self.all_processes),
                    self.file_events_count,
                    self.network_events_count,
                    self.module_events_count,
                    self.dns_events_count,
                    self.suppressed_system_reads,
                    1 if self.is_truncated else 0,
                    self.truncation_reason,
                ),
            )

        return {
            "run_id": self.run_id,
            "total_events": len(final_events),
            "process_count": len(self.all_processes),
            "file_events": self.file_events_count,
            "network_events": self.network_events_count,
            "dns_events": self.dns_events_count,
            "suppressed_system_reads": self.suppressed_system_reads,
            "is_truncated": self.is_truncated,
        }


def parse_and_persist_strace_log(
    run_id: str,
    log_path: str | Path,
    conn: sqlite3.Connection,
    origin: str = "observed",
    expected_cmd: list[str] | str | None = None,
    sandbox_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Helper to parse a strace log file and commit to the database."""
    parser = StraceParser(
        run_id=run_id,
        default_origin=origin,
        expected_cmd=expected_cmd,
        sandbox_dir=sandbox_dir,
    )
    parser.parse_file(log_path)
    return parser.commit_to_db(conn)
