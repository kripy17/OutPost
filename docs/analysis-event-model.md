# OutPost Analysis Event Model Specification (Canonical Telemetry Stream)

**Document Status:** Step 2 Specification (Revised Draft for Review)  
**Target Subsystems:** Dynamic Sandbox Tracing, Provider Ingestion, Forensic Timeline, Correlation Engine  
**Author:** OutPost Core Engineering  
**Revision:** 2.4.0  

---

## 1. Executive Summary & Core Requirements

Dynamic analysis across host sandboxes, external provider imports (`anyrun`, `triage`, `joe`), and playbook simulations previously suffered from three structural weaknesses:
1. **Ephemeral Process Blind Spots:** Periodic `/proc` polling missed short-lived processes (`uname`, `id`, `ls`, transient shell invocations) that execute and terminate within polling sleep windows.
2. **Ambiguous Process Identity:** Using image paths or parent PIDs as part of the primary process identity breaks under `execve` (which mutates binary path and command line within the same PID) and subreaper reparenting (which mutates `ppid` when the immediate parent terminates).
3. **Telemetry Conflation:** Filesystem deltas, kernel syscalls, and synthetic playbook mocks were loosely combined without clear provenance distinctions or network environment boundaries.

This specification defines the **OutPost Canonical Analysis Event Model**. It provides a single, chronologically-ordered event stream per analysis run across **nine fundamental categories**:
- `process`
- `file`
- `registry` (Windows/external adapter only)
- `network`
- `dns`
- `api` (Windows/external adapter only)
- `mutex` (Windows/external adapter only)
- `service` (Windows/external adapter only)
- `module`

---

## 2. Process Identity & PID Namespace Model

### 2.1 Process Identity Tuple: `(run_id, host_pid, start_time_us)`

A process instance in OutPost is strictly identified by the 3-tuple:
$$\text{ProcessID} = (\text{run\_id}, \text{host\_pid}, \text{start\_time\_us})$$

- **`run_id`**: The unique identifier for the analysis session.
- **`host_pid`**: The kernel PID assigned on the host/hypervisor boundary.
- **`start_time_us`**: Integer epoch microseconds computed via exact string splitting:
  ```python
  def parse_strace_ts_to_us(ts_str: str) -> int:
      # Split on decimal point to avoid float precision loss on 10-digit timestamps;
      # handle timestamps with or without fractional microseconds.
      ts_str = ts_str.strip()
      if "." in ts_str:
          sec_str, usec_str = ts_str.split(".", 1)
          return int(sec_str) * 1_000_000 + int(usec_str[:6].ljust(6, "0"))
      return int(ts_str) * 1_000_000
  ```
  - **Child Processes:** Defined as the timestamp of the parent's `clone`, `clone3`, `fork`, or `vfork` syscall return.
  - **Root Payload Process:** Because `bwrap` executes the initial sample image, the host PID initially belongs to `bwrap`. The sample's root identity begins at the `execve` of the target execution command vector. Prior to that `execve`, events belong to supervisor setup and are discarded.

#### Handling `execve` and `execveat`
- Calling `execve` or `execveat` replaces the process image but **preserves** the PID and start time.
- Therefore, `execve` does **not** create a new process identity. It emits a `process_exec` event that updates the process attributes in `analysis_processes`:
  - `exe_path`: updated to the new executable image.
  - `process_name`: updated to the new basename.
  - `command_line`: updated to the new argument list.
  - `env_diff`: records modified or stripped environment variables.

#### Handling Reparenting
- When a process's immediate parent exits, the kernel reparents the process to an ancestor subreaper or the init process (PID 1).
- Reparenting does **not** create a new process identity. The original `parent_pid` at spawn time remains recorded in `initial_ppid`, while the current parent pointer in `analysis_processes` is updated via a `process_reparent` event.

### 2.2 PID Namespace Handling (`--unshare-pid`) & Tracing Boundary

When dynamic execution runs inside bubblewrap with `--unshare-pid`:
- The sample's primary process becomes **PID 2** inside the inner PID namespace (PID 1 is bubblewrap's init reaper).
- On the host, the process receives an arbitrary kernel **host PID** (e.g., host PID 11433).
- Subsequent child processes spawned by the sample receive sequential inner PIDs (e.g., inner PID 3, host PID 11434).

#### Tracing Boundary & Filter Seam (Empirically Verified)
1. **Outer Boundary Tracing:** The tracer (`strace`) runs **outside** the bubblewrap sandbox on the host, tracing the `bwrap` command and all spawned descendants from launch:
   ```bash
   strace -f -ttt -yy --decode-pids=pidns -s 256 -o /supervisor/strace.log bwrap ...
   ```
2. **Empirical Line Structure (Strace 7.2):**
   Every output line follows the whitespace-delimited structure:
   ```text
   <host_pid> <epoch_seconds.microseconds> <syscall_or_event>
   ```
   Example from [`tests/fixtures/c_probe_strace.log:1`](file:///home/kripy/.gemini/antigravity/worktrees/OutPost/inspect_project_state/tests/fixtures/c_probe_strace.log#L1):
   ```text
   11431 1793087029.468321 execve("/usr/bin/bwrap", ["bwrap", ...]) = 0
   ```
3. **Identifying the Sample Start Seam (Empirically Verified):**
   - Lines 1 through 787 in `c_probe_strace.log` contain `bwrap` internal supervisor setup: creating user/PID/mount namespaces, calling `pivot_root`, mounting `/usr`, `/tmp`, bind-mounts, dropping capabilities, and closing inherited host file descriptors.
   - At line 771, `bwrap` (host PID 11432) creates the sample container process:
     ```text
     771: 11432 1793087029.578896 clone(..., child_tidptr=0x7fadc0616e90) = 2 /* 11433 in strace's PID NS */
     ```
   - At line 788, the child process (host PID 11433, inner PID 2) executes the target sample:
     ```text
     788: 11433 1793087029.628538 execve("/tmp/outpost_sandbox_c_probe/probe_elf", ["/tmp/outpost_sandbox_c_probe/probe_elf"], ... <unfinished ...>
     ...
     793: 11433 1793087029.628949 <... execve resumed>) = 0
     ```
   - **Filter Rule:** All lines prior to the matching target command `execve` return (line 793) are discarded as supervisor initialization.
4. **Supervisor vs. Sample Filtering by Process Ancestry:**
   - Filtering is strictly governed by **process ancestry**, not hardcoded host PIDs.
   - Upon the sample start seam (line 793), the host PID of the executing sample is established as the `sample_root_host_pid` (e.g., `11433`).
   - A dynamic tracking set `sample_processes = {sample_root_host_pid}` is initialized.
   - Whenever any process in `sample_processes` spawns a child via `clone()`, `fork()`, `vfork()`, or `clone3()`, the newly created child's host PID is immediately added to `sample_processes`.
   - **Handling Reparented Orphans:** If a child process is orphaned (e.g. via double-fork), the Linux kernel reparents it to namespace PID 1 (host PID 11432, bubblewrap supervisor). However, because `child_host_pid` was registered into `sample_processes` at the moment of fork, the orphaned child remains fully tracked for its entire lifetime.
   - Processes whose ancestry does not trace back to `sample_root_host_pid` (such as the bubblewrap launcher 11431 and supervisor 11432) are excluded from the analysis stream.
5. **PIDNS Decoding Syntax (Strace 7.2 Empirical Finding):**
   Under `--decode-pids=pidns`, strace does **not** emit `(pidns <id>)`. Instead:
   - For `clone()`, `getpid()`, and `wait4()`, the return value is the **inner namespace PID**, followed by a comment with the host PID:
     ```text
     965: 11433 1793087029.636190 <... clone resumed>, child_tidptr=0x7f2d37af9a10) = 3 /* 11434 in strace's PID NS */
     973: 11434 1793087029.665275 <... getpid resumed>) = 3 /* 11434 in strace's PID NS */
     974: 11433 1793087029.684501 wait4(3 /* 11434 in strace's PID NS */ ...
     ```
   - `host_pid`: Column 1 of every line (e.g. `11433`, `11434`).
   - `ns_pid`: Captured from the syscall return value (`= 3`) or wait4 target (`3`).
   - Note: For calls originating from the host namespace before namespace translation (such as line 87 `clone(...) = 11432`), the comment is omitted because strace and the calling process share the same PID namespace.
6. **Tooling & Versions (Host Audit):**
   - Verified on host: `strace 7.2`, `tcpdump 4.99.7`, `bwrap 0.13.1`, Linux kernel `7.2.8`.
   - Verified `kernel.yama.ptrace_scope = 1` successfully traces `bwrap` and all namespace descendants without privilege elevation.

---

## 3. Tracer Placement & Security Isolation

### 3.1 Trace File Security Invariant
> **Critical Rule:** The trace log must never reside inside the sandbox filesystem jail.

If `strace -o` writes to `/tmp/outpost_sandbox_<run_id>/trace.log`, untrusted malware running inside the sandbox could truncate the file, overwrite records, or unlink it.

### 3.2 Secure Host Supervisor Directory
- OutPost creates a host supervisor directory using `tempfile.mkdtemp(prefix="outpost_supervisor_", dir=os.getenv("OUTPOST_SUPERVISOR_DIR", Path.home() / ".local/state/outpost/supervisor"))` with mode `0700` (user-owned, no root requirement).
- Must be a regular file (`strace.log`). Named pipes (`FIFO`) are forbidden because a slow reader would stall or hang the traced guest process.
- Bubblewrap is invoked with explicit mounts that **exclude** the supervisor directory. The untrusted guest has zero visibility or file descriptors to this location.

---

## 4. Telemetry Provenance: Explicit `source` and `origin` Values

To guarantee forensic integrity and prevent narrative invention, telemetry provenance is strictly tracked via two orthogonal enums: `source` (how the data was captured) and `origin` (the operational nature of the execution).

### 4.1 `source` (Collection Mechanism)

| Value | Mechanism | Description |
| :--- | :--- | :--- |
| `traced` | Syscall Interception | Directly observed kernel syscalls via `strace -f -ttt -yy`. |
| `polled` | Periodic `/proc` | Periodic sampling of `/proc/<pid>/cmdline`, `stat`, `status`, and open file descriptors. |
| `captured` | Wire Network PCAP | Raw network frames captured on the network interface / bridge via packet capture. |
| `diffed` | Filesystem Walk | Cryptographic hash and metadata delta between pre-execution and post-execution sandbox state. |
| `reconstructed` | Analytical Inference | Inferred or extrapolated data (e.g., memory carving reconstructions, heuristic parent link rebuilds). |

### 4.2 `origin` (Execution Context)

| Value | Context | Description |
| :--- | :--- | :--- |
| `observed` | Live Detonation | Live execution of an untrusted sample in the dynamic sandbox. |
| `replayed` | Artifact Ingestion | Imported forensic captures (e.g., PCAP or strace log uploaded from external provider). |
| `simulated` | Playbook Scenario | Canned adversary simulation playbooks executed for detection verification. |
| `imported` | Historical Seed | Legacy seeded database samples migrated from external datastores. |
| `test` | Unit Test Fixture | Mocked synthetic data emitted by the test runner. |

---

## 5. Timing, Clocks, Ordering & Ingestion Quotas

### 5.1 Timestamp Precision & Clocks
- Linux `strace -ttt` outputs timestamps formatted as epoch seconds with 6 microsecond decimal places (`1729938400.123456`).
- **Timing Representations:**
  - `timestamp`: Wall-clock UTC string formatted to 6 decimal places: `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
  - `start_time_us`: Integer epoch microseconds (`parse_strace_ts_to_us(ts_str)`).
  - `mono_us`: Microsecond relative offset elapsed from run launch:
    - For live executions: computed from Python `time.monotonic_ns() // 1000`.
    - For imported/replayed/post-hoc logs: computed as `event_epoch_us - run_start_epoch_us`.

### 5.2 Central Timeline Sequencer & Watermark Ordering
Every event within a `run_id` receives a contiguous integer sequence index:
$$\text{seq} \in [0, 1, 2, \dots, N-1]$$
- **Writer Authority:** `seq` is assigned exclusively by the central Timeline Sequencer / DB Writer at commit time, never by individual collectors.
- **Merge Sorting & Watermark:**
  - Events from concurrent collectors (`traced`, `polled`, `diffed`, `captured`) buffer into a priority queue sorted by timestamp.
  - A **watermark delay** (1.0 second) buffers incoming events to allow delayed `/proc` polling samples to arrive and slot into their exact chronological order before contiguous integer `seq` values are committed.
  - **Immediate Run-End Flush:** At process termination or timeout, the watermark buffer flushes immediately; all remaining buffered events are committed without waiting.
  - For live SSE feeds, events inside the uncommitted window stream with `seq = null` (pending sequence status).

### 5.3 Event Quotas & Intelligent Rate Collapsing
Malware employing syscall loops can generate millions of redundant events.

- **Current Implementation Status (Step 2d Baseline):**
  - **Noise Filter (Active):** Reads to system shared libraries, dynamic loader caches, and standard runtime interpreters (`/usr/lib`, `/lib64`, `/etc/ld.so.cache`, Python site-packages/venv stdlib) are suppressed and counted under `suppressed_system_reads` in `run_analysis_stats`.
  - **Per-Category Soft Limits:** File events are capped at 1,000 events; module load events are capped at 500 events.
  - **Guaranteed Category Preservation:** Process lifecycle (`process_create`, `fork`, `exec`, `exit`), network connection attempts, and DNS queries are preserved.
  - **Flat Total Cap (5,000 events):** Ingestion enforces a hard limit of 5,000 total events per run. If exceeded, subsequent tail events are discarded, a `trace_truncated` event marker is appended to the timeline, and `is_truncated = 1` is recorded in `run_analysis_stats`.
- **Known Limitations & Deferred Capabilities:**
  - *Dynamic Sliding-Window Burst Collapsing:* Collapsing repetitive polling loops or high-frequency write bursts into single aggregated events with `burst_count` is deferred to a future milestone.
  - *Cross-Category Dynamic Windowing:* Dynamic proportional decay across prolonged executions is deferred.

- **Truncation Event Marker Format:**
  When quota truncation occurs, the timeline records:
  ```json
  {
    "category": "process",
    "event_type": "trace_truncated",
    "source": "traced",
    "origin": "observed",
    "details": {
      "reason": "total_quota_exceeded (5000)",
      "limit": 5000,
      "message": "Analysis trace reached maximum event limit; subsequent tail events truncated."
    }
  }
  ```

---

## 6. Process Attribution & Correlation Rules

In `analysis_events`, the process link `process_pk` is **nullable** to support un-attributed events.

### 6.1 `captured` Network & DNS Attribution
- Wire PCAP frames have layer 3/4 headers (`src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`) but no inherent process metadata.
- **Port-Time Correlation:** The ingestion engine correlates each captured socket event against the `traced` syscall stream by matching:
  $$(src\_port, dst\_ip, dst\_port) \quad \text{within a } \pm 50\text{ms window of } connect() \text{ or } sendto()$$
- If a match is found, the event links `process_pk`. If no matching syscall is recorded, `process_pk` remains `NULL`.

### 6.2 `diffed` Filesystem Attribution
- Filesystem delta scans detect modified or created files on disk post-mortem.
- If a file path matches an `openat(..., O_CREAT)` or `write()` syscall in the `traced` stream, the `diffed` event links the responsible `process_pk`. Otherwise, `process_pk` remains `NULL`.

---

## 7. Noise Suppression & File Event Policy

Executing standard interpreters (Python, Bash, Node) emits thousands of routine shared library inspections.

### 7.1 File Event Policy
1. **Always Record (Full Audit):**
   - `file_create`, `file_modify`, `file_delete`, `file_rename`, `file_perm_change` are recorded across the entire filesystem regardless of path.
2. **Path-Filtered Reads (`file_read`):**
   - `file_read` events are recorded **only** for paths outside standard system library directories.
   - Monitored paths: `/tmp`, `/var/tmp`, `/dev/shm`, `/home`, the sample file itself, and the sandbox workspace directory.
3. **Suppressed System Reads:**
   - Reads of `/usr/lib*`, `/lib*`, `/etc/ld.so.cache`, and standard Python stdlib modules are suppressed from the main event stream.
   - Aggregate statistics are retained in `run_analysis_stats.suppressed_system_reads`.

---

## 8. Network & DNS Behavior Across Isolation Modes

### 8.1 Default Isolated Mode (`--unshare-net`)
In the default hardened sandbox configuration:
- Network namespace is unshared (`--unshare-net`).
- Only the `lo` loopback interface is present (unconfigured).
- Host `/etc/resolv.conf` is **not** bound into the container.

#### Telemetry Reality
1. **DNS Invocations & Resolver Fallback:**
   - Because `/etc/resolv.conf` is not mounted into the sandbox cage, glibc's internal resolver attempts `openat(AT_FDCWD, "/etc/resolv.conf", O_RDONLY|O_CLOEXEC)`, receives `ENOENT`, and per RFC/glibc standard falls back to nameserver `127.0.0.1:53`.
   - The resolver executes `connect(fd, {sin_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.1")}, 16) = 0` (line 1027 in `c_probe_strace.log`).
   - **Crucial Rule on UDP `connect()`:** On Linux/POSIX, `connect()` on a UDP datagram socket performs no three-way handshake and transmits zero packets across the wire; it merely sets the socket's default destination address in kernel state. A UDP `connect()` returning 0 does **not** signify a successful network exchange or nameserver presence.
   - The actual query attempt occurs when `sendto(...)` or `write(...)` transmits the DNS wire payload (line 1064). With no nameserver bound on `127.0.0.1:53`, the kernel's loopback interface rejects the datagram with an ICMP Port Unreachable message, causing subsequent `poll(...)` to return `POLLERR` (line 1070: `poll([{fd=10, revents=POLLERR}])`) or `recvfrom(...)` to return `ECONNREFUSED`.
   - **Canonical Representation:**
     The event is recorded as `dns_query` with `status="attempted_unanswered"` or `status="failed"`, `domain="<queried_domain>"`, `nameserver="127.0.0.1:53"`, and failure details derived from the `poll`/`recvfrom`/`getaddrinfo` outcome. It is **never** recorded as a successful name resolution.
2. **Socket Connections:** Sockets created with `socket(AF_INET, SOCK_STREAM, ...)` succeed in allocation, but subsequent `connect()` syscalls return immediate kernel errors (`ENETUNREACH` or `ECONNREFUSED`).
3. **Canonical Representation:**
   Syscall tracing records these failed connection attempts as `network_connect` with `status="failed"` and `error_code="ENETUNREACH"`.

### 8.2 Fake-Network Sinkhole Mode (Step 4 Detonation Architecture)
Real DNS resolutions and interactive C2 conversations require the Step 4 network sinkhole architecture:
1. **Virtual Ethernet (`veth` Pair):** The sandbox network namespace connects to an isolated software bridge (`outpost-br0`).
2. **In-Namespace Sinkhole Engine:**
   - **DNS Responder:** Intercepts UDP port 53 queries and resolves all domain names to the sinkhole gateway IP (`10.0.2.2`). Emits genuine `dns_query` and `dns_response` events.
   - **HTTP/HTTPS Responder:** Listens on ports 80/443 returning generic 200 OK responses or payload staging replies.
   - **TCP/UDP Sink:** Swallows reverse shells and C2 beacon traffic.
3. **PCAP Capture:** An external `dumpcap` or raw socket sniffer monitors the `veth` interface from the host, emitting packet-level `source="captured"` events.

---

## 9. Strace Technical Boundaries & Parser Specification

### 9.1 Known Limitations of `strace`
1. **Anti-Ptrace Detection (`PTRACE_TRACEME`):**
   - Malware frequently calls `ptrace(PTRACE_TRACEME, 0, 1, 0)` on startup.
   - Because `strace` is already tracing the process via `PTRACE_ATTACH`/`PTRACE_SEIZE`, the kernel rejects the sample's request with `EPERM`.
   - Malware detecting this error may immediately abort malicious routines.
   - *Future Architectural Evolution:* Subsequent stages will introduce eBPF-based kprobe/tracepoint capture, seccomp user-space notification (`SECCOMP_RET_USER_NOTIF`), or the Linux Audit subsystem (`auditd`) to monitor syscalls without attaching ptrace.
2. **Performance Overhead:**
   - Ptrace requires two context switches per syscall (entry and exit).
   - High-throughput I/O loops or CPU-heavy encryption routines will experience noticeable execution slowdowns.

### 9.2 Parser Edge Cases & Grammar Rules (Empirically Verified)
The OutPost strace parser (`strace_parser.py`) uses regex-based state machines to handle:
1. **Unfinished and Resumed Syscalls (Interleaved Execution):**
   ```text
   11433 1793087029.628538 execve("/tmp/sandbox/probe_elf", ["/tmp/sandbox/probe_elf"], ... <unfinished ...>
   11432 1793087029.628567 <... fstat resumed>, {st_mode=S_IFDIR|0500, st_size=74, ...}) = 0
   11433 1793087029.628949 <... execve resumed>) = 0
   ```
   Maintains `in_flight_syscalls[host_pid]` to reassemble split entries upon `<... <syscall> resumed>`.
2. **PIDNS Child Correlation:**
   ```text
   11433 1793087029.636190 <... clone resumed>, child_tidptr=0x7f2d37af9a10) = 3 /* 11434 in strace's PID NS */
   ```
   - Extracts `inner_pid = 3` from return value.
   - Extracts `host_pid = 11434` from comment `/* 11434 in strace's PID NS */`.
   - Records child process entity in `analysis_processes` with compound key `f"{run_id}:11434:{start_time_us}"`.
3. **Truncated Buffers & String Literals:**
   - Arguments truncated with `...` (via `-s 256`) are stored as captured.
   - **Zero Content Leakage:** File read/write buffer contents are **never** stored in events; only byte lengths, return codes, and file paths are recorded.
4. **Signals & Process Exits:**
   - `11434 1793087029.685214 +++ exited with 0 +++` -> mapped to `process_terminate` with `exit_code=0`.
   - `11433 1793087029.704193 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=3, si_uid=1000, si_status=0, ...} ---` -> reaped child signal notification.

---

## 10. Database Schema, Migration Strategy & Run Stats

### 10.1 Schema Definition: Normalized Processes, Events, and Run Stats

```sql
-- 1. Entity Table: Normalized Process Lifecycle
CREATE TABLE IF NOT EXISTS analysis_processes (
    process_pk TEXT PRIMARY KEY, -- Composite: f"{run_id}:{host_pid}:{start_time_us}"
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    host_pid INTEGER NOT NULL,
    ns_pid INTEGER,
    start_time_us INTEGER NOT NULL,
    initial_ppid INTEGER NOT NULL,
    current_ppid INTEGER NOT NULL,
    exe_path TEXT NOT NULL,
    command_line TEXT NOT NULL,
    process_name TEXT NOT NULL,
    host_id TEXT DEFAULT 'local',
    uid INTEGER,
    gid INTEGER,
    cwd TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(run_id, host_pid, start_time_us)
);

CREATE INDEX IF NOT EXISTS idx_analysis_processes_run ON analysis_processes(run_id);
CREATE INDEX IF NOT EXISTS idx_analysis_processes_host_pid ON analysis_processes(run_id, host_pid);

-- 2. Chronological Canonical Event Stream
CREATE TABLE IF NOT EXISTS analysis_events (
    event_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    mono_us INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN (
        'process', 'file', 'registry', 'network', 'dns', 'api', 'mutex', 'service', 'module'
    )),
    event_type TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN (
        'traced', 'polled', 'captured', 'diffed', 'reconstructed'
    )),
    origin TEXT NOT NULL CHECK (origin IN (
        'observed', 'replayed', 'simulated', 'imported', 'test'
    )),
    -- Process Reference (Nullable for diffed/captured wire events)
    process_pk TEXT REFERENCES analysis_processes(process_pk) ON DELETE CASCADE,
    -- Polymorphic Typed Payload
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(run_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_analysis_events_run_seq ON analysis_events(run_id, seq);
CREATE INDEX IF NOT EXISTS idx_analysis_events_category ON analysis_events(run_id, category);
CREATE INDEX IF NOT EXISTS idx_analysis_events_process ON analysis_events(process_pk);
CREATE INDEX IF NOT EXISTS idx_analysis_events_origin ON analysis_events(origin);

-- 3. Companion Table for Run-Level Counters & Quota Status
CREATE TABLE IF NOT EXISTS run_analysis_stats (
    run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
    total_events INTEGER NOT NULL DEFAULT 0,
    suppressed_system_reads INTEGER NOT NULL DEFAULT 0,
    collapsed_burst_events INTEGER NOT NULL DEFAULT 0,
    is_truncated INTEGER NOT NULL DEFAULT 0,
    truncation_reason TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
```

### 10.2 Foreign Key Enforcement
`PRAGMA foreign_keys = ON;` is enforced on every database connection at [`backend/app/core/db.py:1187`](file:///home/kripy/.gemini/antigravity/worktrees/OutPost/inspect_project_state/backend/app/core/db.py#L1187). SQLite native `json_extract()` is supported (requires SQLite >= 3.38.0).

### 10.3 Direct Service Migration Strategy (No Dual Schema)
To prevent split-schema bugs and performance degradation from virtual views:
- Step 2 directly migrates `detection.py`, `process_tree.py`, and `routes_runs.py` to query `analysis_events` joined with `analysis_processes`.
- Incompatibilities that precluded relying on `legacy_events_compat`:
  1. `seq AS id` is per-run, breaking cross-run uniqueness expectations in queries doing `SELECT id FROM events`.
  2. `process_start_time` is integer epoch microseconds rather than formatted ISO strings.
  3. `json_extract()` on unindexed JSON columns during full detection sweeps causes massive query performance degradation.
  4. Mapping `file_modify`/`file_create` to `file_write` loses `file_rename`, `file_delete`, and `file_perm_change` granularity.
- The legacy `events` table will be safely dropped during Step 2 migration after all services target `analysis_events`.
- **Destructive Migration Safety Protocol:** Dropping the legacy `events` table is a destructive schema change. Following the pattern of migration 32 (`backend/app/core/db.py`), this migration must:
  1. Be registered in `DESTRUCTIVE_MIGRATIONS`.
  2. Automatically generate a timestamped file backup (`outpost.db.backup-YYYYMMDD_HHMMSS`) before modifying table structures.
  3. Re-enable foreign keys and assert `PRAGMA foreign_key_check` passes with zero violations post-drop.

### 10.4 Writer-Side JSON Schema Validation (Strict)
Prior to database insertion, `details_json` payloads are validated using strict Pydantic models configured with `model_config = ConfigDict(extra="forbid")`:
- `ProcessEventDetails`: `child_pid`, `exit_code`, `signal`, `clone_flags`, `exe_path`, `command_line`
- `FileEventDetails`: `file_path`, `old_path`, `bytes_transferred`, `burst_count`, `fd`, `mode`, `sha256`
- `NetworkEventDetails`: `protocol`, `direction`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `status`, `error_code`
- `DnsEventDetails`: `query_name`, `query_type`, `response_ips`, `rcode`, `ttl`
- `ModuleEventDetails`: `module_path`, `base_address`, `module_size`, `sha256`

---

## 11. Design Decisions & Step 2 Implementation Test Plan

### 11.1 Architectural Decisions Summary
1. **Decision on Process Normalization:** Process identity is normalized into `analysis_processes` keyed by `(run_id, host_pid, start_time_us)`. Image mutations via `execve` emit `process_exec` updating attributes; reparenting emits `process_reparent`.
2. **Decision on Dual PIDs:** `host_pid` and `ns_pid` are recorded side-by-side using `strace --decode-pids=pidns`. `ns_pid` is nullable if transient processes terminate before translation.
3. **Decision on Tracer Boundary:** `strace` runs on the host outside `bwrap`, writing to a supervisor directory inaccessible from inside the sandbox. Setup syscalls are discarded up to the sample's `execve`.
4. **Decision on Telemetry Scopes:** Linux strace engine emits `process`, `file`, `network`, `dns`, and `module`. The categories `registry`, `api`, `mutex`, and `service` are reserved for Windows/CAPE external adapters.
5. **Decision on Event Noise & Limits:** System library reads are filtered; repeated bursts are collapsed; core process/network/file events are retained; run events are capped with a `trace_truncated` marker.
6. **Decision on Direct Migration:** Services migrate directly to `analysis_events` in Step 2; no long-lived compatibility views.

### 11.2 Step 2 Implementation Test Plan
During Step 2 implementation, the following unit and integration tests will be developed:
- `test_strace_parser_unfinished_resumed`: Verifies split lines across multiple PIDs reassemble accurately.
- `test_strace_parser_clone3_execveat`: Verifies modern Linux syscall parameter and return decoding.
- `test_strace_parser_noise_filter`: Verifies `/usr/lib` reads are filtered while workspace writes are retained.
- `test_strace_parser_burst_collapsing`: Verifies burst write loops are collapsed into aggregate records.
- `test_analysis_events_schema_crud`: Verifies monotonic `seq` assignment and FK cascade on run deletion.
- `test_analysis_processes_exec_reparent`: Verifies attribute updates on `execve` and parent updates on reparent.
- `test_detection_engine_analysis_events`: Verifies that dynamic analysis detection rules fire against `analysis_events`.
