# Collector Agent Specification

Collectors are intentionally minimal: **read telemetry → normalize → ship.** No business logic belongs here (see `AGENTS.md` rule #2).

## Shared Behavior (both platforms)

- Accept a `run_id` and backend URL via config/CLI args at startup
- Buffer events locally and batch-POST every N seconds (e.g. every 2s or every 20 events, whichever first) — don't POST one event at a time, it's wasteful and slow
- On backend unreachable: retry with backoff, buffer to a local file as a fallback so no data is lost if the backend restarts mid-run
- All timestamps in UTC ISO-8601
- Exit cleanly on a stop signal (used when the observation window ends)

```python
# collectors/common/shipper.py — shared shipping logic
import requests
import time

class Shipper:
    def __init__(self, backend_url: str, run_id: str, batch_size: int = 20, flush_interval: float = 2.0):
        self.backend_url = backend_url
        self.run_id = run_id
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.buffer = []
        self.last_flush = time.time()

    def add(self, event: dict):
        event["run_id"] = self.run_id
        self.buffer.append(event)
        if len(self.buffer) >= self.batch_size or time.time() - self.last_flush > self.flush_interval:
            self.flush()

    def flush(self):
        if not self.buffer:
            return
        try:
            requests.post(f"{self.backend_url}/ingest/batch", json=self.buffer, timeout=5)
            self.buffer.clear()
        except requests.RequestException:
            pass  # retry logic / local fallback file goes here
        self.last_flush = time.time()
```

## Two Modes: Live vs Bounded

Collectors support two run modes, set at startup:

- **Live mode** (`--mode live`): runs indefinitely, no stop signal expected — this is the everyday "watch my system" use case. `outpost watch` (CLI) starts a collector this way.
- **Analysis mode** (`--mode analysis --timeout 240`): runs for a fixed observation window, then exits automatically — used for a deliberate, bounded look at one specific file. `outpost run <sample>` starts a collector this way.

Either way, collectors don't manage anything beyond their own telemetry loop — no VM control, no snapshot logic, nothing infrastructure-related lives here. That keeps them portable: the exact same collector script works whether it's running on your daily machine, a lab box, or inside a VM you've set up yourself (see `docs/05-DEPLOYMENT-SETUP.md`).

## Windows Collector

**Prerequisites:**
- Sysmon installed with `sysmon_config.xml` (tuned from the SwiftOnSecurity baseline — keep Event IDs 1, 3, 11, 12/13/14 enabled, trim noisy defaults)

**Approach:**
- Tail the Sysmon Windows Event Log channel (`Microsoft-Windows-Sysmon/Operational`) using `pywin32`'s `win32evtlog` module, polling for new records
- Map Sysmon Event ID → `event_type`:
  - `1` → `process_create` (extract `ProcessId`, `ParentProcessId`, `Image`, `CommandLine`)
  - `3` → `network_connection` (extract `DestinationIp`, `DestinationPort`, `Protocol`)
  - `11` → `file_write` (extract `TargetFilename`)
  - `12/13/14` → `registry_write` (extract `TargetObject`)
- Normalize each parsed record into the shared schema, pass to `Shipper.add()`

**File:** `collectors/windows/collector_win.py`

```python
# Skeleton — implement per Event ID as above
import win32evtlog
from shipper import Shipper

def parse_sysmon_event(event) -> dict | None:
    ...  # map raw event XML/fields to unified schema dict

def main(run_id: str, backend_url: str):
    shipper = Shipper(backend_url, run_id)
    # open Sysmon channel, poll loop, parse_sysmon_event(), shipper.add()
    ...
```

## Linux Collector

**Prerequisites:**
- `auditd` installed, with rules watching relevant syscalls:

```
# collectors/linux/audit.rules
-a always,exit -F arch=b64 -S execve -k vantage_exec
-a always,exit -F arch=b64 -S connect -k vantage_net
```

**Approach:**
- Tail `/var/log/audit/audit.log` (or use `ausearch -k vantage_exec -k vantage_net` on a polling loop)
- Parse `execve` records → `process_create` (PID, PPID via `/proc/<pid>/stat` lookup at capture time, `comm`, full `argv` as `command_line`)
- Parse `connect` records → `network_connection` (destination IP/port from the syscall args, requires parsing the `saddr` field)
- Normalize into shared schema, pass to `Shipper.add()`

**File:** `collectors/linux/collector_linux.py`

```python
# Skeleton
import subprocess
from shipper import Shipper

def parse_audit_line(line: str) -> dict | None:
    ...  # parse type=SYSCALL / type=EXECVE lines, map to unified schema

def main(run_id: str, backend_url: str):
    shipper = Shipper(backend_url, run_id)
    # tail audit.log, parse_audit_line(), shipper.add()
    ...
```

*(Upgrade path noted in the build plan: swapping this for Falco later gives structured JSON output natively, removing most of the manual parsing — worth doing once the MVP pipeline is proven.)*

## Testing Collectors Safely

Before pointing either collector at a real untrusted sample, validate against a synthetic test script that:
- Spawns 2–3 child processes with identifiable names
- Opens a connection to a test IP/port you control (e.g. a `netcat` listener on the same machine or network segment)

If the dashboard shows the expected process tree and connection for that synthetic script, the pipeline is proven end-to-end before anything real touches it. This is also the fastest way to test **live mode** specifically — start `vantage watch`, run the synthetic script in a normal terminal, and confirm the alert/event stream picks it up in near real time.
