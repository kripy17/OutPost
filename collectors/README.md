# OutPost collectors — live host telemetry (roadmap 2.1)

Two small host agents that read OS telemetry and ship it to the OutPost
backend's existing `POST /ingest/batch` — the layer that turns the platform
into a live monitor. **No business logic lives here**: read → normalize →
ship (docs/03).

| Agent | Source | Event mapping |
|---|---|---|
| `linux/collector_linux.py` | auditd log tail (`/var/log/audit/audit.log`) | `type=EXECVE`/`syscall=59` → `process_create`; `connect`/`saddr=` → `network_connection` |
| `windows/collector_win.py` | Sysmon channel (`Microsoft-Windows-Sysmon/Operational`) | EventID 1 → process_create, 3 → network_connection, 11 → file_write, 12/13/14 → registry_write |

Shared pieces live in `common/`: `schema.py` (the unified `Event` dataclass —
mirrors the backend schema exactly) and `shipper.py` (batch POST with retry +
fallback spooling to `outpost-spool-<run>.jsonl`).

## Verification (roadmap 2.1)

The collectors are the only part of the codebase that needs real host
telemetry, so they were the least-tested. `collectors/tests/test_collectors.py`
locks the **pure parsing + shipping logic** so a fresh checkout can trust
them without an auditd/Sysmon host:

```bash
cd collectors && ../.venv/bin/pytest -q      # 12 tests
```

Covers: auditd EXECVE/connect parsing (incl. the `saddr` hex decoder),
Sysmon event-ID mapping via a stub record, batch-size flushing, spooling when
the backend is down, and spool replay after recovery. `verify.sh` runs this
step between backend and CLI pytest.

Two real bugs were found and fixed while writing these tests:

1. **auditd parser only matched `type=SYSCALL` records** — real auditd emits
   `type=EXECVE` (process args, no pid) and `type=SOCKADDR` (connect dest).
   The regex now matches all three record types and the execve handler falls
   back to `a0="…"` for the program name.
2. **Shipper never replayed the spool on an empty flush** — `flush()` used to
   early-return when the buffer was empty, so a collector with no new events
   would never push spooled events back after the backend recovered. Empty
   flushes now still attempt `_replay_spool()`.

## End-to-end run (live collector → backend → webapp)

The CLI already wires the collectors (`outpost run` analysis mode, `outpost
watch` live mode → `monitoring/session.py::start_local_collector`), so the
end-to-end path is exercised without manual steps:

```bash
# 1. Backend up (port 8001 in this repo — see .freebuff/run.md):
cd backend && CORS_ORIGINS=http://localhost:5174 ../.venv/bin/uvicorn app.main:app --port 8001

# 2. Analysis-mode session — creates the run, starts the collector,
#    executes the sample, stops the collector, completes the run:
OUTPOST_API_URL=http://localhost:8001 ../.venv/bin/outpost run ./sample.bin --timeout 60

# 3. Live-mode session — collector runs indefinitely, dashboard renders alerts:
OUTPOST_API_URL=http://localhost:8001 ../.venv/bin/outpost watch
```

Manual host prerequisites (only needed for real telemetry, not the tests):

- **Linux**: `auditd` running, rules loaded:
  `sudo auditctl -R collectors/linux/audit.rules`
- **Windows**: Sysmon installed with `sysmon_config.xml`:
  `sysmon -accepteula -i collectors/windows/sysmon_config.xml`

A collector that cannot reach the backend spools events to
`outpost-spool-<run_id>.jsonl` in the working directory and replays them on
the next successful flush — no data lost across a backend restart mid-run.
