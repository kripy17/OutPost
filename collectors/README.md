# OutPost collectors — live host telemetry

Two small host agents that read **real OS telemetry** and stream it into an
OutPost **live session**, so the webapp's Live Monitor shows actual
activity from the machine — processes spawning, connections being made, files
touched — instead of just synthetic detonations.

No business logic lives here: each agent just **reads → normalizes → ships**.
All detection, risk scoring, and alerting happens in the backend.

| Agent | Source | Event mapping |
|---|---|---|
| `linux/collector_linux.py` | auditd log tail (`/var/log/audit/audit.log`) | `type=EXECVE`/`syscall=59` → `process_create`; `connect`/`saddr=` → `network_connection` |
| `windows/collector_win.py` | Sysmon channel (`Microsoft-Windows-Sysmon/Operational`) | EventID 1 → process_create, 3 → network_connection, 11 → file_write, 12/13/14 → registry_write |

Shared pieces live in `common/`: `schema.py` (the unified event shape — mirrors
the backend schema) and `shipper.py` (buffered batch POST with retry +
fallback spooling, plus `claim_active_live_run()` for the webapp flow below).

---

## The webapp live flow (recommended)

This is the end-to-end path: you open a live session in the browser, the
collector **auto-claims it**, and real host events stream straight into the
Monitor page — process tree, network table, timeline, and alerts as they fire.

**1. Start the stack** (backend on port 8001 — this repo's port):

```bash
cd backend && CORS_ORIGINS='["http://localhost:5174"]' ../.venv/bin/uvicorn app.main:app --port 8001
cd ../frontend && npm run dev
```

**2. Open the Live Monitor → click “Start live monitoring”.**

The page creates an open `live` session and starts watching it. It now shows
an empty process tree, waiting for events.

**3. Run the collector — it claims that session automatically.**

Just omit `--run-id`; the collector calls `GET /runs/active-live`, which
returns the newest open live session, and streams into it:

```bash
# Linux (auditd)
python collectors/linux/collector_linux.py --mode live

# Windows (Sysmon)
python collectors/windows/collector_win.py --mode live
```

> `--run-id <id>` targets a specific run instead (fine for tests and
> replaying into analysis sessions). `--mode live` runs forever;
> `--mode analysis --timeout 60` runs for 60s then exits.
>
> The backend URL defaults to `http://localhost:8001` and can be overridden
> with `--backend-url` or the `OUTPOST_API_URL` environment variable.

**4. Watch it stream.** Every execve/connect (Linux) or Sysmon event
(Windows) is normalized and batched to `POST /ingest/batch`; detection runs
per batch, so alerts appear in the Monitor's toast stream and alert banner
within seconds.

If you run the collector while the session is already closed, it fails with
a clear message — open a new live session first.

---

## Host prerequisites

Only needed for real telemetry (the tests below don't require a host agent):

**Linux — auditd:**

```bash
sudo pacman -S audit             # Arch; or apt install auditd / dnf install audit
sudo systemctl enable --now auditd
sudo auditctl -R collectors/linux/audit.rules   # watches execve + connect
sudo auditctl -l                 # confirm the rules are loaded
```

**Windows — Sysmon:**

```powershell
# Run as Administrator
sysmon64 -accepteula -i collectors/windows/sysmon_config.xml
```

The collector needs `pywin32` on Windows: `pip install pywin32`.

---

## The CLI paths

The terminal mirrors the same two modes (`outpost watch` / `outpost run`),
each starting the matching local collector for you:

```bash
OUTPOST_API_URL=http://localhost:8001 ../.venv/bin/outpost watch    # live dashboard, runs forever
OUTPOST_API_URL=http://localhost:8001 ../.venv/bin/outpost run ./sample.bin --timeout 60   # bounded analysis
```

`outpost run` creates the run, starts the collector, executes the sample,
observes for the window, then completes the run and prints the full report.

---

## Reliability — spooling

A collector that can't reach the backend (backend restart, network blip)
spools its batch to `outpost-spool-<run_id>.jsonl` in the working directory
and **replays it on the next successful flush** — no events lost mid-run.
On Windows you may want to run the collector as a scheduled task; on Linux,
`systemd` or `nohup` both work.

---

## Verification

The parsing + shipping logic is fully unit-tested so a fresh checkout can
trust the agents without a live auditd/Sysmon host:

```bash
cd collectors && ../.venv/bin/pytest -q      # 12 tests
```

Covers: auditd EXECVE/connect parsing (incl. the `saddr` hex decoder), Sysmon
event-ID mapping via a stub record, batch-size flushing, spooling when the
backend is down, spool replay after recovery, and the live-session claim
helper. `verify.sh` runs this step between backend and CLI pytest.

Two real bugs were found and fixed while writing these tests:

1. **The auditd parser only matched `type=SYSCALL` records** — real auditd
   emits `type=EXECVE` (program args, no pid) and `type=SOCKADDR` (connect
   dest). The regex now matches all three record types, and the execve
   handler falls back to `a0="…"` for the program name.
2. **The shipper never replayed the spool on an empty flush** — `flush()`
   used to early-return when the buffer was empty, so a collector with no
   new events would never push spooled events back after the backend
   recovered. Empty flushes now still attempt `_replay_spool()`.
