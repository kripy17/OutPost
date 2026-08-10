# Windows collector — real-host validation checklist

This is the step-by-step script for whoever has an actual Windows box. The
Windows collector has been **simulated-tested and CI-gated** (see
`scripts/soak_windows_collector.py`), but never run on a real Windows host —
this checklist closes that gap. Work through it top to bottom; every step ends
with a concrete "you should see" so failures are obvious.

**What you're validating:** Sysmon telemetry → `collector_win.py` → OutPost
backend live session → the webapp's Live Monitor / Agents page, plus the
persistent nssm service + daily FP summary.

---

## 0 · Prereqs

| Item | Requirement | How to check |
|---|---|---|
| Windows | 10 or 11, x64 | `winver` |
| Python | 3.10+ on PATH | `python --version` |
| pywin32 | installed | `python -c "import win32evtlog; print('ok')"` |
| Backend | reachable, port 8001 (or set `OUTPOST_API_URL`) | `curl http://<backend>:8001/meta` |
| Sysmon | v14+ (config uses schemaversion 4.90) | `sysmon64 -?` |
| nssm | only for the service step (6) | `choco install nssm` or `scoop install nssm` |

Install the collector's Python deps:

```bat
pip install pywin32
```

> The collector itself needs **no other runtime deps** — the shared shipper
> (`collectors/common/shipper.py`) uses only `requests`.

---

## 1 · Install Sysmon with the tuned config

The repo ships a tuned config that keeps exactly the event IDs the engine
maps (1 process_create, 3 network_connection, 11 file_write, 12/13/14
registry_write) and trims noisy defaults (svchost process spam, DNS :53,
FileCreateTime, ImageLoad, …).

```bat
:: from an elevated (admin) prompt, in the repo's collectors/windows/ dir:
sysmon64 -accepteula -i sysmon_config.xml
```

**You should see:** "Sysmon installed." and a running `Sysmon` service
(`sc query Sysmon` → STATE: RUNNING). Re-apply later edits with
`sysmon64 -c sysmon_config.xml` (no reinstall).

## 2 · Verify the Sysmon channel

```bat
wevtutil gl Microsoft-Windows-Sysmon/Operational
```

**You should see:** `enabled: true` and a non-zero `numberOfLogRecords` after
a minute of normal use (every process start writes Event ID 1). If the
channel is empty, Sysmon is not actually filtering — see step 1.

## 3 · Collector smoke test (foreground, bounded)

This proves the whole parse→ship→backend path without installing anything.
**Run it from an elevated prompt** — the Sysmon channel's default ACL is
admin-readable, and a non-elevated `OpenEventLog` fails with a
`pywintypes.error` access-denied (see troubleshooting below):

```bat
python collectors\windows\collector_win.py --mode analysis --timeout 120 --backend-url http://<backend>:8001
```

Run it for two minutes of normal activity (open a browser, a notepad, ping
something). The collector auto-resolves its own live session
(`source=agent`). Then, from any machine with the CLI:

```bash
outpost show <run_id>        # or look the run up in the webapp History
```

**You should see:** events in the run (process_create from Event ID 1,
network_connection from Event ID 3), `[collector-win] stopped` on exit, and a
live run named `agent-<hostname>-<date>` on the Agents page.

## 4 · Live flow through the webapp (auto-claim)

The recommended path — the browser session IS the session:

1. Open the webapp → **Monitor** → start live monitoring (a `source=live`
   session opens).
2. On Windows, run the collector with **no** `--run-id` (elevated prompt,
   same as step 3):
   ```bat
   python collectors\windows\collector_win.py --mode live --backend-url http://<backend>:8001
   ```
3. The shipper's `resolve_live_run_id()` claims the webapp's open live
   session — real host events stream straight into the Monitor page.

**You should see:** the process tree, network table, and timeline on the
Monitor filling with this machine's real activity, and alerts toasting as
rules fire (e.g. opening `cmd.exe` from Explorer is expected to be quiet; a
`powershell.exe -enc ...` would fire `lolbin-abuse`).

> **Troubleshooting an empty/crashed run:** if the collector dies right after
> the banner with a `pywintypes.error: (5, 'OpenEventLog', 'Access is
> denied.')` — you're not elevated; re-run from an admin prompt. If it runs
> but no events arrive while `wevtutil gli Microsoft-Windows-Sysmon/Operational`
> shows a growing record count, the channel is readable but the config is
> filtering everything out — re-check `sysmon_config.xml` (step 1).

## 5 · First soak — the real-host FP baseline

This is the measurement the modeled soak (`scripts/soak_windows_collector.py`)
approximates: **normal Windows activity must fire ~0 alerts.**

1. Start a fresh live session (webapp Monitor → start live monitoring, or
   just let the agent create one).
2. Run the collector in live mode for a **fixed window** (30–60 min of your
   normal work — browsing, Office, dev tools, no malware).
3. After the window, stop the collector and pull the run's alerts:
   ```bash
   outpost show <run_id>
   ```

**You should see:** zero, or near-zero, alerts. Known-clean behaviors that
are already exempted by detection fixes (they must NOT fire):
- Web browsing fan-out (many distinct hosts on :80/:443 from one pid) —
  `network-scan` exemption
- Fan-out to reputation-clean targets — `network-scan` exemption
- `svchost.exe` writing `TaskCache` (Task Scheduler's own maintenance) —
  `scheduled-task` exemption

**If anything fires:** that's a genuine FP — report the rule id + the
triggering process/command line. This is exactly how the Linux soak found
its two FPs (localhost beaconing, `/sbin/init` masquerade), and how this
soak should find the Windows ones. The engine's per-run dedup and per-rule
storm caps will have held the alert count down regardless.

## 6 · Service install (persistent agent)

```bash
outpost agent install
```

This writes three files to `%USERPROFILE%\.config\outpost\` (or
`%OUTPOST_HOME%` if set):

| File | Purpose |
|---|---|
| `outpost-agent.bat` | collector wrapper — live mode, hourly process/port snapshots |
| `outpost-agent-summary.bat` | daily fired-rule summary (FP-rate measurement) → JSON |
| `outpost-agent-install.bat` | **the one script you run elevated** |

The CLI prints the path; it **never self-elevates**. Run it in an elevated
prompt (right-click → Run as administrator). It:
1. Installs `OutPostAgent` as an **nssm service** (auto-restart on crash,
   like systemd `Restart=on-failure`) and starts it.
2. Creates a **daily scheduled task** `OutPostAgentSummary` (06:00, SYSTEM
   account) that runs the summary batch.

No-nssm fallback (also in the script, commented): an `ONSTART` scheduled
task that launches the collector directly.

**You should see:** `nssm status OutPostAgent` → `SERVICE_RUNNING`; the
Agents page shows your hostname (lowercased) with a fresh last-seen; the
summary task listed in `schtasks /Query /TN OutPostAgentSummary`.

## 7 · Verify the service end to end

```bat
:: service state
nssm status OutPostAgent
:: events still flowing (Sysmon channel advancing)
wevtutil gli Microsoft-Windows-Sysmon/Operational
:: heartbeat on the fleet view — webapp Agents page, your host: last-seen
::   within the last minute, "agent silent" NOT flagged
:: daily summary accumulating (after the first 06:00 run)
type %USERPROFILE%\.config\outpost\outpost-agent-summary.log
```

**You should see:** the summary JSON appending one line per day — `{date,
rules_fired: [...]}`. That log IS the continuous FP measurement: a healthy
host shows an empty `rules_fired` on normal days, and any fired rule is a
candidate FP to triage.

## 8 · What to report back

If anything in steps 3–7 fails or fires, capture:
- The step number and the exact command you ran
- The error text or the alert's `rule_id` + process/command line
- The `outpost show <run_id>` summary for the affected run

A clean pass through steps 1–7 on a real host is the last unverified surface
of the project — it turns the simulated soak gate into a proven one.
