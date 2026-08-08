# OutPost — AI Project Context (handoff doc)

> A dense, self-contained summary of everything built. Give this to any AI
> (or future agent session) to onboard it onto the project fast.

## What it is
**OutPost is a cross-platform behavioral security monitor** — a webapp-first
SOC console with a terminal (CLI) mirror. You upload/detonate malware samples,
it replays their behavioral events (processes, network, files, registry,
persistence) on Windows/Linux/macOS, detects suspicious activity with
OS-aware rules, scores risk, clusters runs into campaigns, and presents it all
through a polished dark/light "deck" UI. No sandbox required — it analyzes
*synthetic event streams* of a sample's behavior.

Repo: `/home/kripy/Projects/OutPost` · published to GitHub as
**kripy17/OutPost** (private). Not a git repo locally — publishing is done via
a temp clone (`/tmp/outpost-clone`) that keeps the remote's LICENSE.

## Architecture (3 tiers + collectors)
```
OutPost/
├── docs/          # 15 spec docs (00–15) + AGENTS.md — the full written spec
├── backend/       # FastAPI + SQLite — API, detection engine, risk, campaigns
├── frontend/      # React 19 + Vite 6 + TypeScript — the primary webapp
├── cli/           # Typer CLI — terminal mirror of the webapp
├── collectors/    # Verified Sysmon (Windows) + auditd (Linux) shippers
├── demo/          # Playwright demo recorder + footage (deck-demo.webm)
├── scripts/       # install.sh · dev.sh · setup.sh · synthetic_demo.py
└── verify.sh      # one-command full verification sweep
```

## Backend (FastAPI, port 8001, SQLite at backend/data/outpost.db)
12 API route modules (`backend/app/api/`): health, runs, alerts, events,
ingest, samples, ioc, rules, watchlist, campaigns, notifications, analysis,
events-stream.

16 services (`backend/app/services/`):
- **detection.py** — OS-aware rule engine (Windows/Linux/macOS), 30+ rules
  across kill-chain stages: LOLBin abuse (`-enc`, certutil, mshta, wscript),
  reverse shells (bash `/dev/tcp`, osascript), persistence (Run keys,
  LaunchAgents, cron), C2 beaconing, ransomware write bursts, masquerading.
- **risk.py** — 0–100 risk with severity bands + MITRE ATT&CK per rule.
- **killchain.py** — attack-chain reconstruction (initial access → execution
  → persistence → C2 → impact) per run.
- **process_tree.py** — parent/child process tree from events.
- **campaigns.py** — auto-groups runs sharing IOCs: signature IP, combined
  timeline, shared-IOC evidence, span.
- **iocs.py / yara.py / enrichment.py** — IOC extraction, bundled YARA,
  VirusTotal-style reputation (AbuseIPDB/VT, cache-first 7-day TTL).
- **report.py / stix.py** — JSON + STIX 2.1 export (real timestamps).
- **events_stream.py** — SSE pub/sub broadcast of fired alerts (asyncio
  queues, 15s keepalive, slow-consumer drop).
- **normalizer.py / rule_generator.py / notifications.py** — normalization,
  rule tuning (DB-backed thresholds), webhook notifications.

**Sample vault** (`routes_samples.py` + `models/samples.py`):
`POST /samples` magic-sniffs bytes — PE → Windows, ELF → Linux, Mach-O →
macOS, **shebangs** (`#!/bin/sh`, `#!/usr/bin/python`), **.lnk/.zip/Office
docs** (zip walk skips compressed data between entries). Stores `family`,
`yara_rules`, `vt_detections`; dedupes by SHA-256 (persists family on
re-upload). `GET /samples` (`?q=` name/hash/family, limit/offset, per-row
detonation count), `GET /samples/{id}` (parsed shape).

Other endpoints: `GET /runs?q=` filter, run notes (`GET/POST /runs/{id}/notes`),
`/campaigns`, `/events` (severity + free-text search), `/ioc/search` (hash
prefix + IP + registry + process), `/rules`, `/watchlist`, `/events/stream`
SSE, `/notifications`.

## Frontend (React 19 + Vite 6 + TS, primary interface)
14 routes: **Overview, Monitor, Events, Search, RunDetail, Compare,
Campaigns, Watchlist, Rules, Samples vault, SampleDetail, Settings, History,
Search**.
- **Overview** — SOC deck: risk-over-time chart (SVG bars by risk band,
  clickable → run detail, hover tooltips), detection-volume mini-chart
  (alerts/hour stacked by rule family), live pulse status bar (backend health,
  latest finding, run count — SSE-pushed).
- **Monitor** — detonate samples (Windows/Linux/macOS synthetic scenarios),
  live toast stream of newest alerts with auto-follow, **Space** shortcut
  ends the analysis.
- **RunDetail** — kill chain, process tree, network, timeline, analyst notes
  box, all in deck panels.
- **Campaigns** — auto-clustered campaign cards with combined timeline +
  shared IOC list.
- **Sample vault** — deck-styled library: stat strip, debounced server-side
  search, platform chips, YARA chips, VT reputation, copy-hash detail page.
- **Design system** — dark/light toggle (`data-theme` + localStorage), deck
  panel system with kicker headers, PageHeader everywhere, tokens in
  `index.css`.

## CLI (terminal mirror, `outpost`)
13 commands: `list`, `show`, `export` (JSON/STIX), `run`, `watch`,
`campaigns`, `compare`, `notes`, `rules`, `samples`, `search`, `watchlist`.
Rich tables, colorized risk + severity accent bars. Backend URL from
`OUTPOST_API_URL` (default `http://localhost:8001`).

## Collectors
- Windows — Sysmon Event IDs 1/3/11/12/13 shipper.
- Linux — auditd (execve, connect, file writes) shipper.
Both functionally verified (12 tests, real bugs fixed).

## Demo & data
Seeds (`cd backend && python -m app.<name>`): `seed_demo` (single run),
`seed_campaign` (**Shelf-Stack** pair sharing C2 `203.0.113.88`), `seed_macos`
(osascript JXA → curl beacon → LaunchAgent persistence; backdated so it never
shadows live detonations). `demo/deck-demo.mjs` — Playwright recorder: 4-act
walkthrough, 19 screenshots in `demo/screenshots/deck/`, `deck-demo.webm`.

## Verification (`./verify.sh`)
Backend pytest **129** · collectors **12** · CLI **8** · frontend build clean
(`tsc --noEmit && vite build`). SSE live-push verified end-to-end. Expected
counts drift as tests are added — README badge says 149 (129+12+8).

## Operations
- Ports: backend **8001**, frontend **5174** (8000/5173 belong to another
  project on this machine — never use them).
- `scripts/install.sh` — one-command setup (venv + pip + npm + .env.local +
  seed). `scripts/dev.sh start|stop|status|logs` — run the stack detached,
  PIDs in `.freebuff/*.pid`, logs in `.freebuff/*.log`.
- Restart backend after backend edits (no `--reload`): `bash
  .freebuff/start-backend.sh` (setsid-detached, kills the stale server first).
- Frontend needs `frontend/.env.local` with `VITE_API_URL=http://localhost:8001`.
- PEP 668 distros (Arch): always use the repo venv, never
  `--break-system-packages`.

## Known gaps
1. No auth/multi-analyst — single-user, no login or API keys.
2. Polling + SSE hybrid — SSE for alerts; some views still poll.
3. macOS has rules + scenario but no collector shipper.
4. YARA rules bundled & read-only (no custom upload UI).
5. Detection rules tuned against seed scenarios, not a real malware corpus.
