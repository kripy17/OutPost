# Build Plan — Ordered Task List

Work through these sequentially. Each task references the relevant spec doc — read it before starting. Paste a task directly into OpenCode/Cursor chat (e.g. "Do Task 4 from docs/06-BUILD-PLAN.md") to have the agent execute it with full context already loaded from AGENTS.md.

## Phase 1 — Backend Core

**Task 1: Scaffold backend project**
- Set up `backend/` per the structure in `docs/01-ARCHITECTURE.md`
- FastAPI app boots, `GET /health` returns `200`

**Task 2: Implement schema + database**
- Implement `EventIn`, `RunSummary`, `Alert`, `ProcessNode`, `NetworkConnection`, `RunNote`, `WatchlistEntry` from `docs/02-BACKEND-SPEC.md`
- Create SQLite tables per the schema in the same doc, including `alerts`
- Acceptance: can insert and query a run + events + an alert via a quick script or test

**Task 3: Implement ingestion endpoint**
- `POST /ingest/batch` — validate each event against `EventIn`, store
- `POST /runs` — create run (accepts `session_type`), return `run_id`
- `POST /runs/{run_id}/complete` — mark complete
- Acceptance: can POST a batch of synthetic events via `curl`/Postman and see them in the DB

**Task 4: Implement process tree builder**
- `app/services/process_tree.py` per the logic outline in `docs/02-BACKEND-SPEC.md`
- Acceptance: given a small synthetic set of `process_create` events, returns correct nested tree

**Task 5: Implement detection heuristics (the flagship feature — don't skip or defer this)**
- `app/services/detection.py` — implement rules 1–6 from `docs/11-DETECTION-LOGIC.md` (defer rule 7, first-seen, until cross-run history exists)
- Wire into `POST /ingest/batch` so detection runs on every incoming event, not just at session end
- `GET /runs/{run_id}/alerts` endpoint
- Acceptance: write one synthetic test script per rule (per `docs/11-DETECTION-LOGIC.md`'s testing guidance), confirm each fires with correct severity and a genuinely specific `details` string — not "suspicious activity detected"

**Task 6: Implement enrichment service**
- `app/services/enrichment.py` — AbuseIPDB + VirusTotal clients, cache-first lookup
- Acceptance: querying a known-bad test IP (documented in AbuseIPDB's own test/demo data) returns a populated `NetworkConnection.reputation`

**Task 7: Implement `GET /runs` and `GET /runs/{run_id}`**
- Wire together process tree + enriched network connections + timeline + alerts into the run detail response
- `RunSummary.highest_severity` derived from that run's alerts
- Acceptance: a full run round-trips from ingestion to a complete, correct API response including alerts

## Phase 2 — Collectors

**Task 8: Windows collector**
- Implement per `docs/03-COLLECTOR-SPEC.md`, supporting both `--mode live` and `--mode analysis --timeout N`
- Test against a synthetic script (spawn processes, connect to a test listener) confirm events arrive at the backend and detection rules fire correctly

**Task 9: Linux collector**
- Implement per `docs/03-COLLECTOR-SPEC.md`, both modes
- Same synthetic-script validation as Task 8

## Phase 3 — CLI Tool

Depends only on Phase 1 — can proceed in parallel with Phase 2 for non-live-mode commands.

**Task 10: Scaffold CLI project**
- Set up `cli/` with Typer app entrypoint per `docs/01-ARCHITECTURE.md` and `docs/09-CLI-SPEC.md`
- ASCII banner renders on every command, `outpost --help` lists all commands (stubs fine for now)

**Task 11: Implement read commands against the live backend**
- `outpost list`, `outpost show <run_id>`, `outpost export <run_id>`
- Alert rendering as bordered `rich.panel.Panel` per `docs/09-CLI-SPEC.md`
- Acceptance: these render real data (including alerts) from a run already in the DB — you don't need collectors working yet to build and test these

**Task 12: Implement `outpost run` (bounded analysis)**
- Local collector start/stop, sample execution, timeout window
- Acceptance: `outpost run <sample>` produces a complete, viewable session including any alerts

**Task 13: Implement `outpost watch` (live monitoring — the flagship CLI command)**
- Live-updating Rich dashboard, desktop notifications on `malicious`-severity alerts
- Acceptance: running `outpost watch` while a synthetic script executes shows the process tree, network connections, and any triggered alerts updating in near-real-time, with a desktop notification firing for the malicious-severity test case

## Phase 4 — Frontend

**Task 14: Scaffold frontend project**
- Vite + React 19 + TypeScript + Tailwind v4 per `docs/01-ARCHITECTURE.md`
- Set up TanStack Query, routing
- Apply the color tokens and typography from `docs/07-UI-DESIGN-SYSTEM.md` from the start — don't scaffold with defaults and restyle later

**Task 15: Run History page**
- `RunList` + `RunCard`, showing session type (live/analysis) and alert count per `docs/04-FRONTEND-SPEC.md`
- Acceptance: renders real data from `GET /runs`

**Task 16: Run Detail page — Process Tree + Alert Banner**
- `ProcessTree` recursive component, `AlertBanner` prominently surfacing any alerts for the session
- Acceptance: renders a real multi-level tree and any real alerts from a completed run

**Task 17: Run Detail page — Network Table + Reputation Badges**
- `NetworkTable` + `ReputationBadge`
- Acceptance: colors correctly reflect `reputation` field from a real enriched run

**Task 18: Run Detail page — Timeline + Export**
- `TimelineView`, `ExportButton`
- Acceptance: full run detail page complete, matches spec

## Phase 5 — Integration & Polish

**Task 19: End-to-end test — Windows**
- Full pipeline: `outpost watch` or `outpost run` on the Windows collector → backend → detection → both CLI and frontend show correct, matching data including alerts

**Task 20: End-to-end test — Linux**
- Same as Task 19, Linux collector

**Task 21: Report export (PDF)**
- `app/services/report.py`, wire to `/runs/{id}/export`, confirm `outpost export --format pdf` matches the webapp's export

**Task 22: Documentation pass**
- README with setup instructions, architecture diagram, demo script for both CLI and webapp, showing at least 3–4 detection rules firing live
- This becomes the basis of your written project report

## Phase 6 — Standout Features (optional, do not start until Phases 1–5 are fully working)

See `docs/10-STANDOUT-FEATURES.md` for the full tiered list with wiring details.

**Task 23:** IOC extraction/export (Tier 1) — highest value-to-effort ratio
**Task 24:** Cross-run IOC search — also unlocks Rule 7 (first-seen process) from `docs/11-DETECTION-LOGIC.md`
**Task 25:** Run comparison/diff
**Task 26:** Personal watchlist
**Task 27:** Auto-generated Suricata/Sigma rule from findings — strongest differentiator, budget real time for it

---

**Do not start Phase 6, or any static analysis/YARA/memory-forensics work from `docs/08-INTEGRATIONS.md`'s Phase 2/3 sections, until Phases 1–5 above are fully working end-to-end.** Resist scope creep until the MVP — including working detection heuristics — is demoable on both platforms, in both interfaces.
