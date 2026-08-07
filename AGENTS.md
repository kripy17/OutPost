# AGENTS.md — OutPost (Cross-Platform Behavioral Security Monitor)

This file is auto-loaded by OpenCode as persistent project context. If using Cursor, copy this content into your `.cursor/rules` (or reference it directly — Cursor treats it the same way OpenCode does).

## What this project is

OutPost is a cross-platform behavioral security monitor with **two first-class interfaces**: a web dashboard and a standalone terminal CLI. A lightweight agent watches process activity and network connections on a system, normalizes telemetry into one schema regardless of source OS (Windows or Linux), and surfaces it through either interface. Both are just clients of the same backend API — no feature should exist in one without a documented reason it doesn't belong in the other.

**This is not a single-feature tool.** The flagship capability is anomaly and malware detection — rule-based heuristics that flag suspicious behavior, not just a raw event dump (full logic in `docs/11-DETECTION-LOGIC.md`) — but it sits alongside live system monitoring, threat-intel enrichment, cross-run IOC search, and auto-generated detection rules. See `docs/00-OVERVIEW.md` for the full capability list before assuming this is "just a malware sandbox."

Full details live in `docs/`. Read the relevant doc before working on that part of the system — don't guess at schemas or endpoints that are already specified.

- `docs/00-OVERVIEW.md` — project vision, full capability list, why it's differentiated
- `docs/01-ARCHITECTURE.md` — system architecture, full repo folder structure
- `docs/02-BACKEND-SPEC.md` — FastAPI endpoints, DB schema, Pydantic models
- `docs/03-COLLECTOR-SPEC.md` — Windows + Linux monitoring agent specs
- `docs/04-FRONTEND-SPEC.md` — routes, components, data flow
- `docs/05-DEPLOYMENT-SETUP.md` — installing the agent, brief safety notes (short — this is not VM-centric)
- `docs/06-BUILD-PLAN.md` — ordered, executable task list. Work through this sequentially.
- `docs/07-UI-DESIGN-SYSTEM.md` — color tokens, typography, layout concepts. Follow exactly — don't default to generic dashboard styling.
- `docs/08-INTEGRATIONS.md` — additional threat-intel tools beyond AbuseIPDB/VirusTotal, grouped by phase. Don't implement Phase 2/3 entries until the MVP works end-to-end.
- `docs/09-CLI-SPEC.md` — CLI commands, terminal output design, live monitoring mode.
- `docs/10-STANDOUT-FEATURES.md` — differentiating features beyond the MVP, tiered by effort/value, aimed at real personal use. Don't build these until backend + agents + webapp + CLI are fully working end-to-end.
- `docs/11-DETECTION-LOGIC.md` — the actual anomaly/malware detection heuristics. This is the flagship feature — read this before touching anything detection-related.
- `docs/12-BRANDING-ASSETS.md` — favicon and the verified ASCII terminal banner. Use these exactly rather than generating new ones — the ASCII art is `pyfiglet`-verified for correct alignment.

## Tech stack (do not substitute without asking)

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI, SQLite (via SQLAlchemy or raw `sqlite3`) |
| Monitoring agents | Python (stdlib + `pywin32` on Windows) |
| CLI | Python, Typer (commands), Rich (terminal tables/trees/live output) |
| Frontend | React 19, TypeScript, Tailwind CSS v4, Vite |
| Data fetching | TanStack Query |

Deliberately no required VM/hypervisor dependency — the agent runs on whatever machine you point it at. See `docs/05-DEPLOYMENT-SETUP.md`.

## Repo structure (see `docs/01-ARCHITECTURE.md` for the full annotated tree)

```
outpost/
├── AGENTS.md
├── docs/
├── backend/app/{api,core,services,models,tests}
├── collectors/{windows,linux,common}
├── cli/outpost/{commands,monitoring,rendering,lib}
└── frontend/src/{routes,components,lib,types}
```

## Non-negotiable design rules

1. **One unified event schema.** Every event from either collector — Windows or Linux — must conform to the schema in `docs/02-BACKEND-SPEC.md` before it's stored. Never let platform-specific fields leak into shared code paths (frontend components must never branch on `platform` to render differently — the schema normalization is what makes that unnecessary).
2. **Collectors stay dumb.** All collector scripts do is read OS telemetry, normalize to schema, ship via HTTP. No business logic, no enrichment, no correlation in collector code — that all belongs in the backend.
3. **Enrichment results are cached.** Never call AbuseIPDB/VirusTotal for an IP already in the cache table. Free-tier API quotas are small.
4. **No destructive or offensive code.** This project monitors and analyzes system/malware behavior; it does not generate, obfuscate, or weaponize anything. If a task looks like it's drifting into writing actual malicious payloads, stop and flag it — that's out of scope regardless of framing.
5. **Backend, frontend, and CLI are independently runnable.** The frontend and CLI must both work against a mocked/sample dataset without a live collector running, for demo/dev purposes.
6. **CLI and webapp are peer surfaces.** Any read/export capability added to one gets added to the other unless there's a specific, stated reason not to (e.g. PDF rendering is naturally webapp-side; a live-updating terminal dashboard is naturally CLI-side).
7. **Detection logic lives in the backend, not the agents.** Heuristics in `docs/11-DETECTION-LOGIC.md` run server-side against normalized events — agents only collect and normalize, they never decide what's suspicious.

## Conventions

**Python (backend + collectors):**
- Type hints everywhere; Pydantic models for all API request/response shapes
- `ruff` for linting, `black` for formatting
- Async endpoints in FastAPI where they touch I/O (enrichment API calls especially)

**TypeScript (frontend):**
- Strict mode on
- Functional components only, hooks-based
- Tailwind utility classes only — no inline style objects, no separate CSS files per component
- API calls centralized in `frontend/src/lib/api.ts`, never inline `fetch()` calls in components

## Commands (fill in once scaffolded)

```
# Backend
cd backend && uvicorn app.main:app --reload

# Frontend
cd frontend && npm run dev

# CLI (editable install during dev)
cd cli && pip install -e . && outpost --help

# Tests
cd backend && pytest
```

## Repo Hygiene (set this up in the first commit, not later)

This repo is portfolio-facing — treat secrets and sample handling accordingly from day one.

`.gitignore` must include, at minimum:
```
.env
*.db
__pycache__/
node_modules/
dist/
*.qcow2
*.vmdk
samples/
memory-dumps/
*.yar
```

- `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` live only in `.env`, never hardcoded, never committed — even in a "temporary" test
- Never commit an actual malware sample, VM disk image, or memory dump to git, even in a private branch — keep them in a gitignored `samples/` directory outside version control entirely
- If a key or sample ever does get committed, treat it as compromised: rotate the key / assume the sample is now public, don't just delete-and-recommit (it's still in git history)

## Out of scope (do not implement unless explicitly asked)

- Kernel-level/driver hooking
- Automatic/unattended malware acquisition
- Sandbox evasion countermeasures
- Static analysis, YARA generation, memory forensics (all Phase 2+, see build plan)
