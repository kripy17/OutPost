# Architecture & Repo Structure

## System Overview

```
┌──────────────────────┐     ┌──────────────────────┐
│   Windows host           │     │   Linux host             │
│   Sysmon + collector       │     │   auditd + collector       │
│   (your machine, a lab      │     │   (your machine, a lab      │
│    box, or a VM — your      │     │    box, or a VM — your      │
│    choice, see docs/05)       │     │    choice, see docs/05)       │
└───────────┬─────────────┘     └───────────┬─────────────┘
            │  POST /ingest/batch (JSON)         │
            └────────────────┬──────────────────┘
                              ▼
                   ┌─────────────────────┐
                   │   FastAPI Backend       │
                   │   normalize · store       │
                   │   detection heuristics      │
                   │   process tree · enrich       │
                   └──────────┬──────────┘
                              │  REST API
                ┌─────────────┴─────────────┐
                ▼                             ▼
     ┌───────────────────┐         ┌───────────────────┐
     │  CLI (outpost)         │         │  React Frontend        │
     │  terminal tables/          │         │  run history, tree,        │
     │  trees, live watch mode,      │         │  network table, export        │
     │  desktop alerts (docs/09)       │         └───────────────────┘
     └───────────────────┘
```

The backend is where the actual intelligence lives — detection heuristics (`docs/11-DETECTION-LOGIC.md`) run here, against normalized events, regardless of which platform or interface they came from. Collectors and the two front-ends are deliberately "thin" around that core.

## Full Repo Structure

```
outpost/
├── AGENTS.md
├── README.md
├── docs/
│   ├── 00-OVERVIEW.md
│   ├── 01-ARCHITECTURE.md
│   ├── 02-BACKEND-SPEC.md
│   ├── 03-COLLECTOR-SPEC.md
│   ├── 04-FRONTEND-SPEC.md
│   ├── 05-DEPLOYMENT-SETUP.md
│   ├── 06-BUILD-PLAN.md
│   ├── 07-UI-DESIGN-SYSTEM.md
│   ├── 08-INTEGRATIONS.md
│   ├── 09-CLI-SPEC.md
│   ├── 10-STANDOUT-FEATURES.md
│   └── 11-DETECTION-LOGIC.md
│
├── backend/
│   ├── pyproject.toml
│   ├── app/
│   │   ├── main.py                  # FastAPI app entrypoint, CORS, router mounting
│   │   ├── api/
│   │   │   ├── routes_ingest.py     # POST /ingest/batch
│   │   │   ├── routes_runs.py       # GET /runs, GET /runs/{id}
│   │   │   ├── routes_alerts.py     # GET /alerts — detection heuristic hits
│   │   │   └── routes_health.py     # GET /health
│   │   ├── core/
│   │   │   ├── config.py            # env vars, API keys (AbuseIPDB/VT), settings
│   │   │   ├── db.py                # SQLite connection/session setup
│   │   │   └── schema.py            # Pydantic models: EventIn, EventOut, RunSummary, Alert
│   │   ├── services/
│   │   │   ├── normalizer.py        # platform-specific → unified schema mapping
│   │   │   ├── process_tree.py      # pid/ppid → tree structure builder
│   │   │   ├── detection.py         # rule-based anomaly/malware heuristics (docs/11)
│   │   │   ├── enrichment.py        # AbuseIPDB / VirusTotal client + cache logic
│   │   │   └── report.py            # report export (JSON/PDF) generation
│   │   ├── models/
│   │   │   ├── run.py               # ORM/table def for runs
│   │   │   └── event.py             # ORM/table def for events, alerts, enrichment_cache
│   │   └── tests/
│   │       ├── test_ingest.py
│   │       ├── test_process_tree.py
│   │       ├── test_detection.py
│   │       └── test_enrichment.py
│   └── data/
│       └── outpost.db              # SQLite file (gitignored)
│
├── collectors/
│   ├── windows/
│   │   ├── collector_win.py
│   │   ├── sysmon_config.xml        # tuned Sysmon config (based on SwiftOnSecurity)
│   │   └── requirements.txt         # pywin32, requests
│   ├── linux/
│   │   ├── collector_linux.py
│   │   ├── audit.rules              # auditd rules for execve/connect
│   │   └── requirements.txt
│   └── common/
│       ├── schema.py                # shared event dataclass, mirrors backend schema
│       └── shipper.py               # HTTP POST helper, retry/buffer logic
│
├── cli/
│   ├── pyproject.toml
│   └── outpost/
│       ├── __init__.py
│       ├── main.py                  # Typer app entrypoint, ASCII banner, command registration
│       ├── commands/
│       │   ├── run.py               # `outpost run <sample>` — bounded analysis session
│       │   ├── watch.py             # `outpost watch` — live monitoring on this machine
│       │   ├── list_runs.py         # `outpost list` — session history
│       │   ├── show.py              # `outpost show <run_id>` — print full report
│       │   ├── export.py            # `outpost export <run_id>`
│       │   └── search.py            # `outpost search <ioc>` — cross-run IOC search
│       ├── monitoring/
│       │   └── session.py           # starts/stops a local collector process, tracks session state
│       ├── rendering/
│       │   └── terminal_views.py    # Rich table/tree/live renderers, shared across commands
│       └── lib/
│           └── api_client.py        # thin wrapper around backend REST API (mirrors frontend/src/lib/api.ts)
│
└── frontend/
    ├── package.json
    ├── vite.config.ts
    ├── tailwind.config.ts
    └── src/
        ├── main.tsx
        ├── routes/
        │   ├── index.tsx            # run history page
        │   └── runs.$runId.tsx      # run detail page
        ├── components/
        │   ├── RunHistory/
        │   ├── ProcessTree/
        │   ├── NetworkTable/
        │   ├── ReputationBadge/
        │   ├── AlertBanner/          # detection heuristic hits, surfaced prominently
        │   ├── TimelineView/
        │   └── ExportButton/
        ├── lib/
        │   └── api.ts               # all backend calls, centralized
        └── types/
            └── index.ts             # shared TS types mirroring backend Pydantic models
```

## Data Flow Summary

**Live monitoring (the everyday use case):** `outpost watch` starts the local collector, which streams events continuously — not bound to a fixed window. Each batch is ingested, run through detection heuristics in real time, and any hit surfaces immediately (terminal alert + desktop notification via the CLI, or a live-updating banner in the webapp).

**Bounded analysis session (for a specific file):** `outpost run <sample>` starts a collector, runs the sample, observes for a fixed window, then stops — same ingestion and detection pipeline, just scoped to one session instead of continuous. Whether that session happens on your own machine or an isolated environment is your call (see `docs/05-DEPLOYMENT-SETUP.md`) — the tool behaves identically either way.

**Both paths, in detail:**
1. Collector (Windows or Linux) observes OS telemetry → normalizes → `POST /ingest/batch`
2. Backend validates against schema, stores raw events tagged with `run_id`
3. Detection service (`docs/11-DETECTION-LOGIC.md`) evaluates new events against heuristic rules, creates `Alert` records for any hits
4. On session completion (or periodically, for live mode): backend builds process tree + deduplicates network destinations
5. Enrichment service queries AbuseIPDB/VirusTotal/abuse.ch for each unique IP (cache-first)
6. Both CLI and frontend fetch/poll and render the same data — tree, table, timeline, and any alerts raised
