# OutPost — Cross-Platform Behavioral Security Monitor

OutPost is a SOC-style malware-analysis console: upload or detonate a sample,
watch its process tree, network connections, and timeline stream in live, and
let OS-aware detection rules fire alerts — all from a browser or the terminal.

The **webapp is the primary interface** (a command-deck style SPA); the **CLI**
mirrors the same API for terminal workflows.

![OutPost deck](demo/screenshots/deck/01-overview-stats.png)

## What it does

- **Detonate samples** — synthetic dropper scenarios per OS (Windows macro →
  LOLBin → C2 beacon; Linux bash → `curl|sh`; macOS osascript/JXA →
  LaunchAgent) stream into a live run; detection fires the same rules a real
  collector feed would.
- **OS-aware detection** — per-platform persistence, LOLBins, and
  masquerading rules; ATT&CK-tagged alerts; a 0–100 risk score per run.
- **Sample vault** — upload binaries; magic-byte sniffing (PE/ELF/Mach-O,
  shebangs, `.lnk`, `.zip`) auto-detects the platform; a pure-Python YARA
  engine scans signatures; SHA-256 reputation cached.
- **Hunt surfaces** — global Events feed (Event-Viewer style), IOC search,
  run Compare, and Campaigns that cluster runs by shared C2 infrastructure.
- **Analyst tools** — per-run notes, live rule-threshold tuning, Suricata/
  Sigma rule generation, STIX 2.1 export, watchlist import/export, webhook
  notifications, and a live SSE push channel (with polling fallback).
- **Collectors** — verified Sysmon (Windows) and auditd (Linux) shippers that
  POST to the same ingest API.

## Stack

- **Backend** — FastAPI + raw SQLite (dependency-light by design), `backend/`
- **Frontend** — React + Vite + TypeScript, `frontend/`
- **CLI** — Typer + Rich, `cli/`
- **Collectors** — `collectors/`
- **Docs** — the spec is 15 markdown files at the repo root (`00-OVERVIEW.md`
  → `13-CAMPAIGN-DEMO.md`, `AGENTS.md`, `docs/14-ROADMAP.md`)

## Quickstart

```bash
# backend (port 8001 — 8000 is often taken)
python3 -m venv .venv && source .venv/bin/activate
pip install -e "./backend[dev]" -e ./cli
cd backend && python -m app.seed_campaign && python -m app.seed_macos
uvicorn app.main:app --port 8001

# frontend (port 5174)
cd frontend && echo "VITE_API_URL=http://localhost:8001" > .env.local && npm i
npm run dev -- --port 5174 --strictPort

# CLI
OUTPOST_API_URL=http://localhost:8001 outpost list
OUTPOST_API_URL=http://localhost:8001 outpost samples
```

## Verify

```bash
bash verify.sh   # backend pytest + collector pytest + CLI pytest + frontend build
```

## Demo

`demo/deck-demo.mjs` records a 4-act walkthrough (Overview → Sample vault →
Monitor detonation → Run detail) as video + screenshots:

```bash
cd demo && npm i && node deck-demo.mjs   # or --rehearse to validate selectors
```

`demo/deck-demo.webm` (≈10 MB) is included in this repo.

## License

MIT — see [LICENSE](LICENSE).
