<div align="center">

# 🛡️ OutPost

### Cross-platform behavioral security monitor — a SOC console in your browser

Detonate samples, watch OS-aware detection rules fire in real time, score risk,
map kill chains, and cluster runs into campaigns — all through a polished
dark/light web deck with a full terminal mirror.

`FastAPI` · `React 19` · `Vite 6` · `SQLite` · `Typer` · `Rich` · `Playwright`

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-backend-009688?style=flat-square)
![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square)
![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?style=flat-square)
![Tests](https://img.shields.io/badge/tests-149%20passing-2ea44f?style=flat-square)
![CI](https://github.com/kripy17/OutPost/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

</div>

---

## What is OutPost?

OutPost watches **process, network, file, and persistence behavior** on
Windows, Linux, and macOS and flags malicious activity with **explainable,
rule-based heuristics** — no ML black box. Every finding is traceable to a
named rule, mapped to the **MITRE ATT&CK** kill chain, and scored 0–100.

It runs **fully synthetic scenarios** out of the box: pick a platform in the
Monitor page, stream a detonation, and watch alerts toast in live as the rules
fire — dynamic malware analysis without a sandbox, hypervisor, or malware.

> Originally built as a BSc Cybersecurity (Year 3) semester project. The
> internal design documents used to build it aren't shipped in this repo.

## ✨ Highlights

| | |
|---|---|
| 🖥️ **OS-aware detection engine** | 30+ rules across Windows / Linux / macOS — LOLBin abuse, reverse shells (`/dev/tcp`, osascript), persistence (Run keys, LaunchAgents, cron), C2 beaconing, ransomware write bursts, process masquerading |
| 🎯 **Risk scoring + ATT&CK** | 0–100 risk per run, severity bands, every rule mapped to a kill-chain stage with a reconstructed attack chain |
| 🗂️ **Campaign clustering** | Runs sharing IOCs are auto-grouped into campaign cards — combined timeline, shared IOC evidence, signature C2 |
| 💾 **Sample vault** | Upload binaries; magic-sniffing detects PE/ELF/Mach-O, **script shebangs**, and **.lnk/.zip/Office archives**; YARA signatures + VirusTotal reputation per sample |
| 📡 **SSE live push** | Fired alerts broadcast over `/events/stream` — the StatusBar pulse and Monitor toasts update instantly |
| 🖇️ **Correlation & intel** | IOC extraction/export, cross-run IOC search, run comparison, personal watchlist, hash/YARA reputation, STIX 2.1 + JSON export, Suricata/Sigma rule generation |
| 📝 **Analyst notes** | Per-run notes via the API, webapp, and `outpost notes` |
| 🎨 **SOC deck UI** | Dark/light themes, risk-over-time + detection-volume charts, kill chain, process tree with reputation halos, live monitor |
| ⌨️ **Terminal mirror** | The `outpost` CLI reaches the same API — 13 commands, Rich tables, colorized risk |
| 🧪 **Collectors** | Verified Sysmon (Windows) and auditd (Linux) shippers |

## 📸 Screenshots

<p align="center">
  <img src="demo/screenshots/deck/01-overview-stats.png" width="49%" alt="Overview — stat strip" />
  <img src="demo/screenshots/deck/02-overview-risk-timeline.png" width="49%" alt="Overview — risk timeline" />
</p>
<p align="center">
  <img src="demo/screenshots/deck/03-overview-detection-volume.png" width="49%" alt="Overview — detection volume" />
  <img src="demo/screenshots/deck/07-vault-stats.png" width="49%" alt="Sample vault" />
</p>
<p align="center">
  <img src="demo/screenshots/deck/11-detonate-live.png" width="49%" alt="Monitor — live detonation" />
  <img src="demo/screenshots/deck/13-detail-top.png" width="49%" alt="Run detail — risk gauge" />
</p>
<p align="center">
  <img src="demo/screenshots/deck/14-detail-killchain.png" width="49%" alt="Run detail — kill chain" />
  <img src="demo/screenshots/deck/18-detail-notes.png" width="49%" alt="Run detail — analyst notes" />
</p>

A full **2-minute video walkthrough** (`demo/deck-demo.webm`, 4 acts: Overview →
Sample vault → Monitor detonation → Run detail) is recorded automatically by
[`demo/deck-demo.mjs`](demo/deck-demo.mjs).

## 🏗️ Architecture

```
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
│ Windows (Sysmon)  │   │ Linux (auditd)    │   │ macOS (rule set)  │
│  collector        │   │  collector        │   │                   │
└─────────┬─────────┘   └─────────┬─────────┘   └─────────┬─────────┘
          └───────────────────────┼───────────────────────┘
                                  ▼  POST /ingest/batch
                 ┌──────────────────────────────────────┐
                 │            FastAPI backend           │
                 │  normalize · store (SQLite)          │
                 │  OS-aware detection engine           │
                 │  risk + ATT&CK · kill chain          │
                 │  process tree · enrichment · YARA    │
                 │  campaign clustering · SSE live push │
                 └───────────────────┬──────────────────┘
                                     │ REST API + SSE
                  ┌──────────────────┴──────────────────┐
                  ▼                                     ▼
        ┌────────────────────┐                ┌────────────────────┐
        │   React webapp     │                │   CLI (outpost)   │
        │   SOC deck UI      │                │   Rich terminal   │
        │   14 pages         │                │   13 commands     │
        └────────────────────┘                └────────────────────┘
```

**The backend is where the intelligence lives.** Collectors stay dumb
(telemetry → normalize → ship); the webapp and CLI are thin clients of one
API and one event schema — no feature lives in only one interface. The
**webapp is the primary interface**; the CLI is its deliberate terminal mirror.

## 🚀 Quickstart

> **PEP 668 note (Arch / Debian / Fedora):** your system Python refuses
> `pip` installs system-wide. That's expected — the installer creates a venv
> for you. Never use `--break-system-packages`.

Requirements: **Python 3.10+** and **Node 18+**.

```bash
# 1. One-command install (venv + backend + CLI + frontend + demo data)
bash scripts/install.sh

# 2. Start the stack (backend :8001 + webapp :5174)
bash scripts/dev.sh start
#    → webapp:  http://localhost:5174   API: http://localhost:8001

# 3. That's it — detonate a sample on the Monitor page.
```

Prefer to drive it by hand? [`scripts/install.sh`](scripts/install.sh) shows
every step it performs, in order.

### Try it without a collector

The webapp and CLI run against **seeded demo data** — no live telemetry
needed:

```bash
source .venv/bin/activate
cd backend && python -m app.seed_demo        # a demo run with alerts
cd .. && outpost list                        # see it in the terminal
outpost campaigns                            # campaign clusters
```

Seeds: `app.seed_demo` (single run), `app.seed_campaign` (the **Shelf-Stack**
campaign pair sharing C2 `203.0.113.88`), `app.seed_macos` (a macOS
LaunchAgent/osascript run).

### CLI usage

```bash
outpost --help          # all commands
outpost list            # session history (colorized risk)
outpost show <run_id>   # full report: risk, kill chain, tree, network
outpost run <sample>    # analyze a synthetic sample
outpost watch           # live event watch mode
outpost search <ioc>    # cross-run IOC search
outpost compare <a> <b> # diff two runs
outpost campaigns       # campaign clusters
outpost samples         # sample vault
outpost rules <run_id>  # Suricata/Sigma detection rules
outpost watchlist       # add|list|remove|export|import
outpost notes <run_id>  # analyst notes
outpost export <run_id> --format json|stix -o out.json
```

Point the CLI at a non-default backend with `OUTPOST_API_URL=http://localhost:8001`.

### Real-machine monitoring

- **Windows** — install Sysmon with `collectors/windows/sysmon_config.xml`,
  then run the collector.
- **Linux** — `sudo auditctl -R collectors/linux/audit.rules` (needs auditd),
  then run the collector.

The collector configs and shippers live in [`collectors/`](collectors/)
(`windows/`, `linux/`, plus shared tests).

## 🧪 Testing

One command runs the whole sweep:

```bash
./verify.sh
```

| Suite | Count | Covers |
|---|---|---|
| Backend pytest | **129** | ingestion, OS-aware rules (win/linux/macOS), risk + ATT&CK, campaigns, events search, samples vault, SSE broadcast, notes, roadmap tiers |
| Collector pytest | **12** | Sysmon + auditd shipping, normalization |
| CLI pytest | **8** | rendering regressions, campaigns output, risk columns |
| Frontend | clean `tsc --noEmit` + Vite build | — |

**CI:** the same sweep runs automatically on every push and pull request via
[GitHub Actions](https://github.com/kripy17/OutPost/actions/workflows/ci.yml)
(the badge above reflects the latest run).

## 📚 Documentation

- **This README** — quickstart, CLI reference, testing, architecture.
- [`demo/README.md`](demo/README.md) — the automated Playwright walkthroughs
  (Shelf-Stack campaign arc + the deck demo video).
- **The code itself** — every backend service, route, and CLI command carries
  docstrings describing what it does and the rule logic behind it.

The original design documents used to build OutPost were internal build
context and aren't shipped in this repository.

## 🔒 Scope & safety

OutPost **monitors and analyzes** behavior — it generates nothing weaponized.
Detection runs on synthetic event streams by default, so the demo is safe to
run anywhere. Real malware should only ever run in an isolated environment
you're prepared to reset. Enrichment
(AbuseIPDB / VirusTotal) needs API keys in `backend/.env` and degrades
gracefully without them.

## 📄 License

[MIT](LICENSE) — built for a BSc Cybersecurity (Year 3) semester project.
