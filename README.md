<div align="center">

# 🛡️ OutPost

### Cross-Platform Behavioral Security & Telemetry Monitor

*A self-hosted, explainable SOC monitoring platform and malware analysis workbench with dual first-class interfaces: a reactive web deck and an interactive terminal console.*

`FastAPI` · `React 19` · `TypeScript` · `Vite 6` · `SQLite / PostgreSQL` · `Typer` · `Rich` · `Playwright`

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-backend-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fkripy17%2FOutPost%2Fmain%2Fbadges%2Ftests.json&style=flat-square)](https://github.com/kripy17/OutPost/actions)
[![Rules](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fkripy17%2FOutPost%2Fmain%2Fbadges%2Frules.json&style=flat-square)](docs/11-DETECTION-LOGIC.md)
[![Commands](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fkripy17%2FOutPost%2Fmain%2Fbadges%2Fcommands.json&style=flat-square)](docs/09-CLI-SPEC.md)
[![Tactics](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fkripy17%2FOutPost%2Fmain%2Fbadges%2Fcoverage.json&style=flat-square)](docs/11-DETECTION-LOGIC.md)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

<p align="center">
  <img src="demo/deck-demo-hero.gif" alt="OutPost — the command deck: risk over time, detection volume, live findings" width="85%">
  <br>
  <em>The Command Deck — risk-over-time, detection volume, and live findings feed.</em>
</p>

</div>

---

## 📖 What is OutPost?

**OutPost** is an open, self-hosted behavioral security monitoring system designed to provide deep observability, anomaly detection, and automated threat triage across Windows, Linux, and macOS endpoints.

Unlike opaque ML-based platforms, OutPost utilizes **deterministic, explainable rule-based heuristics** mapped directly to the **MITRE ATT&CK** matrix. Telemetry is collected directly from kernel and OS primitives (`auditd`/`eBPF` on Linux, `Sysmon` on Windows, and `EndpointSecurity` on macOS), normalized into a single unified event schema, and enriched in real time.

### 🏛️ The Three Explicit Product Domains

```text
                                OUTPOST CONSOLE
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
 1. LIVE MONITORING           2. MALWARE ANALYSIS            3. SIMULATION LAB
 (Real Host Telemetry)        (Real Binary Analysis)         (Safe Rule Testing)
        │                              │                              │
  Host Collectors                Sample Vault                   Attack Playbooks
  [Linux/Windows/macOS]          [Upload & Hashes]              [LOLBin/C2/Ransomware]
        │                              │                              │
  POST /ingest/batch             Static Analysis                POST /runs (source=simulation)
        │                        [PE/ELF/Entropy/YARA]                │
  Persisted `events` Table             │                        Isolated Ingestion
        │                        Dynamic Sandbox                      │
  Event Manager (`/events`)      [Configured / 501]             Rule Tuning & Verification
        │                              │                              │
  Findings Queue (`/findings`)   Analysis Results                     │
        │                              │                              │
  Incident Cases (`/investigations`) ──┘                              │
```

1. **Live Host Monitoring (`source="live"`)**:
   Watches real production endpoints running lightweight collector agents. Raw OS events (process execution, socket connections, file writes, registry changes) flow through the ingestion pipeline into persisted database records and trigger real-time detection heuristics.
2. **Malware Analysis & Sample Vault (`source="sandbox"`)**:
   Provides binary intake, SHA256 deduplication, file magic detection, static disassembly (PE headers, ELF sections, strings, entropy, IOC extraction), YARA signature scanning, and external dynamic sandbox dispatch (Any.Run, Hatching Triage, Joe Sandbox) with transparent API key status.
3. **Simulation Lab (`source="simulation"`)**:
   Safe, deterministic attack scenario playbooks executed in complete isolation from live monitoring feeds to validate rule thresholds, test alert pipelines, and train SOC analysts.

---

## ✨ Flagship Capabilities

| Capability | Description |
|---|---|
| 🖥️ **OS-Aware Detection Engine** | **37 rules** across Linux, Windows, and macOS covering all 14 MITRE tactics (LOLBin execution, reverse shells, C2 beaconing, fan-out file encryption, account enumeration, persistence). |
| 🆔 **Kernel-Resolved Process Identity** | Evaluates true kernel binary paths (auditd `exe=` / Sysmon `Image`) rather than spoofable process command names. |
| 🔬 **Deep Context Modal Workspaces** | 1-click **Process Context Modal** and **Network Context Modal** to inspect parent/child lineage, active sockets, touched files, communicating hosts, and correlated alerts. |
| 🏷️ **Universal Data Provenance** | Clear, honest visual badges across every surface distinguishing `LIVE` host telemetry from `SIMULATION` lab playbooks and `SANDBOX` detonations. |
| ⛈️ **Alert Storm Guard** | Per-rule burst caps (first-seen: 20, beaconing: 15, fan-out: 10, default: 25) with held-back counts preventing console flooding. |
| 🗂️ **Campaign Clustering** | Graph clustering groups sessions and events sharing high-confidence C2s or file hashes into aggregated campaign threat cards. |
| 📡 **Realtime SSE Broadcast** | Server-Sent Events stream live alerts, status transitions, and triage updates without polling. |
| 🔒 **Air-Gapped by Design** | Zero external CDNs, fonts, or analytics. Self-contained fonts and verified offline runtime guarantees. |
| ⌨️ **First-Class CLI Parity** | **31 commands**, full Rich color formatting, interactive TUI console, and headless scripting support. |

---

## 🚀 Quickstart

### Prerequisites
- **Python 3.10+**
- **Node.js 18+**

### Automated 1-Command Setup

```bash
# 1. Clone repository & install all dependencies (backend, CLI, frontend)
./setup.sh

# 2. Start the complete stack (Backend on :8001 + Web Console on :5174)
./start.sh
```

- **Web Console**: [http://localhost:5174](http://localhost:5174)
- **API Documentation**: [http://localhost:8001/docs](http://localhost:8001/docs)

### Docker Deployment

```bash
docker compose up --build
```

---

## ⌨️ OutPost CLI Reference

The `outpost` command-line utility provides comprehensive SOC operations directly inside your terminal.

```bash
# Activate the environment
source .venv/bin/activate
outpost --help
```

### 1. Live Telemetry & Fleet Operations
```bash
outpost watch                          # Stream live host telemetry with recon markers
outpost console                        # Launch the interactive Rich TUI SOC Console
outpost agent run                      # Run host collector in the foreground
outpost agent install                  # Install host collector as a background service
outpost hosts                          # Per-host aggregate telemetry timelines
```

### 2. Triage & Incident Case Management
```bash
outpost alerts                         # Inspect active alert queue (--provenance real|synthetic)
outpost triage <alert_id> <status>     # Move alert (open -> acknowledged -> resolved)
outpost triage resolved 101 102 103    # Bulk status update with optional --comment
outpost allowlist list                 # View active IOC allowlists
outpost allowlist add --ip 1.1.1.1     # Allowlist benign IP from future alert generation
outpost watchlist list                 # View monitored indicator watchlist
outpost investigations list            # View incident investigation cases
outpost investigations create "Case"   # Create new investigation case
```

### 3. Detection Engineering & Rule Ops
```bash
outpost rules list                     # List all 37 active detection rules & MITRE tactics
outpost rules knobs                    # Inspect and tune heuristic thresholds
outpost rules log-patterns             # Inspect anti-forensics & log tampering patterns
outpost coverage                       # Display MITRE ATT&CK coverage matrix (14/14)
outpost yara list                      # List custom YARA signatures
outpost yara test <rule.yar>           # Scan sample vault against YARA rule
```

### 4. Threat Intelligence & Forensics
```bash
outpost search <indicator>             # Cross-session search for IP, domain, hash, or process
outpost campaigns                      # Inspect auto-clustered adversary campaigns
outpost footprint <sample_id>          # Retrieve passive DNS, CT certs, and ASN metadata
outpost intel                          # Check enrichment cache status & trigger refreshes
outpost samples                        # List uploaded binary samples in the vault
outpost compare <run_a> <run_b>        # Diff two execution timelines side-by-side
outpost export <run_id> --format stix  # Export session data as STIX 2.1 or JSON
```

### 5. Administration & Preferences
```bash
outpost auth generate-token            # Generate shared OUTPOST_AGENT_TOKEN
outpost admin backfill-channels        # Backfill channel tags on legacy events
outpost admin pg-migrate               # Export SQLite database to PostgreSQL
outpost settings                       # Inspect console filters & preferences
```

---

## 🏗️ Architecture

```text
┌─────────────────────────┐   ┌─────────────────────────┐   ┌─────────────────────────┐
│     Linux (auditd/eBPF) │   │     Windows (Sysmon)    │   │ macOS (EndpointSecurity)│
│     Collector Agent     │   │     Collector Agent     │   │ Collector Agent         │
└────────────┬────────────┘   └────────────┬────────────┘   └────────────┬────────────┘
             └─────────────────────────────┼─────────────────────────────┘
                                           ▼ POST /ingest/batch
                          ┌─────────────────────────────────┐
                          │         FastAPI Backend         │
                          │   • Unified Event Normalizer    │
                          │   • SQLite / PostgreSQL Storage │
                          │   • 37 Heuristic Rules Engine   │
                          │   • MITRE ATT&CK Risk Scoring   │
                          │   • YARA Lab & IOC Extraction   │
                          │   • Real-Time SSE Event Stream  │
                          └────────────────┬────────────────┘
                                           │ REST API + SSE
                     ┌─────────────────────┴─────────────────────┐
                     ▼                                           ▼
          ┌─────────────────────┐                     ┌─────────────────────┐
          │     Web Console     │                     │     OutPost CLI     │
          │   React 19 + Vite   │                     │     Typer + Rich    │
          │  Tailwind CSS v4    │                     │  Terminal SOC Deck  │
          └─────────────────────┘                     └─────────────────────┘
```

---

## 🧪 Verification & Testing

OutPost maintains a comprehensive automated quality gate verifying every component:

```bash
./verify.sh
```

| Suite | Count | Covers |
|---|---|---|
| Backend pytest | **714** | Ingestion, normalizers, rules engine, risk scoring, campaigns, search, SSE stream, YARA, triage, PostgreSQL runtime dialect |
| Collector pytest | **38** | Linux `auditd`/`eBPF`, Windows `Sysmon`, macOS `EndpointSecurity` shippers |
| CLI pytest | **134** | All 31 CLI commands, Rich table rendering, argument validation, interactive TUI mode |
| Frontend | **365** | Vitest unit tests + clean `tsc --noEmit` + Vite production build |
| ATT&CK Coverage | **14/14** | Complete matrix coverage across ATT&CK tactics with 0 gaps |
| Playwright E2E | **54 checks** | Cross-browser layout verification across 18 routes and 3 responsive viewports |
| **Total Test Count** | **1,251** | **100% Green / 0 Failures** |

---

## 🔒 Scope & Safety Guarantees

OutPost is strictly a **defensive security monitoring and analysis tool**. It contains no weaponized payloads, exploits, or offensive automation.

- **Air-Gap Guarantee**: The web console ships with self-hosted fonts and assets (`frontend/public/fonts/`). No external analytics, trackers, or CDN scripts are loaded.
- **Enrichment Safety**: Threat intelligence APIs (VirusTotal, AbuseIPDB) require explicit user-configured API keys in `.env` and fail closed to offline mode when unconfigured.

---

## 📄 License

Distributed under the [MIT License](LICENSE).
