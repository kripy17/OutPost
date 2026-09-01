<div align="center">

<img src="demo/screenshots/fresh/01_overview.png" alt="OutPost — Behavioral Security Workstation" width="96%">

# OutPost

**Open-Source Behavioral Security Workstation & Dynamic Malware Analysis Engine**

*Real-time host forensics, live adversary simulation, and incident response — all in one self-hosted platform.*

<br>

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React 19](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://typescriptlang.org)
[![Vite 6](https://img.shields.io/badge/Vite-6-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vite.dev)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-4-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com)

<br>

![Tests](https://img.shields.io/badge/tests-1376_passing-brightgreen?style=flat-square)
![Rules](https://img.shields.io/badge/detection_rules-45_active-blue?style=flat-square)
![CLI](https://img.shields.io/badge/cli-32_commands-orange?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-14%2F14_tactics-teal?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Air-Gap](https://img.shields.io/badge/air--gap-verified-critical?style=flat-square)

</div>

---

## What is OutPost?

**OutPost** is a self-hosted security workstation built for SOC analysts, incident responders, and malware researchers. It watches what's running on your machines, flags suspicious behavior using 45 detection rules mapped to the MITRE ATT&CK framework, and lets you investigate threats from a web dashboard or a terminal CLI.

It's built around three core pillars:

```text
                                  ┌─────────────────────────────────────┐
                                  │         OUTPOST WORKSTATION         │
                                  └──────────────┬──────────────────────┘
         ┌───────────────────────────────────────┼───────────────────────────────────────┐
         │                                       │                                       │
   HOST FORENSICS                      DYNAMIC SANDBOX                          SOC OPERATIONS
   & X-RAY ENGINE                     & SIMULATION LAB                        & INCIDENT RESPONSE
         │                                       │                                       │
  • Live /proc introspection            • Live binary detonation              • MITRE ATT&CK triage queue
  • Process causality trees             • Real stdout/stderr streaming        • Investigation case dossiers
  • Network threat matrix               • Multi-stage attack scenarios        • IOC search & watchlists
  • Linux capabilities decoder          • YARA & entropy analysis             • Detection rule engineering
  • Process freeze/kill controls        • Isolation drivers (bwrap/wine)      • Tamper-evident audit trail
  • Differential baseline deltas        • Automated rule evaluation           • Fleet agent management
  • Forensic capsule comparison         • Process lineage tracking            • Notification integrations
```

### Why OutPost?

- **Not a wrapper** — Original detection logic with documented rationale for every rule, not a GUI over someone else's tool.
- **Two equal interfaces** — Web dashboard and Rich terminal TUI both talk to the same backend. Use whichever fits your workflow.
- **Air-gapped by design** — Zero external CDNs, tracking scripts, or font downloads. Ships self-contained, verified offline.
- **Cross-platform telemetry** — Normalizes `auditd`/`eBPF` (Linux), `Sysmon` (Windows), and `EndpointSecurity` (macOS) into one unified schema.

---

## 📸 Feature Tour

### 🎛️ SOC Command Deck — Overview Dashboard

The entry point. Real-time risk trends, live host telemetry pulse, MITRE ATT&CK tactical distribution, and a posture summary across all monitored endpoints.

<p align="center">
  <img src="demo/screenshots/fresh/01_overview.png" alt="SOC Command Deck" width="90%">
</p>

---

### 🔬 Host X-Ray — Deep Process Forensics

Full-spectrum live forensics: every running process with CPU/memory, command lines, parent-child lineage, package manager provenance, Linux capabilities (`CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_PTRACE`), Seccomp mode, mapped `.so` libraries, open file descriptors, and 8-sensor device access detection (microphone, camera, GPU, screen capture).

<p align="center">
  <img src="demo/screenshots/fresh/24_host_xray_command_cockpit.png" alt="Host X-Ray Command Cockpit" width="90%">
</p>

<details>
<summary><b>🌳 Process Causality Tree</b> — Hierarchical parent-child execution graph</summary>
<br>
<p align="center">
  <img src="demo/screenshots/fresh/19_process_causality_tree.png" alt="Process Causality Tree" width="90%">
</p>
</details>

<details>
<summary><b>🌐 Network Threat Matrix</b> — 4-domain socket classification</summary>
<br>
Categorizes every active connection: Public Listeners (<code>0.0.0.0</code>), Outbound C2/External, Loopback IPC, and Multicast — with suspicious port heuristics.
<p align="center">
  <img src="demo/screenshots/fresh/20_network_threat_matrix.png" alt="Network Threat Matrix" width="90%">
</p>
</details>

<details>
<summary><b>💡 Behavioral Insights</b> — Automated heuristic explanations</summary>
<br>
Real-time reasoning cards that flag anomalies: dropped binaries in temp directories, unmanaged processes, public-facing listeners, and elevated Linux capabilities — with actionable remediation steps.
<p align="center">
  <img src="demo/screenshots/fresh/21_behavioral_insights.png" alt="Behavioral Insights" width="90%">
</p>
</details>

<details>
<summary><b>🔍 Process Deep Inspector</b> — Per-process security posture</summary>
<br>
64-bit Linux capabilities bitmask decoding, Seccomp filter mode, <code>NoNewPrivs</code>, namespace isolation, mapped shared libraries, and safe process freeze/kill controls with start-time identity validation.
<p align="center">
  <img src="demo/screenshots/fresh/16_process_xray_drawer.png" alt="Process Inspector" width="90%">
</p>
</details>

<details>
<summary><b>⚡ Differential Baseline Delta</b> — Pre/post-detonation comparison</summary>
<br>
Captures a host snapshot before detonation and computes real-time deltas: spawned processes, opened ports, dropped files, and memory metrics.
<p align="center">
  <img src="demo/screenshots/fresh/22_differential_delta.png" alt="Differential Delta" width="90%">
</p>
</details>

<details>
<summary><b>📑 Forensic Capsule Diffs</b> — Side-by-side environment comparison</summary>
<br>
Export portable <code>.xray.json</code> forensic capsules and visually diff two environments to spot capability escalation, injected libraries, and new listeners.
<p align="center">
  <img src="demo/screenshots/fresh/23_capsule_diff_modal.png" alt="Forensic Capsule Diff" width="90%">
</p>
</details>

---

### 🧪 Live Simulation Lab — Dynamic Malware Sandbox

Execute deterministic multi-stage adversary attack scenarios in isolated sandboxes. Real OS subprocesses run live — genuine PIDs, real terminal stdout/stderr streaming, and automated detection rule evaluation in real time.

<p align="center">
  <img src="demo/screenshots/fresh/14_live_simulation_cockpit.png" alt="Adversary Simulation Lab" width="90%">
</p>

---

### 📦 Malware Sample Vault

Secure sample repository with SHA-256/SSDEEP hashing, Shannon entropy distributions, extracted strings, YARA signature matching, and 1-click micro-sandbox detonation with isolation drivers (Bubblewrap `bwrap`, Wine, or Tempdir).

<p align="center">
  <img src="demo/screenshots/fresh/06_samples.png" alt="Malware Sample Vault" width="90%">
</p>

---

### 🚨 Incident Findings & Alert Triage

Centralized SOC alert queue with MITRE ATT&CK technique mapping, severity filtering, 1-click acknowledgment, false-positive suppression, and instant escalation to investigation case dossiers.

<p align="center">
  <img src="demo/screenshots/fresh/03_findings.png" alt="SOC Findings Queue" width="90%">
</p>

---

### 📂 Investigation Case Dossiers

Full incident response lifecycle: create cases, attach findings and evidence, build timelines, write analyst notes, and track status from `open` → `in_progress` → `closed`.

<p align="center">
  <img src="demo/screenshots/fresh/05_investigations.png" alt="Investigation Dossiers" width="90%">
</p>

---

### 📡 Fleet Agents & Telemetry Collectors

Monitor distributed endpoint agents across Linux (`auditd`/`eBPF`), Windows (`Sysmon`), and macOS (`EndpointSecurity`). Heartbeat tracking, collector diagnostics, and 1-click remote agent deployment.

<p align="center">
  <img src="demo/screenshots/fresh/04_agents.png" alt="Fleet Agents" width="90%">
</p>

---

### 🎯 MITRE ATT&CK Detection Coverage

45 active behavioral detection rules with full MITRE ATT&CK tactic/technique mapping across all 14 tactics. Interactive heatmap, rule weight visualization, gap analysis, and ATT&CK Navigator layer export.

<p align="center">
  <img src="demo/screenshots/fresh/10_coverage.png" alt="MITRE ATT&CK Coverage" width="90%">
</p>

---

<details>
<summary><b>More pages: Event Manager, Rules, Search, Settings, Audit</b></summary>
<br>

#### Event Manager — Real-time Telemetry Stream
<p align="center">
  <img src="demo/screenshots/fresh/02_events.png" alt="Event Manager" width="90%">
</p>

#### Detection Rules — Rule Engineering Studio
<p align="center">
  <img src="demo/screenshots/fresh/09_rules.png" alt="Detection Rules" width="90%">
</p>

#### Global Search & IOC Watchlist
<p align="center">
  <img src="demo/screenshots/fresh/08_search.png" alt="Search" width="90%">
</p>

#### Settings & Notification Integrations
<p align="center">
  <img src="demo/screenshots/fresh/11_settings.png" alt="Settings" width="90%">
</p>

#### Tamper-Evident Audit Trail
<p align="center">
  <img src="demo/screenshots/fresh/12_audit.png" alt="Audit Trail" width="90%">
</p>

</details>

---

## ⌨️ CLI & Interactive SOC Terminal

OutPost ships a standalone CLI with **32 commands** and a full-screen Rich TUI console. Every feature available in the web dashboard is also accessible from the terminal.

```bash
# Launch the interactive SOC Terminal
./cli.sh console

# Stream live host telemetry
./cli.sh watch

# View and triage SOC alerts
./cli.sh alerts

# Deep host forensics — process tree, sockets, capabilities
./cli.sh forensics snapshot
./cli.sh forensics tree
./cli.sh forensics network

# Malware analysis
./cli.sh samples list
./cli.sh analysis launch <sample_id>

# Search IOCs across all runs
./cli.sh search 192.168.1.100

# Detection engineering
./cli.sh rules generate <run_id>
./cli.sh coverage
```

```text
 ╭────────────────────────────── OutPost SOC Terminal ──────────────────────────────╮
 │                                                                                  │
 │  [1] Live Watch        Stream real-time host telemetry & adversary markers       │
 │  [2] Alerts & Triage   Manage SOC queue, view findings & acknowledge alerts      │
 │  [3] Host X-Ray        Inspect live processes, sockets & Linux capabilities      │
 │  [4] Investigations    Track ongoing incident response cases & evidence          │
 │  [5] Detection Rules   View, tune & test 45 MITRE ATT&CK detection rules        │
 │  [6] Malware Vault     List samples, inspect YARA matches & detonate binaries    │
 │                                                                                  │
 ╰──────────────────────────────────────────────────────────────────────────────────╯
```

<details>
<summary><b>Full CLI command reference</b></summary>
<br>

| Command | Description |
|---|---|
| `console` / `tui` | Launch the interactive SOC Terminal TUI |
| `watch` | Live monitoring — real-time process activity & alert feed |
| `alerts` | View open alerts with severity, rule, and process context |
| `triage` | Move alerts through `open` → `acknowledged` → `resolved` |
| `list` | List past monitoring sessions and analysis runs |
| `show <run_id>` | Full report for one session |
| `export <run_id>` | Export to JSON, PDF, CSV, or STIX format |
| `run <sample>` | Bounded analysis — execute, observe, report |
| `search <ioc>` | Cross-run IOC search ("have I seen this before?") |
| `compare <id1> <id2>` | Diff two runs — unique processes, IPs, shared artifacts |
| `forensics snapshot` | Capture live host forensic snapshot |
| `forensics tree` | Display process causality tree |
| `forensics network` | Network connection matrix |
| `forensics baseline` | Create a pre-detonation baseline |
| `forensics diff` | Compute differential delta |
| `forensics freeze/thaw` | Process lifecycle controls (SIGSTOP/SIGCONT) |
| `forensics caps` | Linux capabilities inspection |
| `rules generate` | Auto-generate Suricata/Sigma rules from findings |
| `rules backtest` | Backtest rules against historical data |
| `coverage` | View MITRE ATT&CK detection coverage |
| `samples` | List and manage the malware sample vault |
| `analysis launch` | Launch a detonation analysis job |
| `watchlist add/list` | Personal IOC watchlist management |
| `yara list/test` | YARA rule management and testing |
| `investigations` | Investigation case management |
| `playbooks run` | Execute curated attack scenario playbooks |
| `intel import` | Threat-intel feed import |
| `agent run/install` | Host-agent bootstrap and collector management |
| `admin` | Fleet and backend maintenance |

</details>

---

## 🚀 Installation & Setup

### Prerequisites

| Requirement | Version |
|---|---|
| **Python** | 3.10 or higher |
| **Node.js** | 18 or higher |
| **Git** | Any recent version |

### Linux & macOS

```bash
# 1. Clone the repository
git clone https://github.com/kripy17/OutPost.git
cd OutPost

# 2. Run the automated installer
#    Detects your OS, installs Python/Node dependencies, creates a virtual environment,
#    and builds the frontend — all in one step.
bash scripts/install.sh

# 3. Start OutPost
#    Launches FastAPI backend on port 8001 and React frontend on port 5174.
bash scripts/dev.sh start
```

### Windows (PowerShell)

```powershell
# 1. Clone the repository
git clone https://github.com/kripy17/OutPost.git
cd OutPost

# 2. Run the automated installer
#    Sets up Python venv, Node dependencies, and optionally configures
#    SwiftOnSecurity Sysmon for endpoint telemetry collection.
powershell -ExecutionPolicy Bypass -File scripts\install.ps1

# 3. Start OutPost
powershell -ExecutionPolicy Bypass -File scripts\dev.ps1 start
```

### Access OutPost

Once running, open your browser:

| Service | URL |
|---|---|
| **Web Console** | [http://localhost:5174](http://localhost:5174) |
| **API Docs (Swagger)** | [http://localhost:8001/docs](http://localhost:8001/docs) |
| **CLI** | `./cli.sh --help` (Linux/macOS) or `.\cli.ps1 --help` (Windows) |

### Deploy Agents to Remote Machines

Deploy OutPost telemetry collectors to monitored endpoints with a single command:

**Linux & macOS:**
```bash
curl -fsSL http://<OUTPOST_SERVER>:8001/api/agents/install.sh | sudo bash
```

**Windows (PowerShell):**
```powershell
irm http://<OUTPOST_SERVER>:8001/api/agents/install.ps1 | iex
```

---

## 🏗️ Architecture

```text
┌────────────────────┐    ┌────────────────────┐    ┌────────────────────┐
│  Linux Endpoint    │    │  Windows Endpoint   │    │  macOS Endpoint    │
│  auditd / eBPF     │    │  Sysmon             │    │  EndpointSecurity  │
│  collector_linux.py │    │  collector_win.py   │    │  collector_macos.py│
└─────────┬──────────┘    └─────────┬──────────┘    └─────────┬──────────┘
          │  POST /ingest/batch     │                         │
          └─────────────────────────┼─────────────────────────┘
                                    ▼
                    ┌───────────────────────────────┐
                    │     FastAPI Backend (:8001)    │
                    │  ┌──────────────────────────┐ │
                    │  │ Normalizer → Detection   │ │
                    │  │ Enrichment → Process Tree │ │
                    │  │ Sandbox → Rule Engine     │ │
                    │  └──────────────────────────┘ │
                    │       SQLite / PostgreSQL      │
                    └───────────────┬────────────────┘
                                    │ REST API
                    ┌───────────────┴────────────────┐
                    ▼                                ▼
        ┌──────────────────┐            ┌──────────────────┐
        │  React Web App   │            │  CLI & Rich TUI  │
        │  (:5174)         │            │  32 commands      │
        │  Vite + TS + TW  │            │  Typer + Rich     │
        └──────────────────┘            └──────────────────┘
```

### Tech Stack

| Layer | Technologies |
|---|---|
| **Backend** | Python 3.10+, FastAPI, Pydantic, Uvicorn, SQLite/PostgreSQL |
| **Frontend** | React 19, TypeScript 5.6, Vite 6, TailwindCSS 4, TanStack Query |
| **CLI** | Typer, Rich TUI, PyFiglet, Plyer notifications |
| **Collectors** | `auditd`/`eBPF` (Linux), `Sysmon` (Windows), `EndpointSecurity` (macOS) |
| **Testing** | Pytest (backend/collectors/CLI), Vitest (frontend), Playwright (E2E) |
| **Deployment** | Docker Compose, systemd units, 1-command install scripts |

---

## 🧪 Test Suite

OutPost maintains a rigorous quality gate across all layers:

```bash
# Run the full test suite
./.venv/bin/pytest backend collectors/tests cli/tests
npm --prefix frontend test -- --run
```

| Component | Framework | Tests | Status |
|---|---|---|---|
| Backend Core & APIs | Pytest | **822** | ✅ Passing |
| Telemetry Collectors | Pytest | **43** | ✅ Passing |
| CLI & SOC Terminal | Pytest | **146** | ✅ Passing |
| Frontend Web Console | Vitest | **365** | ✅ Passing |
| **Total** | | **1,376** | **✅ 100% Green** |

---

## 🔒 Security & Air-Gap Design

OutPost is built exclusively as a **defensive** security monitoring tool.

| Principle | Implementation |
|---|---|
| **100% Air-Gapped** | Zero external CDN dependencies. Self-hosted fonts (`IBM Plex Mono`, `JetBrains Mono`). Verified offline operation. |
| **Fail-Closed Privacy** | Threat intel enrichment (VirusTotal, AbuseIPDB) requires explicit API keys. Defaults to safe offline analysis when unconfigured. |
| **Process Safety** | PID start-time identity validation prevents collision attacks before applying freeze/kill controls. |
| **Input Hardening** | 50 MB decompression bomb protection, path traversal canonicalization, parameterized SQL queries, 500 MB upload size limits. |

---

## 📄 Documentation

Full technical specifications live in [`docs/`](docs/):

| Document | Contents |
|---|---|
| [`01-ARCHITECTURE.md`](docs/01-ARCHITECTURE.md) | System design, repo structure |
| [`02-BACKEND-SPEC.md`](docs/02-BACKEND-SPEC.md) | API endpoints, database schema, Pydantic models |
| [`03-COLLECTOR-SPEC.md`](docs/03-COLLECTOR-SPEC.md) | Monitoring agent (Windows + Linux + macOS) |
| [`04-FRONTEND-SPEC.md`](docs/04-FRONTEND-SPEC.md) | Webapp routes and components |
| [`05-DEPLOYMENT-SETUP.md`](docs/05-DEPLOYMENT-SETUP.md) | Installation and safety notes |
| [`09-CLI-SPEC.md`](docs/09-CLI-SPEC.md) | CLI command reference |
| [`11-DETECTION-LOGIC.md`](docs/11-DETECTION-LOGIC.md) | All 45 detection heuristics with rationale |
| [`18-AIR-GAP.md`](docs/18-AIR-GAP.md) | Air-gap verification and offline guarantees |

---

## 📄 License

Distributed under the [MIT License](LICENSE).

---

<div align="center">

**Built by [Krish Patel](https://github.com/kripy17)**

</div>
