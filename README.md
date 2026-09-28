<div align="center">

<img src="demo/screenshots/fresh/01_overview.png" alt="OutPost — Behavioral Security Workstation" width="96%">

# OutPost

**Open-Source Behavioral Security Workstation & Closed-Loop Threat Operations Platform**

*Real-time host forensics, dynamic malware micro-sandboxing, live adversary simulation, and incident response — all in one self-hosted, air-gapped platform.*

<br>

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React 19](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://typescriptlang.org)
[![Vite 6](https://img.shields.io/badge/Vite-6-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vite.dev)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-4-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com)

<br>

![Tests](https://img.shields.io/badge/tests-1533_passing-brightgreen?style=flat-square)
![Rules](https://img.shields.io/badge/detection_rules-48_active-blue?style=flat-square)
![CLI](https://img.shields.io/badge/cli-39_commands-orange?style=flat-square)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-14%2F14_tactics-teal?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Air-Gap](https://img.shields.io/badge/air--gap-verified-critical?style=flat-square)

<p align="center">
  <a href="#-what-is-outpost">What is OutPost?</a> •
  <a href="#-closed-loop-threat-validation">Closed-Loop Validation</a> •
  <a href="#-feature-tour">Feature Tour</a> •
  <a href="#️-cli--interactive-soc-terminal">CLI & TUI</a> •
  <a href="#-installation--quickstart">Quickstart</a> •
  <a href="#️-architecture--cross-platform">Architecture</a> •
  <a href="#-test-suite">Test Suite</a>
</p>

</div>

---

## 🛡️ What is OutPost?

**OutPost** is an enterprise-grade, self-hosted security operations workstation built for SOC analysts, threat hunters, incident responders, and detection engineers. It continuously ingests endpoint telemetry, flags malicious activity across 48 behavioral heuristics mapped to all 14 MITRE ATT&CK tactics, and enables automated investigation and containment from either a rich web dashboard or a high-speed terminal TUI console.

OutPost is architectured around **Five Core Operational Pillars**:

```text
                                  ┌────────────────────────────────────────────────────────┐
                                  │               OUTPOST SOC WORKSTATION                  │
                                  └──────────────────────────┬─────────────────────────────┘
          ┌───────────────────────┬──────────────────────────┼─────────────────────────────┬─────────────────────────┐
          │                       │                          │                             │                         │
   LIVE OPERATIONS          ENDPOINT FLEET            MALWARE & LAB                 DETECTION & INTEL         ADMIN & TOOLS
          │                       │                          │                             │                         │
 • Real-time SOC pulse   • Sensor agent telemetry   • Dynamic sandbox detonation  • 14/14 MITRE ATT&CK matrix • Payload Decoder & Deobf
 • Live telemetry radar  • Host Forensics & /proc   • Attack scenario playbooks   • Threat watchlist (IOCs)   • Threat Intel Extraction
 • Incident findings     • Process tree causality   • Process lineage graphs      • Sigma / Suricata export   • Audit trail integrity
 • Case investigation    • Network threat matrix    • Artifact forensic analysis  • Custom YARA rule test     • Platform health HUD
 • Automated playbooks   • Host containment & kill  • STIX 2.1 bundle export      • Detection backtesting     • Autonomous CLI & TUI
```

### Why OutPost?

- **Closed-Loop Threat Validation** — Directly bridges the gap between black-box malware triage and fleet detection rule testing. Detonated artifact behaviors can be replayed inside the Simulation Lab with a single click.
- **Genuine Execution, Zero Mock Data** — Every process PID, socket, file modification, and telemetry record is produced by real operating system execution.
- **Dual-Interface Parity** — The React 19 web application and the Rich interactive terminal console (TUI) share 100% backend parity.
- **100% Air-Gapped by Design** — Zero external CDN calls, zero analytics scripts, and zero remote font dependencies. Fully verified for offline and restricted defense networks.
- **Unified Multi-OS Normalization** — Ingests telemetry from Linux (`auditd`/`eBPF`), Windows (`Sysmon`), and macOS (`EndpointSecurity`) into a standardized schema.

---

## 🔄 Closed-Loop Threat Validation

OutPost uniquely unites **Black-Box Sample Triage** with **White-Box Simulation Lab Replay**.

When a suspicious binary or administrative script is uploaded:
1. **Pre-Execution Behavioral Forecast**: Static Shannon entropy, strings, and imported symbols predict potential threat levels and actions before running code.
2. **Dynamic Sandbox Micro-Detonation**: The file executes within an isolated cage (Bubblewrap `bwrap` namespaces, Wine, or temporary directories) while syscalls, child processes, fileless in-memory descriptors, and sockets are flight-recorded live.
3. **Verdict & Zero False Positives**:
   - **Benign Software**: Verified with clean verdicts (`VERDICT: CLEAN (BENIGN)`), zero false alerts, and zero containment actions.
   - **Malicious Payloads**: Instant containment recommendations, actionable `iptables` firewall rules, dropped artifact downloads, and a **"Validate in Simulation Lab ↗"** direct pivot.

<p align="center">
  <img src="demo/screenshots/fresh/15_sample_detail_benign.png" alt="Benign Sample Clean Verdict" width="48%">
  <img src="demo/screenshots/fresh/16_sample_detail_adversary.png" alt="Adversary Ransomware Detonation & Containment" width="48%">
</p>
<p align="center">
  <em>Left: Verified Clean Execution (benign_sysinfo_audit.py — Zero False Positives) · Right: Active Ransomware Detonation (adversary_ransomware_sim.py — C2 Containment & Lab Pivot)</em>
</p>

---

## 📸 Feature Tour

### 🎛️ 1. SOC Command Deck — Executive Overview (`/`)
The central operations deck. Features the real-time **DEFCON Posture HUD**, 24-hour alert severity distribution, live endpoint telemetry pulse, active MITRE ATT&CK tactic radar, and fleet health diagnostics.

<p align="center">
  <img src="demo/screenshots/fresh/01_overview.png" alt="SOC Command Deck" width="94%">
</p>

---

### 🔬 2. Host Forensics & Live Process Inspector (`/events`)
Live telemetry stream and process inspection with zero lag. Monitors CPU, RAM, Swap, Disk, and Network I/O throughput alongside running process lineages, binary paths, open sockets, and unmanaged executable warnings.

<p align="center">
  <img src="demo/screenshots/fresh/02_events.png" alt="Host Forensics & Live Process Inspector" width="94%">
</p>

<details>
<summary><b>🔍 Deep Host Forensics Sub-Views (Process Causality Tree, Network Matrix, Behavioral Insights)</b></summary>
<br>

#### 🌳 Process Causality Tree
Hierarchical parent-child visualization linking parent PIDs, shell execution chains, and LOLBin invocations:
<p align="center">
  <img src="demo/screenshots/fresh/19_process_causality_tree.png" alt="Process Causality Tree" width="90%">
</p>

#### 🌐 Network Threat Matrix
4-domain classification dividing all live sockets into Public Listeners (`0.0.0.0`), Outbound C2/External endpoints, Loopback IPC, and Multicast channels:
<p align="center">
  <img src="demo/screenshots/fresh/20_network_threat_matrix.png" alt="Network Threat Matrix" width="90%">
</p>

#### 💡 Automated Behavioral Insights
Heuristic explanations highlighting dropped binaries in temporary folders, elevated Linux capabilities, and public listeners:
<p align="center">
  <img src="demo/screenshots/fresh/21_behavioral_insights.png" alt="Behavioral Insights" width="90%">
</p>

#### ⚡ Differential Baseline Delta & Capsule Diffs
Compares host states before and after detonation to reveal spawned child processes, newly bound ports, and ephemeral files:
<p align="center">
  <img src="demo/screenshots/fresh/22_differential_delta.png" alt="Differential Delta" width="90%">
</p>

</details>

---

### 🧪 3. Adversary Attack Simulation Lab (`/monitor`)
Deterministic adversary attack scenarios and vault executable detonations executed in real-time. Streams genuine terminal stdout/stderr, displays child process causality trees, and maps detection rule hits live during execution.

<p align="center">
  <img src="demo/screenshots/fresh/07_simulation_lab.png" alt="Simulation Lab Scenario Gallery" width="94%">
</p>
<p align="center">
  <img src="demo/screenshots/fresh/14_live_simulation_cockpit.png" alt="Live Execution Flight Recorder" width="94%">
</p>

---

### 📦 4. Malware Sample Vault (`/samples`)
Secure artifact vault supporting drag-and-drop binary ingestion, SHA-256/SSDEEP fingerprinting, Shannon entropy heatmaps, extracted strings, YARA signature matches, and pre-seeded lab verification suites.

<p align="center">
  <img src="demo/screenshots/fresh/06_samples.png" alt="Malware Sample Vault" width="94%">
</p>

---

### 🚨 5. Incident Findings & Alert Triage Queue (`/findings`)
Centralized SOC alert queue with MITRE ATT&CK technique tags, severity badges (`critical`, `malicious`, `suspicious`, `info`), 1-click false-positive suppression, and direct escalation to investigation cases.

<p align="center">
  <img src="demo/screenshots/fresh/03_findings.png" alt="SOC Findings Queue" width="94%">
</p>

---

### 📂 6. Incident Investigation Dossiers (`/investigations`)
Full lifecycle investigation workspace. Build forensic evidence collections, correlate cross-run event timelines, write collaborative analyst notes, and track statuses from `open` → `in_progress` → `closed`.

<p align="center">
  <img src="demo/screenshots/fresh/05_investigations.png" alt="Investigation Dossiers" width="94%">
</p>

---

### 📡 7. Endpoint Fleet & Sensor Management (`/agents` & `/hosts/local`)
Live endpoint agent fleet tracking. Displays enrollment tokens, OS badges, collector health metrics, and deep per-host forensic breakdowns.

<p align="center">
  <img src="demo/screenshots/fresh/04_agents.png" alt="Fleet Agents" width="48%">
  <img src="demo/screenshots/fresh/13_host_detail.png" alt="Host Detail Forensics" width="48%">
</p>

---

### 🎯 8. MITRE ATT&CK Technique Matrix & Coverage Heatmap (`/coverage`)
Comprehensive tactical heatmap covering all 14 MITRE tactics with full Technique Matrix modal, rule weights, detection gaps, and layer export capabilities.

<p align="center">
  <img src="demo/screenshots/fresh/10_coverage.png" alt="MITRE ATT&CK Coverage Heatmap" width="48%">
  <img src="demo/screenshots/fresh/17_mitre_navigator_matrix.png" alt="ATT&CK Technique Matrix" width="48%">
</p>

---

### 🛠️ 9. Rules Studio, Threat Search, Settings & Audit Trail

<details>
<summary><b>View Detection Rules, Global Search, System Settings, and Audit Trail</b></summary>
<br>

#### Detection Rules Studio (`/rules`)
Rule management and tuning studio. Inspect YAML rule definitions, adjust severity weights, and backtest against past telemetry:
<p align="center">
  <img src="demo/screenshots/fresh/09_rules.png" alt="Detection Rules Studio" width="90%">
</p>

#### Global IOC Search & Personal Watchlist (`/search`)
Instant cross-session search across IP addresses, domains, process names, and SHA-256 hashes, with a personal watchlist manager:
<p align="center">
  <img src="demo/screenshots/fresh/08_search.png" alt="Global Search & Threat Watchlist" width="90%">
</p>

#### Tamper-Evident SHA-256 Audit Trail (`/audit`)
Cryptographically chained, immutable audit log of every analyst action, rule change, triage status update, and process kill command:
<p align="center">
  <img src="demo/screenshots/fresh/12_audit.png" alt="Audit Trail" width="90%">
</p>

#### System Settings & Notification Integrations (`/settings`)
Configure data retention windows, telemetry thresholds, and outbound webhook integrations (Slack, Discord, Microsoft Teams, Syslog):
<p align="center">
  <img src="demo/screenshots/fresh/11_settings.png" alt="System Settings" width="90%">
</p>

</details>

---

## ⌨️ CLI & Interactive SOC Terminal

OutPost includes a standalone CLI with **39 commands** and an interactive, full-screen Rich TUI console.

```bash
# Launch the interactive 5-Pillar SOC Terminal Console
./outpost.sh

# Background daemon operations
./outpost.sh start         # Start backend (:8001) & web console (:5174)
./outpost.sh status        # Real-time health diagnostic HUD of all platform components
./outpost.sh stop          # Gracefully stop all services

# Direct CLI commands
./outpost.sh watch         # Stream live host telemetry & detection alerts
./outpost.sh alerts        # View open SOC findings
./outpost.sh forensics snapshot # Capture complete forensic snapshot
./outpost.sh samples list  # List samples in the vault
```

### 5-Pillar TUI Interactive Hotkeys

When running `./outpost.sh` in an interactive terminal, control the entire platform without exiting:

- **`[1]` - `[5]`**: Switch directly between Operational Pillars:
  - `[1]` **Live Operations** (`Host Forensics`, `Telemetry Radar`, `Findings Queue`)
  - `[2]` **Endpoint Fleet** (`Sensor Agents`, `Host Forensics & /proc audit`, `Containment`)
  - `[3]` **Malware & Lab** (`Simulation Lab`, `Detonation Runs`, `Dynamic Sandbox`)
  - `[4]` **Detection & Intel** (`MITRE ATT&CK Matrix`, `Threat Watchlist`, `Rules`)
  - `[5]` **Administration & Tools** (`Payload Decoder`, `IOC Workbench`, `Audit Trail`)
- **`[:]`**: Open universal **In-App Command Palette** to execute any Typer command
- **`[t]`**: Open interactive **Alert Triage Modal** (`acknowledge`, `resolve`, `reopen`)
- **`[c]`**: Interactively **Create Incident Investigation Case**
- **`[i]`**: Toggle **Host Containment / Network Isolation**
- **`[/]`**: Interactive IOC search across historical sessions and telemetry

---

## 🚀 Installation & Quickstart

### Prerequisites

| Requirement | Supported Version |
|---|---|
| **Python** | 3.10, 3.11, 3.12, 3.13, 3.14 |
| **Node.js** | 18 or higher (Node 20+ recommended) |
| **Operating System** | Linux (Ubuntu, Debian, Fedora, Arch, RHEL), macOS, or Windows (WSL2 recommended) |

### Linux & macOS (Universal `./outpost.sh` Launcher)

```bash
# 1. Clone repository
git clone https://github.com/kripy17/OutPost.git
cd OutPost

# 2. Automated setup (creates Python venv, installs dependencies, builds frontend)
./setup.sh

# 3. Start background services and verify status
./outpost.sh start
./outpost.sh status
```

### Windows (PowerShell)

```powershell
# 1. Clone repository
git clone https://github.com/kripy17/OutPost.git
cd OutPost

# 2. Run automated installer
powershell -ExecutionPolicy Bypass -File scripts\install.ps1

# 3. Start OutPost stack
powershell -ExecutionPolicy Bypass -File scripts\dev.ps1 start
```

### Accessing OutPost

| Service | Access URL / Command | Description |
|---|---|---|
| **Web Console** | [http://localhost:5174](http://localhost:5174) | Full React 19 SOC Operations Cockpit |
| **API Documentation** | [http://localhost:8001/docs](http://localhost:8001/docs) | Interactive Swagger / OpenAPI documentation |
| **Interactive SOC TUI** | `./outpost.sh` | Full terminal console with hotkeys `[1]`–`[5]` |
| **CLI Help** | `./outpost.sh --help` | 39 commands across all operational pillars |

### Deploy Telemetry Agents to Remote Endpoints

Deploy collectors to endpoints with a single command:

**Linux & macOS:**
```bash
curl -fsSL http://<OUTPOST_SERVER>:8001/agents/install.sh | sudo bash
```

**Windows (PowerShell):**
```powershell
irm http://<OUTPOST_SERVER>:8001/agents/install.ps1 | iex
```

---

## 🏗️ Architecture & Cross-Platform

```text
┌────────────────────┐    ┌────────────────────┐    ┌────────────────────┐
│   Linux Endpoint   │    │  Windows Endpoint  │    │   macOS Endpoint   │
│   auditd / eBPF    │    │  Microsoft Sysmon  │    │  EndpointSecurity  │
│ collector_linux.py │    │  collector_win.py  │    │ collector_macos.py │
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
        │  (:5174)         │            │  39 commands     │
        │  Vite + TS + TW  │            │  Typer + Rich    │
        └──────────────────┘            └──────────────────┘
```

### OS Compatibility Matrix

- **Linux (Primary / Best for Sandbox Isolation)**: Uses unprivileged user namespaces via Bubblewrap (`bwrap`) for zero-overhead sandbox confinement, Wine for Windows PE execution, and native `/proc` capability audits.
- **Windows**: Full fleet monitoring via dedicated Sysmon collector (`collector_win.py`) mapping Event IDs 1, 3, 6, 7, 8, 10, 11, 12, 13, 14, 23. Cross-platform process lifecycle controls via `psutil`. For hosting the central stack, **WSL2** is recommended.
- **macOS**: Full fleet monitoring via `collector_macos.py` parsing Apple EndpointSecurity & OpenBSM audit records, TCC database access detection, and LaunchDaemon persistence auditing.

---

## 🧪 Test Suite

OutPost enforces a strict quality gate with automated test coverage across all subsystems:

```bash
# Execute the full automated test suite
./.venv/bin/pytest backend collectors/tests cli/tests
npm --prefix frontend test -- --run
```

| Subsystem | Test Framework | Tests Passed | Status |
|---|---|---|---|
| **Backend Core, Forensics & APIs** | Pytest | **864** | ✅ Passing |
| **Advanced Host Forensics & Capabilities** | Pytest | **16** | ✅ Passing |
| **Telemetry Collectors (Linux, Win, Mac)** | Pytest | **47** | ✅ Passing |
| **CLI & SOC Terminal Console** | Pytest | **204** | ✅ Passing |
| **Frontend Web Console (React 19)** | Vitest | **402** | ✅ Passing |
| **Total Test Suite Coverage** | | **1,533** | **✅ 100% Green** |

---

## 🔒 Security & Air-Gap Verification

- **100% Air-Gapped**: Zero external CDN scripts, tracking beacons, or remote web fonts (`IBM Plex Mono` and `JetBrains Mono` are bundled locally). Verified completely functional in network-isolated environments.
- **Fail-Closed Threat Intel**: External enrichment (VirusTotal, AbuseIPDB) requires explicit configuration; default execution operates strictly in offline heuristic mode.
- **Process Target Verification**: Process termination (`freeze`, `kill`, `resume`) validates start-time identity to prevent PID race condition exploits.
- **Input Sanitization**: Decompression bomb limits (50 MB), path traversal canonicalization, parameterized database queries, and 500 MB upload limits.

---

## 📄 Documentation

Comprehensive technical documentation is maintained in [`docs/`](docs/):

| Specification | Description |
|---|---|
| [`01-ARCHITECTURE.md`](docs/01-ARCHITECTURE.md) | Platform architecture, component boundaries, and pipeline flow |
| [`02-BACKEND-SPEC.md`](docs/02-BACKEND-SPEC.md) | FastAPI endpoint contracts, Pydantic schemas, and database models |
| [`03-COLLECTOR-SPEC.md`](docs/03-COLLECTOR-SPEC.md) | Multi-OS agent specifications (Linux, Windows Sysmon, macOS) |
| [`04-FRONTEND-SPEC.md`](docs/04-FRONTEND-SPEC.md) | Web application routing, state stores, and component hierarchy |
| [`05-DEPLOYMENT-SETUP.md`](docs/05-DEPLOYMENT-SETUP.md) | Production setup, systemd services, and air-gap verification |
| [`09-CLI-SPEC.md`](docs/09-CLI-SPEC.md) | Full 39-command Typer CLI reference manual |
| [`11-DETECTION-LOGIC.md`](docs/11-DETECTION-LOGIC.md) | MITRE ATT&CK detection heuristics with detection engineering rationale |
| [`18-AIR-GAP.md`](docs/18-AIR-GAP.md) | Air-gap compliance testing and offline guarantees |

---

## 📄 License

Distributed under the [MIT License](LICENSE).

<div align="center">

**Created by [Krish Patel](https://github.com/kripy17)**

</div>
