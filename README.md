<div align="center">

# 🛡️ OutPost

### Enterprise Cross-Platform Behavioral Security Workstation & Dynamic Malware Sandbox

*An explainable, self-hosted SOC monitoring platform, host forensics engine, and dynamic malware analysis sandbox with dual first-class interfaces: a reactive web console and an interactive terminal TUI.*

`FastAPI` · `React 19` · `TypeScript 5.6` · `Vite 6` · `SQLite / PostgreSQL` · `Typer` · `Rich TUI` · `TailwindCSS`

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-backend-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Tests](https://img.shields.io/badge/tests-1376%20passing-brightgreen?style=flat-square)](https://github.com/kripy17/OutPost/actions)
[![Rules](https://img.shields.io/badge/rules-45%20active-blue?style=flat-square)](docs/11-DETECTION-LOGIC.md)
[![Commands](https://img.shields.io/badge/cli-32%20commands-orange?style=flat-square)](docs/09-CLI-SPEC.md)
[![Tactics](https://img.shields.io/badge/tactics-14%2F14%20covered-teal?style=flat-square)](docs/11-DETECTION-LOGIC.md)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

<p align="center">
  <img src="demo/screenshots/fresh/01_overview.png" alt="OutPost Command Deck" width="92%">
  <br>
  <em>The OutPost Command Deck — real-time risk trends, live telemetry, posture analytics, and SOC findings queue.</em>
</p>

</div>

---

## 📖 What is OutPost?

**OutPost** is an authoritative, open-source security monitoring workstation and dynamic malware analysis engine designed for Security Operations Centers (SOC), incident responders, and malware analysts. 

OutPost pairs real-time kernel telemetry (`auditd`/`eBPF` on Linux, `Sysmon` with SwiftOnSecurity baseline on Windows, and `EndpointSecurity` on macOS) with deep **Host X-Ray Forensics**, **Process Causality Lineage Graphs**, **4-Domain Network Threat Matrices**, and **Automated Behavioral Explanations**.

```text
                                     OUTPOST WORKSTATION
                                              │
        ┌─────────────────────────────────────┼─────────────────────────────────────┐
        │                                     │                                     │
 1. LIVE HOST FORENSICS & X-RAY        2. DYNAMIC MALWARE SANDBOX            3. SOC INCIDENT OPS & TRIAGE
 (Procfs / Sockets / Lineage)         (Live Subprocess Detonations)         (Triage / Cases / SigmaHQ)
        │                                     │                                     │
  • Process Causality Trees             • Live Subprocess Execution           • SOC Findings Queue
  • 4-Domain Network Threat Matrix      • Real Terminal stdout/stderr         • Multi-Stage MITRE ATT&CK
  • Behavioral Heuristic Insights       • Real-Time Process Lineage           • 1-Click Investigation Dossiers
  • Linux Capabilities & Seccomp        • Dynamic Rule Firing & Alerts        • Campaign Correlation & Clusters
  • Process Controls (Freeze/Kill)      • Dropped Binary Tracing & I/O        • High-Risk IOC Watchlist
  • Differential Baseline Engine        • YARA & Entropy String Analysis      • Tamper-Evident Audit Trail
  • Forensic Capsule Comparison         • Isolation Drivers (bwrap/wine)      • Full-Screen Terminal TUI
```

---

## 📸 Visual Tour & Key Interfaces

### Pillar I: Live Host Forensics & X-Ray Workstation

<div align="center">

#### 🎛️ 1. Unified Host X-Ray Command Cockpit
*Full-spectrum target catalog, supervisor launch chains, 8-sensor device access matrix (microphone, camera, GPU, screen capture), open file & deleted inode forensics, live process tree, and PID lifecycle controls.*
<p align="center">
  <img src="demo/screenshots/fresh/24_host_xray_command_cockpit.png" alt="Host X-Ray Command Cockpit" width="88%">
</p>

<br>

#### 🌳 2. Interactive Process Causality Tree
*Hierarchical parent-child process graph tracking process creation, command lines, CPU/memory footprint, and package manager provenance.*
<p align="center">
  <img src="demo/screenshots/fresh/19_process_causality_tree.png" alt="Process Causality Tree" width="88%">
</p>

<br>

#### 🌐 3. Deep 4-Domain Network Threat Matrix
*Host sockets categorized into Public Listeners (`0.0.0.0`), Outbound C2 / Remote Sockets, Loopback IPC, and Multicast discovery with suspicious port tagging.*
<p align="center">
  <img src="demo/screenshots/fresh/20_network_threat_matrix.png" alt="Network Threat Matrix" width="88%">
</p>

<br>

#### 💡 4. Automated Behavioral Heuristic Insights
*Real-time reasoning cards flagging dropped binaries in temp directories, unmanaged processes, public listeners, and elevated Linux capabilities with actionable remediation steps.*
<p align="center">
  <img src="demo/screenshots/fresh/21_behavioral_insights.png" alt="Behavioral Explanations" width="88%">
</p>

<br>

#### 🔬 5. Process Deep Inspector & Security Posture
*Deep process inspection featuring 64-bit Linux Capabilities bitmask decoding, Seccomp mode, mapped `.so` shared libraries, and safe process freeze/kill controls.*
<p align="center">
  <img src="demo/screenshots/fresh/16_process_xray_drawer.png" alt="Process X-Ray Drawer" width="88%">
</p>

<br>

#### ⚡ 6. Differential Host Baseline Delta Engine
*Pre-detonation baseline snapshotting and real-time differential calculation tracking spawned processes, opened ports, and system resource deltas.*
<p align="center">
  <img src="demo/screenshots/fresh/22_differential_delta.png" alt="Differential Host Baseline Delta" width="88%">
</p>

<br>

#### 🔍 7. Forensic Capsule Differential Comparison
*Side-by-side comparison of portable `.xray.json` forensic dossiers to evaluate capability escalation and mapped library injections between environments.*
<p align="center">
  <img src="demo/screenshots/fresh/23_capsule_diff_modal.png" alt="Capsule Differential Comparison" width="88%">
</p>

</div>

---

### Pillar II: Dynamic Malware Sandbox & Adversary Simulation

<div align="center">

#### 🧪 8. Live Adversary Simulation Cockpit
*Deterministic multi-stage adversary scenarios executed live in an isolated sandbox with real-time terminal stdout/stderr streaming, live process PID tracking, and automated detection rule evaluation.*
<p align="center">
  <img src="demo/screenshots/fresh/14_live_simulation_cockpit.png" alt="Adversary Simulation Lab" width="88%">
</p>

<br>

#### 📦 9. Malware Sample Vault & Dynamic Detonation
*Secure sample repository featuring SHA256/SSDEEP hashing, Shannon entropy distributions, extracted strings, YARA signatures, and 1-click micro-sandbox detonation.*
<p align="center">
  <img src="demo/screenshots/fresh/06_samples.png" alt="Malware Sample Vault" width="88%">
</p>

</div>

---

### Pillar III: SOC Incident Response, Threat Hunting & Governance

<div align="center">

#### 🚨 10. SOC Findings Queue & Alert Triage
*Centralized alert triage queue mapped to MITRE ATT&CK techniques, featuring 1-click allowlisting, process context inspection, and instant case escalation.*
<p align="center">
  <img src="demo/screenshots/fresh/03_findings.png" alt="SOC Findings Queue" width="88%">
</p>

<br>

#### 📂 11. Incident Investigation Case Dossiers
*Full incident response lifecycle management with attached telemetry findings, evidence timelines, forensic artifact attachments, and analyst notes.*
<p align="center">
  <img src="demo/screenshots/fresh/05_investigations.png" alt="Investigations Dossier" width="88%">
</p>

<br>

#### 📡 12. Fleet Telemetry Collectors & Agent Health
*Live monitoring of distributed endpoint agents across Linux (`auditd`/`eBPF`), Windows (`Sysmon`), and macOS (`EndpointSecurity`) with heartbeat tracking and collector diagnostics.*
<p align="center">
  <img src="demo/screenshots/fresh/04_agents.png" alt="Fleet Telemetry Agents" width="88%">
</p>

<br>

#### 🎯 13. Universal Forensic Search & Active Watchlist
*Sub-millisecond global search across IOCs, hosts, hashes, and processes, paired with an active surveillance watchlist flagging suspicious connections in real time.*
<p align="center">
  <img src="demo/screenshots/fresh/08_search.png" alt="Universal Search" width="88%">
</p>

<br>

#### 📐 14. Detection Rule Studio & MITRE ATT&CK Coverage
*45 active behavioral detection rules with live tuning parameters, custom YARA rule compiler, false-positive suppressions, and a 14/14 MITRE ATT&CK tactic coverage heatmap.*
<p align="center">
  <img src="demo/screenshots/fresh/10_coverage.png" alt="MITRE ATT&CK Coverage Matrix" width="88%">
</p>

<br>

#### 🔐 15. Tamper-Evident Audit Trail & Console Themes
*Cryptographically hashed audit log recording every analyst mutation, paired with alert notification integrations (Slack, Discord, Telegram, Webhook, SMTP) and customizable theme studio.*
<p align="center">
  <img src="demo/screenshots/fresh/12_audit.png" alt="Tamper-Evident Audit Trail" width="88%">
</p>

</div>

---

## ✨ Flagship Capabilities Matrix

| Capability | Description |
|---|---|
| ⚡ **Live Subprocess Sandbox** | Executes binaries in isolated micro-sandboxes (Bubblewrap `bwrap`, Headless Wine, or Tempdir) capturing genuine OS PIDs, parent-child lineages, and live stdout/stderr streams. |
| 📊 **Differential Baseline Delta** | Captures host snapshot prior to detonation and computes differential deltas across spawned processes, listening sockets, dropped files, and memory metrics. |
| 🌳 **Process Causality Graphs** | Reconstructs deep parent-child process execution trees with package manager provenance (`dpkg`, `rpm`, `pacman`), command lines, and container attribution (`Docker`, `Podman`, `K8s`). |
| 🌐 **4-Domain Network Threat Matrix** | Classifies active connections into Public Listeners (`0.0.0.0`), Outbound C2 / External Sockets (with suspicious port heuristics), Loopback IPC, and Multicast discovery. |
| 🛡️ **Linux Posture & Capability Decoder** | Decodes 64-bit Linux capabilities (`CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_PTRACE`), Seccomp filter modes, `NoNewPrivs`, and open file descriptor inodes. |
| 🛑 **Process Lifecycle Controls** | Safe process controls (Freeze `SIGSTOP`, Resume `SIGCONT`, Terminate `SIGTERM`, Kill `SIGKILL`) with start-time identity validation to prevent PID reuse hazards. |
| 🎯 **Universal Target Resolver** | Syntax search supporting `:8000` (port), `pid:1234`, `file:/etc/passwd`, `service:systemd`, IP lookups, and keyword resolution. |
| 📑 **Portable Forensic Capsules** | 1-click export of sanitized `.xray.json` forensic capsules and side-by-side visual diffing between baseline and compromised states. |
| ⌨️ **Standalone SOC Terminal (TUI)** | 32 commands, live telemetry watchers, rich full-screen TUI console, and headless scripting workflows. |
| 🔒 **Air-Gapped by Design** | Zero external CDNs, fonts, or tracking scripts. Self-contained fonts and verified offline runtime guarantees. |

---

## 🚀 Quickstart

### 1-Command Automated Installation

OutPost includes automated dependency diagnostics that detect environment requirements and configure them seamlessly:

#### Linux & macOS
```bash
# Clone the repository
git clone https://github.com/kripy17/OutPost.git
cd OutPost

# Run automated installer (configures Python 3.10+, venv, Node.js, and dependencies)
bash scripts/install.sh

# Start the full stack (FastAPI backend on :8001 + React console on :5174)
bash scripts/dev.sh start
```

#### Windows (PowerShell)
```powershell
# Clone the repository
git clone https://github.com/kripy17/OutPost.git
cd OutPost

# Run automated installer (handles Python, Node.js, venv, and SwiftOnSecurity Sysmon)
powershell -ExecutionPolicy Bypass -File scripts\install.ps1

# Start the full stack
powershell -ExecutionPolicy Bypass -File scripts\dev.ps1 start
```

- **Web Console**: [http://localhost:5174](http://localhost:5174)
- **API Documentation (Swagger UI)**: [http://localhost:8001/docs](http://localhost:8001/docs)

### 1-Click Remote Fleet Agent Deployment

Deploy OutPost sensor collectors to remote fleet machines with a single command:

- **Linux & macOS**:
  ```bash
  curl -fsSL http://<OUTPOST_SERVER>:8001/api/agents/install.sh | sudo bash
  ```
- **Windows**:
  ```powershell
  irm http://<OUTPOST_SERVER>:8001/api/agents/install.ps1 | iex
  ```

---

## ⌨️ OutPost CLI & Interactive SOC Terminal

OutPost includes a powerful standalone executable CLI and full-screen Rich TUI console. Run commands directly using `./cli.sh` (Linux / macOS) or `.\cli.ps1` (Windows):

```bash
# Launch the interactive SOC Terminal TUI
./cli.sh console

# Stream live host telemetry & recon markers
./cli.sh watch

# View and acknowledge open SOC alerts
./cli.sh alerts

# Inspect live host processes, sockets & capabilities
./cli.sh xray
```

```text
 ╭────────────────────────────── OutPost SOC Terminal ──────────────────────────────╮
 │                                                                                  │
 │  [1] Live Watch        Stream real-time host telemetry & adversary markers       │
 │  [2] Alerts & Triage   Manage SOC queue, view findings & acknowledge alerts      │
 │  [3] Host X-Ray        Inspect live processes, sockets & Linux capabilities      │
 │  [4] Investigations    Track ongoing incident response cases & evidence          │
 │  [5] Detection Rules   View, tune & test 45 MITRE ATT&CK detection rules         │
 │  [6] Malware Vault     List samples, inspect YARA matches & detonate binaries    │
 │                                                                                  │
 ╰──────────────────────────────────────────────────────────────────────────────────╯
```

---

## 🧪 Automated Verification Suite

OutPost maintains a rigorous quality gate verifying every backend service, API endpoint, collector shipper, CLI tool, and frontend component:

```bash
# Run complete test suite (Backend, Collectors, CLI, and Frontend)
./.venv/bin/pytest backend collectors/tests cli/tests
npm --prefix frontend test -- --run
```

| Component | Test Suite | Test Count | Result |
|---|---|---|---|
| **Backend Core & APIs** | Pytest (`backend/`) | **822 tests** | **100% Passed** |
| **Telemetry Collectors** | Pytest (`collectors/tests/`) | **43 tests** | **100% Passed** |
| **CLI & SOC Terminal** | Pytest (`cli/tests/`) | **146 tests** | **100% Passed** |
| **Frontend Web Console** | Vitest (`frontend/src/test/`) | **365 tests** | **100% Passed** |
| **Total Automated Tests** | **Full Quality Gate** | **1,376 tests** | **100% Green / 0 Failures** |

---

## 🔒 Security Architecture & Air-Gap Design

OutPost is built exclusively as a **defensive security monitoring workstation and dynamic malware analysis engine**.

- **100% Air-Gapped Operation**: Operates fully isolated without external CDN dependencies, self-hosted fonts (`IBM Plex Mono`, `JetBrains Mono`), and local-only assets.
- **Fail-Closed Privacy**: External threat intelligence enrichment (VirusTotal, AbuseIPDB) requires explicit user-configured API keys and defaults to safe offline analysis when unconfigured.
- **Process Identity Verification**: Prevents PID collision attacks by verifying start-time identity hashes before applying process freeze or termination signals.
- **Decompression & Payload Hardening**: Hardened with 50 MB bounded decompression bomb protection, strict path traversal defenses, and SQL query parameterization.

---

## 📄 License

Distributed under the [MIT License](LICENSE).
