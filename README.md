<div align="center">

# 🛡️ OutPost

### Advanced Cross-Platform Behavioral Security Workstation & Dynamic Malware Analysis Sandbox

*A self-hosted, explainable SOC monitoring platform, host forensics engine, and dynamic malware sandbox with dual first-class interfaces: a reactive web deck and an interactive terminal console.*

`FastAPI` · `React 19` · `TypeScript` · `Vite 6` · `SQLite / PostgreSQL` · `Typer` · `Rich TUI` · `Playwright`

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-backend-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Tests](https://img.shields.io/badge/tests-1391%20passing-brightgreen?style=flat-square)](https://github.com/kripy17/OutPost/actions)
[![Rules](https://img.shields.io/badge/rules-40%20active-blue?style=flat-square)](docs/11-DETECTION-LOGIC.md)
[![Commands](https://img.shields.io/badge/cli-32%20commands-orange?style=flat-square)](docs/09-CLI-SPEC.md)
[![Tactics](https://img.shields.io/badge/tactics-14%2F14%20covered-teal?style=flat-square)](docs/11-DETECTION-LOGIC.md)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

<p align="center">
  <img src="demo/screenshots/fresh/01_overview.png" alt="OutPost Command Deck" width="90%">
  <br>
  <em>The Command Deck — real-time risk trends, live telemetry, posture analytics, and SOC findings queue.</em>
</p>

</div>

---

## 📖 What is OutPost?

**OutPost** is an authoritative, open-source security monitoring workstation and dynamic malware analysis engine designed for security operations centers (SOC) and malware reverse engineers. 

OutPost pairs real-time kernel telemetry (`auditd`/`eBPF` on Linux, `Sysmon` with SwiftOnSecurity baseline on Windows, `EndpointSecurity` on macOS) with deep **Host X-Ray Forensics**, **Process Causality Lineage Graphs**, **Network Threat Matrices**, and **Automated Behavioral Heuristics** inspired by modern host inspection toolkits.

```text
                                     OUTPOST WORKSTATION
                                              │
        ┌─────────────────────────────────────┼─────────────────────────────────────┐
        │                                     │                                     │
 1. LIVE HOST X-RAY                   2. DYNAMIC MALWARE LAB                3. SOC INCIDENT OPS
 (Procfs / Sockets / Lineage)         (Live Subprocess Sandbox)             (Triage / Cases / Rules)
        │                                     │                                     │
  • Process Causality Trees             • Live Subprocess Detonations         • SOC Findings Queue
  • 4-Domain Network Matrix             • Real Terminal stdout/stderr         • Multi-Stage MITRE ATT&CK
  • Behavioral Explanations             • Dynamic Rule Firing                 • 1-Click Pivot Modals
  • Linux Capabilities & Seccomp        • Dropped Binary Tracing              • Campaign Clustering
  • Process Controls (Freeze/Kill)      • YARA & Entropy Analysis             • Forensic Export (.xray.json)
```

---

## 📸 Visual Tour & Key Interfaces

<div align="center">

### 🎛️ 1. Unified Host X-Ray Command Cockpit
*Full-spectrum target catalog, supervisor launch chain, 8-sensor device access matrix (microphone, camera, GPU, screen capture), open file & deleted inode forensics, live process tree, and PID lifecycle controls.*
<img src="demo/screenshots/fresh/24_host_xray_command_cockpit.png" alt="Host X-Ray Command Cockpit" width="85%">

<br><br>

### 🌳 2. Interactive Process Causality Tree
*Hierarchical parent-child process graph tracking process creation, command lines, CPU/memory footprint, and package status.*
<img src="demo/screenshots/fresh/19_process_causality_tree.png" alt="Process Causality Tree" width="85%">

<br><br>

### 🌐 3. Deep Network Threat Matrix
*Sockets categorized into Public Listeners (0.0.0.0), Outbound C2/Remote Sockets, Loopback IPC, and Multicast discovery.*
<img src="demo/screenshots/fresh/20_network_threat_matrix.png" alt="Network Threat Matrix" width="85%">

<br><br>

### 💡 4. Automated Behavioral Heuristic Explanations
*Real-time reasoning cards flagging dropped binaries in temp paths, public listeners, and elevated capabilities with next-step actions.*
<img src="demo/screenshots/fresh/21_behavioral_insights.png" alt="Behavioral Explanations" width="85%">

<br><br>

### ⚡ 5. Differential Host Baseline Delta Engine
*Pre-detonation baseline snapshotting and real-time differential calculation tracking spawned processes, opened ports, and resource spikes.*
<img src="demo/screenshots/fresh/22_differential_delta.png" alt="Differential Host Baseline Delta" width="85%">

<br><br>

### 🔍 6. Forensic Capsule Differential Comparison
*Side-by-side comparison of `.xray.json` forensic dossiers to evaluate capability escalation and mapped library injections.*
<img src="demo/screenshots/fresh/23_capsule_diff_modal.png" alt="Capsule Differential Comparison" width="85%">

<br><br>

### 🔬 7. Process X-Ray Inspector & Security Posture
*Deep process inspection featuring Linux Capabilities bitmask decoding, Seccomp mode, shared `.so` libraries, and process freeze/kill controls.*
<img src="demo/screenshots/fresh/16_process_xray_drawer.png" alt="Process X-Ray Drawer" width="85%">

<br><br>

### 🧪 7. Dynamic Sandbox Simulation Cockpit
*Subprocess execution cockpit streaming real-time terminal stdout/stderr and live detection rules.*
<img src="demo/screenshots/fresh/14_live_simulation_cockpit.png" alt="Simulation Lab" width="85%">

<br><br>

### 🚨 8. SOC Findings Queue & Incident Cases
*Triaged alerts with MITRE ATT&CK mapping, quick pivots, allowlists, and deep investigation case workflows.*
<img src="demo/screenshots/fresh/03_findings.png" alt="Findings Queue" width="85%">

</div>

---

## ✨ Flagship Capabilities

| Feature | Description |
|---|---|
| ⚡ **Differential Delta Engine** | Capture host baseline before dynamic malware detonation; automatically calculates added/removed processes, new listeners, and resource deltas. |
| 🔍 **Capsule Diff Comparison** | 1-click side-by-side comparison of `.xray.json` forensic dossiers highlighting capability divergence and mapped library deltas. |
| 🌳 **Process Causality Tree** | Live hierarchical process tree built directly from `/proc` PPID causality mapping with expand/collapse, search filtering, and 1-click X-Ray inspection. |
| 🌐 **4-Domain Network Matrix** | Categorizes all host sockets into Public Listeners (`0.0.0.0`), Outbound Connections (public vs LAN with suspicious port detection: 4444, 1337, etc.), Loopback IPC, and Multicast. |
| 💡 **Behavioral Heuristics Engine** | Heuristic reasoning cards (Critical / Attention / Info) flagging unmanaged binary drops (`/tmp`, `/dev/shm`), external listeners, and elevated capabilities with actionable next steps. |
| 🛡️ **Runtime Security Posture** | 64-bit Linux Capabilities decoder (`CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_PTRACE`), Seccomp filter status, `NoNewPrivs`, and container/cgroup attribution (`Docker`, `Podman`, `K8s`, `systemd`). |
| 🛑 **Process Lifecycle Controls** | Freeze (`SIGSTOP`), Resume (`SIGCONT`), Terminate (`SIGTERM`), and Kill (`SIGKILL`) active processes with PID start-time validation to prevent PID reuse hazards. |
| 📦 **Package Provenance** | Resolves binaries against system package managers (`pacman`, `dpkg`, `rpm`) and highlights unmanaged binary drops. |
| 📑 **Portable Forensic Capsule** | 1-click export of comprehensive `.xray.json` forensic dossiers containing sanitized process metadata, security posture, libraries, and open sockets. |
| 🎯 **Universal Target Resolver** | Syntax search supporting `:8000` (port), `pid:123`, `file:/path`, `service:systemd`, and keyword resolution. |
| ⌨️ **Rich SOC Terminal (TUI)** | 31 commands, interactive terminal console, and automated CLI workflows. |
| 🔒 **Air-Gapped by Design** | Zero external CDNs, fonts, or analytics. Self-contained fonts and verified offline runtime guarantees. |

---

## 🚀 Quickstart

### 1-Command Automated Installation

OutPost features automated dependency diagnostics that detect missing tools and install them for you seamlessly:

#### Linux & macOS
```bash
# Clone the repository
git clone https://github.com/kripy17/OutPost.git
cd OutPost

# Run automated installer (handles Python, Node.js, venv, and optional auditd setup)
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
- **API Documentation**: [http://localhost:8001/docs](http://localhost:8001/docs)

### 1-Click Remote Agent Deployment

Deploy OutPost sensor collectors to remote fleet machines with a single command:

- **Linux / macOS**:
  ```bash
  curl -fsSL http://<OUTPOST_SERVER>:8001/api/agents/install.sh | sudo bash
  ```
- **Windows**:
  ```powershell
  irm http://<OUTPOST_SERVER>:8001/api/agents/install.ps1 | iex
  ```

---

## ⌨️ OutPost CLI & Terminal Console

OutPost provides a standalone executable CLI and interactive full-screen TUI console. Run commands directly using `./cli.sh` (Linux / macOS) or `.\cli.ps1` (Windows):

```bash
# Launch the interactive SOC Terminal TUI
./cli.sh console

# Run CLI commands directly
./cli.sh --help
./cli.sh watch
./cli.sh alerts
```

```text
 ╭───────────────────────── OutPost SOC Terminal ─────────────────────────╮
 │                                                                         │
 │  [1] Live Watch      Stream live host telemetry & recon markers         │
 │  [2] Alerts & Triage Manage SOC queue and acknowledge alerts            │
 │  [3] Host X-Ray      Inspect live processes, sockets & capabilities     │
 │  [4] Investigations  Track ongoing incident response cases             │
 │  [5] Detection Rules View & tune 40 MITRE ATT&CK detection rules       │
 │                                                                         │
 ╰─────────────────────────────────────────────────────────────────────────╯
```

---

## 🧪 Automated Verification Suite

OutPost maintains a rigorous quality gate verifying every backend service, API endpoint, collector shipper, and frontend component:

```bash
# Run backend tests
./.venv/bin/pytest backend

# Run collector tests
./.venv/bin/pytest collectors/tests

# Run CLI tests
./.venv/bin/pytest cli/tests

# Run frontend tests
npm --prefix frontend test -- --run
```

| Test Suite | Count | Result |
|---|---|---|
| Backend Pytest | **812 tests** | **100% Passed** |
| Collector Pytest | **40 tests** | **100% Passed** |
| CLI Pytest | **146 tests** | **100% Passed** |
| Frontend Vitest | **365 tests** | **100% Passed** |
| Playwright E2E | **21 route tests** | **100% Passed** |
| Telemetry Authenticity | **7 live tests** | **100% Passed** |
| **Total Test Count** | **1,391 tests** | **100% Green / 0 Failures** |

---

## 🔒 Security & Air-Gap Architecture

OutPost is strictly a **defensive security monitoring and dynamic analysis workstation**. It contains no weaponized exploits or destructive payloads.

- **Air-Gap Verification**: Operates completely offline with zero external CDN dependencies, self-hosted fonts, and verified loopback communication.
- **Fail-Closed Privacy**: Threat intelligence enrichment requires user-provided API keys in `.env` and defaults to safe offline analysis when unconfigured.
- **Process Identity Safety**: Prevents PID collision attacks by verifying start-time identity hashes before applying process freeze or termination controls.

---

## 📄 License

Distributed under the [MIT License](LICENSE).
