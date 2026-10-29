# OutPost — Malware Analysis Workbench & Behavioral Security Monitor

[![Tests](https://img.shields.io/badge/tests-813%20passed-brightgreen.svg)](backend/README.md)
[![Python](https://img.shields.io/badge/python-3.12%20%7C%203.14-blue.svg)](backend/README.md)
[![Frontend](https://img.shields.io/badge/frontend-React%2018%20%7C%20Vite%20%7C%20Tailwind-61dafb.svg)](frontend/README.md)
[![Air-Gap](https://img.shields.io/badge/air--gap-zero%20cloud%20egress-success.svg)](docs/18-AIR-GAP.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**OutPost** is an offline-first, dual-layer **Static and Dynamic Malware Analysis Workbench & Behavioral Threat Forecaster** engineered for malware analysts, reverse engineers, incident responders, and detection teams.

Designed from the ground up for air-gapped lab networks and forensic environments, OutPost delivers rapid binary triage, automated Remote Access Trojan (RAT) configuration extraction, zero-execution Layer-1 behavioral threat forecasting, bubblewrap-isolated dynamic detonation, interactive parent-child process causality trees, and Sigma-powered MITRE ATT&CK® detection engineering—**without requiring external cloud telemetry or third-party API keys**.

---

![OutPost Malware Analysis Vault](docs/screenshots/01_malware_vault.png)

---

## Key Highlights & Capabilities

- **Multi-Format Static Analysis Dossier**: Deep format parsing of Portable Executable (PE), Executable and Linkable Format (ELF), Mach-O, scripts, and archives. Calculates SHA-256, ImpHash, SSDEEP, and TLSH fuzzy hashes alongside PE section entropy visualizers.
- **Embedded RAT Decoders**: Automated extraction and decryption of obfuscated configuration blocks for high-threat malware families, including **Remcos RAT**, **AsyncRAT**, **RedLine Stealer**, and **Cobalt Strike Beacons**.
- **Layer-1 Pre-Execution Behavioral Forecaster**: Predicts potential C2 endpoints, persistence footholds, and MITRE ATT&CK techniques heuristically *before* binary execution, eliminating blind detonations.
- **Isolated Dynamic Detonation (Bubblewrap)**: Safely launches Linux binaries and scripts inside unprivileged user namespaces (`bwrap`) with read-only root mounts and loopback networking, capturing every syscall via `strace`.
- **Causality Process Tree**: Reconstructs execution timelines into interactive parent-child lineage graphs with argument trees, PID mapping, and syscall timelines.
- **Detection Rules Studio & Sigma Transpiler**: Author, validate, test, and tune behavioral detection rules against live telemetry.
- **14-Tactic ATT&CK Coverage Heatmap**: Visualizes detection coverage density across the full enterprise MITRE ATT&CK framework.
- **Air-Gap First Architecture**: SQLite WAL backend, zero cloud calls, SSRF-guarded multi-channel alerting (Slack, Discord, Telegram, Webhook), and complete offline operation.

---

## 60-Second Quickstart

### Option A: One-Command Launcher (Recommended)

OutPost provides a turnkey launch script that sets up dependencies, builds the frontend, and initializes local SQLite databases:

```bash
# Clone the repository
git clone https://github.com/kripy17/OutPost.git
cd OutPost

# Start the full stack with demo malware samples and telemetry pre-seeded
./start.sh --demo
```

Once running, navigate to **`http://localhost:5174`** in your browser. The REST API and OpenAPI documentation are available at **`http://localhost:8001/docs`**.

To launch without seeding demo data:
```bash
./start.sh
```

### Option B: Docker Compose

```bash
docker-compose up -d
```

### Option C: Manual Setup

<details>
<summary>Click to view manual step-by-step setup</summary>

#### 1. Backend Setup
```bash
# Set up Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Seed demo threat data
python -m app.seed_demo

# Start FastAPI backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --reload
```

#### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev -- --port 5174
```
</details>

---

## Analyst Workspaces Tour

OutPost provides 11 dedicated, responsive workspaces designed for specialized threat workflows:

### 1. Malware Vault & Catalog (`/samples`)
Multi-format repository of ingested malware binaries, malicious documents, and suspicious scripts. Categorizes files by threat family, architecture, platform, risk score, and submission timestamp.

![Malware Vault](docs/screenshots/01_malware_vault.png)

---

### 2. Deep Static Dossier & Layer-1 Forecast (`/samples/:id`)
Comprehensive forensic inspection displaying cryptographic hashes, TLSH clustering, PE section entropy, string categorization, YARA rule hits, extracted RAT configuration parameters, and Layer-1 pre-execution behavioral predictions.

![Static Dossier & Threat Forecast](docs/screenshots/02_sample_detail.png)

---

### 3. Simulation Lab & Probe Launcher (`/monitor`)
Interactive environment to test detection rules, execute ground-truth probes, and verify sandbox containment.

![Simulation Lab](docs/screenshots/03_simulation_lab.png)

---

### 4. Dynamic Detonation Runs (`/analysis`)
Historical ledger of all containerized sandbox detonations, tracking run status, duration, process counts, syscall volume, and detected MITRE techniques.

![Detonation Runs](docs/screenshots/04_detonation_runs.png)

---

### 5. Run Dossier & Process Causality Tree (`/runs/:id`)
Deep forensic view of an individual dynamic detonation. Features an interactive parent-child process tree, network socket destinations with geo-enrichment, file system modifications, and alert timelines.

![Run Dossier & Process Tree](docs/screenshots/05_run_detail.png)

---

### 6. Real-Time Telemetry Stream (`/events`)
Live streaming endpoint telemetry viewer with facet filters (host, process, event type), timestamp scrubbing, and raw event JSON inspection.

![Telemetry Stream](docs/screenshots/06_telemetry_stream.png)

---

### 7. Detection Rules Studio (`/rules`)
Rule authoring workbench supporting Sigma and custom behavioral YAML rules. Includes real-time syntax checking, telemetry backtesting, and false-positive tuning knobs.

![Detection Rules Studio](docs/screenshots/07_rules_studio.png)

---

### 8. Enterprise ATT&CK Matrix Coverage (`/coverage`)
Interactive heatmap displaying detection coverage across all 14 Enterprise MITRE ATT&CK tactics, highlighting gaps and rule density.

![MITRE ATT&CK Matrix](docs/screenshots/08_mitre_coverage.png)

---

### 9. High-Priority Threat Watchlist (`/watchlist`)
Pin high-severity indicators of compromise (C2 IPs, domains, SHA-256 hashes) to trigger instant alerts upon subsequent sightings across the fleet or sandbox.

![Threat Watchlist](docs/screenshots/09_threat_watchlist.png)

---

### 10. Universal IOC Search (`/search`)
Sub-millisecond global search across all samples, detonation artifacts, process commands, IP addresses, domains, and alert rules.

![IOC Search](docs/screenshots/10_ioc_search.png)

---

### 11. Air-Gap Governance & Alert Settings (`/settings`)
Configure multi-channel outbound alert integrations (Slack, Discord, Telegram, generic Webhook) with strict SSRF validation, audit logging, and SQLite database retention policies.

![Air-Gap Settings](docs/screenshots/11_settings_airgap.png)

---

## OutPost Command-Line Interface (CLI)

The `outpost` CLI provides analysts with full terminal control over static analysis, configuration decoding, sandbox execution, and rule testing:

```bash
# 1. Run offline static analysis on a sample
./cli.sh scan ./malware_sample.exe

# 2. Extract and decrypt embedded RAT configurations (Remcos, AsyncRAT, RedLine, Cobalt Strike)
./cli.sh decode ./suspect_binary.exe

# 3. Detonate safely inside the local bubblewrap sandbox with strace
./cli.sh detonate ./malicious_script.sh --timeout 30

# 4. Search across all stored IOCs, samples, and runs
./cli.sh search 89.208.107.165

# 5. List and validate active detection rules
./cli.sh rules list

# 6. Launch the interactive Rich terminal UI (TUI)
./cli.sh tui
```

---

## Architecture & Security Boundary

```
                                  AIR-GAP BOUNDARY (NO EGRESS)
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │                                                                                        │
 │  ┌─────────────────────┐       ┌──────────────────────┐       ┌─────────────────────┐  │
 │  │   Analyst Browser   │ <───> │ React 18 / Vite SPA  │ <───> │  FastAPI REST API   │  │
 │  │ (Forensic Dark UI)  │       │ (Port 5174 / dist)   │       │     (Port 8001)     │  │
 │  └─────────────────────┘       └──────────────────────┘       └──────────┬──────────┘  │
 │                                                                          │             │
 │                                                  ┌───────────────────────┴──────────┐  │
 │                                                  │                                  │  │
 │                                        ┌─────────▼────────┐               ┌─────────▼────────┐
 │                                        │ Static Analysis  │               │ Dynamic Sandbox  │
 │                                        │ - PE / ELF / Zip │               │ - Bubblewrap     │
 │                                        │ - RAT Decoders   │               │ - strace parser  │
 │                                        │ - TLSH / Entropy │               │ - Process Tree   │
 │                                        │ - Layer-1 Pre-Fx │               │ - Net Intercept  │
 │                                        └─────────┬────────┘               └─────────┬────────┘
 │                                                  │                                  │  │
 │                                                  └───────────────────────┬──────────┘  │
 │                                                                          │             │
 │                                                                ┌─────────▼──────────┐  │
 │                                                                │ SQLite WAL Backend │  │
 │                                                                │  (Zero Ext. DBs)   │  │
 │                                                                └────────────────────┘  │
 └────────────────────────────────────────────────────────────────────────────────────────┘
```

### Lab VM Isolation & Safety Guarantees
- **Disposable Lab VM Boundary**: OutPost is designed to operate inside a dedicated forensic Linux virtual machine (QEMU/KVM, VMware, or VirtualBox). The VM boundary is the primary containment layer.
- **Bubblewrap (`bwrap`) Containment**: Dynamic execution drops all host capabilities, binds `/` as read-only, restricts `/proc`, creates a clean private `/tmp`, and disconnects host networking namespaces.
- **Host Safety Guard (Dev-Probe Mode)**: When executed outside a virtual machine, dynamic detonation enforces safety controls to prevent accidental host compromise.
- **Air-Gap Verification**: OutPost contains automated egress gates ([`scripts/gate_backend_egress.py`](scripts/gate_backend_egress.py)) ensuring no telemetry, analytics, or licensing pings ever leak across network boundaries.

---

## Subdirectory Documentation Index

Detailed documentation is available in each dedicated directory:

- [Backend Documentation (`backend/README.md`)](backend/README.md) — FastAPI routing, static parsers, RAT decoders, bubblewrap sandbox, and pytest guides.
- [Frontend Documentation (`frontend/README.md`)](frontend/README.md) — React 18 architecture, workspace routing, Tailwind tokens, and Vitest suite.
- [CLI Reference (`cli/README.md`)](cli/README.md) — Command-line syntax, arguments, decoding commands, and interactive TUI guide.
- [Specifications & Specs (`docs/README.md`)](docs/README.md) — Technical specifications, ADRs, threat models, and lab VM setup instructions.
- [Scripts & Quality Gates (`scripts/README.md`)](scripts/README.md) — Screenshot capture tools, CI egress gates, and verification scripts.

---

## Testing & Quality Assurance

OutPost enforces strict quality gates across backend engines and frontend components:

```bash
# Run backend pytest suite (813 tests passing)
pytest -q

# Run frontend Vitest suite (57 test suites passing)
npm test --prefix frontend

# Verify air-gap network boundary compliance
python scripts/gate_backend_egress.py
```

---

## Author & Contributors

- **Krish Patel** ([@kripy17](https://github.com/kripy17)) — Sole Author, Architect & Maintainer

---

## License

OutPost is licensed under the MIT License. See [`LICENSE`](LICENSE) for details.
