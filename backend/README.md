# OutPost Backend — Malware Analysis & Behavioral Detection Engine

The **OutPost Backend** is an offline-first, high-performance Python/FastAPI service engineered for static malware analysis, Layer-1 pre-execution behavioral threat forecasting, dynamic sandbox detonation (via Linux `bwrap`), real-time endpoint telemetry streaming, and MITRE ATT&CK® detection engineering.

Designed for air-gapped forensic environments, all analysis engines run locally with zero cloud telemetry egress.

---

## Architecture Overview

```
backend/
├── app/
│   ├── main.py                     # FastAPI application entrypoint & middleware
│   ├── seed_demo.py                # Standalone demo data seeder (samples, runs, rules)
│   ├── api/                        # REST API endpoint route controllers
│   │   ├── routes_samples.py       # Malware Vault ingest, static dossiers, Layer-1 forecast
│   │   ├── routes_runs.py          # Dynamic detonation runs, process trees, network sockets
│   │   ├── routes_sandbox.py       # Sandbox execution triggers and bwrap dispatch
│   │   ├── routes_events.py        # Real-time telemetry ingestion and streaming
│   │   ├── routes_rules.py         # Detection Rules Studio & Sigma transpiler
│   │   ├── routes_watchlist.py     # High-priority IOC watchlist tracking
│   │   ├── routes_search.py        # Global cross-artifact IOC and hash search
│   │   ├── routes_notifications.py # Multi-channel alerting (Webhook, Slack, Discord, Telegram)
│   │   └── routes_diagnostics.py   # Air-gap health, database backups, audit logs
│   ├── core/                       # Core infrastructure
│   │   ├── database.py             # SQLite WAL connection management
│   │   ├── schema.py               # Database schema definition & migration runner
│   │   └── auth.py                 # Constant-time token authentication & RBAC
│   ├── models/                     # Data models and domain queries
│   └── services/                   # Core threat analysis engines
│       ├── static/                 # Static analysis pipeline
│       │   ├── pipeline.py         # Orchestrator for archive inspection & format parsers
│       │   ├── formats/            # PE, ELF, Mach-O, shell script, and document parsers
│       │   ├── decoders/           # RAT configuration decoders (Remcos, AsyncRAT, RedLine, Cobalt Strike)
│       │   ├── fidelity.py         # TLSH fuzzy hashing, SSDEEP, entropy calculations
│       │   └── yara_scanner.py     # Multi-rule YARA matching engine
│       ├── behavioral_forecaster.py# Layer-1 pre-execution heuristic threat predictor
│       ├── dynamic_sandbox.py      # Bubblewrap containerized execution sandbox
│       ├── strace_parser.py        # Syscall trace parser (process spawn, file write, network connect)
│       ├── process_tree.py         # Parent-child causality tree reconstruction
│       ├── detection.py            # Real-time Sigma & behavioral rule evaluator
│       └── notifications.py        # SSRF-guarded alert dispatch with audit trail
└── tests/                          # 800+ automated unit and integration tests
```

---

## Core Capabilities

### 1. Static Malware Analysis & Configuration Decoders
- **Binary Format Parsing**: Deep inspection of PE headers, section entropy, rich headers, imported API hashes (ImpHash), export tables, and ELF sections without external tools.
- **Embedded RAT Decoders**: Automated extraction and decryption of configuration blocks:
  - **Remcos RAT**: RC4 key extraction, C2 domains/ports, mutexes, keylogger settings.
  - **AsyncRAT**: PBKDF2/AES key derivation, embedded pastebin URLs, backup C2s.
  - **RedLine Stealer**: XOR string decoders, target wallet patterns, Telegram bot tokens.
  - **Cobalt Strike**: Beacon configuration extraction (sleep time, jitter, C2 HTTP headers).
- **Fuzzy Hashing & Similarity**: TLSH (Trend Micro Locality Sensitive Hash) and SSDEEP for clustering malware variants across campaigns.
- **Archive Auto-Unpacking**: Deep inspection of ZIP, TAR, GZ, and composite archive payloads.

### 2. Layer-1 Pre-Execution Behavioral Threat Forecaster
Heuristically inspects static artifacts (suspicious API import combinations, high-entropy overlay payloads, decoded network endpoints) to forecast potential threat behaviors *before* dynamic execution:
- Predicted C2 endpoints and beaconing intervals.
- Projected persistence mechanisms (Registry `Run` keys, scheduled tasks, crontab).
- Automated mapping to MITRE ATT&CK techniques with analytical rationale.

### 3. Isolated Dynamic Sandbox (Bubblewrap)
- **Linux Namespaces**: Utilizes `bwrap` (Bubblewrap) to isolate guest processes with read-only root filesystems, unshared network namespaces, and restricted `/proc`.
- **Syscall Auditing**: Traces `execve`, `connect`, `openat`, and `unlinkat` via `strace`.
- **Causality Graph**: Rebuilds the parent-child process tree displaying execution sequence, process arguments, and exit statuses.

### 4. Real-Time Detection & Telemetry Engine
- **In-Memory Rule Evaluator**: Evaluates endpoint events against Sigma-based behavioral rules.
- **ATT&CK Coverage**: Automatically correlates alerts to the 14 Enterprise MITRE ATT&CK tactics.
- **Audit & Governance**: Maintains immutable audit logs of all configuration changes and alert dispatches.

---

## Getting Started

### Prerequisites
- Python 3.12 or 3.14
- Linux (recommended for `bwrap` sandbox) or macOS
- SQLite 3.35+

### Installation & Local Setup

```bash
# Navigate to the repository root
cd /path/to/OutPost

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Seed demo threat data (6 malware samples, detonation runs, and rules)
python -m app.seed_demo
```

### Starting the Backend Server

```bash
# Run FastAPI server on port 8000
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The REST API will be available at `http://127.0.0.1:8000`.  
Interactive OpenAPI documentation is hosted at `http://127.0.0.1:8000/docs`.

---

## Running Automated Tests

OutPost includes a comprehensive suite of over 800 automated tests covering all parsing pipelines, sandbox boundaries, and detection rules.

```bash
# Run the full test suite
pytest -q

# Run static analysis and decoder tests specifically
pytest backend/app/tests/test_pe_elf_static_parsers.py -v
pytest backend/app/tests/test_static_strings.py -v

# Run dynamic sandbox and process tree tests
pytest backend/app/tests/test_process_tree.py -v
pytest backend/app/tests/test_sandbox_run.py -v
```
