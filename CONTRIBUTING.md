# Contributing to OutPost

Thank you for your interest in contributing to OutPost. OutPost is an offline, local-first security analysis workbench built with Python (FastAPI backend, Typer CLI, auditd/Sysmon collectors) and TypeScript (React 19 frontend).

To maintain the architectural integrity, offline guarantees, and forensic reliability of the platform, all contributions must adhere to the engineering standards outlined below.

---

## 1. Development Principles

1. **Local-First & Air-Gap Parity**: By default, OutPost generates zero outbound network traffic. Telemetry ingestion, detection rule evaluation, timeline correlation, and query hunting must operate entirely on the local machine. Third-party enrichment or webhooks must remain strictly opt-in and pass through the SSRF validation guard (`backend/app/core/ssrf.py`).
2. **Deterministic & Reproducible**: Detections, risk scores, and forensic normalizations must be deterministic. Avoid nondeterministic sorting, race conditions, or unseeded random state in test pipelines.
3. **Evidence Integrity**: Operational mutations (containment, process termination, rule modifications) must write to the tamper-evident audit trail with SHA-256 hash chaining.
4. **No Marketing Claims in Code**: Code comments, docstrings, and UI strings must accurately describe the underlying implementation. Do not claim kernel-level eBPF or EndpointSecurity hooks unless the native kernel code is present and active.

---

## 2. Environment Setup

### Prerequisites
- **Python**: 3.10 or newer (tested on 3.12 and 3.14)
- **Node.js**: 18.0 or newer (Node 20+ / 22 recommended)
- **npm**: 9.0 or newer
- **SQLite**: 3.35+ (with trigger support)

### Automated Setup
Clone the repository and run the setup script:
```bash
git clone https://github.com/kripy17/OutPost.git
cd OutPost
./setup.sh
```

This creates a virtual environment at `.venv`, installs backend and CLI packages in editable mode with development dependencies, and installs frontend npm packages.

To activate the virtual environment:
```bash
source .venv/bin/activate
```

---

## 3. Running Services Locally

Start the full stack (FastAPI backend on port 8001 and Vite frontend on port 5174):
```bash
./outpost.sh start
```

To start with pre-populated demo telemetry for interface testing:
```bash
./outpost.sh start --demo
```

To stop all background services:
```bash
./outpost.sh stop
```

To launch the full-screen terminal user interface (TUI):
```bash
./outpost.sh tui
```

---

## 4. Testing & Verification

OutPost enforces strict CI gates across backend, collectors, CLI, and frontend. Before submitting a pull request, run the test suites:

### Running Individual Test Suites
```bash
# Backend pytest suite (966 tests)
pytest backend/app/tests

# Collector pytest suite (55 tests)
pytest collectors/tests

# CLI pytest suite (208 tests)
pytest cli/tests

# Frontend Vitest suite (441 tests)
cd frontend && npm test
```

### Static Analysis & Type Checking
```bash
# Frontend TypeScript check
cd frontend && npx tsc --noEmit

# Backend Ruff lint
ruff check backend/
```

### Full Verification Sweep
Run the complete CI verification pipeline locally:
```bash
bash scripts/verify.sh
```

---

## 5. Coding Standards

- **Python**:
  - Format using standard PEP 8 conventions.
  - Use modern type annotations (`str | None`, `list[dict]`).
  - Keep route handlers focused on validation and authorization; implement business logic in `backend/app/services/` or `backend/app/models/`.
  - Prohibit importing external HTTP client libraries outside of sanctioned seams (`scripts/gate_backend_egress.py`).
- **Frontend**:
  - React 19 functional components with TypeScript strict mode.
  - TailwindCSS 4 utility classes for styling adhering to the design system in `docs/07-UI-DESIGN-SYSTEM.md`.
  - No inline styles or custom ad-hoc color hexes; use theme tokens.
- **Detection Engineering**:
  - Behavioral detection rules belong in `backend/app/services/detection.py`.
  - Every new rule must register metadata in `RULE_META` in `backend/app/services/risk.py` mapping to MITRE ATT&CK technique and tactic.
  - Every rule requires both a true-positive test case and a false-positive baseline assertion.

---

## 6. Pull Request Process

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Write unit tests covering both positive and negative cases for all code changes.
3. Verify all existing tests pass and no regression gates fail (`bash scripts/verify.sh`).
4. If updating detection rules, CLI commands, or tests, update badge metadata by running:
   ```bash
   bash scripts/refresh-badges.sh
   ```
5. Ensure your commit messages clearly describe the problem solved and the rationale for implementation decisions.
6. Open a pull request against `main`.

---

## 7. Security Disclosures

Do not report security vulnerabilities through public GitHub issues. Please review [SECURITY.md](SECURITY.md) for our responsible disclosure procedure and contact details.
