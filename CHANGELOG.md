# Changelog

All notable changes to the OutPost platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.2] - 2026-10-20

### Security & Architecture Hardening (Comprehensive Review Defect Rework)
- **Defect 1: Static Verdict Engine**: Neutralized stripped symbol scoring on standard system binaries, sanitized URL extraction against embedded NUL bytes, restricted malicious verdicts to authoritative threat indicators or explicit suspicious heuristics, and expanded validation corpus with 75 clean OS binaries (0.0% false-positive rate verified).
- **Defect 2: Static Worker Subprocess**: Enforced `NO_PROXY="*"` and stripped operator secrets in minimal worker environment, made worker path resolution robust across working directories, and added structured error reporting when process rlimits fail.
- **Defect 3: Agent Authentication**: Hardened HMAC validation with server-side SHA-256 payload digest verification in `auth_gate`, cryptographically bound authenticated agents to `host_id`, and added persistent `agent_nonces` database table preventing replay attacks.
- **Defect 4: Audit Chain Verification**: Stored entry hashes explicitly in the database, flagged missing hashes as tampering, added tail truncation detection and checkpoint keypair signature verification, and enforced canonical compact RFC 8785 JSON serialization.
- **Defect 5: Compound Process Identity**: Propagated `process_start_time` across all non-process telemetry events, flagged PID-bearing events lacking start time, keyed process maps by compound key `host_id:boot_id:pid` preventing PID reuse collisions across reboots and fleet hosts, and added `host_id` to `alerts` table.
- **Defect 6: Linux Collection & Auditd Rules**: Extended `audit.rules` to capture successful file creation, write opens, renames, permission modifications, and connect syscalls with documented noise controls. Updated collector to correlate multi-record syscall and path events and track connection statuses.
- **Defect 7: Sandbox Limits & Network Rewording**: Enforced `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_CORE`, `RLIMIT_AS` (1GB ceiling), and `RLIMIT_NPROC` (bounded safely for unshare/clone). Reworded synthetic network capture log output to honestly state packet reconstruction.
- **Defect 8: Detection Coverage Honesty**: Declared `required_telemetry` across all 48 rules in `RULE_META`, added `/runs/{run_id}/coverage` endpoint surfacing evaluable vs not_evaluable states for missing data sources, and verified alert cap preserves first alert for distinct entities.
- **Defect 9: Packaging & Test Verification**: Added missing `pyyaml>=6.0` dependency, declared all `app.services.static` subpackages in `pyproject.toml`, and verified 1,706 passing automated tests across all suites.

---

## [0.3.1] - 2026-10-18

### Corrected README & Documentation Claims
- **Linux Collector Data Source**: Corrected documentation and UI strings in `CommandPalette.tsx` and `routes/agents.tsx` claiming "eBPF kernel probes". Documented that the Linux collector uses standard `auditd` netlink/log tailing and `/proc` process correlation.
- **macOS Collector Implementation**: Clarified that macOS telemetry collection operates via `psutil` userland process polling and connection diffing rather than direct Apple EndpointSecurity C framework event streaming.
- **Validation Corpus Methodology**: Removed inaccurate claims of "zero mock or synthetic data". Documented that the 10-sample validation corpus relies on synthetically generated test binaries (`_generate_synthetic_sample`) to benchmark static analysis detection and false-positive rates.
- **Sandbox Network Capabilities**: Corrected claims regarding sandbox network sinkholing and packet capture. Clarified that local sandbox runs enforce complete network isolation via Bubblewrap (`--unshare-net`) and that PCAP captures and C2 indicators are synthetic reconstructions parsed from stdout/stderr regex extraction.
- **Test and Rule Counts**: Updated README test count from stale 1,642 to verified 1,670 passing tests across backend, collectors, CLI, and frontend. Verified 48 active behavioral detection rules and 39 CLI command groups (127 leaf commands).

### Added
- **Repository Governance**: Added `CONTRIBUTING.md` and `CHANGELOG.md` to track architectural guidelines and verified platform changes.
- **Process Termination Verification**: Added `expected_create_time` parameter to `ProcessKillIn` and passed it through to `host_forensics.control_process()` in `routes_host_forensics.py` to ensure start-time identity validation is available across both `/action` and `/kill` endpoints.

---

## [0.3.0] - 2026-10-13

### Added
- **Analyst Workspaces & Case Management**: Multi-tab investigation workspaces with live event tagging, IOC extraction, task tracking, and forensic report export.
- **Evidence Integrity**: SHA-256 hash-chained audit logging with SQLite engine triggers enforcing update and delete immutability (`trg_audit_log_no_update`, `trg_audit_log_no_delete`).
- **SSRF Hardening**: Implemented strict IP and loopback destination validation for all outbound webhook deliveries and threat intelligence lookups (`backend/app/core/ssrf.py`).
- **Ordered Migrations**: Numbered schema migrations with automatic integrity checks and dual-dialect support for SQLite and PostgreSQL.
- **Architecture Decision Records (ADRs)**: Documented architectural choices in `docs/adr/0001` through `0005`.

---

## [0.2.0] - 2026-08-30

### Added
- **Dynamic Micro-Sandbox**: Bubblewrap container isolation for untrusted Linux binaries and scripts with unshared namespaces (PID, IPC, UTS, network) and Wine translation support.
- **MITRE ATT&CK Matrix Navigator**: Interactive Enterprise tactic coverage heatmap mapping 48 behavioral rules across all 14 tactics.
- **Multi-OS Telemetry Ingestion**: Sysmon XML channel parsing for Windows and auditd syscall normalization for Linux.
- **Terminal User Interface (TUI)**: Rich-based full-screen SOC terminal interface with keyboard-driven alert triage and event querying.

---

## [0.1.0] - 2026-08-14

### Initial Release
- Core FastAPI backend with SQLite storage.
- React/TypeScript web console with live event stream.
- In-process behavioral detection engine with initial rule set.
- Basic host telemetry collectors for Linux and Windows.
- CLI application for session management and alert listing.
