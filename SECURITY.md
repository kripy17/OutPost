# OutPost Security Policy and Handling Architecture

## 1. Vulnerability Disclosure & Reporting

We take the security and integrity of OutPost and host endpoints seriously. If you identify a security vulnerability, we request that you practice responsible disclosure by contacting the maintainers privately rather than opening a public issue.

- **Contact**: `security@outpost-edr.internal` (or report via private vulnerability reporting on GitHub)
- **Response SLA**: Initial triage within 24 hours; technical assessment and remediation plan within 48 hours.
- **Scope**: All OutPost backend APIs, telemetry ingestion pipelines, sensor collectors, containment controls, audit log cryptographic verification mechanisms, and sandbox isolation workers.

Please include:
1. Detailed description of the vulnerability and attack vector.
2. Reproduction steps, proof-of-concept payload, or script.
3. Impact assessment across confidentiality, integrity, and availability.

---

## 2. Supported Versions

| Version | Status | Security Patches |
| :--- | :--- | :--- |
| **0.3.x (Current)** | Supported | Active security updates |
| **0.2.x** | Supported | Critical vulnerabilities only |
| **< 0.2.0** | End of Life | Not supported; upgrade required |

---

## 3. Safe-Handling Guidance for Malware Samples & Vault

OutPost is designed for endpoint detection and active malware detonation. Handling live malware requires defensive safeguards at every level of the pipeline:

### Storage Architecture
- **Restricted Access Permissions**: All ingested binaries are saved exclusively with `0600` (`-rw-------`) mode permissions, restricted to the OutPost backend service UID.
- **Non-Executable Extension**: Samples are saved with a `.bin` extension within the vault (`backend/data/samples/<sample_id>.bin`) to prevent accidental desktop execution or shell invocation.
- **Isolation from System Search**: The vault directory is excluded from OS desktop indexing and local thumbnail generators.

### Secure Sample Export
- **Password-Protected ZIP Container**: Live samples exported via the API (`GET /samples/{sample_id}/export-zip`) are compressed in standard PKWARE password-protected ZIP archives using the standard malware research extraction password:
  ```text
  infected
  ```
- **Malware Notice**: Every exported container includes an automated `WARNING_MALWARE_NOTICE.txt` header warning analysts of live binary risks.
- **Never Detonate on Host**: Never extract or run exported samples directly on the host or analysis workstation. All live executions must occur inside isolated virtualization guests, disposable containers, or the OutPost sandbox worker.

---

## 4. Sandbox Isolation and Execution Safeguards

Dynamic malware analysis is dangerous if unconstrained:
- **Sandbox Worker Isolation**: Static file parsing and dynamic detonations run inside resource-constrained sandboxes (cgroups memory, CPU quotas, process namespace `CLONE_NEWPID`, network namespace isolation `CLONE_NEWNET`, and read-only scratch directories).
- **Network Containment**: Untrusted binaries are executed with network namespace isolation to prevent rogue outbound command-and-control (C2) or lateral infection.
- **Timeouts & Watchdogs**: Hard execution deadlines (default 10s-30s) automatically terminate runaway processes and fork bombs.

---

## 5. Evidence Integrity & Cryptographic Audit Trail

OutPost records all operational decisions and telemetry transitions in an append-only, tamper-evident audit log:
- **Cryptographic Hash Chaining**: Every log row commits to the SHA-256 digest of the previous row (`prev_hash`) and computes a canonical SHA-256 digest over all action fields (`entry_hash`).
- **Engine-Level Immutability**: Database triggers `trg_audit_log_no_update` and `trg_audit_log_no_delete` abort any `UPDATE` or `DELETE` at the SQLite engine level.
- **Cryptographic Checkpoints**: Periodic signed checkpoints commit to the head of the log with local HMAC keys, allowing analysts to export signed verification bundles (`GET /audit/checkpoint/export`) for out-of-band immutable cold storage.
