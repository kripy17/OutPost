# OutPost Security Threat Model & Control Matrix

**Document Identifier**: `docs/20-THREAT-MODEL.md`  
**Classification**: Engineering & Security Review Specification  
**Status**: Authoritative

---

## 1. System Overview & Scope

OutPost is an enterprise endpoint detection, threat response, and binary detonation platform. Because OutPost routinely ingests hostile malware binaries, processes high-volume host telemetry, and commands disruptive endpoint containment actions (network isolation, process termination), it operates under an explicit threat model with defined trust boundaries and cryptographic verification controls.

---

## 2. Core Assets

| Asset ID | Asset Name | Description | Required Security Properties |
| :--- | :--- | :--- | :--- |
| **A-1** | **Endpoint Telemetry** | Streamed event batches (processes, network connections, file modifications, registry edits). | Integrity, Authenticity, Non-tampering |
| **A-2** | **Malware Samples & Vault** | Stored hostile binaries uploaded by analysts or carved from endpoints. | Safe storage (`0600`), Non-executability, Safe export |
| **A-3** | **Containment Authority** | API endpoints commanding host isolation, process freeze, and process kill. | Least privilege, Authenticity, Mandatory justification |
| **A-4** | **Credentials & Keys** | Salted password hashes, agent HMAC signing secrets, audit signing keys. | Strict confidentiality, Restrictive disk permissions |
| **A-5** | **Audit Trail & Evidence Chain** | Forensic chain of custody records and analyst decision logs. | Cryptographic immutability, Tamper-evidence, Non-repudiation |

---

## 3. Threat Actors

| Actor ID | Actor | Description & Assumptions |
| :--- | :--- | :--- |
| **TA-1** | **Hostile Sample** | Live malware executing within analysis workers; attempts host escape, network beaconing, or parser denial of service. |
| **TA-2** | **Compromised Endpoint** | Host running an enrolled agent whose OS kernel or collector process has been subverted by an adversary. |
| **TA-3** | **Network Attacker** | Untrusted external or adjacent adversary attempting SSRF, replay attacks, man-in-the-middle interception, or session hijacking. |
| **TA-4** | **Unauthorized User / Viewer** | Authenticated user possessing read-only privileges attempting unauthorized configuration edits or containment commands. |
| **TA-5** | **Malicious Database Admin** | Adversary with direct access to disk storage attempting to silently rewrite history or alter audit rows. |

---

## 4. Trust Boundaries

```
[ Compromised Endpoint / Agent ]
           │
      (TB-2) HMAC-SHA256 Signature + Nonce + Timestamp Verification
           ▼
[ OutPost Backend API ] ◄──(TB-1)── [ Network Attacker / Public Internet ]
      │         │                     (SSRF Guard, IP Blocking, CSP Headers)
      │         └───(TB-3)──► [ Web Browser / Analyst TUI ] (RBAC + HttpOnly)
      │
 (TB-4) Isolated Subprocess (cgroups, PID/Net Namespace, Drop Caps)
      ▼
[ Static Worker / Dynamic Sandbox ] (Hostile Sample TA-1)
      │
 (TB-5) Engine-level SQLite Triggers (Abort UPDATE & DELETE)
      ▼
[ SQLite Database & Audit Log ] (Tamper-Evident Hash Chain)
```

- **TB-1 (Network Ingress & Egress)**: Boundaries between external networks and OutPost. Enforces SSRF prevention, scheme restriction, private range blocking, and HTTP security headers.
- **TB-2 (Agent Telemetry Ingress)**: Boundary between endpoint sensor and ingestion pipeline. Enforces HMAC-SHA256 request signatures, millisecond timestamp expiry, and nonce deduplication.
- **TB-3 (Client Authentication & RBAC)**: Boundary between human operators and API. Enforces token validation, rate-limited login, and fine-grained role partitioning (`admin`, `responder`, `analyst`, `viewer`).
- **TB-4 (Hostile Input Execution)**: Boundary between backend process and untrusted binary inspection. Isolates workers via resource quotas, separate memory spaces, and network disconnects.
- **TB-5 (Data Layer Immutability)**: Boundary between backend code and database engine. Enforces unmodifiable audit tables via database triggers and cryptographic hash chains.

---

## 5. Threat Control & Test Verification Matrix

Every identified threat is linked to an implemented control and an automated test gate in the test suite:

| Threat ID | Threat Description | Boundary | Defensive Control | Automated Test Gate |
| :--- | :--- | :--- | :--- | :--- |
| **T-01** | Adversary attempts to tamper with or rewrite historical audit records. | TB-5 | SQLite database engine triggers (`trg_audit_log_no_update`, `trg_audit_log_no_delete`) abort any mutation. SHA-256 hash chaining links every entry to `prev_hash`. | `test_audit_chain_integrity.py::test_sqlite_trigger_prevents_updates`, `test_audit_chain_integrity.py::test_tamper_detection_pinpoints_first_break` |
| **T-02** | Operator webhooks target cloud metadata (169.254.169.254) or internal services (SSRF). | TB-1 | Strict SSRF validation in `backend/app/core/ssrf.py`: blocks loopback, link-local, RFC 1918, cloud metadata hosts/IPs, non-HTTP schemes, and credentials. | `test_ssrf_protection.py::test_validate_outbound_url_blocks_cloud_metadata`, `test_ssrf_protection.py::test_settings_api_rejects_ssrf_webhook` |
| **T-03** | Malicious binary in vault is accidentally executed by local desktop or file scanner. | TB-4 | Restrictive `0600` permissions on disk; saved with `.bin` non-executable extension; safe export packaged as password-protected ZIP (`password: infected`). | `test_samples.py::test_sample_restrictive_permissions_and_safe_zip_export` |
| **T-04** | Adversary captures and replays legitimate agent telemetry to spoof fleet status. | TB-2 | Per-agent HMAC-SHA256 signature verification over canonical request components, with anti-replay signature cache and mandatory single-use nonces. | `test_agents.py::test_agent_telemetry_signature_replay_rejected` |
| **T-05** | Read-only user or analyst commands destructive network containment or process kill. | TB-3 | Role-Based Access Control: containment authority is restricted to `responder` and `admin`. Mandatory justification reason required for destructive operations. | `test_agents.py::test_containment_role_enforcement`, `test_audit_chain_integrity.py::test_mutating_endpoints_record_audit` |
| **T-06** | Compromised agent issues fake containment orders to isolate peer endpoints. | TB-2 | Agent credentials explicitly rejected from accessing management and containment endpoints (`/agents/{id}/isolate`). | `test_agents.py::test_agent_token_forbidden_from_isolation` |
| **T-07** | Attacker executes brute-force password guessing against operator authentication. | TB-3 | Sliding-window `LoginRateLimiter` enforces lockout after 5 failed attempts; all failed and successful attempts recorded in tamper-evident audit log. | `test_ops.py::test_failed_login_lands_in_audit`, `test_auth.py::test_login_rate_limiter` |
| **T-08** | Untrusted binary crashes parser and takes down primary backend API process. | TB-4 | Static analysis runs in resource-limited isolated worker processes with CPU/memory ceilings, returning structured errors rather than crashing the API. | `test_static_worker_isolation.py::test_parser_crash_does_not_affect_api` |
| **T-09** | XSS injection via attacker-controlled process names or command lines in browser. | TB-3 | Strict Content-Security-Policy headers; zero inline script execution; React DOM text-node escaping for all telemetry strings. | `test_meta.py::test_security_headers_present` |
| **T-10** | Database admin rewrites entire SQLite file to produce a forged valid hash chain. | TB-5 | Periodic cryptographically signed checkpoints signed with separate private key; public key fingerprint and bundle exportable out-of-band. | `test_audit_chain_integrity.py::test_cryptographic_checkpoint_signing_and_verification` |

---

## 6. Verification and Maintenance

This threat model is maintained alongside the codebase. Any addition of mutating endpoints or external communication channels must:
1. Identify applicable trust boundaries and threat vectors.
2. Implement explicit input validation and authorization checks.
3. Add a corresponding test case to the automated CI test suite.
