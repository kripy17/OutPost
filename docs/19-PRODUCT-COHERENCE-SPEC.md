# OutPost — Product Coherence, Operational Reality & Architecture Blueprint

## 1. Core Product Vision — Source of Truth

OutPost is a self-hosted security monitoring and investigation platform for endpoints and their activity, with an integrated event manager, detection engine, investigation/case workflow, and dedicated malware-analysis capability.

```text
                 ┌──────────────────────────────┐
                 │        MONITORED HOSTS        │
                 │ Linux auditd / eBPF           │
                 │ Windows Sysmon                │
                 └──────────────┬───────────────┘
                                │
                                ▼
                     ┌──────────────────┐
                     │    INGESTION     │
                     │ normalize/store  │
                     └────────┬─────────┘
                              │
                 ┌────────────┴────────────┐
                 ▼                         ▼
        ┌─────────────────┐       ┌─────────────────┐
        │  EVENT MANAGER  │       │   DETECTION     │
        │ all telemetry   │       │ 37+ rules       │
        └────────┬────────┘       └────────┬────────┘
                 │                         │
                 │                         ▼
                 │                  ┌──────────────┐
                 │                  │   FINDINGS   │
                 │                  └──────┬───────┘
                 │                         │
                 └────────────┬────────────┘
                              ▼
                     ┌──────────────────┐
                     │  INVESTIGATION   │
                     │ case / evidence  │
                     └────────┬─────────┘
                              │
                ┌─────────────┼─────────────┐
                ▼             ▼             ▼
              Host           IOC          Process
              context        intel        context
                │             │             │
                └─────────────┴─────────────┘


        SEPARATE PRODUCT BOUNDARIES

        ┌─────────────────────┐
        │   MALWARE ANALYSIS  │
        │ Sample → Static →   │
        │ Dynamic → Findings  │
        └─────────────────────┘

        ┌─────────────────────┐
        │   SIMULATION LAB    │
        │ Synthetic attacks   │
        │ Rule testing only   │
        └─────────────────────┘
```

---

## 2. Core Operational Workflows

### Workflow A: Live Security Monitoring (Primary Spine)
```text
MONITORED HOST
    ↓
COLLECTOR (Linux auditd/eBPF, Windows Sysmon)
    ↓
INGESTION (POST /ingest/events, POST /ingest/batch)
    ↓
PERSISTED TELEMETRY (events table, SQLite/Postgres)
    ↓
EVENT MANAGER (/events)
    ↓
DETECTION ENGINE (37+ behavioral rules)
    ↓
FINDINGS (/findings)
    ↓
INVESTIGATION / CASE (/investigations)
    ↓
PROCESS / NETWORK / IOC / HOST PIVOTS
```

### Workflow B: Malware Analysis (Isolated Lab)
```text
MALWARE SAMPLE
    ↓
SAMPLE VAULT (/samples)
    ↓
STATIC ANALYSIS (PE/ELF/Mach-O, Entropy, Hashes, Strings, YARA)
    ↓
DYNAMIC ANALYSIS (External VM Sandbox if configured / Local Subprocess Trace)
    ↓
BEHAVIORAL OBSERVATIONS
    ↓
FINDINGS / IOCS / INVESTIGATION
```

### Workflow C: Simulation Lab (Testing & Detection Engineering)
```text
SIMULATION PLAYBOOK (/monitor or /simulation)
    ↓
SYNTHETIC TELEMETRY (source=simulation, quarantined)
    ↓
DETECTION ENGINE
    ↓
FINDINGS (labeled simulation)
    ↓
RULE VALIDATION / TUNING
```

> **Invariant**: Simulation telemetry must NEVER masquerade as live endpoint monitoring or pollute default operational feeds.

---

## 3. What to Remove / Consolidate

1. **Remove `/history` as a primary product page**:
   - Continuous endpoint monitoring is an ongoing stream (`Host → Events → Findings → Case`), not a collection of "runs".
   - Keep "runs" internally for Malware Analysis Jobs and Simulation Playbooks.
2. **Remove the decorative "campaign spotlight" from Overview**:
   - Overview must answer: *"What is happening on my monitored infrastructure right now?"*
   - Campaigns are secondary correlation analytics accessible from Findings and Investigations.
3. **Remove Threat Footprint from primary top-level navigation**:
   - Footprint is an IOC/investigation enrichment drawer, not a top-level daily monitoring surface.
4. **Remove decorative / meaningless analytics**:
   - No fake risk gauges, random trend charts, or arbitrary posture scores.
   - Every metric must answer an operational question (e.g. Events/sec, Open findings by severity, Host telemetry health).
5. **Eliminate Dynamic Sandbox Ambiguity**:
   - A normal local subprocess execution is **not** a secure malware sandbox.
   - Clearly label local execution as a **Local Subprocess Trace** and require configured API keys for Any.Run / Hatching Triage / Joe Sandbox VM detonation (returning HTTP 501 if unconfigured).
6. **Remove Sample Upload and Host Monitoring from Simulation Lab**:
   - Simulation Lab contains **only simulations & attack playbooks**.
   - Sample uploads live exclusively in **Malware Analysis → Sample Vault**.
   - Host monitoring lives exclusively in **Overview**, **Event Manager**, and **Fleet / Host Workspace**.
7. **Unify Search & IOC System**:
   - Consolidate `/ioc/search`, `/iocs`, and `/search` into one authoritative **Global Search (`/search`)** supporting text and qualifiers (`type:`, `host:`, `rule:`, `severity:`, `case:`), linking directly to entity workspaces.

---

## 4. Feature Matrix & Product Boundaries

| Domain | Surface / Route | Purpose & Scope | Data Source |
|---|---|---|---|
| **Live Monitoring** | **Overview (`/`)** | Operational SOC Cockpit: telemetry health, open findings, active cases, live event stream, host fleet. | Persisted `real` DB records |
| **Live Monitoring** | **Event Manager (`/events`)** | Authoritative SIEM workspace: filterable, searchable, real-time event log with process, network, and case pivots. | Persisted `events` table (SSE) |
| **Live Monitoring** | **Findings (`/findings`)** | Triage queue of detections generated by the engine, linking to host, process, IOC, and case actions. | Persisted `alerts` table |
| **Live Monitoring** | **Fleet / Hosts (`/agents`, `/hosts/:id`)** | Endpoint inventory, real telemetry health (auditd, Sysmon, eBPF), capability matrix, host timeline, and containment. | Persisted `agents` & `events` |
| **Live Monitoring** | **Investigations (`/investigations`)** | Case management & evidence container binding findings, events, hosts, processes, IOCs, and notes. | Persisted `investigations` |
| **Live Monitoring** | **Search (`/search`)** | Unified search across events, hosts, findings, IOCs, investigations, samples, and runs. | Grouped global search model |
| **Live Monitoring** | **Watchlist (`/watchlist`)** | High-priority indicator monitoring and matching. | Persisted IOC watchlist |
| **Malware Analysis** | **Sample Vault (`/samples`)** | Binary upload, static analysis (PE/ELF/Mach-O, Shannon entropy, fuzzy hashes, YARA, strings). | Stored binary files (`.bin`) |
| **Malware Analysis** | **Analysis Jobs (`/analysis`)** | Discrete execution runs with honest sandbox boundaries (cloud VM if keyed, or local trace). | `analysis_job` runs |
| **Lab** | **Simulation Lab (`/monitor`)** | Adversary attack scenario playbooks for detection rule testing and training (quarantined). | `source = simulation` |
| **Detection** | **Rules (`/rules`)** | Behavioral detection rule catalog, tuning, suppressions, and Sigma/Suricata transpilation. | Active detection engine |
| **Detection** | **ATT&CK Coverage (`/coverage`)** | MITRE ATT&CK matrix coverage derived strictly from active detection rules. | Active rule metadata |
| **Detection** | **YARA Studio** | YARA rule testing and pattern matching. | YARA engine |
| **System** | **Audit Log (`/audit`)** | Immutable trail of analyst actions (triage, suppressions, case edits, key rotations). | `audit_log` table |
| **System** | **Settings (`/settings`)** | API keys (AbuseIPDB, VirusTotal, Sandboxes), retention policies, auth settings. | `settings` table |

---

## 5. Architectural Invariants

1. **Empty ≠ Clean**:
   - A fresh install or empty database displays: `"Telemetry status: No data received — connect a collector to begin monitoring"`.
   - Never assert `"0 Threats / Risk Clean"` when telemetry has not been collected.
2. **Telemetry Capability Honesty**:
   - If a platform does not collect a telemetry type (e.g. Linux registry writes), display: `"Registry activity: Not supported on Linux"`, never `"Registry writes: 0"`.
3. **Strict Data Provenance**:
   - Every event and run carries explicit provenance (`live`, `simulation`, `sandbox`, `unknown`).
   - Operational endpoints (`/events`, `/findings`, `/overview`, `/hosts`) default to `include_synthetic=false` at the backend layer.
4. **Real-time Pipeline**:
   - `Collector → POST /ingest/events → DB commit → SSE broadcast → React Query invalidation → UI update`.
   - Zero synthetic polling loops or fake animation timers on operational pages.
