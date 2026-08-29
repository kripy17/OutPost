# Tool Integrations — Logic & Wiring

Covers integrations beyond the MVP's AbuseIPDB/VirusTotal IP enrichment (already specified in `docs/02-BACKEND-SPEC.md`). Each entry states what the tool does, what it returns, and exactly where it plugs into the architecture. Grouped by priority — don't reach for Phase 2/3 tools until the MVP pipeline from `06-BUILD-PLAN.md` is fully working.

---

## MVP-tier additions (low effort, high value — worth adding alongside AbuseIPDB/VT)

### 1. VirusTotal File Hash Lookup (pre-flight check) — SHIPPED

**What it does:** Before detonating a sample, hash it (SHA256) and query VirusTotal's file-hash endpoint. If the hash is already known, you get an instant multi-vendor verdict without needing to detonate at all.

**Why it's worth adding to MVP:** it's the same VirusTotal API key you already have for IP lookups, costs one extra call, and is a genuinely strong demo moment — "this sample's hash is already flagged malicious by 45/70 vendors" shown *before* the detonation even starts.

**Wiring:**
- New endpoint: `POST /samples/check-hash` — accepts a SHA256, calls `GET https://www.virustotal.com/api/v3/files/{hash}`
- Add `known_verdict` field to the run record if a match is found, surfaced in the UI as a badge before/alongside the live detonation result
- Logic lives in `app/services/enrichment.py` alongside the existing IP lookup — same client, different endpoint

### 2. abuse.ch URLhaus (domain/URL reputation) — SHIPPED (opt-in: `OUTPOST_ABUSECH_ENABLED=1`)

**What it does:** Free, no-authentication API that tracks known malicious URLs and the malware families associated with them — complements AbuseIPDB, which is IP-only, by covering domains/URLs.

**Wiring:**
- `POST https://urlhaus-api.abuse.ch/v1/host/` with the observed domain (if a `network_connection` event includes a resolved hostname, not just an IP)
- Returns `url_status`, associated `tags` (often includes the malware family name if known)
- Add alongside the existing enrichment call in `enrichment.py`; cache identically to IP results

### 3. abuse.ch ThreatFox (IOC-to-malware-family mapping) — SHIPPED (opt-in: `OUTPOST_ABUSECH_ENABLED=1`)

**What it does:** Free IOC feed mapping IPs/domains/hashes to known malware families and campaigns. This is what upgrades a network connection from "malicious" to "malicious — associated with AsyncRAT" in your report.

**Wiring:**
- `POST https://threatfox-api.abuse.ch/api/v1/` with `{"query": "search_ioc", "search_term": "<ip_or_domain>"}`
- If matched, returns `malware` (family name), `confidence_level`, `threat_type`
- Store `malware_family` as an additional field on `NetworkConnection` (extend the Pydantic model in `docs/02-BACKEND-SPEC.md`), display in the reputation badge tooltip

---

## Phase 2 additions (after MVP is fully working)

### 4. MITRE ATT&CK Technique Tagging (rule-based, no ML needed) — SHIPPED

**What it does:** Maps observed behavior patterns to ATT&CK technique IDs using simple rule matching — no ML required for a solid first pass.

**Wiring:**
- New file: `app/services/attack_mapping.py`, containing a small local ruleset, e.g.:
  ```python
  RULES = [
      {"technique": "T1055", "name": "Process Injection", "match": lambda e: e["event_type"] == "process_create" and "svchost" in e.get("process_name", "") and e.get("ppid_name") not in EXPECTED_SVCHOST_PARENTS},
      {"technique": "T1071", "name": "Application Layer Protocol (C2)", "match": lambda e: e["event_type"] == "network_connection" and e.get("dest_port") in SUSPICIOUS_PORTS},
      {"technique": "T1547", "name": "Registry Run Keys", "match": lambda e: e["event_type"] == "registry_write" and "\\Run\\" in e.get("registry_key", "")},
  ]
  ```
- Run this against a completed run's events at the same time as enrichment; attach matched technique IDs to the run summary
- Direct payoff: this is the exact bridge to BeyondLabs' existing MITRE ATT&CK coverage matrix if you integrate later — same technique ID taxonomy, zero translation needed

### 5. YARA Rule Generation (starter rules from observed static features) — SHIPPED

**What it does:** YARA is the industry-standard pattern-matching engine for identifying malware by content signatures. `yara-python` lets you both write and run rules programmatically.

**Status:** Implemented — `app/services/static_analysis.py` extracts strings/imports/entropy pre-detonation, `app/services/rule_generator.py` auto-generates draft YARA rules from distinctive observed features, and the webapp's YARA lab (`app/services/yara.py`, `/yara` routes) lets you write, test, and apply rules against vault samples. A Sigma YAML transpiler is also included for importing external rule packs.

### 6. CAPA (capability detection for PE files) — SHIPPED

**What it does:** Mandiant/FireEye's open-source tool that identifies capabilities in a binary via static analysis — e.g. "may create a process," "may encrypt files," "may communicate over HTTP" — without executing it.

**Status:** Implemented as an optional subprocess in `app/services/static_analysis.py` (`run_capa`). When a `capa` binary is on PATH, static analysis runs `capa --json <tempfile>` (timeout `OUTPOST_CAPA_TIMEOUT`, default 120s), parses rule matches into capability entries tagged `source: "capa"` alongside the built-in heuristics (`source: "heuristic"`). When the binary is absent the result reports `available: false` honestly — no fake data.

---

## Phase 3 additions (longer-term)

### 7. Volatility3 (memory forensics) — SHIPPED

**What it does:** Analyzes a memory dump captured from the monitored system during/after a session — can recover injected code, hidden processes, and network artifacts that pure log-based telemetry misses.

**Status:** Implemented in `app/services/memory_forensics.py`. Upload a dump to the sample vault, then `POST /runs/{run_id}/memory-scan` with `{ "dump_sample_id": ... }`. Runs `windows.pslist` (+ best-effort `windows.netscan`) via the volatility3 binary (`OUTPOST_VOLATILITY_PATH`, or `vol`/`volatility3` on PATH; timeout `OUTPOST_VOLATILITY_TIMEOUT`, default 300s), parses process/connection rows, and cross-references memory-resident process names against the run's telemetry — processes visible in memory but never logged are surfaced as a `hidden_processes` finding. Missing tool → honest 501 with setup guidance.

---

## Integration Priority Summary

| Tool | Status | Effort | Payoff |
|---|---|---|---|
| VirusTotal hash lookup | Shipped | Low | High — great demo moment |
| abuse.ch URLhaus + ThreatFox | Shipped (opt-in: `OUTPOST_ABUSECH_ENABLED=1`) | Low | High — family attribution + domain listings |
| MITRE ATT&CK mapping | Shipped | Medium | High — coverage map + navigator |
| YARA generation | Shipped | Medium-High | Draft rules per run + YARA lab |
| CAPA | Shipped (optional binary) | Medium | Complementary static signal |
| Volatility3 | Shipped (optional binary) | High | Hidden-process cross-reference |
