# Tool Integrations — Logic & Wiring

Covers integrations beyond the MVP's AbuseIPDB/VirusTotal IP enrichment (already specified in `docs/02-BACKEND-SPEC.md`). Each entry states what the tool does, what it returns, and exactly where it plugs into the architecture. Grouped by priority — don't reach for Phase 2/3 tools until the MVP pipeline from `06-BUILD-PLAN.md` is fully working.

---

## MVP-tier additions (low effort, high value — worth adding alongside AbuseIPDB/VT)

### 1. VirusTotal File Hash Lookup (pre-flight check)

**What it does:** Before detonating a sample, hash it (SHA256) and query VirusTotal's file-hash endpoint. If the hash is already known, you get an instant multi-vendor verdict without needing to detonate at all.

**Why it's worth adding to MVP:** it's the same VirusTotal API key you already have for IP lookups, costs one extra call, and is a genuinely strong demo moment — "this sample's hash is already flagged malicious by 45/70 vendors" shown *before* the detonation even starts.

**Wiring:**
- New endpoint: `POST /samples/check-hash` — accepts a SHA256, calls `GET https://www.virustotal.com/api/v3/files/{hash}`
- Add `known_verdict` field to the run record if a match is found, surfaced in the UI as a badge before/alongside the live detonation result
- Logic lives in `app/services/enrichment.py` alongside the existing IP lookup — same client, different endpoint

### 2. abuse.ch URLhaus (domain/URL reputation)

**What it does:** Free, no-authentication API that tracks known malicious URLs and the malware families associated with them — complements AbuseIPDB, which is IP-only, by covering domains/URLs.

**Wiring:**
- `POST https://urlhaus-api.abuse.ch/v1/host/` with the observed domain (if a `network_connection` event includes a resolved hostname, not just an IP)
- Returns `url_status`, associated `tags` (often includes the malware family name if known)
- Add alongside the existing enrichment call in `enrichment.py`; cache identically to IP results

### 3. abuse.ch ThreatFox (IOC-to-malware-family mapping)

**What it does:** Free IOC feed mapping IPs/domains/hashes to known malware families and campaigns. This is what upgrades a network connection from "malicious" to "malicious — associated with AsyncRAT" in your report.

**Wiring:**
- `POST https://threatfox-api.abuse.ch/api/v1/` with `{"query": "search_ioc", "search_term": "<ip_or_domain>"}`
- If matched, returns `malware` (family name), `confidence_level`, `threat_type`
- Store `malware_family` as an additional field on `NetworkConnection` (extend the Pydantic model in `docs/02-BACKEND-SPEC.md`), display in the reputation badge tooltip

---

## Phase 2 additions (after MVP is fully working)

### 4. MITRE ATT&CK Technique Tagging (rule-based, no ML needed)

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

### 5. YARA Rule Generation (starter rules from observed static features)

**What it does:** YARA is the industry-standard pattern-matching engine for identifying malware by content signatures. `yara-python` lets you both write and run rules programmatically.

**Wiring:**
- Requires a static-analysis pre-pass (extract strings, imports from the sample file) — a new `app/services/static_analysis.py` using Python's `pefile` library for Windows PE files
- Auto-generate a draft rule from distinctive strings observed (e.g. unique C2 domain strings, unusual import combinations), write to a `.yar` file per run
- This is genuinely good "future expansion" material to mention in your report even if you don't fully implement rule generation — documenting the intended integration point shows forward planning

### 6. CAPA (capability detection for PE files)

**What it does:** Mandiant/FireEye's open-source tool that identifies capabilities in a binary via static analysis — e.g. "may create a process," "may encrypt files," "may communicate over HTTP" — without executing it.

**Wiring:** Run as a subprocess (`capa <sample_path> --json`) during the static-analysis pre-pass, parse the JSON output, attach identified capabilities to the run's pre-detonation summary. Good complementary signal alongside live detonation results — shows what the sample *could* do vs. what it *actually did* during your observation window.

---

## Phase 3 additions (longer-term)

### 7. Volatility3 (memory forensics)

**What it does:** Analyzes a memory dump captured from the monitored system during/after a session — can recover injected code, hidden processes, and network artifacts that pure log-based telemetry misses.

**Wiring:** This one only makes sense if you're deliberately running the sample inside a VM you control — capture a memory dump via your hypervisor's tooling (e.g. `VBoxManage debugvm <vm> dumpvmcore` for VirtualBox, or the equivalent for whatever you're using) at the end of the observation window, run `vol3` plugins (`windows.pslist`, `windows.netscan`) against it, cross-reference results against your Sysmon-derived process tree — discrepancies (a process Volatility sees that Sysmon didn't log) are themselves an interesting finding worth surfacing. Not applicable to live monitoring on a real machine, for obvious reasons.

---

## Integration Priority Summary

| Tool | Phase | Effort | Payoff |
|---|---|---|---|
| VirusTotal hash lookup | MVP | Low | High — great demo moment |
| abuse.ch URLhaus | MVP | Low | Medium — domain coverage AbuseIPDB lacks |
| abuse.ch ThreatFox | MVP | Low | High — turns "malicious IP" into "malicious IP, AsyncRAT" |
| MITRE ATT&CK mapping | Phase 2 | Medium | High — direct bridge to BeyondLabs later |
| YARA generation | Phase 2 | Medium-High | Medium — good report material even if partial |
| CAPA | Phase 2 | Medium | Medium — good complementary static signal |
| Volatility3 | Phase 3 | High | High, but out of scope for a first semester |
