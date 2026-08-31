# Standout Features

Everything here is optional beyond the MVP (Phases 1–5 in `docs/06-BUILD-PLAN.md`). These are picked specifically to make the tool something you'd actually reach for during real analysis work later, not just demo-day polish. Grouped by tier — do Tier 1 first if time is short.

---

## Tier 1 — High value, low-to-moderate effort

### 1. IOC Extraction & Export

**What it does:** Auto-collects every IOC observed in a run — IPs, domains, file hashes, file paths, registry keys — into one clean, exportable list (CSV or plain text). This is the single most reusable output of any analysis session; you'll want this list to paste into other tools, tickets, or a personal notes file constantly.

**Wiring:** `GET /runs/{run_id}/iocs` — a simple aggregation query over the `events` table, deduplicated. `outpost export --format csv` and a webapp export button both call it. No new analysis logic needed — this is pure aggregation of data you already have.

### 2. Cross-Run IOC Search ("have I seen this before?")

**What it does:** Turns your own run history into a personal threat-intel database. Search any IP/domain/hash across every run you've ever done — genuinely useful the moment you're analyzing a second sample from what turns out to be the same campaign.

**Wiring:** `GET /ioc/search?value=<ioc>` — queries the `events` table (and `enrichment_cache`) across all `run_id`s, returns which runs contained it and when. `outpost search <ioc>` on the CLI side. This is the feature most worth having for actual repeated personal use — prioritize it if you only build a couple of these.

### 3. At-a-Glance Verdict Score

**What it does:** A single computed score/verdict per run (e.g. Clean / Suspicious / Malicious) instead of making the analyst read the whole report to form a judgment.

**Wiring:** Simple weighted rule, computed in `app/services/process_tree.py` or a new `app/services/verdict.py`:
```python
def compute_verdict(network_connections, process_events):
    if any(c["reputation"] == "malicious" for c in network_connections):
        return "malicious"
    if any(c["reputation"] == "suspicious" for c in network_connections) or len(process_events) > SUSPICIOUS_PROCESS_THRESHOLD:
        return "suspicious"
    return "clean"
```
Displayed as the badge in `RunSummary` (webapp run list) and the first line of `outpost show` output.

### 4. Screenshot Capture During Detonation

**What it does:** Periodic screenshots of the screen during a bounded analysis session — catches ransomware notes, fake alert popups, or any GUI element that pure telemetry (process/network events) completely misses. This only applies if you're running the sample inside a VM you're watching (there's no "screen" to capture for headless live monitoring of a real machine). Also a strong, visual "wow" moment in a demo.

**Wiring:** If using a VM, call your hypervisor's screenshot tooling on an interval (e.g. every 10s, `VBoxManage controlvm <vm> screenshotpng <path>` for VirtualBox) from the CLI's `monitoring/session.py` alongside starting the collector. Stored as run artifacts, shown in a simple gallery in both the webapp run detail page and referenced by path in `outpost show`.

---

## Tier 2 — Good value, moderate effort

### 5. Run Comparison / Diff

**What it does:** Side-by-side diff of two runs — which processes/connections are unique to each, which are shared. Useful for comparing two variants of the same malware family, or the same sample before/after a patch.

**Wiring:** `GET /runs/{id}/compare/{other_id}` — set difference over each run's process names and IPs. `outpost compare <id1> <id2>` prints a simple three-column view (only in A / only in B / shared).

### 6. Personal IOC Watchlist

**What it does:** A list of IPs/domains/hashes *you* personally flag (from your own prior research), checked automatically against every new run — independent of AbuseIPDB/VirusTotal. Useful once you've been doing this a while and start recognizing infrastructure reused across samples you've seen before.

**Wiring:** `watchlist` table (already in `docs/02-BACKEND-SPEC.md`), checked during the enrichment step alongside the external API calls. `outpost notes` / a simple webapp form to add entries.

### 7. Per-Run Analyst Notes

**What it does:** Free-text notes attached to a run — your own observations, hypotheses, or reminders for a later report.

**Wiring:** `run_notes` table (already in `docs/02-BACKEND-SPEC.md`), `POST/GET /runs/{id}/notes`, `outpost notes add <run_id> "..."`.

---

## Tier 3 — Strong differentiator, higher effort

### 8. Auto-Generated Suricata/Sigma Rule from Findings

**What it does:** Takes the observed malicious IPs/domains from a completed run and auto-generates a starter Suricata rule (network-based) or Sigma rule (log-based) that would detect this specific behavior in a real environment.

**Why it's worth the effort specifically for you:** this is the one feature that explicitly closes the loop between offensive analysis (what did the malware do) and defensive detection content (how would I catch it next time) — directly tying back to your SOC/Blue Team background and, later, to BeyondLabs. It's the single most differentiating feature on this whole list precisely because almost no student-built sandbox does it.

**Wiring:** `app/services/rule_generator.py` — template-based, not ML:
```python
def generate_suricata_rule(run_id: str, dest_ip: str, dest_port: int) -> str:
    return (
        f'alert tcp any any -> {dest_ip} {dest_port} '
        f'(msg:"Possible C2 traffic observed in sandbox run {run_id}"; '
        f'sid:{hash(run_id) % 1000000}; rev:1;)'
    )
```
Start simple (one rule per malicious IP) — a naive but *correct* rule is more valuable here than an ambitious one that doesn't compile.

### 9. Fuzzy-Hash Family Clustering (no ML required)

**What it does:** Uses `ssdeep` (context-triggered piecewise hashing) to compare a new sample against previously analyzed ones and flag likely-same-family matches, without any machine learning.

**Wiring:** Compute `ssdeep.hash(sample_bytes)` at ingestion time, store alongside the run, compare against all prior runs' fuzzy hashes via `ssdeep.compare()`. Surface matches above a similarity threshold as "possibly related to run X" in the report.

---

## Implemented Enterprise Flagship Capabilities (Shipped & Verified)

### 10. Unified Host X-Ray Forensics & Process Causality
- **Deep Procfs Introspection**: Live `/proc` inspection with Linux 64-bit Capabilities bitmask decoding (`CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_PTRACE`), Seccomp mode, `NoNewPrivs`, namespaces, and mapped `.so` libraries.
- **Process Causality Tree**: Hierarchical parent-child process tree built directly from `/proc` PPID mapping with package manager provenance (`pacman`, `dpkg`, `rpm`).
- **Safe Process Lifecycle Controls**: Real-time process controls (`SIGSTOP`, `SIGCONT`, `SIGTERM`, `SIGKILL`) with PID start-time identity validation to prevent PID reuse race conditions.

### 11. 4-Domain Network Threat Matrix
- **Socket Categorization**: Categorizes all host sockets into Public Listeners (`0.0.0.0`), Outbound C2 / External Sockets, Loopback IPC, and Multicast discovery with suspicious port heuristics (e.g. 4444, 1337, 8888).

### 12. Pre/Post-Detonation Differential Baseline Delta Engine
- **Host Baseline Snapshots**: Captures a snapshot of host processes, network listeners, and system metrics before detonation.
- **Real-Time Differential Delta**: Automatically computes added/removed processes, newly opened sockets, dropped temporary files, and resource deltas upon execution completion.

### 13. Side-by-Side Forensic Capsule Diffs
- **Portable Forensic Dossiers**: 1-click export of sanitized `.xray.json` forensic capsules.
- **Interactive Visual Diffing**: Side-by-side modal diff comparing two capsules to highlight capability divergence, new network listeners, and injected libraries.

### 14. Live Adversary Simulation Lab & Subprocess Streaming
- **Live Multi-Stage Scenarios**: Executes deterministic attack scenarios in isolated sandboxes.
- **Real-Time Telemetry & Lineage**: Streams genuine OS process IDs, command lines, and terminal stdout/stderr live to the web console via Server-Sent Events (SSE).
- **Automated Behavioral Detections**: Automatically evaluates the detection rule engine against live events, triggering alerts and updating risk scores.

### 15. Incident Investigation Dossiers & Timeline Workflows
- **Case Dossier Management**: Create and manage investigations with attached findings, evidence timelines, notes, and lifecycle status (`open`, `in_progress`, `closed`).
- **1-Click Findings Escalation**: Seamlessly escalate alerts from the findings queue, sample detonations, or simulation runs directly into case dossiers.
