# OutPost Malware Analysis Workbench — Core Analyst Tasks

> **Architecture Transition Notice**: This document specifies the 8 core analyst workflows for the **OutPost Static and Dynamic Malware Analysis Workbench**. OutPost is dedicated to malware analysis: uploading samples, detonating them in isolated environments, observing process trees, file drops, network sockets, and system mutations, matching behavioral and YARA rules, and evaluating live background processes.

---

## Task 1: Upload Sample & Perform Static Triage

- **Analyst Intent**: Ingest an unknown binary or script (PE, ELF, shell script, document), extract metadata, hashes, sections, entropy, imports/exports, strings, and run static YARA and capability rules without executing code.
- **Measurable Target**:
  - **Action Count**: $\le 2$ actions (file drop/select + click "Analyze").
  - **Time**: $< 15$ seconds to complete static extraction and render triage summary.
- **Screen State**:
  - Identification strip displaying: SHA-256, SHA-1, MD5, ssdeep, TLSH, MIME type, file size, architecture, and packer detection flags.
  - Section entropy visualization highlighting packed/encrypted sections (entropy $\ge 7.2$).
  - Grouped imports/exports matrix identifying sensitive API families (process injection, cryptography, anti-analysis, evasion).
  - ASCII and UTF-16 strings search with IOC auto-extraction (IPs, URLs, domains, registry paths).
  - YARA matches displayed with exact rule IDs, match offsets, and matched strings.
- **Dataset Used**: Standard corpus of benign and malicious PE/ELF samples.
- **Measurement Methodology**: Time from sample upload completion to full DOM rendering of static analysis results.
- **Pass Criterion**: Complete static triage rendered within 15 seconds; zero unhandled parser crashes; all findings show provenance and confidence.

---

## Task 2: Dynamic Detonation & Process Tree Observation

- **Analyst Intent**: Execute a sample inside an isolated, resource-constrained Linux sandbox to observe process spawning, command-line arguments, parent-child relationships, syscalls, and termination codes.
- **Measurable Target**:
  - **Action Count**: 1 click ("Detonate Sample").
  - **Time**: Real-time streaming updates during execution; full process tree rendered $< 5$ seconds after execution run finishes.
- **Screen State**:
  - Interactive process lineage tree showing parent PID, child PIDs, executable paths, invocation timestamps, CLI arguments, and exit codes.
  - Syscall timeline (from strace/eBPF) with filtering by category (file, net, process, memory).
  - Resource usage meters tracking CPU, memory, process count (pids cgroup), and execution timeout status.
- **Dataset Used**: Detonation runs of Linux ELF malware and test emulation binaries.
- **Measurement Methodology**: Execution timing audit verifying sandbox launch, real-time process event delivery, and tree layout rendering.
- **Pass Criterion**: Full process hierarchy accurately constructed; every process node includes PID, start timestamp, and command line; short-lived child processes captured without omission.

---

## Task 3: File System & Mutation Verification (Dropped & Modified Files)

- **Analyst Intent**: Detect all file creations, modifications, and deletions executed by the sample during detonation, extract dropped payloads, and identify persistence mechanisms.
- **Measurable Target**:
  - **Action Count**: 1 click (switch to "Files & Persistence" tab).
  - **Time**: $< 3$ seconds to render the complete file mutation list.
- **Screen State**:
  - Table of filesystem mutations classified by action: `CREATED`, `MODIFIED`, `DELETED`.
  - For dropped/created files: file path, size, SHA-256 hash, and one-click artifact download.
  - Highlighted persistence indicators (crontab entries, systemd service units, autostart scripts, shell profile modifications).
  - Diff viewer for modified system configuration files.
- **Dataset Used**: Sandboxed detonation runs with multi-stage droppers.
- **Measurement Methodology**: DOM rendering audit comparing filesystem diffs against sandbox overlayfs/snapshot ground truth.
- **Pass Criterion**: 100% of created/modified files logged; cryptographic hashes computed for all dropped artifacts; clear provenance indicating observed filesystem diffs.

---

## Task 4: Network & DNS Traffic Inspection with Real PCAP

- **Analyst Intent**: Observe network connections, DNS lookups, HTTP requests, and raw socket traffic initiated by the malware; download a true capture file for Wireshark inspection.
- **Measurable Target**:
  - **Action Count**: 1 click (switch to "Network & Traffic" tab) + 1 click ("Download PCAP").
  - **Time**: $< 3$ seconds to display network IOC table; instant download trigger for `.pcap`.
- **Screen State**:
  - Network connections table: timestamp, protocol, source IP/port, destination IP/port, connection state, byte counters.
  - DNS query log: queried domain, record type, resolved IP responses, resolution latency.
  - HTTP transaction stream: request method, URL, headers, status code, response MIME type.
  - Prominent "Download PCAP" button serving real raw traffic captured via `tcpdump` inside the network namespace (never synthetic or reconstructed).
- **Dataset Used**: Detonation run exhibiting outbound beaconing and DNS queries in isolated netns.
- **Measurement Methodology**: Network event count validation and verification of downloaded PCAP headers (`0xa1b2c3d4` magic).
- **Pass Criterion**: All network connections and DNS queries visible with timestamps; downloaded PCAP opens cleanly in tshark/Wireshark with verified packet data.

---

## Task 5: Detection Rules Evaluation & ATT&CK Mapping

- **Analyst Intent**: Review all detection rules triggered across static and dynamic analysis stages, understand why each rule fired, and map techniques to the MITRE ATT&CK matrix.
- **Measurable Target**:
  - **Action Count**: 0 additional actions (summary card on Report Overview) or 1 click to view detailed rule match drawer.
  - **Time**: $< 2$ seconds to inspect firing criteria for any flagged behavior.
- **Screen State**:
  - Fired rules table categorized by engine: Static YARA, Behavioral Event Stream, Capability (capa).
  - Per-rule card detailing: Rule ID, severity (Critical, High, Medium, Low), MITRE ATT&CK technique IDs and names, plain-language description.
  - Triggering evidence panel: exact event tokens, offsets, or syscall parameters that satisfied the rule logic, with `source` provenance clearly tagged (`traced`, `polled`, `observed-by-hook`).
- **Dataset Used**: Analysis runs across benign utilities and multi-stage malware samples.
- **Measurement Methodology**: Audit of rule evaluation engine execution time and UI detail drawer render latency.
- **Pass Criterion**: All triggered rules listed with severity and ATT&CK mappings; zero silent false-positive suppressions; triggering events explicitly linked to the analysis event stream.

---

## Task 6: Author, Test, and Backtest Custom Detection Rules

- **Analyst Intent**: Create custom behavioral YAML rules or YARA signatures, validate syntax, and test them against historical sample runs in the library before production deployment.
- **Measurable Target**:
  - **Action Count**: $\le 3$ clicks (Open Rules Editor -> Paste/Edit -> Click "Backtest").
  - **Time**: $< 10$ seconds to run backtest against existing sample library.
- **Screen State**:
  - In-browser rule editor with YAML/YARA syntax validation, schema linting, and auto-completion.
  - Backtest results pane displaying: hit count, matching sample IDs, execution run timestamps, and matched event tokens.
  - Single-click action to save and activate the rule in the active rule set.
- **Dataset Used**: Existing sample library containing historical analysis event streams.
- **Measurement Methodology**: Time from backtest submission to completion report render across sample archive.
- **Pass Criterion**: Rule validates against schema; backtest returns accurate matches without false positives on known-clean baseline samples.

---

## Task 7: Live Process Inspection & Triage (Background Process Flagging)

- **Analyst Intent**: Snapshot live background processes on the host, evaluate static and behavioral heuristics to flag suspicious processes, and inspect process memory and open sockets.
- **Measurable Target**:
  - **Action Count**: 1 click ("Refresh Process Snapshot") or search input to filter.
  - **Time**: $< 5$ seconds to snapshot live processes, evaluate heuristics, and display flagged list.
- **Screen State**:
  - Dense live process table: PID, PPID, executable path, command line, user/UID, CPU %, Memory (RSS), open sockets.
  - Suspicious process highlights: badge indicating risk score, flagged heuristic reasons (e.g., hidden executable, unlinked binary, suspicious network listening port, masquerading process name).
  - Process detail drawer: memory map, environment variables, loaded shared libraries, and safe kill action.
- **Dataset Used**: Live host system process snapshot with test benign and anomalous background processes.
- **Measurement Methodology**: psutil capture latency and heuristic evaluation execution time measurement.
- **Pass Criterion**: Accurate host process table rendered in $< 5$ seconds; suspicious processes prominently highlighted; kill action prompts confirmation and cleanly dispatches signal.

---

## Task 8: Structured Analysis Report Export (JSON & PDF)

- **Analyst Intent**: Export a comprehensive, self-contained forensic report of an analysis run for archiving, sharing with threat intel platforms, or executive reporting.
- **Measurable Target**:
  - **Action Count**: 1 click ("Export" -> select JSON or PDF).
  - **Time**: $< 5$ seconds to generate and deliver the complete report file.
- **Screen State**:
  - Export menu offering:
    1. **Structured JSON**: Full analysis event stream, static metadata, rule matches, and IOC list conforming to the Analysis Event Model schema.
    2. **Executive & Technical PDF**: Formatted document with sample identification strip, static entropy visual, process execution timeline, network connections, and triggered rule details.
  - Strict provenance attribution on every section: labeled as `traced`, `polled`, `observed-by-hook`, or `static-extracted`.
- **Dataset Used**: Completed analysis run with rich static and dynamic telemetry.
- **Measurement Methodology**: Generation latency measurement and schema validation of exported JSON; PDF layout verification.
- **Pass Criterion**: JSON validates against Analysis Event Model schema; PDF renders all tables, hashes, and ATT&CK matrices cleanly without layout overflow.
