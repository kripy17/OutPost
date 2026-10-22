# OutPost Core Analyst Tasks

This document defines the 8 primary analyst workflows supported by OutPost. Every page, navigation element, API route, and CLI command exists to serve one or more of these tasks. Features, routes, or visual elements that do not directly support these tasks are removed or decoupled.

---

## Task 1: Triage a Queue of 20 Alerts by Keyboard

- **Analyst Intent**: Rapidly review, classify, and disposition incoming high-volume alerts without taking hands off the keyboard or waiting for page reloads.
- **Measurable Target**:
  - **Action Count**: $\le 20$ keyboard keystrokes to disposition 20 alerts (1 keystroke per alert disposition).
  - **Time**: $< 60$ seconds total ($\le 3$ seconds per alert).
  - **Interaction**:
    - `j` / `k` or `Down` / `Up`: Navigate queue rows.
    - `a`: Acknowledge alert (marks `acknowledged` and automatically advances cursor to next unreviewed alert).
    - `x`: Resolve / Suppress alert (opens quick resolution prompt, records disposition, advances to next).
    - `Enter`: Toggle focus between queue list and docked detail inspection pane.
- **Screen State**:
  - Dense, high-information-density table displaying: Severity badge, Alert Timestamp (UTC), Rule Name, Host ID / Hostname, Primary Entity (PID/Process or Source IP), Status, and Occurrence Count.
  - Active keyboard selection row visibly highlighted with distinct focus outline.
  - Disposition counter header showing real-time progress: `X unreviewed remaining`.
  - Zero full-page reloads; status changes apply optimistically with immediate visual confirmation.
- **Dataset Used**: 20 replayed enterprise detection alerts (sourced from public multi-stage telemetry replays).
- **Measurement Methodology**: Automated Playwright keystroke audit recording per-keystroke timestamps and UI state transitions, supplemented by human operator stopwatch verification.
- **Pass Criterion**: All 20 alerts dispositioned in $< 60$ seconds with 0 mouse clicks, unreviewed counter decreases to 0, and database state confirms all 20 rows updated.

---

## Task 2: Explain Why an Alert Fired Without Leaving It

- **Analyst Intent**: Understand root cause, triggering rule criteria, process lineage, and environmental context directly from the triage screen without losing position in the alert queue.
- **Measurable Target**:
  - **Action Count**: 0 additional actions (instant update in docked pane upon row selection) or $\le 1$ action (press `Enter` or click row).
  - **Time**: $< 3$ seconds to locate the explanation and evidence.
- **Screen State**:
  - Docked detail pane rendered alongside the queue containing:
    1. **Detection Logic & Rationale**: Plain-language description of what triggered the rule and MITRE ATT&CK technique mapping.
    2. **Triggering Fields**: Table of exact event field values that satisfied the rule (e.g., `process.command_line`, `network.destination_ip`, `file.path`), with triggering tokens highlighted.
    3. **Process Lineage Tree**: Visual parent-child hierarchy with process names, PIDs, and process start times.
    4. **Correlated Event Window**: Chronological list of neighboring telemetry events from the same host within $\pm 5$ minutes of the alert timestamp.
    5. **Host Context**: Host status, OS platform, IP address, and collector agent health.
- **Dataset Used**: Replayed alert with complete correlated host telemetry window.
- **Measurement Methodology**: Time from row selection change to full render of rule rationale, matched tokens, and process lineage in the DOM.
- **Pass Criterion**: Docked inspector updates synchronously in $< 200$ ms; all 5 context components are visible on screen without modal overlays or route navigation.

---

## Task 3: Find All Hosts That Ran a Binary in the Last 7 Days

- **Analyst Intent**: Execute a fleet-wide retrohunt for a suspicious binary executable name or cryptographic hash (SHA-256/MD5) across historical host executions.
- **Measurable Target**:
  - **Action Count**: $\le 3$ actions (Navigate to Events, enter binary name or hash in query bar with 7d time range, press `Enter`).
  - **Time**: $< 3$ seconds query latency across 100,000+ indexed events; $< 10$ seconds total workflow.
- **Screen State**:
  - Events workspace opening directly on search input and primary events table.
  - Time range selector set to `Last 7 Days` (persisted in URL query parameter `?range=7d`).
  - Search query bar accepting syntax such as `process_name:"mimikatz.exe"` or `sha256:<hash>` or plain-text token.
  - Facet sidebar showing distinct `host_id` values with execution count distribution.
  - Primary data table columns: `Timestamp`, `Host`, `Process Name`, `Executable Path`, `Command Line`, `SHA-256`, `User`.
  - Clicking any `Host` cell pivots directly to that host's timeline.
- **Dataset Used**: Minimum 100,000 events spanning 7 days across at least 5 hosts, stored in SQLite/PostgreSQL with compound indexes on `(run_id, timestamp)` and `(host_id, timestamp)`.
- **Measurement Methodology**: Automated performance test issuing API queries with SQL `EXPLAIN QUERY PLAN` verification confirming index usage, plus UI stopwatch measurement.
- **Pass Criterion**: Backend query executes in $< 500$ ms on 100k events; UI renders matching host list and facets in $< 3$ seconds; index scan verified.

---

## Task 4: Open a Case from an Alert and Attach Evidence

- **Analyst Intent**: Escalate an alert into an active investigation case, attaching triggering alerts, events, and entity artifacts with immutable cryptographic provenance.
- **Measurable Target**:
  - **Action Count**: $\le 4$ actions (Click "Open Case" on alert detail, input or confirm title/severity, confirm creation, attach related telemetry items as evidence).
  - **Time**: $< 15$ seconds to complete case creation and evidence linkage.
- **Screen State**:
  - Modal or docked drawer with pre-filled case title (derived from alert and host) and severity.
  - On submit, redirects or links directly to the created Case URL: `/cases/{case_id}`.
  - Case workspace renders:
    1. **Case Overview**: Title, Status (`Open`, `In Progress`, `Closed`), Severity, Assignee, Created Date.
    2. **Evidence Locker**: Table of attached evidence items showing Evidence Type (Alert, Event, File, Network Flow), Identifier, Cryptographic Hash (SHA-256), Added By, and Timestamp.
    3. **Investigation Timeline**: Consolidated chronological timeline of all attached events.
    4. **Analyst Notes**: Markdown-capable incident notebook with audit tracking.
- **Dataset Used**: Active alert linked to host events.
- **Measurement Methodology**: End-to-end case escalation flow test asserting case creation, evidence foreign key constraints, and hash computation.
- **Pass Criterion**: Case created with attached alert and event; SHA-256 evidence hash recorded; audit chain checkpoint created; case URL resolvable.

---

## Task 5: Isolate a Host and See Verified Enforcement

- **Analyst Intent**: Sever network connectivity to an actively compromised endpoint to stop lateral movement, and verify that the agent on the host has confirmed enforcement.
- **Measurable Target**:
  - **Action Count**: $\le 3$ actions (Select host in Hosts table, click "Isolate Host", confirm isolation modal).
  - **Time**:
    - `Isolation Requested` state: $< 1$ second (immediate UI and DB update).
    - `Isolated (Enforced)` state: within 1 agent heartbeat interval ($\le 35$ seconds with default 30s heartbeat interval, or $< 5$ seconds after agent check-in).
- **Screen State**:
  - Host Detail header displaying an unambiguous containment status pill:
    - `Active / Uncontained` (normal operating state).
    - `Isolation Requested` (command queued; displays timestamp dispatched, last agent check-in time, and a visible countdown/timer to next expected heartbeat).
    - `Isolated (Enforced)` (agent confirmed local firewall / interface cut with agent timestamp).
    - `Isolation Failed` (agent reported failure, displaying specific error reason).
  - Containment event recorded with agent cryptographic verification in the audit trail.
  - Prominent "Release Isolation" action enabled only when host is in confirmed contained state.
- **Dataset Used**: Real or simulated local collector agent connected to backend via authenticated heartbeat loop.
- **Measurement Methodology**: Integration test triggering isolation command, asserting immediate `isolation_requested` database state, simulating agent report receipt, and asserting transition to `enforced`.
- **Pass Criterion**: Console never shows `enforced` until agent submits containment report; requested state displays immediately with last check-in timestamp; countdown timer active.

---

## Task 6: Analyze a Suspicious File and Read a Verdict with Evidence

- **Analyst Intent**: Submit an unknown executable, script, or document for static analysis and receive an evidence-backed risk verdict without synthetic certainty or heuristic inflation.
- **Measurable Target**:
  - **Static Triage**: $< 5$ seconds for file ingestion, format detection, indicator extraction, and evidence verdict.
  - **Dynamic Analysis** (Supporting / Experimental): Bounded by explicit sandbox timeout ($\le 60$ seconds), with mandatory Analysis Fidelity Block disclosing environment limits.
- **Screen State**:
  - Sample workspace displaying:
    1. **Verdict Block**: Evidence-bounded verdict (`clean`, `no_indicators_found_limited`, `suspicious`, `malicious`, or `insufficient_evidence`). A `malicious` verdict strictly requires at least one authoritative threat signal (matched YARA signature, decoded C2 configuration, known threat hash).
    2. **Analysis Fidelity Disclosures**: Discloses format identification, parser coverage, worker subprocess isolation status, and explicit list of "What could not be analyzed".
    3. **Extracted Indicators**: Deduped URLs, IPs, domains, and cryptographic hashes with physical location rankings (`.text`, `.data`, `.rsrc`, overlay) and provenance tags.
    4. **Format Structure**: Deep format inspector (PE sections, ELF segments, script deobfuscation stages, Office macros, PDF objects) and hex view.
- **Dataset Used**: Corpus of clean system binaries (`/bin/ls`, `/usr/bin/python3`), synthetic threat samples, and unknown/random data blobs.
- **Measurement Methodology**: Automated API timing test measuring time from file upload POST to static report return; verdict regression test against clean binaries.
- **Pass Criterion**: Static analysis finishes in $< 5$ seconds; clean binaries return `no_indicators_found_limited` with 0 false positives; random data returns `insufficient_evidence`; fidelity disclosures populated.

---

## Task 7: Create a Rule from an Event and See Its Historical Matches

- **Analyst Intent**: Rapidly author a custom detection rule directly from an observed adversary event in the telemetry stream and test its efficacy against historical event data before activating it.
- **Measurable Target**:
  - **Action Count**: $\le 4$ actions (Click "Create Rule from Event" in event drawer, refine pre-populated matching condition, click "Run Backtest", save rule).
  - **Time**: $< 20$ seconds to author and backtest; $< 3$ seconds backtest query latency across 100,000 historical events.
- **Screen State**:
  - Rule creation drawer pre-populating rule fields from selected event (e.g. process name, command-line regex, parent process, target file path).
  - Syntax validator checking detection syntax in real-time.
  - "Backtest" button executing search against historical ingested events.
  - Match count result banner: `Backtest matched X events across Y hosts in the last 30 days`, with a preview table of matching records to confirm rule precision and false-positive risk before activation.
- **Dataset Used**: 100,000 historical event records spanning 30 days.
- **Measurement Methodology**: Automated backtest performance benchmark measuring query execution time and verifying result record preview.
- **Pass Criterion**: Backtest completes in $< 3$ seconds on 100k events; preview displays exact matching historical rows; rule saves with `testing` or `active` status.

---

## Task 8: Export a Report

- **Analyst Intent**: Generate an audit-ready, shareable incident report or static file analysis brief for stakeholders, team leads, or regulatory recordkeeping.
- **Measurable Target**:
  - **Action Count**: $\le 2$ actions (Click "Export Report" on Case or Sample page, select format PDF or JSON, confirm).
  - **Time**: $< 5$ seconds to generate and trigger browser file download.
- **Screen State**:
  - Modal or dropdown offering export formats: `PDF (Executive & Forensic Brief)` or `JSON (Structured Case Bundle)`.
  - Generated report contains: Case summary, timeline of key events, host identity and attribution, attached evidence table with SHA-256 hashes, remediation actions taken (e.g. isolation status), and cryptographic audit chain checkpoint references.
  - No marketing or decorative filler; strictly data, timestamps, hashes, and analyst notes.
- **Dataset Used**: Active case with $\ge 5$ evidence items and timeline entries.
- **Measurement Methodology**: Automated API test checking `/investigations/{id}/export/pdf` and `/investigations/{id}/export/json` response times and PDF/JSON structural validation.
- **Pass Criterion**: Export finishes in $< 5$ seconds; PDF is valid binary document; JSON parses with all evidence hashes; audit log records export event.
