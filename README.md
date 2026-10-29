# OutPost

> [!WARNING]
> **Active Scope Reset & Rebuild in Progress**
>
> OutPost is undergoing an active scope reset and redesign from a distributed SOC / host telemetry platform into a dedicated, offline-first **Static and Dynamic Malware Analysis Workbench**.
>
> Fleet collectors, host forensics, alert queues, incident cases, and multi-node Postgres runtimes have been archived to branch [`forensics-platform`](https://github.com/kripy17/OutPost/tree/forensics-platform).
>
> Active development is currently underway on branch [`inspect_project_state`](https://github.com/kripy17/OutPost/tree/inspect_project_state). Target analyst workflows, tasks, and time budgets are documented in [`docs/analyst-tasks.md`](https://github.com/kripy17/OutPost/blob/inspect_project_state/docs/analyst-tasks.md).
>
> Core workbench focus areas:
> - **Static Analysis**: Format identification, hashes, sections, entropy, capabilities, imports/exports.
> - **Dynamic Detonation**: Isolated execution via Bubblewrap user namespaces, process tree construction, behavioral telemetry.
> - **Detection Engineering**: YARA signature scanning and behavioral heuristic rules.
> - **Analyst Workbench UI & CLI**: Dedicated sample triage console and offline command-line workflow (`scan`, `list`, `show`, `rules`, `export`).

---

## Current Architecture & Scope Bounds

- **Lab VM Isolation Boundary:** OutPost is designed to be installed by the user inside a disposable Linux lab VM. The VM is the security boundary, and snapshot rollback is the user's responsibility. OutPost does not manage hypervisors or VM clones directly.
- **Host Safety Guard (Dev-Probe Mode):** When run on a non-virtualized host workstation, the dynamic engine executes exclusively harmless, built-in probes whose SHA-256 digests are pinned in source code. Any user uploads or modified binaries are strictly refused.
- **Telemetry Ingestion & Event Model:** Traces are captured via supervisor-isolated `strace`, filtered by process ancestry, cleansed of system library noise, and persisted to SQLite (`analysis_processes`, `analysis_events`).
- **Quota Limitations:** Telemetry ingestion currently enforces a 5,000-event cap with tail truncation and marker injection. Dynamic rate collapsing (burst windowing) is deferred to future work.
- **Windows Executables:** Dynamic execution targets Linux binaries (ELF) and scripts within the Linux environment. Windows sample execution requires running the stack inside a Windows guest VM with native collectors (ETW / Sysmon / driver) and is planned for future work.

---

## Legacy Event Pipeline Retirement & Development Roadmap

> [!NOTE]
> **Legacy Event Pipeline Retirement:**
> The legacy `events` table (originating from the fleet-era Sysmon / endpoint telemetry schema) is currently maintained in read-only compatibility mode and is being progressively retired according to the following schedule:
> - **Step 2 (Completed):** Dynamic sandbox isolation & telemetry capture (`analysis_processes`, `analysis_events` established, tested against ground-truth probes, and integrated into run detail views and CLI).
> - **Step 3 (In Progress):** Offline static binary analysis (format parsers, hashes, entropy, capability identification, YARA scanning).
> - **Step 4:** Network protocol research & safe offline packet decoding.
> - **Step 5:** Behavioral detection engine migration (`detection.py`, `risk.py`) adapted to structured `analysis_events`.
> - **Step 6:** Live process monitoring (`live_monitor` streaming telemetry during detonation), run reporting, IOC extraction, and threat intelligence enrichment migrated to `analysis_events`.
> - **Step 7:** Legacy `events` table dropped via destructive migration and schema finalized.
