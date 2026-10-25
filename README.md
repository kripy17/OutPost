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
