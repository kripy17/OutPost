# OutPost — Project Overview

**Type:** Semester Mini Project — BSc Cybersecurity, Year 3


## What OutPost Is

OutPost is a cross-platform behavioral security monitor. A lightweight agent watches process activity and network connections on a system, flags anomalies and malicious behavior using engineered detection heuristics, enriches findings against threat intelligence, and helps turn what it finds into actual detection content. It works two ways: as an always-on monitor for your own system, or as a focused tool for observing exactly what a suspicious file does when it runs.

It ships with two full interfaces — a web dashboard and a terminal CLI — both equal citizens talking to the same backend, so it's just as useful for visual exploration as it is for a quick terminal check.

## Core Capabilities (deliberately more than one feature)

1. **Live System Monitoring** — always-on visibility into what's running on a machine and what it's talking to over the network
2. **Anomaly & Malware Detection** — the flagship capability. Rule-based heuristics flag suspicious behavior — masquerading processes, living-off-the-land binary abuse, C2-style beaconing, persistence mechanisms — without needing ML. Full logic in `docs/11-DETECTION-LOGIC.md`
3. **Threat Intel Enrichment** — automatic IP/domain/hash reputation lookups against free sources (AbuseIPDB, VirusTotal, abuse.ch)
4. **IOC Tooling** — extraction, export, and cross-run search, so your own analysis history becomes a searchable personal threat-intel record over time
5. **Detection Content Generation** — auto-drafts Suricata/Sigma rules from what it finds, closing the loop from "here's what this did" to "here's how you'd catch it next time"

## Why This Beats a Typical Student "Malware Sandbox" Project

Most comparable student projects are single-platform, single-purpose, and produce a raw log dump instead of an analyst-facing report. OutPost normalizes telemetry across Windows and Linux into one schema, ships two full interfaces instead of one, and treats detection as real engineered logic (documented rules with a stated rationale) rather than a passive pipe from OS event to screen.

## Documentation Map

`AGENTS.md` at the repo root is the entry point and doc index for anyone (or any AI agent) working in this codebase. All technical specs live under `docs/`:

- `docs/01-ARCHITECTURE.md` — system design, full repo structure
- `docs/02-BACKEND-SPEC.md` — API, database, Pydantic models
- `docs/03-COLLECTOR-SPEC.md` — the monitoring agent (Windows + Linux)
- `docs/04-FRONTEND-SPEC.md` — webapp routes and components
- `docs/05-DEPLOYMENT-SETUP.md` — installing the agent, brief safety notes
- `docs/06-BUILD-PLAN.md` — ordered, executable task list
- `docs/07-UI-DESIGN-SYSTEM.md` — visual identity, color/type system
- `docs/08-INTEGRATIONS.md` — additional threat-intel tools beyond the MVP
- `docs/09-CLI-SPEC.md` — the `outpost` command-line tool
- `docs/10-STANDOUT-FEATURES.md` — differentiating features beyond MVP
- `docs/11-DETECTION-LOGIC.md` — the actual anomaly/malware detection heuristics

## Deliverables Checklist

- [ ] GitHub repo with a clear README (architecture diagram, setup instructions, stated scope boundaries)
- [ ] Working demo: live monitoring mode running on a real machine, plus a deliberate analysis of at least one test sample
- [ ] At least 3–4 working detection heuristics catching real test behavior, shown live
- [ ] Sample report exported (JSON and/or PDF) as an example artifact
- [ ] Short "what's next" section citing the standout-features roadmap — shows the project has real legs beyond the deadline

## Risk Register

| Risk | Mitigation |
|---|---|
| Real malware samples cause unwanted side effects on the monitored machine | Prefer synthetic test scripts (mimic the behavior, zero real risk) for development and demo; use an isolated environment only if you deliberately choose to test a real sample — see `docs/05-DEPLOYMENT-SETUP.md` |
| Linux agent runs behind schedule | Windows path is fully demoable alone if needed — Linux becomes a documented "in progress, architecture ready" fallback |
| Free-tier API rate limits hit during testing | Local caching layer (see `docs/02-BACKEND-SPEC.md`) minimizes redundant calls |
| Scope creep toward Phase 2/3 features mid-semester | Explicit non-goals stated per doc — refer back to them if tempted to add scope |

## Why This Is a Strong Differentiator

Most student "malware analysis" projects fall into one of two traps: static-analysis-only (safe but shallow), or a thin wrapper around an existing sandbox with no original engineering. OutPost is neither — it's original cross-platform telemetry normalization, real rule-based detection logic with a stated rationale for each rule, two full analyst-facing interfaces, and a direct path from "here's what happened" to "here's a detection rule for it." That combination is the improvement angle.
