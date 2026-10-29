# OutPost Technical Documentation

This directory contains the technical specifications, architectural decision records (ADRs), threat models, and operational setup guides for the **OutPost Malware Analysis Workbench**.

---

## Documentation Index

### Architecture & System Design
- [01-ARCHITECTURE.md](file:///home/kripy/.gemini/antigravity/worktrees/OutPost/inspect_project_state/docs/01-ARCHITECTURE.md) — End-to-end system topology, dual-layer static & dynamic inspection architecture, and forensic data pipeline.
- [02-BACKEND-SPEC.md](file:///home/kripy/.gemini/antigravity/worktrees/OutPost/inspect_project_state/docs/02-BACKEND-SPEC.md) — FastAPI service architecture, database persistence, and analysis engine specifications.
- [04-FRONTEND-SPEC.md](file:///home/kripy/.gemini/antigravity/worktrees/OutPost/inspect_project_state/docs/04-FRONTEND-SPEC.md) — React/Vite UI architecture, workspace routing, state management, and real-time streaming interfaces.
- [09-CLI-SPEC.md](file:///home/kripy/.gemini/antigravity/worktrees/OutPost/inspect_project_state/docs/09-CLI-SPEC.md) — Command-line interface syntax, terminal rendering, and interactive TUI design.
- [adr/](file:///home/kripy/.gemini/antigravity/worktrees/OutPost/inspect_project_state/docs/adr/) — Architectural Decision Records documenting key engineering trade-offs.

### Malware Analysis & Dynamic Detonation
- [analysis-event-model.md](file:///home/kripy/.gemini/antigravity/worktrees/OutPost/inspect_project_state/docs/analysis-event-model.md) — Unified forensic event schema, process tree causality mapping, and syscall normalization.
- [lab-vm-setup.md](file:///home/kripy/.gemini/antigravity/worktrees/OutPost/inspect_project_state/docs/lab-vm-setup.md) — Safe sandbox isolation environment setup guide (`bwrap` namespaces, QEMU/KVM hypervisors, and guest network restrictions).
- [strings_categorization_specification.md](file:///home/kripy/.gemini/antigravity/worktrees/OutPost/inspect_project_state/docs/strings_categorization_specification.md) — Static string classification engine: C2 endpoints, registry keys, APIs, and cryptor flags.

### Security, Air-Gap & Compliance
- [18-AIR-GAP.md](file:///home/kripy/.gemini/antigravity/worktrees/OutPost/inspect_project_state/docs/18-AIR-GAP.md) — Air-gap governance rules, offline bundle packing, zero-telemetry egress verification, and local threat feeds.
- [20-THREAT-MODEL.md](file:///home/kripy/.gemini/antigravity/worktrees/OutPost/inspect_project_state/docs/20-THREAT-MODEL.md) — Host isolation boundaries, anti-analysis countermeasures, and malicious payload sanitization.
- [known_defects.md](file:///home/kripy/.gemini/antigravity/worktrees/OutPost/inspect_project_state/docs/known_defects.md) — Known issue tracker, edge case behaviors, and forensic analysis caveats.

### Visual Assets & Screenshots
- [screenshots/](file:///home/kripy/.gemini/antigravity/worktrees/OutPost/inspect_project_state/docs/screenshots/) — High-resolution interface captures of the 11 analyst workspaces embedded across product documentation.
