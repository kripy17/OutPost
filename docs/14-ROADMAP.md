# OutPost Roadmap — next features & improvements

> Companion to the build plan (docs/06). Everything here is planned against the
> actual codebase (schema, detection rules, webapp routes, CLI) — nothing is
> aspirational. Items are Tier-1 first because they fit the current
> architecture with zero new infrastructure; later tiers grow the platform
> into a real EDR.

## Tier 1 — fit the existing architecture (no new infra)

### 1.1 Global Events page (Windows Event Viewer–style feed) — DONE
- `GET /events` — filterable, paginated feed across *all* runs: by event type,
  platform, run severity (has-alert), and free-text (process / path / IP /
  command line).
- Webapp `/events` route with filter bar, results table, and an event detail
  drawer linking back to the source run.
- **Acceptance**: filters compose; pagination offset works; unknown filter
  values → 422; each row links to its run; detail drawer shows every field.

### 1.2 OS-aware detection rules — DONE
- Rules select their tables by `event.platform` instead of assuming Windows:
  - Persistence: registry Run keys (Windows) **and** shell/autostart files
    (`~/.bashrc`, `/etc/cron*`, systemd units, `/etc/rc.local` — Linux).
  - LOLBins: `curl | sh`, `wget | sh`, `python3 -c`, `bash -i`, `/dev/tcp`,
    `base64 -d` (Linux) alongside the existing Windows list.
  - Masquerading: per-OS legitimate-path tables (`/usr/bin/bash` vs
    `C:\Windows\System32\svchost.exe`).
- Monitor page lets you choose the platform for the synthetic detonation so
  the OS-aware rules are demoable live without a collector.
- **Acceptance**: a Linux scenario (bash → curl|sh → beacon → burst → `~/.bashrc`
  write) fires lolbin + autostart-persistence + beacon + rename-burst; the
  Windows scenario still fires its original rules; no regression in rule 1–7.

### 1.3 Run risk score + MITRE ATT&CK tags — DONE
- `services/risk.py` maps every rule to an ATT&CK technique/tactic and a
  weight; `RunSummary.risk_score` = sum of distinct fired rules' weights
  (capped 0–100). `GET /rules/meta` exposes the map.
- Webapp: risk gauge on the run detail header, risk badge on history cards,
  ATT&CK technique chip on every alert.
- **Acceptance**: score scales with distinct rules; cap at 100; chips match the
  `GET /rules/meta` map; CLI `show` unaffected (extra field ignored).

### 1.4 Sample binary auto-detection (OS sniffing) — DONE (extended)
- Upload a sample to a new `POST /samples`; sniff magic bytes (PE `MZ` →
  windows, ELF `\x7fELF` → linux, Mach-O `\xfe\xed\xfa` → macos), store the
  hash + type, and pre-fill the detonation platform.
- **Acceptance**: each magic family classifies correctly; unknown bytes → 422
  with a readable message; hash (SHA-256) stored and searchable via IOC search.
- **Extended beyond spec**: script shebangs (`#!/bin/sh`, `#!/usr/bin/python`),
  `.lnk` shortcuts, and ZIP containers are sniffed too; a Sample Vault
  (`/samples` webapp page + `outpost samples` CLI) lists every uploaded binary
  with family, YARA hits, reputation, and detonation counts.

> Status as of 2026-08-07: all items below are shipped and verified
> (`verify.sh` — backend 129, collectors 12, CLI 8, frontend build clean).
> 2.1 collectors are functionally tested but not load-tested at the
> roadmap's 10k-events/hour acceptance; no auth/multi-analyst model exists.

## Tier 2 — analyst power tools

### 2.1 Live collectors (real EDR ingestion)
- Per-OS agents that post to the existing `POST /ingest/batch`: Sysmon/ETW on
  Windows, auditd/fanotify on Linux. The endpoint, detection, and enrichment
  already exist — this is the layer that makes OutPost a live monitor.
- **Acceptance**: a collector posts 10k events/hour without backpressure; a
  live session shows alerts within one poll interval.

### 2.2 Hash + file reputation & YARA scanning — DONE
- Extend the enrichment cache from IPs to SHA-256 hashes; a `yara` service
  scans uploaded samples against a bundled rule set.
- **Acceptance**: hash reputation shows on the detail page; YARA match surfaces
  as a new alert rule.

### 2.3 Rule editor (tune thresholds, add patterns) — DONE (thresholds)
- Webapp CRUD over the rule tables in `detection.py` (persisted to DB):
  LOLBin patterns, persistence paths, beacon window/variance, burst thresholds.
- **Acceptance**: editing a threshold changes behavior without restarting the
  backend; invalid patterns rejected with feedback.

### 2.4 Kill-chain correlation — DONE
- Sequence alerts across a run (`dropper → lolbin → beacon → persistence`)
  and render a chain diagram on the detail page; feed campaigns clustering
  with correlated chains, not just shared IPs.
- **Acceptance**: a full-chain run renders a connected chain; partial chains
  show only the observed links.

## Tier 3 — platform bets

### 3.1 Alert notifications — DONE
- Webhook/email/push on new malicious alerts (CLI already depends on `plyer`).
- **Acceptance**: a rule firing in a live session triggers the configured
  channel within 5 s.

### 3.2 macOS support — DONE
- Requires a `runs.platform` migration (the current DB CHECK constraint only
  allows `windows`/`linux`): rebuild the runs table, widen the literal, add
  macOS persistence (LaunchAgents/launchd) + LOLBins (`osascript`) + profiles.
- **Acceptance**: macOS scenario fires its rules; migration runs on existing
  DBs without data loss. A `seed_macos.py` scenario now demonstrates it.

### 3.3 STIX/MISP export & shared watchlists — DONE
- Export findings as STIX 2.1 bundles; import/export watchlist entries as
  CSV/JSON for analyst-team sharing.
- **Acceptance**: STIX bundle validates against the 2.1 schema; round-trip
  watchlist import preserves labels.
