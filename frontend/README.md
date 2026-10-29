# OutPost Frontend — Analyst UI & Malware Analysis Workspaces

The **OutPost Frontend** is a modern, responsive Single Page Application (SPA) purpose-built for malware analysts, reverse engineers, and incident responders. Built with **React 18**, **TypeScript**, **Vite**, and **Tailwind CSS**, it delivers low-latency visualization of static binary structures, pre-execution threat predictions, containerized dynamic sandbox telemetry, and ATT&CK® matrix coverage.

---

## Architecture & Technology Stack

```
frontend/
├── src/
│   ├── App.tsx                     # Top-level application router & layout provider
│   ├── main.tsx                    # React DOM mounting & TanStack Query client
│   ├── foundation/                 # Design system tokens, keyboard shortcuts, modal dialogs
│   │   ├── shell.tsx               # Primary application navigation shell & header
│   │   ├── keymap.ts               # Analyst hotkeys (triage navigation, focus search)
│   │   ├── tokens.ts               # Threat severity color palette & design tokens
│   │   └── time.tsx                # Relative & ISO 8601 forensic timestamp formatters
│   ├── routes/                     # Workspace route views
│   │   ├── samples.tsx             # Malware Vault & catalog dashboard
│   │   ├── sampleDetail.tsx        # Deep static dossier & Layer-1 threat forecast
│   │   ├── monitor.tsx             # Dynamic simulation lab & probe runner
│   │   ├── analysis.tsx            # Detonation runs list
│   │   ├── runDetail.tsx           # Run dossier: process tree, network map, timeline
│   │   ├── events.tsx              # Telemetry stream & live event viewer
│   │   ├── rules.tsx               # Detection Rules Studio & Sigma editor
│   │   ├── coverage.tsx            # MITRE ATT&CK coverage matrix
│   │   ├── watchlist.tsx           # High-priority IOC hunt watchlist
│   │   ├── search.tsx              # Universal IOC and hash search
│   │   └── settings.tsx            # Air-gap governance, webhooks, audit log
│   ├── components/                 # Reusable UI components
│   │   ├── staticAnalysis/         # Section entropy charts, decoded configs, strings
│   │   ├── dynamicAnalysis/        # Process tree canvas, network connection table
│   │   ├── detectionRules/         # Rule testing playground, rule filters
│   │   └── ProcessTree/            # Visual causality tree with PID lineage
│   └── lib/                        # State management, API clients, decoder utilities
│       ├── api.ts                  # Typed Axios/Fetch client & query hooks
│       ├── cyberDecoder.ts         # Analyst utilities (base64, hex, rot13, timestamps)
│       ├── theme.ts                # Analyst visual themes (Forensic Dark, High Contrast)
│       └── useEventStream.ts       # SSE real-time telemetry consumer hook
```

---

## Analyst Workspaces

| Workspace | Route | Key Capabilities |
|:---|:---|:---|
| **Malware Vault** | `/samples` | Multi-format binary vault (PE, ELF, Mach-O, scripts). Risk scoring, malware family attribution, and archive inspection. |
| **Static Dossier & Forecast** | `/samples/:id` | Decoded RAT configurations (Remcos, AsyncRAT, RedLine, Cobalt Strike), section entropy visualization, string hunting, YARA matches, and Layer-1 pre-execution behavioral forecast. |
| **Simulation Lab** | `/monitor` | Controlled threat simulation and interactive probe execution against the isolated container. |
| **Detonation Dossier** | `/runs/:id` | Interactive parent-child process execution tree, network socket destinations with geo-enrichment, and syscall audit timeline. |
| **Telemetry Stream** | `/events` | Real-time endpoint event log with live streaming, facet filters (host, process, event type), and JSON inspector. |
| **Rules Studio** | `/rules` | Sigma and behavioral rule editor with syntax validation, live telemetry testing, and false-positive suppression tuning. |
| **ATT&CK Coverage** | `/coverage` | 14-tactic Enterprise ATT&CK matrix heatmap tracking detection coverage density. |
| **IOC Watchlist** | `/watchlist` | Pin malicious IPs, domains, and file hashes to trigger instant high-severity analyst notifications on sighting. |
| **Global IOC Search** | `/search` | Sub-millisecond cross-artifact search across samples, dynamic runs, alerts, and hosts. |
| **Air-Gap Settings** | `/settings` | Multi-channel alert dispatch (Slack, Discord, Telegram, Webhook), SQLite retention policies, and database backup. |

---

## Development Setup

### Prerequisites
- Node.js 18+ (tested with Node 20 & 22)
- npm 9+

### Commands

```bash
# Install dependencies
npm install

# Start local development server with Hot Module Replacement (HMR)
npm run dev

# Build production bundle to dist/
npm run build

# Preview production build locally on port 5173
npm run preview -- --host 127.0.0.1 --port 5173

# Run the full Vitest suite (components, routes, integration tests)
npm test

# Run a specific workspace test
npx vitest run src/test/allPagesWorkspace.test.tsx
```

---

## Environment Variables

When running against a non-standard backend URL, configure `.env` or set the environment variable:

```bash
# Configure custom backend REST API URL (default: http://localhost:8000)
VITE_API_URL=http://127.0.0.1:8000
```
