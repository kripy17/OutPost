# Frontend Specification (React 19 + TypeScript + Tailwind v4)

## Routes

| Path | Page | Purpose |
|---|---|---|
| `/` | Run History | List of all past sessions (live monitoring + bounded analyses), sortable/filterable by platform, session type, alert severity |
| `/runs/:runId` | Run Detail | Process tree + network connections + timeline + alerts for one session |

## Shared Types (mirror backend Pydantic models exactly)

```typescript
// src/types/index.ts
export type Platform = "windows" | "linux";
export type Reputation = "clean" | "suspicious" | "malicious" | "unknown";
export type SessionType = "live" | "analysis";
export type Severity = "suspicious" | "malicious";

export interface RunSummary {
  run_id: string;
  sample_name: string;
  platform: Platform;
  session_type: SessionType;
  started_at: string;
  completed_at: string | null;
  process_count: number;
  unique_ips: number;
  alert_count: number;
  highest_severity: Severity | null;
}

export interface Alert {
  id: number;
  run_id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  triggered_at: string;
  related_pid: number | null;
  related_ip: string | null;
  details: string;
}

export interface ProcessNode {
  pid: number;
  ppid: number | null;
  process_name: string;
  command_line: string | null;
  children: ProcessNode[];
}

export interface NetworkConnection {
  dest_ip: string;
  dest_port: number | null;
  protocol: string | null;
  first_seen: string;
  reputation: Reputation;
  abuse_score: number | null;
  vt_malicious_count: number | null;
  malware_family: string | null;
}
```

## API Client (centralized — no inline fetch in components)

```typescript
// src/lib/api.ts
const BASE_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export async function getRuns(): Promise<RunSummary[]> {
  const res = await fetch(`${BASE_URL}/runs`);
  if (!res.ok) throw new Error("Failed to fetch runs");
  return res.json();
}

export async function getRunDetail(runId: string) {
  const res = await fetch(`${BASE_URL}/runs/${runId}`);
  if (!res.ok) throw new Error("Failed to fetch run detail");
  return res.json();
}

export async function getAlerts(runId: string): Promise<Alert[]> {
  const res = await fetch(`${BASE_URL}/runs/${runId}/alerts`);
  if (!res.ok) throw new Error("Failed to fetch alerts");
  return res.json();
}
```

Use **TanStack Query** for all fetching (`useQuery`) — gives you caching, loading/error states, and refetch-on-focus for free, which matters here since a run may still be in progress when the analyst is viewing it.

## Component Breakdown

**`components/RunHistory/`**
- `RunList.tsx` — table/grid of runs, links to detail page
- `RunCard.tsx` — single row: sample name, platform icon, timestamp, risk badge

**`components/ProcessTree/`**
- `ProcessTree.tsx` — recursive tree renderer (parent → children), collapsible nodes
- Keep this dependency-free if possible (a recursive component over `ProcessNode` is enough); reach for a graph library only if the tree rendering genuinely gets unmanageable

**`components/AlertBanner/`**
- `AlertBanner.tsx` — the most important component on the run detail page. Renders each `Alert` prominently (rule name, severity color, `details` text) at the top of the page, above the process tree — an analyst should see "3 malicious alerts" before they see anything else
- Empty state matters too: a session with zero alerts should show a calm, clearly "clean" state, not just an absence of UI

**`components/NetworkTable/`**
- `NetworkTable.tsx` — sortable table of `NetworkConnection[]`
- `ReputationBadge.tsx` — colored badge (green/yellow/red) driven by `reputation` field — this is the single highest-value visual in the whole app, get this one right

**`components/TimelineView/`**
- `TimelineView.tsx` — chronological list of all events (process + network combined), sorted by `timestamp`

**`components/ExportButton/`**
- `ExportButton.tsx` — calls `/runs/{id}/export`, triggers file download

## Data Flow Per Page

**Run History (`/`):**
1. `useQuery(["runs"], getRuns)`
2. Render `<RunList runs={data} />`

**Run Detail (`/runs/:runId`):**
1. `useQuery(["run", runId], () => getRunDetail(runId))` and `useQuery(["alerts", runId], () => getAlerts(runId))`
2. If `completed_at` is null (including any `session_type: "live"` run still active), poll every few seconds — `refetchInterval` in TanStack Query handles this cleanly
3. Render `<AlertBanner alerts={alerts} />` first, then `<ProcessTree root={data.process_tree} />`, `<NetworkTable connections={data.network_connections} />`, `<TimelineView events={data.timeline} />`

## Styling Notes

- Tailwind utility classes only, no separate CSS files
- Risk/reputation colors should be consistent everywhere they appear (define once, e.g. in a `constants.ts`, reuse — don't hardcode `bg-red-500` in three different components)
- Dark mode isn't required for MVP, but if you want it free: stick to Tailwind's semantic color tokens instead of raw colors, it costs nothing extra now and pays off later
