// Pure derivations for the findings triage queue — extracted so the aging
// and tab-count contracts (what "oldest first" means, how the live badges
// sum) are unit-testable without rendering the page.

import type { QueueResponse } from "../types";

export const PAGE = 25;

export const STATUS_TABS: { v: "open" | "acknowledged" | "resolved" | "all"; label: string; tone: "malicious" | "suspicious" | "clean" | "muted" }[] = [
  { v: "open", label: "Open", tone: "malicious" },
  { v: "acknowledged", label: "Acknowledged", tone: "suspicious" },
  { v: "resolved", label: "Resolved", tone: "clean" },
  { v: "all", label: "All", tone: "muted" },
];

/** Compact relative age: "12s" / "5m" / "3h" / "2d", "—" for unparseable
 *  timestamps. `now` is injectable so tests pin the clock. */
export function ageLabel(ts: string, now: number = Date.now()): string {
  const then = new Date(ts).getTime();
  if (Number.isNaN(then)) return "—";
  const secs = Math.max(0, Math.floor((now - then) / 1000));
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h`;
  return `${Math.floor(secs / 86400)}d`;
}

/** Live badge per status tab. The "All" badge sums the three status buckets
 *  (the response's per-status totals are the live counts across the active
 *  non-status filters); a missing bucket reads 0. */
export function statusTabCount(tab: (typeof STATUS_TABS)[number]["v"], data: QueueResponse | undefined): number | null {
  if (!data) return null;
  if (tab === "open") return data.open;
  if (tab === "acknowledged") return data.acknowledged;
  if (tab === "resolved") return data.resolved;
  return data.open + data.acknowledged + data.resolved;
}
