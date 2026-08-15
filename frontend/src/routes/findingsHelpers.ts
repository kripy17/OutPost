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

// Per-status-tab provenance preference — an analyst's "real hosts first"
// choice survives navigation the way the search draft does, keyed by status
// so each tab (Open / Acknowledged / Resolved / All) remembers its own split.
// Mirrors the History archive's hide-synthetic default without forcing it.
export const PROVENANCE_STORAGE_PREFIX = "outpost-queue-provenance-";

/** The saved provenance for one status tab, "" when unset — never throws
 *  (storage may be unavailable in private mode / tests). */
export function readSavedProvenance(status: string): "" | "real" | "synthetic" {
  try {
    const v = localStorage.getItem(`${PROVENANCE_STORAGE_PREFIX}${status}`);
    return v === "real" || v === "synthetic" ? v : "";
  } catch {
    return "";
  }
}

/** Persist the provenance for one status tab; clearing ("") removes it so
 *  the tab falls back to "all provenance". Failures are swallowed — the
 *  filter still applies for this visit. */
export function writeSavedProvenance(status: string, value: "" | "real" | "synthetic"): void {
  try {
    if (value) localStorage.setItem(`${PROVENANCE_STORAGE_PREFIX}${status}`, value);
    else localStorage.removeItem(`${PROVENANCE_STORAGE_PREFIX}${status}`);
  } catch {
    /* storage unavailable — the filter still works for this visit */
  }
}

/** The archive's legacy show-synthetic key — now a fallback the History page
 *  reads only when the shared queue preference is unset. Kept in sync by
 *  writeArchiveShowSynthetic; cleared here so a preference wipe restores the
 *  archive's real-first default too. (Literal, not imported: the archive
 *  helpers already import this module, so an import back would be circular.) */
const LEGACY_HISTORY_SYNTHETIC_KEY = "outpost-history-synthetic";

/** One-click reset of the triage preferences (Settings): wipes every saved
 *  per-tab provenance choice — Open / Acknowledged / Resolved / All — plus
 *  the archive's legacy fallback key, restoring the fresh-install defaults:
 *  each queue tab shows all provenance and History reads real-telemetry-first.
 *  Unrelated keys are untouched. Never throws. */
export function clearSavedProvenances(): void {
  try {
    // Collect first, then remove — the Storage API (and the minimal mock in
    // the test setup) is enumerated via length/key(i), not Object.keys.
    const doomed: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(PROVENANCE_STORAGE_PREFIX)) doomed.push(key);
    }
    for (const key of doomed) localStorage.removeItem(key);
    localStorage.removeItem(LEGACY_HISTORY_SYNTHETIC_KEY);
  } catch {
    /* storage unavailable — nothing to clear */
  }
}

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
