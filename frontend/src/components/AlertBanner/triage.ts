// Alert triage ordering — pure helpers for the run-detail triage panel:
// "aging" surfaces the alerts open longest first, "time" is the default
// newest-first feed. Exported for the unit tests.

import type { Alert } from "../../types";

/** Triage sort modes. `time` keeps the feed's chronological order; `aging`
 *  surfaces the alerts that have been OPEN longest — the ones an analyst
 *  should triage first — then the already-triaged ones newest-first. */
export type TriageSort = "time" | "aging";

export function sortAlertsForTriage(alerts: Alert[], mode: TriageSort): Alert[] {
  if (mode === "time") return alerts;
  const sorted = [...alerts].sort((a, b) => {
    const aOpen = a.status === "open";
    const bOpen = b.status === "open";
    if (aOpen !== bOpen) return aOpen ? -1 : 1; // open alerts first
    if (aOpen) return a.triggered_at.localeCompare(b.triggered_at); // oldest-open first
    return b.triggered_at.localeCompare(a.triggered_at); // triaged: newest first
  });
  return sorted;
}

/** Human "open since" label, e.g. "open since 12m" / "open since 3h". */
export function openDuration(alert: Alert, now: number = Date.now()): string | null {
  if (alert.status !== "open") return null;
  const mins = Math.max(0, Math.floor((now - new Date(alert.triggered_at).getTime()) / 60_000));
  if (mins < 1) return "open · just now";
  if (mins < 60) return `open since ${mins}m`;
  return `open since ${Math.floor(mins / 60)}h`;
}
