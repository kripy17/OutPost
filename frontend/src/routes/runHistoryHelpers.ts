// Pure helpers for the session-history page — extracted so the archive's
// summary-strip arithmetic (the four Stat cards) is unit-testable.

import type { RunSummary } from "../types";

export interface ArchiveTotals {
  totalAlerts: number;
  malicious: number;
  totalRisk: number;
}

/** The archive's summary strip: alert count, malicious-session count, and
 *  cumulative risk across the visible run list. Empty list → all zeros. */
export function archiveTotals(runs: RunSummary[]): ArchiveTotals {
  return {
    totalAlerts: runs.reduce((n, r) => n + r.alert_count, 0),
    malicious: runs.filter((r) => r.highest_severity === "malicious").length,
    totalRisk: runs.reduce((n, r) => n + (r.risk_score ?? 0), 0),
  };
}
