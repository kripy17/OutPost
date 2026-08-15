// Pure helpers for the session-history page — extracted so the archive's
// summary-strip arithmetic (the four Stat cards) and its synthetic-toggle
// persistence are unit-testable.

import type { RunSummary } from "../types";
import { readSavedProvenance, writeSavedProvenance } from "./findingsHelpers";

/** Legacy key the archive used before the queue shared its real-first
 *  preference; kept in sync so older readers keep working. */
const LEGACY_SYNTHETIC_KEY = "outpost-history-synthetic";

/** Does the archive show synthetic runs? The real-first preference is shared
 *  with the findings queue's Open tab: "real" hides synthetics (real
 *  telemetry first), "synthetic" shows them, and unset falls back to the
 *  archive's own legacy key then to the real-first default (demo mode is off
 *  by default). Never throws. */
export function readArchiveShowSynthetic(): boolean {
  const shared = readSavedProvenance("open");
  if (shared === "real") return false;
  if (shared === "synthetic") return true;
  try {
    return localStorage.getItem(LEGACY_SYNTHETIC_KEY) === "1";
  } catch {
    return false;
  }
}

/** Persist the archive's synthetic toggle and mirror it to the shared
 *  real-first preference the queue's Open tab reads and writes, so the two
 *  surfaces never disagree: showing synthetics = queue "all" (key cleared),
 *  hiding them = queue "real". Failures are swallowed — the choice still
 *  applies for this visit. */
export function writeArchiveShowSynthetic(show: boolean): void {
  writeSavedProvenance("open", show ? "" : "real");
  try {
    localStorage.setItem(LEGACY_SYNTHETIC_KEY, show ? "1" : "0");
  } catch {
    /* storage unavailable */
  }
}

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
