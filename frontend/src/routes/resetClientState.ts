// One-click client-state reset (Settings) — the shared clear behind the
// "Reset client-side state" action: the queue/archive provenance preferences,
// the IOC search draft, and the Rules-page drafts (YARA authoring, enum
// pattern tables, log-pattern tables). Pure and testable; every clear is
// defensive (never throws), and the report tells the caller what existed so
// the confirmation message names exactly what was wiped.

import { clearSavedProvenances, readSavedProvenance, STATUS_TABS } from "./findingsHelpers";
import { readSavedQuery, writeSavedQuery } from "./searchHelpers";
import {
  clearEnumDrafts,
  clearLogDrafts,
  clearYaraDraft,
  readEnumDrafts,
  readLogDrafts,
  readYaraDraft,
} from "./rulesDrafts";

export interface ClientStateReport {
  /** status tabs with a saved provenance split (0–4) */
  queueTabs: number;
  /** an IOC search query draft exists */
  searchDraft: boolean;
  /** the YARA authoring draft exists */
  yaraDraft: boolean;
  /** platforms with saved enum-pattern rows */
  enumPlatforms: number;
  /** kinds with saved log-pattern rows */
  logKinds: number;
}

export function anyClientState(report: ClientStateReport): boolean {
  return (
    report.queueTabs > 0 ||
    report.searchDraft ||
    report.yaraDraft ||
    report.enumPlatforms > 0 ||
    report.logKinds > 0
  );
}

export function readClientState(): ClientStateReport {
  return {
    queueTabs: STATUS_TABS.filter((t) => readSavedProvenance(t.v) !== "").length,
    searchDraft: readSavedQuery() !== "",
    yaraDraft: readYaraDraft() !== null,
    enumPlatforms: Object.keys(readEnumDrafts() ?? {}).length,
    logKinds: Object.keys(readLogDrafts() ?? {}).length,
  };
}

/** Wipe every known client-side preference/draft, returning what existed
 *  before the wipe so the caller can report it. Never throws. */
export function resetClientState(): ClientStateReport {
  const before = readClientState();
  clearSavedProvenances();
  writeSavedQuery("");
  clearYaraDraft();
  clearEnumDrafts();
  clearLogDrafts();
  return before;
}
