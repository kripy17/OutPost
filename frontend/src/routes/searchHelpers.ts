// Pure derivations for the IOC search page — the draft-persistence contract
// (investigations resume mid-thought) and the platform chip tone, extracted
// so both are unit-testable.

import type { Platform } from "../types";

export const SEARCH_STORAGE = "outpost-search-query";

/** The last submitted query, or "" — never throws (storage may be
 *  unavailable in private mode / tests). */
export function readSavedQuery(): string {
  try {
    return localStorage.getItem(SEARCH_STORAGE) ?? "";
  } catch {
    return "";
  }
}

/** Persist the submitted query; clearing removes the draft. Storage failures
 *  are swallowed — the search still works for this visit. */
export function writeSavedQuery(q: string): void {
  try {
    if (q) localStorage.setItem(SEARCH_STORAGE, q);
    else localStorage.removeItem(SEARCH_STORAGE);
  } catch {
    /* storage unavailable — query still works for this visit */
  }
}

/** Chip tone per platform — windows accent, linux clean, everything else
 *  muted (macos/unknown are honest "can't tell" states, not branded). */
export function platformTone(p: Platform | string): string {
  return p === "windows"
    ? "border-accent/50 text-accent"
    : p === "linux"
      ? "border-risk-clean/50 text-risk-clean"
      : "border-text-faint text-text-muted";
}
