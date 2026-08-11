// Event Log filter persistence — the URL-mirror + localStorage restore logic,
// extracted so it's unit-testable in isolation from the virtualized feed.

/** The persisted Event-Log filter set (localStorage, key `outpost-events-filters`). */
export type SavedFilters = {
  category?: string;
  severity?: string;
  platform?: string;
  source?: string;
  q?: string;
  pids?: number[];
};

/** Resolve the persisted filter set for a fresh EventsPage mount. Returns null
 *  when the URL carries any filter param (deep links win), storage is empty,
 *  or the stored JSON is corrupt/unavailable. Callers feed the result into
 *  useState initializers — a mount effect would be too late, because the
 *  URL-mirror effect would clobber storage with the empty default first. */
export function resolveSavedFilters(
  hasParam: (k: string) => string | null,
  readStorage: () => string | null,
): SavedFilters | null {
  if (["type", "severity", "platform", "source", "q", "pid"].some((k) => hasParam(k))) return null;
  try {
    const raw = readStorage();
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? (parsed as SavedFilters) : null;
  } catch {
    return null;
  }
}
