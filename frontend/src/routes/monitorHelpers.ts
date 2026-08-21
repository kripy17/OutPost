// Monitor reconciliation helpers — pure derivations over the run-detail
// alert set, extracted so the live recon highlight set and the kind badges
// are unit-testable in isolation. The run-detail poll is the source of truth
// for which enumeration pids/kinds exist (SSE may miss an alert if the tab
// was closed); a fresh fetch recomputes these from the alert's related_pids
// and details.

import { enumKindsFromDetails } from "../lib/constants";

/** The enumeration pids across every enumeration-burst alert in the set —
 *  the recon highlight set. Returns null when no burst exists (nothing to
 *  highlight), a non-empty set otherwise. */
export function reconciledReconPids(
  alerts: { rule_id: string; related_pids?: number[] | null }[],
): Set<number> | null {
  const set = new Set<number>();
  for (const a of alerts) {
    if (a.rule_id === "enumeration-burst") {
      (a.related_pids ?? []).forEach((p) => set.add(p));
    }
  }
  return set.size > 0 ? set : null;
}

/** The distinct enumeration kinds across every enumeration-burst alert, in
 *  first-seen order — the kind badges above the recon panel. Returns null
 *  when no burst exists. */
export function reconciledKinds(alerts: { rule_id: string; details: string }[]): string[] | null {
  const bursts = alerts.filter((a) => a.rule_id === "enumeration-burst");
  if (bursts.length === 0) return null;
  const kinds: string[] = [];
  for (const a of bursts) {
    for (const k of enumKindsFromDetails(a.details)) if (!kinds.includes(k)) kinds.push(k);
  }
  return kinds;
}
