// Which suppressions are ACTIVE for a run — pure derivation shared by the
// SuppressionPanel (run-detail bottom panel) and the per-alert one-click
// "suppress this rule" button, so the two surfaces can never disagree.
//
// Scope rules (backend `rules_suppressions`):
//  - run-scoped (run_id set)        → always applies to that run
//  - global VALUE-scoped (no run_id, value set) → applies when the value
//    matches this run's sample name (e.g. beaconing → "detonate-demo.sh")
//  - global whole-rule (no run_id, no value) → NOT listed here: it applies to
//    every run but is managed on the Rules page, never the run surfaces

import type { Suppression } from "../../types";

export function activeSuppressions(
  all: Suppression[],
  runId: string,
  sampleName?: string | null,
): Suppression[] {
  return all.filter((s) => {
    if (s.run_id === runId) return true;
    if (s.run_id != null) return false;
    if (!s.value) return false; // global whole-rule — Rules-page territory
    return !!sampleName && s.value.toLowerCase() === sampleName.toLowerCase();
  });
}

/** Rule ids effectively suppressed for the run — the set the alert rows and
 *  the panel both read to decide "suppressed" vs "can suppress". */
export function suppressedRuleIds(
  all: Suppression[],
  runId: string,
  sampleName?: string | null,
): Set<string> {
  return new Set(activeSuppressions(all, runId, sampleName).map((s) => s.rule_id));
}
