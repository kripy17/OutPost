// activeSuppressions / suppressedRuleIds — the single derivation shared by
// the run-detail SuppressionPanel and the per-alert "suppress this rule"
// button, so the two surfaces can never disagree about what's suppressed.

import { describe, expect, it } from "vitest";
import { activeSuppressions, suppressedRuleIds } from "../components/TriagePanels/suppressions";
import type { Suppression } from "../types";

function sup(partial: Partial<Suppression> & { rule_id: string }): Suppression {
  return {
    id: 1,
    run_id: null,
    value: null,
    reason: null,
    created_at: "2026-08-16T00:00:00Z",
    ...partial,
  };
}

const RUN = "run-abc";

describe("activeSuppressions", () => {
  it("keeps run-scoped suppressions for this run only", () => {
    const all = [
      sup({ id: 1, rule_id: "beaconing", run_id: RUN }),
      sup({ id: 2, rule_id: "masquerading", run_id: "run-other" }),
    ];
    const active = activeSuppressions(all, RUN);
    expect(active.map((s) => s.id)).toEqual([1]);
  });

  it("keeps global value-scoped suppressions matching the sample name, case-insensitively", () => {
    const all = [
      sup({ id: 1, rule_id: "beaconing", value: "Detonate-Demo.SH" }),
      sup({ id: 2, rule_id: "first-seen", value: "other-sample.exe" }),
    ];
    const active = activeSuppressions(all, RUN, "detonate-demo.sh");
    expect(active.map((s) => s.id)).toEqual([1]);
  });

  it("drops global value-scoped suppressions when no sample name is known", () => {
    const all = [sup({ id: 1, rule_id: "beaconing", value: "detonate-demo.sh" })];
    expect(activeSuppressions(all, RUN)).toEqual([]);
    expect(activeSuppressions(all, RUN, null)).toEqual([]);
  });

  it("excludes global whole-rule suppressions — Rules-page territory, not run surfaces", () => {
    const all = [sup({ id: 1, rule_id: "first-seen" })];
    expect(activeSuppressions(all, RUN)).toEqual([]);
  });
});

describe("suppressedRuleIds", () => {
  it("returns the set of rule ids effectively suppressed for the run", () => {
    const all = [
      sup({ id: 1, rule_id: "beaconing", run_id: RUN }),
      sup({ id: 2, rule_id: "masquerading", value: "detonate-demo.sh" }),
      sup({ id: 3, rule_id: "first-seen", value: "unrelated.exe" }),
    ];
    expect(suppressedRuleIds(all, RUN, "detonate-demo.sh")).toEqual(new Set(["beaconing", "masquerading"]));
  });
});
