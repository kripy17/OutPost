// Coverage matrix contract — the pure derivation behind the ATT&CK matrix.
// Locks the semantics verify.sh gates on: all 14 Enterprise tactics are
// represented in the canonical list, rules bucket by tactic, gaps are the
// tactics with no rule, and unknown-tactic rules land in a catch-all instead
// of vanishing. Also locks severityTone's malicious-vs-suspicious split.

import { describe, expect, it } from "vitest";
import { buildCoverage, severityTone, TACTICS, TACTIC_BLURB } from "../routes/coverageHelpers";
import type { RuleMeta } from "../types";

function rule(id: string, tactic: string, technique: string, severity: "suspicious" | "malicious" = "suspicious"): RuleMeta {
  return { rule_id: id, rule_name: id, tactic, technique, weight: 10, severity };
}

const SAMPLE_RULES: RuleMeta[] = [
  rule("lolbin-abuse", "Execution", "T1059", "malicious"),
  rule("masquerading", "Defense Evasion", "T1036", "suspicious"),
  rule("registry-persistence", "Persistence", "T1547", "suspicious"),
  rule("beaconing", "Command and Control", "T1071", "suspicious"),
  rule("ransomware-burst", "Impact", "T1486", "malicious"),
  // A second rule sharing a tactic+technique must not double-count techniques.
  rule("unusual-port", "Command and Control", "T1071", "suspicious"),
];

describe("buildCoverage", () => {
  it("keeps the canonical list at all 14 Enterprise tactics", () => {
    expect(TACTICS).toHaveLength(14);
    // Every tactic has a one-line "what it means" blurb for gap columns.
    for (const t of TACTICS) {
      expect(TACTIC_BLURB[t], `missing blurb for ${t}`).toBeTruthy();
    }
  });

  it("buckets rules by tactic and derives covered/gaps from the canonical list", () => {
    const c = buildCoverage(SAMPLE_RULES);
    // Canonical TACTICS order — Execution → Persistence → Defense Evasion → C2 → Impact.
    expect(c.covered).toEqual(["Execution", "Persistence", "Defense Evasion", "Command and Control", "Impact"]);
    // The canonical 14 minus the 5 covered — gaps are the visible blind spots.
    expect(c.gaps).toHaveLength(9);
    expect(c.gaps).not.toContain("Execution");
    expect(c.gaps).toContain("Discovery");
    expect(c.gaps).toContain("Exfiltration");
    expect(c.byTactic.get("Execution")).toHaveLength(1);
    // Two rules sharing a technique count once.
    expect(c.techniqueCount).toBe(5);
  });

  it("never drops a rule whose tactic is not in the canonical list", () => {
    const c = buildCoverage([...SAMPLE_RULES, rule("future-rule", "Cloud Stuff", "T9999")]);
    expect(c.unknownTactics).toEqual(["Cloud Stuff"]);
    // The canonical count still sums: all rules render somewhere.
    const rendered = [...c.byTactic.values()].reduce((n, rs) => n + rs.length, 0);
    expect(rendered).toBe(SAMPLE_RULES.length + 1);
  });

  it("handles an empty rule set — every tactic is a gap, zero techniques", () => {
    const c = buildCoverage([]);
    expect(c.gaps).toHaveLength(14);
    expect(c.covered).toHaveLength(0);
    expect(c.techniqueCount).toBe(0);
  });
});

describe("severityTone", () => {
  it("maps malicious to the malicious chip tone and anything else to suspicious", () => {
    expect(severityTone("malicious")).toContain("risk-malicious");
    expect(severityTone("suspicious")).toContain("risk-suspicious");
    expect(severityTone("suspicious")).not.toContain("risk-malicious");
  });
});
