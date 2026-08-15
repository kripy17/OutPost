// History-page helpers — the archive's summary-strip arithmetic (the four
// Stat cards: sessions / alerts / malicious / cumulative risk).

import { describe, expect, it } from "vitest";
import { archiveTotals } from "../routes/runHistoryHelpers";
import type { RunSummary } from "../types";

function run(over: Partial<RunSummary>): RunSummary {
  return {
    run_id: "run",
    sample_name: "sample",
    platform: "linux",
    session_type: "analysis",
    started_at: "2026-08-14T11:00:00Z",
    completed_at: null,
    process_count: 1,
    unique_ips: 1,
    alert_count: 0,
    highest_severity: null,
    risk_score: 0,
    ...over,
  };
}

describe("archiveTotals", () => {
  it("sums alert counts across runs", () => {
    const { totalAlerts } = archiveTotals([run({ alert_count: 2 }), run({ alert_count: 5 }), run({ alert_count: 0 })]);
    expect(totalAlerts).toBe(7);
  });

  it("counts only malicious-severity sessions", () => {
    const { malicious } = archiveTotals([
      run({ highest_severity: "malicious" }),
      run({ highest_severity: "suspicious" }),
      run({ highest_severity: null }),
      run({ highest_severity: "malicious" }),
    ]);
    expect(malicious).toBe(2);
  });

  it("sums cumulative risk", () => {
    const { totalRisk } = archiveTotals([run({ risk_score: 40 }), run({ risk_score: 0 }), run({ risk_score: 87 })]);
    expect(totalRisk).toBe(127);
  });

  it("returns all zeros for an empty list", () => {
    expect(archiveTotals([])).toEqual({ totalAlerts: 0, malicious: 0, totalRisk: 0 });
  });

  it("a single clean run contributes nothing but a session", () => {
    expect(archiveTotals([run({})])).toEqual({ totalAlerts: 0, malicious: 0, totalRisk: 0 });
  });
});
