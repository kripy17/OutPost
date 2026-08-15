// History-page helpers — the archive's summary-strip arithmetic (the four
// Stat cards: sessions / alerts / malicious / cumulative risk) and the
// synthetic-toggle persistence shared with the findings queue's Open tab.

import { beforeEach, describe, expect, it } from "vitest";
import { PROVENANCE_STORAGE_PREFIX } from "../routes/findingsHelpers";
import { archiveTotals, readArchiveShowSynthetic, writeArchiveShowSynthetic } from "../routes/runHistoryHelpers";
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

describe("synthetic toggle shared with the queue (real hosts first)", () => {
  beforeEach(() => localStorage.clear());

  it("hides synthetics when the queue's Open tab prefers real hosts", () => {
    localStorage.setItem(`${PROVENANCE_STORAGE_PREFIX}open`, "real");
    expect(readArchiveShowSynthetic()).toBe(false);
  });

  it("shows synthetics when the queue's Open tab focuses synthetic", () => {
    localStorage.setItem(`${PROVENANCE_STORAGE_PREFIX}open`, "synthetic");
    expect(readArchiveShowSynthetic()).toBe(true);
  });

  it("falls back to the legacy archive key when the queue never chose", () => {
    localStorage.setItem("outpost-history-synthetic", "1");
    expect(readArchiveShowSynthetic()).toBe(true);
    localStorage.setItem("outpost-history-synthetic", "0");
    expect(readArchiveShowSynthetic()).toBe(false);
  });

  it("defaults to real telemetry first on a fresh install", () => {
    expect(readArchiveShowSynthetic()).toBe(false);
  });

  it("ignores a corrupted shared value and falls through to the legacy key", () => {
    localStorage.setItem(`${PROVENANCE_STORAGE_PREFIX}open`, "banana");
    localStorage.setItem("outpost-history-synthetic", "1");
    expect(readArchiveShowSynthetic()).toBe(true);
  });

  it("showing synthetics clears the queue key (all provenance) and sets the legacy key", () => {
    writeArchiveShowSynthetic(true);
    expect(localStorage.getItem(`${PROVENANCE_STORAGE_PREFIX}open`)).toBeNull();
    expect(localStorage.getItem("outpost-history-synthetic")).toBe("1");
    expect(readArchiveShowSynthetic()).toBe(true);
  });

  it("hiding synthetics writes 'real' to the queue key and clears the legacy key", () => {
    writeArchiveShowSynthetic(false);
    expect(localStorage.getItem(`${PROVENANCE_STORAGE_PREFIX}open`)).toBe("real");
    expect(localStorage.getItem("outpost-history-synthetic")).toBe("0");
    expect(readArchiveShowSynthetic()).toBe(false);
  });

  it("toggling round-trips: hide then show converges to all provenance", () => {
    writeArchiveShowSynthetic(false);
    writeArchiveShowSynthetic(true);
    expect(localStorage.getItem(`${PROVENANCE_STORAGE_PREFIX}open`)).toBeNull();
    expect(readArchiveShowSynthetic()).toBe(true);
  });
});
