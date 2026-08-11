// Unit tests for the Overview's pure logic — the duplicate-finding collapse
// and the risk-trend aggregation. These encode the dashboard's two behaviors:
// identical findings fold into ×N rows, and the risk trend is per-sample with
// empty live-monitor sessions defaulted out.

import { describe, expect, it } from "vitest";
import { aggregateTrend, ageBucket, collapseFindings, openSince, sortFindingsRiskFirst } from "../routes/overviewHelpers";
import type { GlobalAlert, RuleMeta, RunSummary } from "../types";

function alert(over: Partial<GlobalAlert>): GlobalAlert {
  return {
    id: null,
    run_id: "r1",
    rule_id: "unusual-port",
    rule_name: "Uncommon port",
    severity: "suspicious",
    triggered_at: "2026-08-08T12:00:00Z",
    related_pid: null,
    related_ip: "203.0.113.88",
    details: "C2 port",
    status: "open",
    status_comment: null,
    status_at: null,
    sample_name: "sample.exe",
    ...over,
  };
}

describe("collapseFindings", () => {
  it("collapses consecutive identical rule+sample into one group with a count", () => {
    const groups = collapseFindings([
      alert({ rule_id: "lolbin-abuse", triggered_at: "2026-08-08T12:00:04Z" }),
      alert({ rule_id: "lolbin-abuse", triggered_at: "2026-08-08T12:00:01Z" }),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0].count).toBe(2);
    expect(groups[0].rule_id).toBe("lolbin-abuse");
  });

  it("keeps different rules as separate rows", () => {
    const groups = collapseFindings([
      alert({ rule_id: "lolbin-abuse" }),
      alert({ rule_id: "unusual-port" }),
    ]);
    expect(groups).toHaveLength(2);
  });

  it("does not collapse identical findings more than 5 minutes apart", () => {
    const groups = collapseFindings([
      alert({ rule_id: "lolbin-abuse", triggered_at: "2026-08-08T12:10:00Z" }),
      alert({ rule_id: "lolbin-abuse", triggered_at: "2026-08-08T12:00:00Z" }),
    ]);
    expect(groups).toHaveLength(2);
  });

  it("tracks the set of runs behind a collapsed group", () => {
    const groups = collapseFindings([
      alert({ rule_id: "lolbin-abuse", run_id: "rA", triggered_at: "2026-08-08T12:00:03Z" }),
      alert({ rule_id: "lolbin-abuse", run_id: "rA", triggered_at: "2026-08-08T12:00:02Z" }),
      alert({ rule_id: "lolbin-abuse", run_id: "rB", triggered_at: "2026-08-08T12:00:01Z" }),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0].runs.size).toBe(2);
  });
});

function run(over: Partial<RunSummary>): RunSummary {
  return {
    run_id: "x",
    sample_name: "a.bin",
    platform: "windows",
    session_type: "analysis",
    started_at: "2026-08-08T12:00:00Z",
    completed_at: null,
    process_count: 0,
    unique_ips: 0,
    alert_count: 0,
    highest_severity: null,
    risk_score: 0,
    ...over,
  };
}

describe("sortFindingsRiskFirst", () => {
  function group(over: Partial<GlobalAlert>, count = 1) {
    return {
      key: `${over.rule_id}|${over.sample_name ?? "s"}`,
      rule_id: over.rule_id ?? "unusual-port",
      sample_name: over.sample_name ?? "s.exe",
      count,
      runs: new Set([over.run_id ?? "r1"]),
      first: alert(over),
    };
  }

  const meta = (rule_id: string, weight: number, severity: "malicious" | "suspicious"): RuleMeta => ({
    rule_id,
    rule_name: rule_id,
    technique: "T1",
    tactic: "Execution",
    weight,
    severity,
  });

  it("puts malicious above suspicious regardless of recency", () => {
    const byRule = new Map([
      ["lolbin-abuse", meta("lolbin-abuse", 70, "malicious")],
      ["unusual-port", meta("unusual-port", 50, "suspicious")],
    ]);
    const groups = [
      group({ rule_id: "unusual-port", severity: "suspicious", triggered_at: "2026-08-08T12:00:00Z" }),
      group({ rule_id: "lolbin-abuse", severity: "malicious", triggered_at: "2026-08-08T11:00:00Z" }),
    ];
    const sorted = sortFindingsRiskFirst(groups, byRule);
    expect(sorted.map((g) => g.rule_id)).toEqual(["lolbin-abuse", "unusual-port"]);
  });

  it("breaks severity ties by rule weight then recency", () => {
    const byRule = new Map([
      ["attack-chain", meta("attack-chain", 90, "malicious")],
      ["lolbin-abuse", meta("lolbin-abuse", 70, "malicious")],
    ]);
    const groups = [
      group({ rule_id: "lolbin-abuse", severity: "malicious", triggered_at: "2026-08-08T12:00:00Z" }),
      group({ rule_id: "attack-chain", severity: "malicious", triggered_at: "2026-08-08T11:00:00Z" }),
    ];
    const sorted = sortFindingsRiskFirst(groups, byRule);
    expect(sorted.map((g) => g.rule_id)).toEqual(["attack-chain", "lolbin-abuse"]);
  });
});

describe("openSince + ageBucket", () => {
  const base = "2026-08-08T12:00:00Z";
  const now = new Date(base).getTime();

  it("labels open alerts with their age and buckets hot/warm/fresh", () => {
    expect(openSince(alert({ status: "open", triggered_at: "2026-08-08T11:30:00Z" }), now)).toBe("open since 30m");
    expect(ageBucket(alert({ status: "open", triggered_at: "2026-08-08T11:30:00Z" }), now)).toBe(1);
    expect(openSince(alert({ status: "open", triggered_at: "2026-08-08T09:00:00Z" }), now)).toBe("open since 3h");
    expect(ageBucket(alert({ status: "open", triggered_at: "2026-08-08T09:00:00Z" }), now)).toBe(2);
    expect(ageBucket(alert({ status: "open", triggered_at: "2026-08-08T11:59:00Z" }), now)).toBe(0);
  });

  it("returns null / fresh for non-open alerts", () => {
    expect(openSince(alert({ status: "acknowledged" }), now)).toBeNull();
    expect(ageBucket(alert({ status: "resolved" }), now)).toBe(0);
  });
});

describe("aggregateTrend", () => {
  it("groups by sample, keeping the peak risk and session count", () => {
    const bars = aggregateTrend([
      run({ sample_name: "evil.exe", risk_score: 40, started_at: "2026-08-08T10:00:00Z" }),
      run({ sample_name: "evil.exe", risk_score: 90, started_at: "2026-08-08T11:00:00Z" }),
      run({ sample_name: "clean.bin", risk_score: 10, started_at: "2026-08-08T12:00:00Z" }),
    ]);
    expect(bars).toHaveLength(2);
    const evil = bars.find((b) => b.sample === "evil.exe")!;
    expect(evil.peak).toBe(90);
    expect(evil.count).toBe(2);
    expect(evil.last).toBe("2026-08-08T11:00:00Z");
  });

  it("defaults out risk-0 live-monitor sessions", () => {
    const bars = aggregateTrend([
      run({ sample_name: "Live monitor — 2026-08-07 09:00:00", session_type: "live", risk_score: 0 }),
      run({ sample_name: "Live monitor — 2026-08-07 10:00:00", session_type: "live", risk_score: 0 }),
      run({ sample_name: "real.bin", risk_score: 30 }),
    ]);
    expect(bars).toHaveLength(1);
    expect(bars[0].sample).toBe("real.bin");
  });

  it("keeps live sessions that produced a finding", () => {
    const bars = aggregateTrend([
      run({ sample_name: "host-live", session_type: "live", risk_score: 55 }),
      run({ sample_name: "clean.bin", risk_score: 0 }),
    ]);
    expect(bars).toHaveLength(2);
  });

  it("sorts chronologically by newest run", () => {
    const bars = aggregateTrend([
      run({ sample_name: "old.bin", risk_score: 90, started_at: "2026-08-01T00:00:00Z" }),
      run({ sample_name: "new.bin", risk_score: 10, started_at: "2026-08-08T00:00:00Z" }),
    ]);
    expect(bars.map((b) => b.sample)).toEqual(["old.bin", "new.bin"]);
  });
});
