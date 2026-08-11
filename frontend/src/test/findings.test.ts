// Findings triage queue contracts — the pure derivations behind the queue:
// age labels (what "oldest first" renders) and the live status-tab badges
// (the "All" badge must sum the three status buckets).

import { describe, expect, it } from "vitest";
import { ageLabel, PAGE, STATUS_TABS, statusTabCount } from "../routes/findingsHelpers";
import type { QueueResponse } from "../types";

const NOW = new Date("2026-08-11T12:00:00Z").getTime();

function queue(over: Partial<QueueResponse> = {}): QueueResponse {
  return { total: 10, open: 4, acknowledged: 3, resolved: 2, sort: "aging", limit: 25, offset: 0, alerts: [], ...over };
}

describe("ageLabel", () => {
  it("renders s/m/h/d buckets against the injected clock", () => {
    expect(ageLabel("2026-08-11T11:59:50Z", NOW)).toBe("10s");
    expect(ageLabel("2026-08-11T11:50:00Z", NOW)).toBe("10m");
    expect(ageLabel("2026-08-11T09:00:00Z", NOW)).toBe("3h");
    expect(ageLabel("2026-08-09T12:00:00Z", NOW)).toBe("2d");
  });

  it("clamps future timestamps to 0s and flags unparseable ones", () => {
    expect(ageLabel("2026-08-11T12:00:30Z", NOW)).toBe("0s");
    expect(ageLabel("not-a-date", NOW)).toBe("—");
  });
});

describe("STATUS_TABS + statusTabCount", () => {
  it("offers the four queue views in order", () => {
    expect(STATUS_TABS.map((t) => t.v)).toEqual(["open", "acknowledged", "resolved", "all"]);
  });

  it("counts each status from its live bucket", () => {
    const data = queue();
    expect(statusTabCount("open", data)).toBe(4);
    expect(statusTabCount("acknowledged", data)).toBe(3);
    expect(statusTabCount("resolved", data)).toBe(2);
  });

  it("sums the three buckets for the All badge", () => {
    expect(statusTabCount("all", queue())).toBe(9);
  });

  it("returns null before data loads (the badge renders '…')", () => {
    expect(statusTabCount("open", undefined)).toBeNull();
    expect(statusTabCount("all", undefined)).toBeNull();
  });
});

describe("PAGE", () => {
  it("is the pagination page size used by the queue fetch", () => {
    expect(PAGE).toBe(25);
  });
});
