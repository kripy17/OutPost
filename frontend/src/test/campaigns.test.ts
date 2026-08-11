// Campaign list sorting — the pure sorter behind the deck's three sort modes.
// Locks stability (equal keys keep API order) and each mode's priority:
// reputation = externally-flagged/watchlisted first, size = most member runs
// first, newest = most recent span first.

import { describe, expect, it } from "vitest";
import { CAMPAIGN_SORTS, sortCampaigns } from "../routes/campaignsHelpers";
import type { Campaign } from "../types";

function campaign(key: string, extra: Partial<Campaign> = {}): Campaign {
  return {
    key,
    reputation: null,
    watchlist: false,
    watchlist_label: null,
    runs: [],
    span_start: null,
    span_end: null,
    iocs: { ips: [], registry_keys: [], file_paths: [], processes: [] },
    timeline: [],
    ...extra,
  };
}

const BASE: Campaign[] = [
  campaign("mal", { reputation: "malicious", span_start: "2026-08-01T00:00:00Z", runs: [null as never, null as never] as never }),
  campaign("sus", { reputation: "suspicious", span_start: "2026-08-03T00:00:00Z", runs: [null as never] as never }),
  campaign("unk", { reputation: "unknown", span_start: "2026-08-02T00:00:00Z", runs: [] }),
  campaign("nul", { reputation: null, span_start: null, runs: [] }),
];

describe("CAMPAIGN_SORTS", () => {
  it("offers the three persisted modes with titles", () => {
    expect(CAMPAIGN_SORTS.map((s) => s.key)).toEqual(["reputation", "size", "newest"]);
    for (const s of CAMPAIGN_SORTS) expect(s.title.length).toBeGreaterThan(10);
  });
});

describe("sortCampaigns", () => {
  it("sorts by reputation rank first — malicious before suspicious, then unknown/null (treated alike) in stable input order", () => {
    const out = sortCampaigns([...BASE].reverse(), "reputation");
    // null and unknown share the rank-2 bucket; stable sort keeps their input
    // order (nul before unk after the reverse).
    expect(out.map((c) => c.key)).toEqual(["mal", "sus", "nul", "unk"]);
  });

  it("sorts by member-run count descending", () => {
    const out = sortCampaigns([...BASE].reverse(), "size");
    expect(out[0].key).toBe("mal"); // 2 runs
    expect(out[1].key).toBe("sus"); // 1 run
    // Both empty-run campaigns sort to the tail, stable in input order.
    expect(out.slice(2).map((c) => c.key).sort()).toEqual(["nul", "unk"]);
  });

  it("sorts by most recent span start; null spans sink to the end", () => {
    const out = sortCampaigns([...BASE].reverse(), "newest");
    expect(out[0].key).toBe("sus"); // 08-03
    expect(out[1].key).toBe("unk"); // 08-02
    expect(out[2].key).toBe("mal"); // 08-01
    expect(out[3].key).toBe("nul"); // null span
  });

  it("is stable — equal keys keep API order", () => {
    const a = campaign("a", { reputation: "suspicious" });
    const b = campaign("b", { reputation: "suspicious" });
    const out = sortCampaigns([a, b], "reputation");
    expect(out).toEqual([a, b]);
  });

  it("does not mutate the input list", () => {
    const input = [...BASE];
    sortCampaigns(input, "newest");
    expect(input.map((c) => c.key)).toEqual(BASE.map((c) => c.key));
  });
});
