// Campaign list sorting — the pure sorter behind the deck's three sort modes.
// Locks stability (equal keys keep API order) and each mode's priority:
// reputation = externally-flagged/watchlisted first, size = most member runs
// first, newest = most recent span first.

import { describe, expect, it } from "vitest";
import { CAMPAIGN_SORTS, clusterBars, reputationFill, sortCampaigns, topMembers, topologyClusters, type TopologyStripRow } from "../routes/campaignsHelpers";
import type { Reputation } from "../types";
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

describe("topologyClusters", () => {
  function cluster(ip: string, sample_count: number, extra: Partial<Parameters<typeof topologyClusters>[0][number]> = {}): Parameters<typeof topologyClusters>[0][number] {
    return {
      ip,
      sample_count,
      members: [],
      reputation: "unknown",
      checked_at: null,
      ...extra,
    };
  }

  it("marks clusters that already have a campaign by IP", () => {
    const rows = topologyClusters(
      [cluster("203.0.113.88", 3), cluster("198.51.100.7", 2)],
      [{ key: "203.0.113.88" } as never],
    );
    const byIp = Object.fromEntries(rows.map((r) => [r.ip, r.inCampaign]));
    expect(byIp["203.0.113.88"]).toBe(true);
    expect(byIp["198.51.100.7"]).toBe(false);
  });

  it("sorts by shared-sample count descending, IP tiebreak", () => {
    const rows = topologyClusters(
      [cluster("10.0.0.1", 2), cluster("10.0.0.9", 2), cluster("10.0.0.3", 5), cluster("10.0.0.4", 1)],
      [],
    );
    expect(rows.map((r) => r.ip)).toEqual(["10.0.0.3", "10.0.0.1", "10.0.0.9", "10.0.0.4"]);
  });

  it("is empty when the topology has no clusters", () => {
    expect(topologyClusters([], [])).toEqual([]);
  });

  it("keeps cluster reputation and member data intact", () => {
    const rows = topologyClusters(
      [cluster("203.0.113.88", 2, { reputation: "malicious", members: [{ sample_name: "a.bin", hits: 3, run_ids: ["r1"] }] })],
      [],
    );
    expect(rows[0].reputation).toBe("malicious");
    expect(rows[0].members[0].sample_name).toBe("a.bin");
  });
});

describe("clusterBars", () => {
  function row(ip: string, sample_count: number, extra: Partial<TopologyStripRow> = {}): TopologyStripRow {
    return {
      ip,
      sample_count,
      members: [],
      reputation: "unknown",
      checked_at: null,
      inCampaign: false,
      ...extra,
    };
  }

  it("scales bar width to the loudest cluster (max = 100)", () => {
    const bars = clusterBars([row("a", 10), row("b", 5), row("c", 2)]);
    expect(bars.map((b) => b.pct)).toEqual([100, 50, 20]);
  });

  it("caps the rows shown and keeps the largest first", () => {
    const rows = [row("a", 9), row("b", 8), row("c", 7), row("d", 6)];
    expect(clusterBars(rows, 2).map((b) => b.ip)).toEqual(["a", "b"]);
  });

  it("is empty when there are no clusters", () => {
    expect(clusterBars([])).toEqual([]);
  });

  it("carries reputation, campaign mark, and the member sample link", () => {
    const bars = clusterBars([
      row("203.0.113.88", 4, {
        reputation: "malicious",
        inCampaign: true,
        members: [{ sample_name: "evil.bin", hits: 3, run_ids: ["r1"] }],
      }),
      row("10.0.0.1", 1),
    ]);
    expect(bars[0]).toMatchObject({
      ip: "203.0.113.88",
      sample_count: 4,
      reputation: "malicious",
      inCampaign: true,
      memberSample: "evil.bin",
    });
    expect(bars[1].memberSample).toBe("");
  });

  it("keeps the full member list for the hover tooltip", () => {
    const members = [{ sample_name: "a.bin", hits: 1, run_ids: ["r1"] }];
    const bars = clusterBars([row("203.0.113.88", 2, { members })]);
    expect(bars[0].members).toEqual(members);
  });
});

describe("topMembers", () => {
  function member(name: string, hits: number) {
    return { sample_name: name, hits, run_ids: ["r1"] };
  }

  it("sorts by hit count descending with a name tiebreak", () => {
    const { rows } = topMembers([member("b.bin", 2), member("a.bin", 2), member("c.bin", 9)]);
    expect(rows.map((m) => m.sample_name)).toEqual(["c.bin", "a.bin", "b.bin"]);
  });

  it("caps the rows and counts the overflow", () => {
    const all = Array.from({ length: 12 }, (_, i) => member(`s${i}.bin`, 1));
    const { rows, more } = topMembers(all, 8);
    expect(rows.length).toBe(8);
    expect(more).toBe(4);
  });

  it("has no overflow when everything fits", () => {
    const { rows, more } = topMembers([member("a.bin", 1)], 8);
    expect(rows.length).toBe(1);
    expect(more).toBe(0);
  });
});

describe("reputationFill", () => {
  const REPS: Reputation[] = ["malicious", "suspicious", "unknown", "clean"];

  it("gives every reputation a distinct fill so pattern carries meaning", () => {
    const fills = REPS.map((r) => reputationFill(r).background);
    expect(new Set(fills).size).toBe(4);
  });

  it("malicious is solid (no hatch) with the risk token", () => {
    const f = reputationFill("malicious");
    expect(f.background).toBe("var(--risk-malicious)");
    expect(f.background).not.toContain("repeating-linear-gradient");
  });

  it("suspicious is diagonal-hatched with the risk token", () => {
    const f = reputationFill("suspicious");
    expect(f.background).toContain("repeating-linear-gradient(45deg");
    expect(f.background).toContain("var(--risk-suspicious)");
  });

  it("unknown is crosshatched (two directions) with the muted token", () => {
    const f = reputationFill("unknown");
    const matches = f.background.match(/repeating-linear-gradient/g) ?? [];
    expect(matches.length).toBe(2);
    expect(f.background).toContain("var(--text-muted)");
  });

  it("clean is vertically-hatched with the clean token", () => {
    const f = reputationFill("clean");
    expect(f.background).toContain("repeating-linear-gradient(90deg");
    expect(f.background).toContain("var(--risk-clean)");
  });

  it("keeps opacity in (0, 1] for legibility over the fill", () => {
    for (const r of REPS) {
      const { opacity } = reputationFill(r);
      expect(opacity).toBeGreaterThan(0);
      expect(opacity).toBeLessThanOrEqual(1);
    }
  });
});
