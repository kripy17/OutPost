// Unit tests for the Rules/Campaigns persistence additions:
//  - readYaraDraft / readEnumDrafts validation — corrupt or malformed storage
//    must degrade to null (restore falls back to defaults), never throw or
//    restore garbage.
//  - sortCampaigns — the Campaigns ordering contract (reputation / size /
//    newest), including stability for ties.

import { describe, expect, it } from "vitest";
import { readEnumDrafts, readYaraDraft, writeEnumDrafts } from "../routes/rules";
import { sortCampaigns } from "../routes/campaigns";
import type { Campaign, EnumPatternRow } from "../types";

function campaign({ key, ...over }: Omit<Partial<Campaign>, "key"> & { key: string }): Campaign {
  return {
    runs: [],
    iocs: { ips: [], registry_keys: [], file_paths: [], processes: [] },
    timeline: [],
    span_start: null,
    span_end: null,
    reputation: null,
    watchlist: false,
    watchlist_label: null,
    ...over,
    key,
  };
}

describe("readYaraDraft", () => {
  const valid = { ruleText: "rule x { condition: true }", family: "custom", description: "d", scope: "all", picked: [] };

  it("returns the saved draft", () => {
    localStorage.setItem("outpost-yara-draft", JSON.stringify(valid));
    expect(readYaraDraft()).toEqual(valid);
  });

  it("returns null when nothing is stored", () => {
    localStorage.removeItem("outpost-yara-draft");
    expect(readYaraDraft()).toBeNull();
  });

  it("returns null on corrupt JSON instead of throwing", () => {
    localStorage.setItem("outpost-yara-draft", "{nope");
    expect(readYaraDraft()).toBeNull();
  });

  it("rejects drafts with an invalid scope", () => {
    localStorage.setItem("outpost-yara-draft", JSON.stringify({ ...valid, scope: "admin" }));
    expect(readYaraDraft()).toBeNull();
  });

  it("rejects drafts missing the rule text", () => {
    localStorage.setItem("outpost-yara-draft", JSON.stringify({ family: "custom" }));
    expect(readYaraDraft()).toBeNull();
  });

  it("filters picked to strings only", () => {
    localStorage.setItem("outpost-yara-draft", JSON.stringify({ ...valid, picked: ["a", 42, "b"] }));
    expect(readYaraDraft()?.picked).toEqual(["a", "b"]);
  });
});

describe("readEnumDrafts", () => {
  const row: EnumPatternRow = { pattern: "whoami", label: "identity" };

  it("returns the saved per-platform drafts", () => {
    localStorage.setItem("outpost-enum-drafts", JSON.stringify({ linux: [row] }));
    expect(readEnumDrafts()).toEqual({ linux: [row] });
  });

  it("drops malformed rows instead of failing", () => {
    localStorage.setItem("outpost-enum-drafts", JSON.stringify({ linux: [row, { pattern: 7 }] }));
    expect(readEnumDrafts()).toEqual({ linux: [row] });
  });

  it("returns null when no platform has a valid row", () => {
    localStorage.setItem("outpost-enum-drafts", JSON.stringify({ linux: [{ pattern: 7 }] }));
    expect(readEnumDrafts()).toBeNull();
  });

  it("returns null on corrupt JSON", () => {
    localStorage.setItem("outpost-enum-drafts", "["); // array, not object
    expect(readEnumDrafts()).toBeNull();
  });
});

describe("writeEnumDrafts (storage honesty)", () => {
  it("stores drafts when non-empty", () => {
    writeEnumDrafts({ linux: [{ pattern: "whoami", label: "identity" }] });
    expect(localStorage.getItem("outpost-enum-drafts")).toContain("whoami");
  });

  it("removes the key when cleared (discard leaves no stale entry)", () => {
    writeEnumDrafts({ linux: [{ pattern: "whoami", label: "identity" }] });
    writeEnumDrafts({});
    expect(localStorage.getItem("outpost-enum-drafts")).toBeNull();
  });
});

describe("sortCampaigns", () => {
  const mal = campaign({ key: "5.6.7.8", reputation: "malicious", runs: [{ run_id: "r1" } as never], span_start: "2026-08-01T00:00:00Z" });
  const sus = campaign({ key: "1.2.3.4", reputation: "suspicious", runs: [{ run_id: "r2" } as never, { run_id: "r3" } as never], span_start: "2026-08-05T00:00:00Z" });
  const unk = campaign({ key: "9.9.9.9", reputation: null, runs: [{ run_id: "r4" } as never, { run_id: "r5" } as never, { run_id: "r6" } as never], span_start: "2026-08-03T00:00:00Z" });

  it("sorts reputation-first (malicious → suspicious → unknown)", () => {
    expect(sortCampaigns([unk, mal, sus], "reputation").map((c) => c.key)).toEqual(["5.6.7.8", "1.2.3.4", "9.9.9.9"]);
  });

  it("sorts by member-run count descending", () => {
    expect(sortCampaigns([mal, unk, sus], "size").map((c) => c.key)).toEqual(["9.9.9.9", "1.2.3.4", "5.6.7.8"]);
  });

  it("sorts by most recent span start first", () => {
    expect(sortCampaigns([mal, unk, sus], "newest").map((c) => c.key)).toEqual(["1.2.3.4", "9.9.9.9", "5.6.7.8"]);
  });

  it("is stable for ties (keeps input order) and does not mutate the input", () => {
    const a = campaign({ key: "a", reputation: "unknown" });
    const b = campaign({ key: "b", reputation: "unknown" });
    const input = [a, b];
    const out = sortCampaigns(input, "reputation");
    expect(out.map((c) => c.key)).toEqual(["a", "b"]);
    expect(input.map((c) => c.key)).toEqual(["a", "b"]); // not mutated
  });
});
