// Findings triage queue contracts — the pure derivations behind the queue:
// age labels (what "oldest first" renders) and the live status-tab badges
// (the "All" badge must sum the three status buckets).

import { beforeEach, describe, expect, it } from "vitest";
import {
  ageLabel,
  clearSavedProvenances,
  PAGE,
  PROVENANCE_STORAGE_PREFIX,
  provenanceChips,
  provenanceLabel,
  readSavedProvenance,
  STATUS_TABS,
  statusTabCount,
  writeSavedProvenance,
} from "../routes/findingsHelpers";
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

describe("provenance persistence (per status tab)", () => {
  beforeEach(() => localStorage.clear());

  it("saves and restores the choice per status tab, independently", () => {
    expect(readSavedProvenance("open")).toBe("");
    writeSavedProvenance("open", "real");
    expect(readSavedProvenance("open")).toBe("real");
    // The other tabs keep their own (empty) preference.
    expect(readSavedProvenance("acknowledged")).toBe("");
    writeSavedProvenance("acknowledged", "synthetic");
    expect(readSavedProvenance("open")).toBe("real");
    expect(readSavedProvenance("acknowledged")).toBe("synthetic");
    expect(localStorage.getItem(`${PROVENANCE_STORAGE_PREFIX}open`)).toBe("real");
  });

  it("clearing removes the preference so the tab falls back to all", () => {
    writeSavedProvenance("open", "real");
    writeSavedProvenance("open", "");
    expect(readSavedProvenance("open")).toBe("");
    expect(localStorage.getItem(`${PROVENANCE_STORAGE_PREFIX}open`)).toBeNull();
  });

  it("ignores corrupted values and reads empty when never saved", () => {
    writeSavedProvenance("open", "");
    expect(readSavedProvenance("open")).toBe("");
    localStorage.setItem(`${PROVENANCE_STORAGE_PREFIX}open`, "banana");
    expect(readSavedProvenance("open")).toBe("");
  });
});

describe("clearSavedProvenances (Settings one-click wipe)", () => {
  beforeEach(() => localStorage.clear());

  it("wipes every per-tab choice plus the archive's legacy key", () => {
    writeSavedProvenance("open", "real");
    writeSavedProvenance("acknowledged", "synthetic");
    writeSavedProvenance("all", "real");
    localStorage.setItem("outpost-history-synthetic", "1");
    clearSavedProvenances();
    for (const t of STATUS_TABS.map((s) => s.v)) {
      expect(readSavedProvenance(t)).toBe("");
      expect(localStorage.getItem(`${PROVENANCE_STORAGE_PREFIX}${t}`)).toBeNull();
    }
    expect(localStorage.getItem("outpost-history-synthetic")).toBeNull();
  });

  it("sweeps stray prefixed keys beyond the four known tabs", () => {
    localStorage.setItem(`${PROVENANCE_STORAGE_PREFIX}legacy-tab`, "real");
    clearSavedProvenances();
    expect(localStorage.getItem(`${PROVENANCE_STORAGE_PREFIX}legacy-tab`)).toBeNull();
  });

  it("leaves unrelated preferences untouched", () => {
    localStorage.setItem("outpost-palette", "teal");
    localStorage.setItem("outpost-theme-v2", "dark");
    clearSavedProvenances();
    expect(localStorage.getItem("outpost-palette")).toBe("teal");
    expect(localStorage.getItem("outpost-theme-v2")).toBe("dark");
  });

  it("is a no-op when nothing is saved", () => {
    expect(() => clearSavedProvenances()).not.toThrow();
    expect(readSavedProvenance("open")).toBe("");
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

describe("provenanceLabel + provenanceChips (sweep saved-split strip)", () => {
  beforeEach(() => localStorage.clear());

  it("labels the three provenance values with the shared vocabulary", () => {
    expect(provenanceLabel("real")).toBe("real hosts");
    expect(provenanceLabel("synthetic")).toBe("synthetic");
    expect(provenanceLabel("")).toBe("all");
  });

  it("shows the active tab's effective split and the others' saved values", () => {
    writeSavedProvenance("open", "real");
    writeSavedProvenance("acknowledged", "synthetic");
    expect(provenanceChips("open", "real")).toEqual([
      { tab: "open", label: "Open", value: "real", active: true },
      { tab: "acknowledged", label: "Acknowledged", value: "synthetic", active: false },
      { tab: "resolved", label: "Resolved", value: "", active: false },
      { tab: "all", label: "All", value: "", active: false },
    ]);
  });

  it("an explicit effective split overrides the active tab's saved value", () => {
    writeSavedProvenance("open", "real");
    const open = provenanceChips("open", "synthetic").find((c) => c.tab === "open");
    expect(open?.value).toBe("synthetic"); // what the queue is actually showing
    expect(open?.active).toBe(true);
  });

  it("other tabs stay independent of the active tab's choice", () => {
    writeSavedProvenance("all", "real");
    const chips = provenanceChips("open", "");
    expect(chips.find((c) => c.tab === "all")?.value).toBe("real");
    expect(chips.find((c) => c.tab === "open")?.value).toBe("");
  });
});

describe("PAGE", () => {
  it("is the pagination page size used by the queue fetch", () => {
    expect(PAGE).toBe(25);
  });
});
