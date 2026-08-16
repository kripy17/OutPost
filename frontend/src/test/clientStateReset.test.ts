// The Settings "Reset client-side state" contract — one confirmed click wipes
// every known preference/draft (per-tab provenance, IOC search draft, YARA /
// enum / log-pattern drafts) and reports what existed, while unrelated keys
// and corrupted drafts are handled without throwing.

import { beforeEach, describe, expect, it } from "vitest";
import { anyClientState, clientStateSummary, readClientState, resetClientState } from "../routes/resetClientState";
import { writeSavedProvenance } from "../routes/findingsHelpers";
import { writeSavedQuery } from "../routes/searchHelpers";
import { writeYaraDraft } from "../routes/rulesDrafts";
import type { EnumPatternRow } from "../types";

const ROW: EnumPatternRow = { pattern: "cmd /c whoami", label: "identity probe" };

function seedEverything() {
  writeSavedProvenance("open", "real");
  writeSavedProvenance("acknowledged", "synthetic");
  writeSavedQuery("185.220.101.34");
  writeYaraDraft({ ruleText: "rule x { strings: $a = \"y\" condition: $a }", family: "custom", description: "d", scope: "all", picked: [] });
  localStorage.setItem("outpost-enum-drafts", JSON.stringify({ linux: [ROW] }));
  localStorage.setItem("outpost-log-drafts", JSON.stringify({ webshell: { windows: [ROW] } }));
}

describe("resetClientState", () => {
  beforeEach(() => localStorage.clear());

  it("reports every category that has saved state", () => {
    seedEverything();
    expect(readClientState()).toEqual({
      queueTabs: 2,
      searchDraft: true,
      yaraDraft: true,
      enumPlatforms: 1,
      logKinds: 1,
    });
    expect(anyClientState(readClientState())).toBe(true);
  });

  it("wipes all five categories in one call and reports what existed", () => {
    seedEverything();
    const cleared = resetClientState();
    expect(cleared.queueTabs).toBe(2);
    expect(cleared.searchDraft).toBe(true);
    expect(cleared.yaraDraft).toBe(true);
    expect(cleared.enumPlatforms).toBe(1);
    expect(cleared.logKinds).toBe(1);
    expect(readClientState()).toEqual({ queueTabs: 0, searchDraft: false, yaraDraft: false, enumPlatforms: 0, logKinds: 0 });
    expect(anyClientState(readClientState())).toBe(false);
    // The underlying keys are really gone.
    expect(localStorage.getItem("outpost-queue-provenance-open")).toBeNull();
    expect(localStorage.getItem("outpost-search-query")).toBeNull();
    expect(localStorage.getItem("outpost-yara-draft")).toBeNull();
    expect(localStorage.getItem("outpost-enum-drafts")).toBeNull();
    expect(localStorage.getItem("outpost-log-drafts")).toBeNull();
  });

  it("leaves unrelated preferences untouched", () => {
    seedEverything();
    localStorage.setItem("outpost-palette", "teal");
    localStorage.setItem("outpost-theme-v2", "dark");
    resetClientState();
    expect(localStorage.getItem("outpost-palette")).toBe("teal");
    expect(localStorage.getItem("outpost-theme-v2")).toBe("dark");
  });

  it("a partial state reports only what is saved", () => {
    writeSavedQuery("203.0.113.88");
    expect(readClientState()).toEqual({
      queueTabs: 0,
      searchDraft: true,
      yaraDraft: false,
      enumPlatforms: 0,
      logKinds: 0,
    });
    const cleared = resetClientState();
    expect(cleared.searchDraft).toBe(true);
    expect(cleared.queueTabs).toBe(0);
    expect(readClientState().searchDraft).toBe(false);
  });

  it("corrupted drafts read as absent and never throw", () => {
    localStorage.setItem("outpost-yara-draft", "{not json");
    localStorage.setItem("outpost-enum-drafts", "42");
    localStorage.setItem("outpost-log-drafts", "[[[");
    expect(readClientState().yaraDraft).toBe(false);
    expect(() => resetClientState()).not.toThrow();
    expect(localStorage.getItem("outpost-yara-draft")).toBeNull();
  });

  it("an empty store reports nothing and reset is a safe no-op", () => {
    expect(readClientState()).toEqual({ queueTabs: 0, searchDraft: false, yaraDraft: false, enumPlatforms: 0, logKinds: 0 });
    expect(anyClientState(readClientState())).toBe(false);
    expect(() => resetClientState()).not.toThrow();
  });
});

describe("clientStateSummary (shared reset wording)", () => {
  beforeEach(() => localStorage.clear());

  it("names every category that was wiped, in the Settings/palette wording", () => {
    seedEverything();
    const summary = clientStateSummary(resetClientState());
    expect(summary).toBe("cleared 2 provenance tabs, the search draft, the YARA draft, 1 enum table, 1 log-pattern table");
  });

  it("singularizes a single provenance tab", () => {
    writeSavedProvenance("open", "real");
    expect(clientStateSummary(resetClientState())).toBe("cleared 1 provenance tab");
  });

  it("reports when nothing was saved", () => {
    expect(clientStateSummary(resetClientState())).toBe("nothing was saved");
  });
});
