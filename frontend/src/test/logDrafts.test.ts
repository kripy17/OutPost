// Log-pattern draft persistence (rules.tsx → rulesDrafts.ts) — the same
// contract as the YARA/enum drafts: restore in useState initializers, clear
// on successful save, corrupt storage degrades to null (never throws), and
// rows that don't match the EnumPatternRow shape are filtered out.

import { beforeEach, describe, expect, it } from "vitest";
import { clearLogDrafts, readLogDrafts, writeLogDrafts, type LogDrafts } from "../routes/rulesDrafts";
import type { EnumPatternRow } from "../types";

const row = (over: Partial<EnumPatternRow> = {}): EnumPatternRow => ({ pattern: "EventID=1102", label: "log clear", ...over });

const drafts: LogDrafts = {
  log_clear: {
    windows: [row()],
    linux: [row({ pattern: "audit.*cleared", label: "audit log cleared" })],
  },
  service_stop: {
    windows: [row({ pattern: "Service Control Manager", label: "svc stop" })],
  },
};

beforeEach(() => localStorage.clear());

describe("readLogDrafts / writeLogDrafts", () => {
  it("round-trips a valid draft set", () => {
    writeLogDrafts(drafts);
    expect(readLogDrafts()).toEqual(drafts);
  });

  it("returns null when nothing is stored", () => {
    expect(readLogDrafts()).toBeNull();
  });

  it("returns null on corrupt JSON instead of throwing", () => {
    localStorage.setItem("outpost-log-drafts", "{nope");
    expect(readLogDrafts()).toBeNull();
  });

  it("returns null for valid JSON that is not an object (array / scalar)", () => {
    localStorage.setItem("outpost-log-drafts", "[]");
    expect(readLogDrafts()).toBeNull();
    localStorage.setItem("outpost-log-drafts", "42");
    expect(readLogDrafts()).toBeNull();
  });

  it("filters malformed rows to valid EnumPatternRows only", () => {
    const dirty: LogDrafts = {
      log_clear: {
        windows: [row(), { pattern: "x" } as unknown as EnumPatternRow, null as unknown as EnumPatternRow],
      },
      service_stop: {},
    };
    writeLogDrafts(dirty);
    expect(readLogDrafts()?.log_clear.windows).toEqual([row()]);
  });

  it("drops kinds/platforms that end up empty after filtering", () => {
    const dirty = {
      log_clear: { windows: [] },
      service_stop: { windows: [row()] },
    } as unknown as LogDrafts;
    writeLogDrafts(dirty);
    const out = readLogDrafts();
    expect(out).not.toBeNull();
    expect(out!.log_clear).toBeUndefined();
    expect(out!.service_stop.windows).toEqual([row()]);
  });

  it("returns null when every row is invalid", () => {
    const dirty = { log_clear: { windows: [{ pattern: 7 } as unknown as EnumPatternRow] } } as unknown as LogDrafts;
    writeLogDrafts(dirty);
    expect(readLogDrafts()).toBeNull();
  });
});

describe("clearLogDrafts", () => {
  it("removes the stored draft", () => {
    writeLogDrafts(drafts);
    clearLogDrafts();
    expect(readLogDrafts()).toBeNull();
  });

  it("writeLogDrafts with an empty set also clears storage", () => {
    writeLogDrafts(drafts);
    writeLogDrafts({} as LogDrafts);
    expect(readLogDrafts()).toBeNull();
  });
});
