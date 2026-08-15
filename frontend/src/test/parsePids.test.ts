// parsePids — the `pid` URL/filter value parser. The contract (from the
// docstring): one integer, or a comma-separated list (the recon-sweep jump —
// every enumerating PID at once). Invalid tokens are dropped silently; the
// backend 422s on genuinely bad input, so the frontend never blocks a typed
// token — it just ignores what isn't a positive integer.

import { describe, expect, it } from "vitest";
import { parsePids } from "../routes/eventsHelpers";

describe("parsePids", () => {
  it("parses a single pid", () => {
    expect(parsePids("5001")).toEqual([5001]);
  });

  it("parses a comma-separated recon list in order", () => {
    expect(parsePids("710,711,712")).toEqual([710, 711, 712]);
  });

  it("trims whitespace around tokens", () => {
    expect(parsePids(" 710 , 711 , 712 ")).toEqual([710, 711, 712]);
  });

  it("dedupes repeated pids", () => {
    expect(parsePids("5001,5001,5001")).toEqual([5001]);
  });

  it("dedupes across a mixed list while keeping first-seen order", () => {
    expect(parsePids("710,712,710,711,712")).toEqual([710, 712, 711]);
  });

  it("silently drops non-numeric tokens", () => {
    expect(parsePids("abc")).toEqual([]);
  });

  it("silently drops zero and negative pids", () => {
    expect(parsePids("0")).toEqual([]);
    expect(parsePids("-5")).toEqual([]);
    expect(parsePids("0,-5,1")).toEqual([1]);
  });

  it("drops invalid tokens but keeps the valid ones (mixed list)", () => {
    expect(parsePids("710,abc,0,712,-1,714")).toEqual([710, 712, 714]);
  });

  it("drops fractional and non-integer numerics", () => {
    expect(parsePids("1.5")).toEqual([]);
    expect(parsePids("710,1.5,712")).toEqual([710, 712]);
  });

  it("returns an empty list for null and empty input", () => {
    expect(parsePids(null)).toEqual([]);
    expect(parsePids("")).toEqual([]);
  });
});
