// Regression tests for Event Log filter persistence. The contract:
//   - A bare /events visit (no filter params in the URL) restores the last-used
//     filter set from localStorage.
//   - Any filter param in the URL wins — deep links keep their explicit state.
//   - Missing / corrupt / unreadable storage degrades to "no saved filters".
// This locks the ordering bug where the URL-mirror effect wrote the empty
// default into localStorage *before* the restore read it, silently killing
// persistence on every remount.

import { describe, expect, it } from "vitest";
import { resolveSavedFilters } from "../routes/events";
import type { SavedFilters } from "../routes/events";

const saved: SavedFilters = { severity: "malicious", category: "network_connection", q: "8.8.8.8", pids: [1001, 1002] };
const storage = JSON.stringify(saved);

const noParams = () => null;
const params = (k: string) => (k === "severity" ? "suspicious" : null);
const read = () => storage;

describe("resolveSavedFilters", () => {
  it("restores the saved set on a bare visit", () => {
    expect(resolveSavedFilters(noParams, read)).toEqual(saved);
  });

  it("returns null when the URL carries any filter param (deep link wins)", () => {
    expect(resolveSavedFilters(params, read)).toBeNull();
  });

  it("returns null when storage is empty", () => {
    expect(resolveSavedFilters(noParams, () => null)).toBeNull();
  });

  it("returns null on corrupt JSON instead of throwing", () => {
    expect(resolveSavedFilters(noParams, () => "{not json")).toBeNull();
  });

  it("returns null when storage access throws (privacy mode / blocked)", () => {
    expect(
      resolveSavedFilters(noParams, () => {
        throw new Error("SecurityError");
      }),
    ).toBeNull();
  });

  it("returns null on valid-but-non-object storage", () => {
    expect(resolveSavedFilters(noParams, () => "42")).toBeNull();
  });
});
