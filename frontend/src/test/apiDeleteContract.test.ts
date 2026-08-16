// DELETE contract (lib/api.ts, exercised through every delete surface).
// A DELETE may legitimately answer 204 (no content) OR 200 with a body — both
// are success. Regression: three helpers used to require exactly 204
// (removeSuppression, watchlistRemove, resetTuning — the last two via their
// own inline fetches), so a backend that 200s a DELETE with a body threw a
// misleading "DELETE ... → 200" error. All three now route through the shared
// `del()` helper; this locks the relaxed contract for every one of them:
// 204 and 200 resolve, any non-ok status throws with the path + status.

import { afterEach, describe, expect, it, vi } from "vitest";
import { removeSuppression, resetTuning, watchlistRemove } from "../lib/api";

/** [name, fire] — the three DELETE surfaces, keyed for readable failures. */
const DELETERS: Array<[string, () => Promise<void>]> = [
  ["removeSuppression", () => removeSuppression(7)],
  ["watchlistRemove", () => watchlistRemove("203.0.113.99")],
  ["resetTuning", () => resetTuning("beaconing.min_interval")],
];

function stubStatus(status: number) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({ ok: status < 400, status, json: async () => ({}) }),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("DELETE contract", () => {
  it.each(DELETERS)("%s accepts 204 (no content) as success", async (_name, fire) => {
    stubStatus(204);
    await expect(fire()).resolves.toBeUndefined();
  });

  it.each(DELETERS)("%s accepts 200 with a body as success", async (_name, fire) => {
    stubStatus(200);
    await expect(fire()).resolves.toBeUndefined();
  });

  it.each(DELETERS)("%s throws a clear error on a non-ok status", async (_name, fire) => {
    stubStatus(500);
    await expect(fire()).rejects.toThrow(/DELETE .*→ 500/);
  });
});
