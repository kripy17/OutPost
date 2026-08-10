// The Settings "Clear demo data" danger-zone flow (runResetFlow):
//   - cancel leaves the store untouched (no call, no busy, no reload)
//   - success shows the cleared/kept summary and reloads after a beat
//   - failure shows an error and clears the busy state, never reloads
// Wording is asserted too: 1 run/session singularizes.

import { afterEach, describe, expect, it, vi } from "vitest";
import { runResetFlow } from "../routes/settings";
import type { ResetResult } from "../lib/api";

const OK_RESULT: ResetResult = {
  status: "ok",
  host_id: "archlinux",
  kept_runs: 3,
  demo_mode: false,
  deleted_runs: 2,
  deleted_events: 512,
  deleted_alerts: 41,
};

function flowDeps() {
  const confirm = vi.fn(() => true);
  const resetStore = vi.fn<() => Promise<ResetResult>>(() => Promise.resolve(OK_RESULT));
  const setBusy = vi.fn();
  const setMsg = vi.fn();
  const reload = vi.fn();
  return { deps: { confirm, resetStore, setBusy, setMsg, reload }, confirm, resetStore, setBusy, setMsg, reload };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("runResetFlow — confirmation", () => {
  it("does nothing when the operator cancels the confirm", async () => {
    const { deps, confirm, resetStore, setBusy, setMsg, reload } = flowDeps();
    confirm.mockReturnValue(false);
    await runResetFlow(deps);
    expect(confirm).toHaveBeenCalledOnce();
    expect(resetStore).not.toHaveBeenCalled();
    expect(setBusy).not.toHaveBeenCalled();
    expect(setMsg).not.toHaveBeenCalled();
    expect(reload).not.toHaveBeenCalled();
  });

  it("clears the store on confirm and reloads after the beat", async () => {
    vi.useFakeTimers();
    const { deps, resetStore, setBusy, setMsg, reload } = flowDeps();
    const p = runResetFlow(deps);
    expect(setBusy).toHaveBeenCalledWith("reset"); // busy set before the await resolves
    await p;
    expect(resetStore).toHaveBeenCalledOnce();
    expect(setMsg).toHaveBeenCalledWith({
      ok: true,
      text: "Cleared 2 demo/synthetic runs (512 events) — kept 3 local-host sessions. Reloading…",
    });
    expect(reload).not.toHaveBeenCalled(); // deferred
    vi.advanceTimersByTime(900);
    expect(reload).toHaveBeenCalledOnce();
  });

  it("singularizes 1 run / 1 session in the summary", async () => {
    vi.useFakeTimers();
    const { deps, setMsg, reload } = flowDeps();
    resetStoreMock(deps, 1);
    await runResetFlow(deps);
    expect(setMsg).toHaveBeenCalledWith({
      ok: true,
      text: "Cleared 1 demo/synthetic run (6 events) — kept 1 local-host session. Reloading…",
    });
    vi.advanceTimersByTime(900);
    expect(reload).toHaveBeenCalledOnce();
  });

  it("shows the API error and clears busy without reloading on failure", async () => {
    vi.useFakeTimers();
    const { deps, resetStore, setBusy, setMsg, reload } = flowDeps();
    resetStore.mockRejectedValue(new Error("auth required"));
    await runResetFlow(deps);
    expect(setMsg).toHaveBeenCalledWith({ ok: false, text: "auth required" });
    expect(setBusy).toHaveBeenLastCalledWith(null);
    vi.advanceTimersByTime(2000);
    expect(reload).not.toHaveBeenCalled();
  });

  it("falls back to a generic message for non-Error rejections", async () => {
    const { deps, resetStore, setMsg } = flowDeps();
    resetStore.mockRejectedValue("boom");
    await runResetFlow(deps);
    expect(setMsg).toHaveBeenCalledWith({ ok: false, text: "Reset failed." });
  });
});

function resetStoreMock(deps: Parameters<typeof runResetFlow>[0], deletedRuns: number) {
  (deps.resetStore as ReturnType<typeof vi.fn>).mockResolvedValue({
    ...OK_RESULT,
    deleted_runs: deletedRuns,
    kept_runs: 1,
    deleted_events: 6,
    deleted_alerts: 3,
  });
}
