// Settings page pure helpers — the "Clear demo data" flow (dependency-injected
// for deterministic tests) and the login-guard label helpers. Moved out of the
// route file so the page stays fast-refreshable and the helpers stay
// unit-testable in isolation.

import type { ResetResult } from "../lib/api";

/** The Settings "Clear demo data" flow, extracted for deterministic tests.
 *  Branches: cancel → no-op; success → busy then a confirmation message plus a
 *  deferred reload; failure → error message and busy cleared. */
export async function runResetFlow(deps: {
  confirm: () => boolean;
  resetStore: () => Promise<ResetResult>;
  setBusy: (b: "reset" | null) => void;
  setMsg: (m: { ok: boolean; text: string } | null) => void;
  reload: () => void;
}): Promise<void> {
  if (!deps.confirm()) return;
  deps.setBusy("reset");
  try {
    const out = await deps.resetStore();
    deps.setMsg({
      ok: true,
      text: `Cleared ${out.deleted_runs} demo/synthetic run${out.deleted_runs === 1 ? "" : "s"} (${out.deleted_events} events) — kept ${out.kept_runs} local-host session${out.kept_runs === 1 ? "" : "s"}. Reloading…`,
    });
    window.setTimeout(() => deps.reload(), 900);
  } catch (e) {
    deps.setMsg({ ok: false, text: e instanceof Error ? e.message : "Reset failed." });
    deps.setBusy(null);
  }
}

/** Pure label helpers for the login-guard panel. */
export function rateLimitBadge(enabled: boolean): string {
  return enabled ? "active" : "auth off · inactive";
}

export function lockedIpsText(n: number): string {
  if (n === 0) return "No IPs currently locked out.";
  return `${n} IP${n === 1 ? " is" : "s are"} locked out — even valid passwords are refused until the cooldown expires.`;
}
