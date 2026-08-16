// shouldShowLogin — the optional-auth boot gate decision (main.tsx Layout).
// Locks both states of the gate: enabled+unauthenticated shows the login
// screen, every other state shows the app. The signature takes NO pathname —
// the regression this guards is the removed `/login` special-case: the gate
// used to treat `/login` differently while the router never registered the
// path, so a direct visit 404'd. Every path (including `/login`) must be
// identical to the gate now, with the route itself rendering the screen.

import { describe, expect, it } from "vitest";
import { shouldShowLogin } from "../routes/authGate";
import type { MeResponse } from "../lib/api";

function me(overrides: Partial<MeResponse> = {}): MeResponse {
  return {
    enabled: true,
    authenticated: false,
    role: "admin",
    read_only: false,
    credential_mode: "hash",
    expires_at: null,
    ...overrides,
  };
}

describe("shouldShowLogin", () => {
  it("shows the login screen when auth is enabled and unauthenticated", () => {
    expect(shouldShowLogin(me())).toBe(true);
  });

  it("hides the login screen when authenticated", () => {
    expect(shouldShowLogin(me({ authenticated: true, role: "admin" }))).toBe(false);
    expect(shouldShowLogin(me({ authenticated: true, role: "analyst", read_only: true }))).toBe(false);
  });

  it("hides the login screen when auth is disabled (zero-config default)", () => {
    expect(shouldShowLogin(me({ enabled: false }))).toBe(false);
  });

  it("hides the login screen while the boot probe is still loading", () => {
    expect(shouldShowLogin(undefined)).toBe(false);
  });
});
