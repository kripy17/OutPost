import type { MeResponse } from "../lib/api";

/** Optional-auth boot gate (used by the Layout in main.tsx).
 *
 * Pure so it's unit-testable: show the login screen exactly when the backend
 * has auth enabled AND this browser has no valid session. Takes no pathname —
 * every path is treated identically, `/login` itself included: the router
 * registers `/login` as a real route, so the sign-in screen renders there in
 * both states (the gate short-circuits to it everywhere else while
 * unauthenticated, and the route renders it when authenticated).
 *
 * History: the gate used to special-case `location.pathname !== "/login"`,
 * but `/login` was never in the router — so a direct visit 404'd instead of
 * showing the sign-in screen. Dropping the special-case AND registering the
 * route fixed both halves; this helper locks the decision.
 */
export function shouldShowLogin(me: MeResponse | undefined): boolean {
  return me !== undefined && me.enabled && !me.authenticated;
}
