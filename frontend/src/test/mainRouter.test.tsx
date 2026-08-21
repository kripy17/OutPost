// The /login route fix, covered at the router level. Regression: /login was
// referenced by the boot gate's special-case but never registered, so a
// direct visit rendered the 404 page in both auth states. Now the route is
// registered AND the gate special-case is gone — this test renders the REAL
// router (from ./appRouter, where it lives so main.tsx can stay an
// export-less fast-refreshable entry) at /login and asserts the sign-in
// screen appears:
//   - unauthenticated: the boot gate short-circuits to it from /login
//   - authenticated: the /login route renders it inside the layout
// The NotFound page must never appear in either state.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { RouterProvider } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

const ok = (data: unknown) => ({ ok: true, status: 200, json: async () => data });

let meResponse: Record<string, unknown>;

beforeEach(() => {
  meResponse = {
    enabled: true,
    authenticated: false,
    role: "admin",
    read_only: false,
    credential_mode: "hash",
    expires_at: null,
  };
  // Route-aware fetch: serve every endpoint the boot shell touches so the
  // Layout (and Nav, in the authenticated case) renders without real I/O.
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      const u = String(url);
      if (u.includes("/auth/me")) return Promise.resolve(ok(meResponse));
      if (u.includes("/meta")) return Promise.resolve(ok({ first_run: false, demo_mode: false, version: "test" }));
      if (u.includes("/platform")) {
        return Promise.resolve(
          ok({ os: "linux", name: "Linux", release: "6.7", machine: "x86_64", python: "3.12", collector: "auditd" }),
        );
      }
      if (u.includes("/alerts")) return Promise.resolve(ok([]));
      if (u.includes("/runs")) return Promise.resolve(ok([]));
      return Promise.resolve(ok({}));
    }),
  );
});

/** Mount the real app at /login with the current meResponse. */
async function renderAtLogin() {
  window.history.pushState({}, "", "/login");
  vi.resetModules();
  const { router } = await import("../appRouter");
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe("the /login route", () => {
  it("renders the sign-in screen when unauthenticated (gate path)", async () => {
    await renderAtLogin();
    expect(await screen.findByRole("heading", { name: /sign in/i })).toBeInTheDocument();
    expect(screen.queryByText(/nothing on this route/i)).not.toBeInTheDocument();
  });

  it("renders the sign-in screen when authenticated (route path, not a 404)", async () => {
    meResponse = { ...meResponse, authenticated: true };
    await renderAtLogin();
    expect(await screen.findByRole("heading", { name: /sign in/i })).toBeInTheDocument();
    expect(screen.queryByText(/nothing on this route/i)).not.toBeInTheDocument();
  });
});
