// P1.4 — Host investigation: the P0.6 GET /hosts/{host_id}/timeline contract
// consumed by a first-class /hosts/:hostId workspace.
//
// Part 1 pins the api.ts contract (URL + filter params). Part 2 renders the
// routed workspace and asserts the host context strip, the kind-filtered
// feed, per-kind deep-links, the honest empty feed for a known-but-quiet
// host, the unknown-host 404 state, and load-more pagination.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { RouterProvider } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getHostTimeline } from "../lib/api";

const ORIGINAL_FETCH = globalThis.fetch;
const BASE = "http://localhost:8001"; // VITE_API_URL in the test env

// ---------------------------------------------------------------------------
// Part 1 — api.ts contract
// ---------------------------------------------------------------------------

describe("P1.4 host timeline API contract", () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
    vi.restoreAllMocks();
  });

  it("getHostTimeline GETs /hosts/{id}/timeline with the filter params", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({ host_id: "archlinux", total: 0, limit: 50, offset: 0, timeline: [] }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    ) as unknown as typeof fetch;
    await getHostTimeline("archlinux", { kind: "event", eventType: "process_create", q: "bash", limit: 25, offset: 25 });
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/hosts/archlinux/timeline?kind=event&event_type=process_create&q=bash&limit=25&offset=25`),
      expect.anything(),
    );
  });
});

// ---------------------------------------------------------------------------
// Part 2 — the routed workspace
// ---------------------------------------------------------------------------

const ok = (data: unknown, status = 200) => ({ ok: status < 400, status, json: async () => data });

const TIMELINE_RESPONSE = {
  host_id: "archlinux",
  platform: "linux",
  last_heartbeat: "2026-08-18T09:00:00Z",
  total: 4,
  limit: 50,
  offset: 0,
  timeline: [
    {
      kind: "finding",
      timestamp: "2026-08-18T08:55:00Z",
      id: "41",
      title: "beaconing",
      subtitle: "detonate-demo.sh",
      payload: { alert_id: 41, run_id: "runbeacon1", severity: "malicious", status: "open" },
    },
    {
      kind: "event",
      timestamp: "2026-08-18T08:54:00Z",
      id: "7",
      title: "network connection",
      subtitle: "curl",
      payload: { event_id: 7, run_id: "runbeacon1", event_type: "network_connection", pid: 123, process_name: "curl" },
    },
    {
      kind: "session",
      timestamp: "2026-08-18T08:50:00Z",
      id: "job1",
      title: "evil.exe",
      subtitle: "analysis_job · windows · completed",
      payload: { run_id: "job1", kind: "analysis_job" },
    },
    {
      kind: "ioc",
      timestamp: "2026-08-18T08:40:00Z",
      id: "ioc1",
      title: "203.0.113.88",
      subtitle: "ip · confirmed-malicious",
      payload: { ioc_id: "ioc1", value: "203.0.113.88", type: "ip", disposition: "confirmed-malicious", reputation: "malicious" },
    },
  ],
};

const QUIET_RESPONSE = { host_id: "soak-box", platform: "linux", total: 0, limit: 50, offset: 0, timeline: [] };

const PAGE2_RESPONSE = {
  host_id: "archlinux",
  platform: "linux",
  last_heartbeat: "2026-08-18T09:00:00Z",
  total: 5,
  limit: 2,
  offset: 2,
  timeline: [
    {
      kind: "investigation",
      timestamp: "2026-08-18T08:30:00Z",
      id: "inv1",
      title: "C2 beaconing across agent fleet",
      subtitle: "active",
      payload: { investigation_id: "inv1", status: "active" },
    },
  ],
};

function shellStub(overrides: { onTimeline?: (u: string) => unknown }) {
  return vi.fn((input: RequestInfo | URL) => {
    const u = String(input);
    if (u.includes("/auth/me"))
      return Promise.resolve(ok({ enabled: true, authenticated: true, role: "analyst", read_only: false, credential_mode: "hash", expires_at: null }));
    if (u.includes("/meta")) return Promise.resolve(ok({ first_run: false, demo_mode: false, version: "test" }));
    if (u.includes("/platform")) return Promise.resolve(ok({ os: "linux", name: "Linux", release: "6.7", machine: "x86_64", python: "3.12", collector: "auditd" }));
    if (u.includes("/health")) return Promise.resolve(ok(true));
    if (u.includes("/campaigns") || u.includes("/events") || u.includes("/rules/meta")) return Promise.resolve(ok([]));
    if (u.includes("/runs")) return Promise.resolve(ok([]));
    if (u.includes("/alerts")) return Promise.resolve(ok([]));
    if (u.includes("/investigations")) return Promise.resolve(ok({ total: 0, limit: 50, offset: 0, investigations: [] }));

    if (u.includes("/timeline")) {
      // The override may return a plain payload (wrapped in ok 200 here) or
      // an already-built response (e.g. the 404 error branch) — use as-is.
      const r = overrides.onTimeline ? overrides.onTimeline(u) : TIMELINE_RESPONSE;
      if (r && typeof r === "object" && "ok" in r && "json" in r) return Promise.resolve(r);
      return Promise.resolve(ok(r));
    }
    return Promise.resolve(ok({}));
  });
}

describe("P1.4 host workspace (routed)", () => {
  beforeEach(() => {
    localStorage.clear();
  });
  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
    vi.restoreAllMocks();
  });

  /** Reset modules so the router singleton is created AFTER the pushState,
   *  making the initial route the one under test (mainRouter.test pattern). */
  async function renderAt(path: string) {
    window.history.pushState({}, "", path);
    vi.resetModules();
    const { router: freshRouter } = await import("../appRouter");
    return render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <RouterProvider router={freshRouter} />
      </QueryClientProvider>,
    );
  }

  it("renders host context + the merged feed with kind chips and deep-links", async () => {
    vi.stubGlobal("fetch", shellStub({}));
    await renderAt("/hosts/archlinux");
    // Header + host context strip (the strip renders once the query lands).
    // "linux" appears twice (the nav platform chip + the host context strip).
    await waitFor(() => expect(screen.getByText(/heartbeat/)).toBeTruthy(), { timeout: 5000 });
    expect(screen.getAllByText("linux").length).toBeGreaterThan(0);
    // Feed entries with their kind chips.
    await waitFor(() => expect(screen.getAllByText("beaconing").length).toBeGreaterThan(0), { timeout: 5000 });
    expect(screen.getByText("network connection")).toBeTruthy();
    expect(screen.getByText("203.0.113.88")).toBeTruthy();
    // "4 entries" total.
    expect(screen.getByText("4 entries")).toBeTruthy();
    // Deep-links: finding → run detail; event → run detail; analysis_job
    // session → analysis workspace; ioc → pre-filled IOC search.
    expect(Array.from(document.querySelectorAll("a")).find((a) => a.getAttribute("href") === "/runs/runbeacon1")).toBeTruthy();
    expect(Array.from(document.querySelectorAll("a")).find((a) => a.getAttribute("href") === "/analysis/job1")).toBeTruthy();
    expect(Array.from(document.querySelectorAll("a")).find((a) => a.getAttribute("href") === "/search?q=203.0.113.88")).toBeTruthy();
  });

  it("kind tabs apply the server-side filter (refetch with ?kind=)", async () => {
    const seen: string[] = [];
    vi.stubGlobal(
      "fetch",
      shellStub({
        onTimeline: (u) => {
          if (u.includes("kind=event")) seen.push("event-filtered");
          return TIMELINE_RESPONSE;
        },
      }),
    );
    await renderAt("/hosts/archlinux");
    await waitFor(() => expect(screen.getByText("archlinux")).toBeTruthy(), { timeout: 5000 });
    fireEvent.click(screen.getByRole("button", { name: "Events" }));
    await waitFor(() => expect(seen).toContain("event-filtered"), { timeout: 5000 });
    // The event-type chips appear only in the Events tab.
    expect(screen.getByRole("button", { name: "Process" })).toBeTruthy();
  });

  it("a known-but-quiet host renders the honest empty feed with context", async () => {
    vi.stubGlobal("fetch", shellStub({ onTimeline: () => QUIET_RESPONSE }));
    await renderAt("/hosts/soak-box");
    await waitFor(() => expect(screen.getByText("soak-box")).toBeTruthy(), { timeout: 5000 });
    await waitFor(() => expect(screen.getByText(/No activity recorded for this host/)).toBeTruthy(), { timeout: 5000 });
  });

  it("an unknown host renders the 404 state", async () => {
    vi.stubGlobal(
      "fetch",
      shellStub({
        onTimeline: () => ok({ detail: "Unknown host: ghost" }, 404),
      }),
    );
    await renderAt("/hosts/ghost");
    // The error branch renders once the query rejects; the kicker and title
    // both carry the message so find the state via the body copy + link.
    await waitFor(() => expect(screen.getByText(/no event, heartbeat, or snapshot carries this id/)).toBeTruthy(), { timeout: 5000 });
    expect(screen.getByText(/Back to the fleet/)).toBeTruthy();
  });

  it("pagination path: a larger total surfaces the Load more button and fetches the next offset", async () => {
    const big = { ...TIMELINE_RESPONSE, total: 120 };
    const seenOffsets: string[] = [];
    vi.stubGlobal(
      "fetch",
      shellStub({
        onTimeline: (u) => {
          if (u.includes("offset=50")) {
            seenOffsets.push("offset-50");
            return PAGE2_RESPONSE;
          }
          return big;
        },
      }),
    );
    await renderAt("/hosts/archlinux");
    await waitFor(() => expect(screen.getByText(/120 entries/)).toBeTruthy(), { timeout: 5000 });
    fireEvent.click(screen.getByText(/Load more/));
    await waitFor(() => expect(seenOffsets).toContain("offset-50"), { timeout: 5000 });
  });
});
