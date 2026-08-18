// P1.3 — Global search UX: the P0.5 GET /search contract consumed by the
// webapp as a first-class scope on the /search page.
//
// Part 1 pins the page's IOC scope regression — a bare visit keeps running
// the legacy /ioc/search (all deep-link behavior preserved). Part 2 renders
// the routed page in global mode and asserts grouped results with per-group
// totals, the qualifier echo, the honest empty state, and the deep-links
// into each resource's workspace.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { RouterProvider } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { globalSearch } from "../lib/api";

const ORIGINAL_FETCH = globalThis.fetch;
const BASE = "http://localhost:8001"; // VITE_API_URL in the test env

// ---------------------------------------------------------------------------
// Part 1 — api.ts contract (globalSearch was pinned in p08; re-pin the URL
// here so this suite is self-contained)
// ---------------------------------------------------------------------------

describe("P1.3 global search API contract", () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
    vi.restoreAllMocks();
  });

  it("globalSearch GETs /search with q + limit", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ q: "203.0.113.88", qualifiers: {}, groups: {} }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    ) as unknown as typeof fetch;
    await globalSearch("203.0.113.88", 10);
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/search?q=203.0.113.88&limit=10`),
      expect.anything(),
    );
  });
});

// ---------------------------------------------------------------------------
// Part 2 — the routed page: IOC regression + global rendering
// ---------------------------------------------------------------------------

const ok = (data: unknown) => ({ ok: true, status: 200, json: async () => data });

const GLOBAL_RESPONSE = {
  q: "203.0.113.88",
  qualifiers: { type: "finding", status: "open" },
  groups: {
    findings: {
      total: 2,
      hits: [
        {
          group: "findings", id: "41", kind: "malicious", title: "beaconing",
          subtitle: "detonate-demo.sh", payload: { alert_id: 41, run_id: "runbeacon1", severity: "malicious", status: "open" },
        },
        {
          group: "findings", id: "42", kind: "suspicious", title: "network-scan",
          subtitle: "triple-threat.exe", payload: { alert_id: 42, run_id: "runscan", severity: "suspicious", status: "open" },
        },
      ],
    },
    iocs: {
      total: 1,
      hits: [
        {
          group: "iocs", id: "ioc1", kind: "ip", title: "203.0.113.88",
          subtitle: "confirmed-malicious", payload: { ioc_id: "ioc1", value: "203.0.113.88", type: "ip", disposition: "confirmed-malicious" },
        },
      ],
    },
    artifacts: {
      total: 1,
      hits: [
        {
          group: "artifacts", id: "s1", kind: "windows", title: "evil.exe",
          subtitle: "7ccd9bfcb65b… · 1024 bytes", payload: { sample_id: "s1", original_name: "evil.exe" },
        },
      ],
    },
    hosts: {
      total: 1,
      hits: [
        { group: "hosts", id: "archlinux", kind: "host", title: "archlinux", subtitle: "linux", payload: { host_id: "archlinux", platform: "linux" } },
      ],
    },
    sessions: {
      total: 2,
      hits: [
        {
          group: "sessions", id: "runbeacon1", kind: "monitoring_session", title: "detonate-demo.sh",
          subtitle: "monitoring_session · windows · completed", payload: { run_id: "runbeacon1", kind: "monitoring_session" },
        },
        {
          group: "sessions", id: "job1", kind: "analysis_job", title: "evil.exe",
          subtitle: "analysis_job · windows · completed", payload: { run_id: "job1", kind: "analysis_job" },
        },
      ],
    },
    investigations: {
      total: 1,
      hits: [
        {
          group: "investigations", id: "inv1", kind: "active", title: "C2 beaconing across agent fleet",
          subtitle: "active · 2 findings · 1 refs", payload: { investigation_id: "inv1", status: "active" },
        },
      ],
    },
    campaigns: {
      total: 1,
      hits: [
        {
          group: "campaigns", id: "203.0.113.88", kind: "campaign", title: "203.0.113.88",
          subtitle: "malicious · 9 runs", payload: { key: "203.0.113.88", reputation: "malicious" },
        },
      ],
    },
  },
};

const EMPTY_RESPONSE = {
  q: "zzz-no-match",
  qualifiers: {},
  groups: Object.fromEntries(
    ["findings", "iocs", "artifacts", "hosts", "sessions", "investigations", "campaigns"].map((g) => [g, { total: 0, hits: [] }]),
  ),
};

function shellStub(overrides: { onSearch?: (u: string) => unknown }) {
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
    if (u.includes("/search")) return Promise.resolve(ok(overrides.onSearch ? overrides.onSearch(u) : EMPTY_RESPONSE));
    return Promise.resolve(ok({}));
  });
}

describe("P1.3 search page (routed)", () => {
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

  it("IOC scope is the default: a bare visit keeps the legacy /ioc/search behavior", async () => {
    const seen: string[] = [];
    const stub = shellStub({
      onSearch: (u) => {
        if (u.includes("/ioc/search")) seen.push("ioc-search-called");
        return EMPTY_RESPONSE;
      },
    });
    vi.stubGlobal("fetch", stub);
    await renderAt("/search?q=185.220.101.34");
    // The IOC deep-link runs the legacy search and renders its title.
    await waitFor(() => expect(screen.getByText(/have I seen this before\?/)).toBeTruthy());
    await waitFor(() => expect(seen).toContain("ioc-search-called"));
  });

  it("global mode renders grouped results with totals and qualifier echo", async () => {
    vi.stubGlobal("fetch", shellStub({ onSearch: () => GLOBAL_RESPONSE }));
    await renderAt("/search?mode=global");
    // The heading AND the toggle tab both say "Global search" — assert the
    // toggle is the active tab, which is the unambiguous mode signal.
    await waitFor(() => expect(screen.getByRole("tab", { name: "Global search" }).getAttribute("aria-selected")).toBe("true"));
    const input = screen.getByPlaceholderText(/203\.0\.113\.88/) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "203.0.113.88" } });
    fireEvent.click(screen.getByText("Search"));
    // Summary line.
    await waitFor(() => expect(screen.getByText(/9 matches across 7 resources/)).toBeTruthy());
    // Qualifier echo.
    expect(screen.getByText("type:finding")).toBeTruthy();
    expect(screen.getByText("status:open")).toBeTruthy();
    // Group headers + per-group totals. "Investigations" also appears in
    // the nav rail, so assert presence via getAllByText.
    expect(screen.getAllByText("Findings").length).toBeGreaterThan(0);
    expect(screen.getAllByText("IOCs").length).toBeGreaterThan(0);
    expect(screen.getByText("Sessions & jobs")).toBeTruthy();
    expect(screen.getAllByText("Investigations").length).toBeGreaterThan(0);
    // Hit rows.
    await waitFor(() => expect(screen.getAllByText("beaconing").length).toBeGreaterThan(0));
    expect(screen.getAllByText("203.0.113.88").length).toBeGreaterThan(0);
    expect(screen.getByText("C2 beaconing across agent fleet")).toBeTruthy();
  });

  it("renders the honest empty state when no resource matches", async () => {
    vi.stubGlobal("fetch", shellStub({ onSearch: () => EMPTY_RESPONSE }));
    await renderAt("/search?mode=global");
    await waitFor(() => expect(screen.getByRole("tab", { name: "Global search" }).getAttribute("aria-selected")).toBe("true"));
    const input = screen.getByPlaceholderText(/203\.0\.113\.88/) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "zzz-no-match" } });
    fireEvent.click(screen.getByText("Search"));
    await waitFor(() => expect(screen.getByText(/No matches across any resource/)).toBeTruthy());
  });

  it("deep-links each group into its workspace", async () => {
    vi.stubGlobal("fetch", shellStub({ onSearch: () => GLOBAL_RESPONSE }));
    await renderAt("/search?mode=global");
    await waitFor(() => expect(screen.getByRole("tab", { name: "Global search" }).getAttribute("aria-selected")).toBe("true"));
    const input = screen.getByPlaceholderText(/203\.0\.113\.88/) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "203.0.113.88" } });
    fireEvent.click(screen.getByText("Search"));
    await waitFor(() => expect(screen.getAllByText("beaconing").length).toBeGreaterThan(0));
    // Findings → run detail; IOC → pre-filled legacy search; artifact → sample.
    // (The investigation title also contains "beaconing", so find by href.)
    expect(Array.from(document.querySelectorAll("a")).find((a) => a.getAttribute("href") === "/runs/runbeacon1")).toBeTruthy();
    expect(Array.from(document.querySelectorAll("a")).find((a) => a.getAttribute("href") === "/search?q=203.0.113.88")).toBeTruthy();
    expect(Array.from(document.querySelectorAll("a")).find((a) => a.getAttribute("href") === "/samples/s1")).toBeTruthy();
    // Hosts → fleet page (no host workspace yet); investigation → workspace.
    expect(Array.from(document.querySelectorAll("a")).find((a) => a.getAttribute("href") === "/agents")).toBeTruthy();
    expect(Array.from(document.querySelectorAll("a")).find((a) => a.getAttribute("href") === "/investigations/inv1")).toBeTruthy();
    // Campaigns → clusters page.
    expect(Array.from(document.querySelectorAll("a")).find((a) => a.getAttribute("href") === "/campaigns")).toBeTruthy();
  });

  it("analysis jobs deep-link into the analysis workspace; sessions into run detail", async () => {
    vi.stubGlobal("fetch", shellStub({ onSearch: () => GLOBAL_RESPONSE }));
    await renderAt("/search?mode=global");
    await waitFor(() => expect(screen.getByRole("tab", { name: "Global search" }).getAttribute("aria-selected")).toBe("true"));
    const input = screen.getByPlaceholderText(/203\.0\.113\.88/) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "203.0.113.88" } });
    fireEvent.click(screen.getByText("Search"));
    // The analysis_job session hit ("evil.exe" in Sessions & jobs) links to
    // /analysis/job1; the monitoring_session hit links to /runs/runbeacon1.
    await waitFor(() => expect(screen.getAllByText("detonate-demo.sh").length).toBeGreaterThan(0));
    const jobLink = Array.from(document.querySelectorAll("a")).find((a) => a.getAttribute("href") === "/analysis/job1");
    expect(jobLink).toBeTruthy();
    const sessionLink = Array.from(document.querySelectorAll("a")).find((a) => a.getAttribute("href") === "/runs/runbeacon1");
    expect(sessionLink).toBeTruthy();
  });
});
