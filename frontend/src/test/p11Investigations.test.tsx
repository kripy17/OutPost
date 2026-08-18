// P1.1 — Investigations: the P0.3 backend consumed by the webapp.
//
// Part 1 pins the api.ts investigation functions against mocked fetch
// (URL, method, body, response typing) — the CLI mirrors the same endpoints
// via api_client.py. Part 2 renders the real router at /investigations and
// /investigations/:id and asserts the workspace surfaces the header,
// findings, refs, and notes with real data.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { RouterProvider } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  addInvestigationNote,
  addInvestigationRef,
  closeInvestigation,
  createInvestigation,
  getInvestigation,
  listInvestigations,
  patchInvestigation,
  removeInvestigationRef,
  reopenInvestigation,
  setAlertInvestigation,
} from "../lib/api";

const ORIGINAL_FETCH = globalThis.fetch;
const BASE = "http://localhost:8001"; // VITE_API_URL in the test env

function mockFetchOnce(status: number, body: unknown) {
  globalThis.fetch = vi.fn().mockResolvedValue(
    new Response(body === null || status === 204 ? null : JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  ) as unknown as typeof fetch;
}

// ---------------------------------------------------------------------------
// Part 1 — api.ts contract (same endpoints the CLI api_client.py hits)
// ---------------------------------------------------------------------------

describe("P1.1 investigation API contracts", () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
    vi.restoreAllMocks();
  });

  it("createInvestigation POSTs /investigations with title + tags", async () => {
    mockFetchOnce(201, {
      id: "inv1", title: "C2 beaconing", status: "created", severity: null, conclusion: null,
      created_by: "analyst", created_at: "2026-08-17T00:00:00Z", updated_at: null, closed_at: null,
      finding_count: 0, ref_count: 0, tags: ["c2"],
    });
    const out = await createInvestigation({ title: "C2 beaconing", tags: ["c2"] });
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/investigations`),
      expect.objectContaining({ method: "POST", body: JSON.stringify({ title: "C2 beaconing", tags: ["c2"] }) }),
    );
    expect(out.status).toBe("created");
  });

  it("listInvestigations GETs /investigations with status + q filters", async () => {
    mockFetchOnce(200, { total: 1, limit: 50, offset: 0, investigations: [] });
    await listInvestigations({ status: "active", q: "beacon" });
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/investigations?status=active&q=beacon`),
      expect.anything(),
    );
  });

  it("getInvestigation GETs the detail payload with findings/refs/notes", async () => {
    mockFetchOnce(200, {
      id: "inv1", title: "Case", status: "active", severity: "malicious", conclusion: null,
      created_by: "analyst", created_at: "2026-08-17T00:00:00Z", updated_at: "2026-08-17T01:00:00Z",
      closed_at: null, finding_count: 1, ref_count: 2, tags: [],
      findings: [{ id: 7, run_id: "r1", rule_id: "beaconing", rule_name: "beaconing", severity: "malicious", triggered_at: "2026-08-17T00:30:00Z", related_pid: null, related_ip: "203.0.113.1", details: "beaconing", status: "open", status_comment: null, status_at: null, source: "detection", confidence: "high", disposition: null, seen_at: null, investigation_id: "inv1" }],
      refs: [{ investigation_id: "inv1", ref_type: "ioc", ref_id: "203.0.113.1", added_at: "2026-08-17T00:00:00Z" }],
      notes: [{ id: 1, investigation_id: "inv1", note: "Beacons every 30s", actor: "analyst", created_at: "2026-08-17T00:00:00Z" }],
    });
    const out = await getInvestigation("inv1");
    expect(fetch).toHaveBeenCalledWith(expect.stringContaining(`${BASE}/investigations/inv1`), expect.anything());
    expect(out.findings[0].investigation_id).toBe("inv1");
    expect(out.notes[0].actor).toBe("analyst");
    expect(out.refs[0].ref_type).toBe("ioc");
  });

  it("patchInvestigation PATCHes status; close/reopen POST the lifecycle routes", async () => {
    mockFetchOnce(200, { id: "inv1", title: "Case", status: "contained", finding_count: 0, ref_count: 0, tags: [] });
    await patchInvestigation("inv1", { status: "contained" });
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/investigations/inv1`),
      expect.objectContaining({ method: "PATCH", body: JSON.stringify({ status: "contained" }) }),
    );

    mockFetchOnce(200, { id: "inv1", title: "Case", status: "closed", finding_count: 0, ref_count: 0, tags: [] });
    await closeInvestigation("inv1", { conclusion: "FP — demo noise" });
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/investigations/inv1/close`),
      expect.objectContaining({ method: "POST", body: JSON.stringify({ conclusion: "FP — demo noise" }) }),
    );

    mockFetchOnce(200, { id: "inv1", title: "Case", status: "active", finding_count: 0, ref_count: 0, tags: [] });
    await reopenInvestigation("inv1");
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/investigations/inv1/reopen`),
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("ref add/remove and note append hit the right routes", async () => {
    mockFetchOnce(201, { investigation_id: "inv1", ref_type: "host", ref_id: "archlinux", added_at: "2026-08-17T00:00:00Z" });
    await addInvestigationRef("inv1", { ref_type: "host", ref_id: "archlinux" });
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/investigations/inv1/refs`),
      expect.objectContaining({ method: "POST", body: JSON.stringify({ ref_type: "host", ref_id: "archlinux" }) }),
    );

    mockFetchOnce(204, null);
    await removeInvestigationRef("inv1", "archlinux");
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/investigations/inv1/refs/archlinux`),
      expect.objectContaining({ method: "DELETE" }),
    );

    mockFetchOnce(201, { id: 2, investigation_id: "inv1", note: "Confirmed", actor: "analyst", created_at: "2026-08-17T00:00:00Z" });
    await addInvestigationNote("inv1", { note: "Confirmed" });
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/investigations/inv1/notes`),
      expect.objectContaining({ method: "POST", body: JSON.stringify({ note: "Confirmed" }) }),
    );
  });

  it("setAlertInvestigation carries the current status so detach never moves triage state", async () => {
    mockFetchOnce(200, { id: 7, run_id: "r1", rule_id: "beaconing", rule_name: "beaconing", severity: "malicious", triggered_at: "2026-08-17T00:00:00Z", related_pid: null, related_ip: null, details: "d", status: "acknowledged", status_comment: null, status_at: null });
    await setAlertInvestigation(7, null, "acknowledged");
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/alerts/7`),
      expect.objectContaining({ method: "PATCH", body: JSON.stringify({ status: "acknowledged", investigation_id: null }) }),
    );
  });
});

// ---------------------------------------------------------------------------
// Part 2 — the workspace renders with real data (route-level)
// ---------------------------------------------------------------------------

const ok = (data: unknown) => ({ ok: true, status: 200, json: async () => data });

const INVESTIGATION_DETAIL = {
  id: "inv1", title: "C2 beaconing across agent fleet", status: "active", severity: "malicious",
  conclusion: null, created_by: "analyst", created_at: "2026-08-17T00:00:00Z",
  updated_at: "2026-08-17T01:00:00Z", closed_at: null, finding_count: 1, ref_count: 2,
  tags: ["c2", "fleet"],
  findings: [{
    id: 7, run_id: "r1", rule_id: "beaconing", rule_name: "beaconing", severity: "malicious",
    triggered_at: "2026-08-17T00:30:00Z", related_pid: null, related_ip: "203.0.113.1",
    details: "beaconing to 203.0.113.1 every 30s", status: "open", status_comment: null,
    status_at: null, source: "detection", confidence: "high", disposition: null,
    seen_at: null, investigation_id: "inv1",
  }],
  refs: [
    { investigation_id: "inv1", ref_type: "ioc", ref_id: "203.0.113.1", added_at: "2026-08-17T00:00:00Z" },
    { investigation_id: "inv1", ref_type: "run", ref_id: "r1", added_at: "2026-08-17T00:00:00Z" },
  ],
  notes: [
    { id: 1, investigation_id: "inv1", note: "Beacons every 30s — matches detonate-demo pattern", actor: "analyst", created_at: "2026-08-17T00:00:00Z" },
  ],
};

describe("P1.1 investigation workspace (routed)", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        const u = String(url);
        if (u.includes("/auth/me")) {
          return Promise.resolve(ok({ enabled: true, authenticated: true, role: "analyst", read_only: false, credential_mode: "hash", expires_at: null }));
        }
        if (u.includes("/meta")) return Promise.resolve(ok({ first_run: false, demo_mode: false, version: "test" }));
        if (u.includes("/platform")) return Promise.resolve(ok({ os: "linux", name: "Linux", release: "6.7", machine: "x86_64", python: "3.12", collector: "auditd" }));
        if (u.includes("/investigations/inv1")) return Promise.resolve(ok(INVESTIGATION_DETAIL));
        if (u.includes("/investigations")) return Promise.resolve(ok({ total: 1, limit: 50, offset: 0, investigations: [{ ...INVESTIGATION_DETAIL, findings: undefined, refs: undefined, notes: undefined }] }));
        // Overview shell surfaces (rendered before the navigation settles) —
        // empty collections keep the spotlight panels from crashing.
        if (u.includes("/campaigns") || u.includes("/runs") || u.includes("/events")) return Promise.resolve(ok([]));
        if (u.includes("/rules/meta") || u.includes("/rules")) return Promise.resolve(ok([]));
        if (u.includes("/alerts")) return Promise.resolve(ok({ total: 0, open: 0, acknowledged: 0, resolved: 0, sort: "aging", limit: 24, offset: 0, alerts: [] }));
        return Promise.resolve(ok({}));
      }),
    );
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

  it("renders the list page with the case title", async () => {
    await renderAt("/investigations");
    await waitFor(() => expect(screen.getByText("Investigations")).toBeTruthy(), { timeout: 5000 });
    await waitFor(() => expect(screen.getByText("C2 beaconing across agent fleet")).toBeTruthy(), { timeout: 5000 });
  });

  it("renders the workspace: header, findings, refs, notes", async () => {
    await renderAt("/investigations/inv1");
    await waitFor(() => expect(screen.getByText("C2 beaconing across agent fleet")).toBeTruthy(), { timeout: 5000 });
    // Findings panel: rule name + details (the rule id chip renders the same
    // string, so assert via the unique detail text).
    await waitFor(() => expect(screen.getAllByText("beaconing").length).toBeGreaterThan(0), { timeout: 5000 });
    expect(screen.getByText(/beaconing to 203\.0\.113\.1/)).toBeTruthy();
    // Refs panel.
    expect(screen.getByText("203.0.113.1")).toBeTruthy();
    // Notes panel.
    expect(screen.getByText(/Beacons every 30s/)).toBeTruthy();
    // Close action present while open.
    expect(screen.getByText("Close case")).toBeTruthy();
  });
});
