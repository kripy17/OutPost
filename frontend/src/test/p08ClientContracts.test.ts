// P0.8 — client contracts for the P0.5/P0.6/P0.7 surfaces.
//
// api.ts is the webapp's ONE backend-call boundary (docs/04). These tests
// pin the new client functions (globalSearch, getHostTimeline, analysis-job
// CRUD) against mocked fetch: correct URL, query params, method, body, and
// response typing. Mirrors cli/tests/test_p0_8.py — the CLI hits the same
// endpoints via api_client.py (terminal parity).

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { cancelAnalysisJob, createAnalysisJob, getAnalysisJob, getHostTimeline, globalSearch, listAnalysisJobs } from "../lib/api";

const ORIGINAL_FETCH = globalThis.fetch;
const BASE = "http://localhost:8001"; // VITE_API_URL in the test env

function mockFetchOnce(status: number, body: unknown) {
  globalThis.fetch = vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }),
  ) as unknown as typeof fetch;
}

beforeEach(() => {
  localStorage.clear();
});

afterEach(() => {
  globalThis.fetch = ORIGINAL_FETCH;
  vi.restoreAllMocks();
});

describe("P0.8 client contracts", () => {
  it("globalSearch hits /search with q + limit", async () => {
    mockFetchOnce(200, {
      q: "203.0.113.1",
      qualifiers: {},
      groups: {
        findings: { total: 1, hits: [{ group: "findings", id: "7", kind: "malicious", title: "beaconing", subtitle: "run1", payload: {} }] },
        iocs: { total: 0, hits: [] },
        artifacts: { total: 0, hits: [] },
        hosts: { total: 0, hits: [] },
        sessions: { total: 0, hits: [] },
        investigations: { total: 0, hits: [] },
        campaigns: { total: 0, hits: [] },
      },
    });
    const out = await globalSearch("203.0.113.1", 5);
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/search?q=203.0.113.1&limit=5`),
      expect.anything(),
    );
    expect(out.groups.findings.hits[0].title).toBe("beaconing");
    expect(out.groups.campaigns.total).toBe(0);
  });

  it("getHostTimeline hits /hosts/{id}/timeline with kind + q + pagination", async () => {
    mockFetchOnce(200, {
      host_id: "archlinux",
      platform: "linux",
      last_heartbeat: null,
      total: 3,
      limit: 20,
      offset: 0,
      timeline: [
        { kind: "finding", timestamp: "2026-08-17T10:00:00Z", id: "7", title: "beaconing", subtitle: "malicious", payload: {} },
        { kind: "ioc", timestamp: "2026-08-17T08:00:00Z", id: "i1", title: "203.0.113.1", subtitle: "ip", payload: {} },
      ],
    });
    const out = await getHostTimeline("archlinux", { kind: "finding", q: "beacon", limit: 20 });
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/hosts/archlinux/timeline?kind=finding&q=beacon&limit=20`),
      expect.anything(),
    );
    expect(out.total).toBe(3);
    expect(out.timeline[0].kind).toBe("finding");
  });

  it("createAnalysisJob POSTs /analysis with the body", async () => {
    mockFetchOnce(201, {
      run_id: "run1",
      backend: "watched-host",
      status: "queued",
      progress: 0,
      events: 0,
      alerts: 0,
      risk_score: 0,
    });
    const out = await createAnalysisJob({ backend: "watched-host", sample_name: "x.bin", platform: "linux" });
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/analysis`),
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ backend: "watched-host", sample_name: "x.bin", platform: "linux" }),
      }),
    );
    expect(out.status).toBe("queued");
  });

  it("listAnalysisJobs GETs /analysis with filters", async () => {
    mockFetchOnce(200, { total: 0, limit: 50, offset: 0, jobs: [] });
    await listAnalysisJobs({ backend: "static", status: "completed" });
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/analysis?backend=static&status=completed`),
      expect.anything(),
    );
  });

  it("getAnalysisJob + cancelAnalysisJob hit the run-scoped endpoints", async () => {
    mockFetchOnce(200, { run_id: "run1", backend: "static", status: "completed", progress: 100, events: 0, alerts: 0, risk_score: 0 });
    const got = await getAnalysisJob("run1");
    expect(got.status).toBe("completed");
    expect(fetch).toHaveBeenCalledWith(expect.stringContaining(`${BASE}/analysis/run1`), expect.anything());

    mockFetchOnce(200, { run_id: "run1", backend: "watched-host", status: "canceled", progress: 0, events: 0, alerts: 0, risk_score: 0 });
    const canceled = await cancelAnalysisJob("run1");
    expect(canceled.status).toBe("canceled");
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`${BASE}/analysis/run1/cancel`),
      expect.objectContaining({ method: "POST" }),
    );
  });
});
