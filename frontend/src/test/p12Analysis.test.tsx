// P1.2 — Analysis workflow: the P0.2 persisted-jobs backend + P0.7
// run-update stream consumed by the webapp.
//
// Part 1 pins the two new api.ts functions (observations + findings) against
// mocked fetch — createAnalysisJob/list/get/cancel were already pinned in
// p08ClientContracts. Part 2 renders the real router at /analysis and
// /analysis/:runId: the launch form POSTs the right body and navigates into
// the workspace; the workspace renders status/progress/observations/findings;
// cancel flips a queued job to its terminal state; a failed job surfaces its
// error honestly; and a run-update SSE frame with the job's id drives the
// page from queued → completed through the shared stream hub.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { RouterProvider } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getAnalysisFindings, getAnalysisObservations } from "../lib/api";

const ORIGINAL_FETCH = globalThis.fetch;
const BASE = "http://localhost:8001"; // VITE_API_URL in the test env
const RUN = "j0b123456789";

function mockFetchOnce(status: number, body: unknown) {
  globalThis.fetch = vi.fn().mockResolvedValue(
    new Response(body === null || status === 204 ? null : JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  ) as unknown as typeof fetch;
}

// ---------------------------------------------------------------------------
// Part 1 — api.ts contract for the two new analysis sub-resources
// ---------------------------------------------------------------------------

describe("P1.2 analysis API contracts", () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
    vi.restoreAllMocks();
  });

  it("getAnalysisObservations GETs the observations payload", async () => {
    mockFetchOnce(200, {
      backend: "static",
      observations: [{ kind: "strings", data: ["cmd.exe"] }],
    });
    const out = await getAnalysisObservations(RUN);
    expect(fetch).toHaveBeenCalledWith(expect.stringContaining(`${BASE}/analysis/${RUN}/observations`), expect.anything());
    expect(out.observations[0].kind).toBe("strings");
  });

  it("getAnalysisFindings GETs the run's findings (alert rows)", async () => {
    mockFetchOnce(200, [
      {
        id: 9, run_id: RUN, rule_id: "beaconing", rule_name: "beaconing", severity: "malicious",
        triggered_at: "2026-08-17T00:30:00Z", related_pid: null, related_ip: "203.0.113.1",
        details: "beaconing to 203.0.113.1", status: "open", status_comment: null, status_at: null,
        source: "detection", confidence: "high", disposition: null, seen_at: null, investigation_id: null,
      },
    ]);
    const out = await getAnalysisFindings(RUN);
    expect(fetch).toHaveBeenCalledWith(expect.stringContaining(`${BASE}/analysis/${RUN}/findings`), expect.anything());
    expect(out[0].investigation_id).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Part 2 — routed workspace + launch form
// ---------------------------------------------------------------------------

const ok = (data: unknown, status = 200) => ({
  ok: true,
  status,
  json: async () => data,
});

function makeStub(opts: {
  runId: string;
  job: () => Record<string, unknown>;
  observations?: unknown;
  findings?: unknown;
  postAnalysis?: (body: Record<string, unknown>) => Record<string, unknown>;
}) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const u = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    if (u.includes("/auth/me"))
      return Promise.resolve(ok({ enabled: true, authenticated: true, role: "analyst", read_only: false, credential_mode: "hash", expires_at: null }));
    if (u.includes("/meta")) return Promise.resolve(ok({ first_run: false, demo_mode: false, version: "test" }));
    if (u.includes("/platform")) return Promise.resolve(ok({ os: "linux", name: "Linux", release: "6.7", machine: "x86_64", python: "3.12", collector: "auditd" }));
    if (u.includes("/health")) return Promise.resolve(ok(true));
    // Overview shell surfaces (Nav status cluster + spotlight) — empty.
    if (u.includes("/campaigns") || u.includes("/events") || u.includes("/rules/meta")) return Promise.resolve(ok([]));
    if (u.includes("/runs")) return Promise.resolve(ok([]));
    if (u.includes("/alerts")) return Promise.resolve(ok([]));
    if (u.includes("/investigations"))
      return Promise.resolve(ok({ total: 1, limit: 50, offset: 0, investigations: [{ id: "inv1", title: "C2 beaconing", status: "active" }] }));
    if (u.includes("/samples"))
      return Promise.resolve(ok({
        total: 1, returned: 1,
        samples: [{
          sample_id: "s1", original_name: "dropper.bin", sha256: "a".repeat(64),
          detected_platform: "windows", size: 1024, created_at: "2026-08-17T00:00:00Z",
          family: null, yara_rules: [], vt_detections: null, malware_family: null, runs_count: 0,
        }],
      }));
    // Cancel first — it also POSTs under /analysis.
    if (u.includes(`/analysis/${opts.runId}/cancel`) && method === "POST")
      return Promise.resolve(ok({ ...opts.job(), status: "canceled", finished_at: "2026-08-17T01:00:00Z" }));
    if (u.includes("/analysis") && method === "POST") {
      const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
      const created = opts.postAnalysis
        ? opts.postAnalysis(body)
        : { run_id: "newrun", backend: body.backend, status: "completed", progress: 100, events: 0, alerts: 0, risk_score: 0, sample_name: "dropper.bin" };
      return Promise.resolve(ok(created, 201));
    }
    if (u.includes(`/analysis/${opts.runId}/observations`)) return Promise.resolve(ok(opts.observations));
    if (u.includes(`/analysis/${opts.runId}/findings`)) return Promise.resolve(ok(opts.findings));
    if (u.includes("/analysis/")) return Promise.resolve(ok(opts.job()));
    if (u.includes("/analysis")) return Promise.resolve(ok({ total: 1, limit: 100, offset: 0, jobs: [opts.job()] }));
    return Promise.resolve(ok({}));
  });
}

const STATIC_JOB = () => ({
  run_id: RUN, backend: "static", status: "completed", timeout_seconds: null,
  started_at: "2026-08-17T00:00:00Z", finished_at: "2026-08-17T00:00:05Z",
  error: null, progress: 100, result: null, sample_name: "dropper.bin",
  events: 0, alerts: 1, risk_score: 8,
});

const QUEUED_JOB = () => ({
  run_id: RUN, backend: "watched-host", status: "queued", timeout_seconds: 120,
  started_at: null, finished_at: null, error: null, progress: 0, result: null,
  sample_name: "dropper.bin", events: 0, alerts: 0, risk_score: 0,
});

const OBSERVATIONS = {
  backend: "static",
  observations: [
    { kind: "strings", data: ["C:\\Windows\\System32\\cmd.exe", "https://evil.example/x"] },
    { kind: "iocs", data: { urls: ["https://evil.example/x"], ips: ["203.0.113.9"], domains: ["evil.example"], hashes: [], emails: [] } },
    { kind: "pe", data: { machine: "x86-64", bits: 64, entry_point_rva: 4096, imports: ["KERNEL32.dll"] } },
  ],
};

const FINDINGS = [
  {
    id: 9, run_id: RUN, rule_id: "beaconing", rule_name: "beaconing", severity: "malicious",
    triggered_at: "2026-08-17T00:30:00Z", related_pid: null, related_ip: "203.0.113.1",
    details: "beaconing to 203.0.113.1 every 30s", status: "open", status_comment: null,
    status_at: null, source: "detection", confidence: "high", disposition: null,
    seen_at: null, investigation_id: null,
  },
];

describe("P1.2 analysis workspace (routed)", () => {
  beforeEach(() => localStorage.clear());
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

  it("renders the completed static job: stats, observations, findings", async () => {
    const jobState = STATIC_JOB();
    vi.stubGlobal(
      "fetch",
      makeStub({ runId: RUN, job: () => jobState, observations: OBSERVATIONS, findings: FINDINGS }),
    );
    await renderAt(`/analysis/${RUN}`);
    await waitFor(() => expect(screen.getByText("dropper.bin")).toBeTruthy(), { timeout: 5000 });
    // Status pill + derived stats.
    await waitFor(() => expect(screen.getAllByText("completed").length).toBeGreaterThan(0), { timeout: 5000 });
    expect(screen.getByText("8")).toBeTruthy(); // risk score
    // Observations: strings + IOC chips + PE metadata.
    await waitFor(() => expect(screen.getByText("C:\\Windows\\System32\\cmd.exe")).toBeTruthy(), { timeout: 5000 });
    expect(screen.getByText("203.0.113.9")).toBeTruthy();
    expect(screen.getByText("KERNEL32.dll")).toBeTruthy();
    // Findings: rule name + details + the attach picker.
    expect(screen.getByText(/beaconing to 203\.0\.113\.1 every 30s/)).toBeTruthy();
    expect(screen.getByText("Attach to investigation…")).toBeTruthy();
  });

  it("cancel flips a queued job to its terminal state", async () => {
    let jobState: Record<string, unknown> = QUEUED_JOB();
    // The persisted row flips on cancel — the workspace's post-success
    // invalidation refetches the job, so the GET must return canceled too
    // (otherwise the UI would legitimately revert to the stale queued row).
    const stub = makeStub({ runId: RUN, job: () => jobState, observations: OBSERVATIONS, findings: FINDINGS });
    const realStub = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const u = String(input);
      if (u.includes(`/analysis/${RUN}/cancel`)) {
        jobState = { ...jobState, status: "canceled", finished_at: "2026-08-17T01:00:00Z" };
      }
      return stub(input, init);
    });
    vi.stubGlobal("fetch", realStub);
    await renderAt(`/analysis/${RUN}`);
    await waitFor(() => expect(screen.getByText("Cancel job")).toBeTruthy(), { timeout: 5000 });
    fireEvent.click(screen.getByText("Cancel job"));
    // The cancel mutation seeds the canceled state into the cache — the
    // button disappears and the honest terminal panel renders.
    await waitFor(() => expect(screen.getByText("Job canceled")).toBeTruthy(), { timeout: 5000 });
    expect(screen.queryByText("Cancel job")).toBeNull();
  });

  it("surfaces a failed job's error honestly", async () => {
    const jobState = { ...QUEUED_JOB(), status: "failed", error: "executor unavailable", progress: 30 };
    vi.stubGlobal(
      "fetch",
      makeStub({ runId: RUN, job: () => jobState, observations: OBSERVATIONS, findings: FINDINGS }),
    );
    await renderAt(`/analysis/${RUN}`);
    await waitFor(() => expect(screen.getByText("Job failed")).toBeTruthy(), { timeout: 5000 });
    expect(screen.getByText("executor unavailable")).toBeTruthy();
  });

  it("launches a static job from the form and navigates into the workspace", async () => {
    const jobState = STATIC_JOB();
    const created = { run_id: "newrun", backend: "static", status: "completed", progress: 100, events: 0, alerts: 0, risk_score: 0, sample_name: "dropper.bin" };
    const postAnalysis = vi.fn((body: Record<string, unknown>) => {
      expect(body).toEqual({ backend: "static", sample_id: "s1" });
      return created;
    });
    vi.stubGlobal(
      "fetch",
      makeStub({ runId: RUN, job: () => jobState, observations: OBSERVATIONS, findings: FINDINGS, postAnalysis }),
    );
    await renderAt("/analysis");
    await waitFor(() => expect(screen.getByText("New analysis")).toBeTruthy(), { timeout: 5000 });
    fireEvent.click(screen.getByText("New analysis"));
    await waitFor(() => expect(screen.getByText("Backend")).toBeTruthy(), { timeout: 5000 });
    // Pick the sample from the library (artifact selection) — the page also
    // has a backend filter select, so find the combobox holding the sample.
    const selects = screen.getAllByRole("combobox") as HTMLSelectElement[];
    const artifactSelect = selects.find((s) => Array.from(s.options).some((o) => o.value === "s1"))!;
    fireEvent.change(artifactSelect, { target: { value: "s1" } });
    fireEvent.click(screen.getByText("Launch analysis"));
    // POST fired with the right body, then the app navigated to the workspace.
    await waitFor(() => expect(postAnalysis).toHaveBeenCalled(), { timeout: 5000 });
    await waitFor(() => expect(screen.getByText("dropper.bin")).toBeTruthy(), { timeout: 5000 });
  });
});

// ---------------------------------------------------------------------------
// Part 3 — realtime: a run-update SSE frame drives queued → completed
// ---------------------------------------------------------------------------

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  url: string;
  closed = false;
  private listeners = new Map<string, (e: MessageEvent) => void>();
  constructor(url: string) {
    this.url = url;
    FakeEventSource.instances.push(this);
  }
  addEventListener(name: string, fn: (e: MessageEvent) => void) {
    this.listeners.set(name, fn);
  }
  close() {
    this.closed = true;
  }
  fire(name: string, data: unknown) {
    this.listeners.get(name)?.({ data: JSON.stringify(data) } as MessageEvent);
  }
}

describe("P1.2 realtime job progress (SSE)", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.resetModules();
    FakeEventSource.instances = [];
    vi.stubGlobal("EventSource", FakeEventSource);
  });
  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("a run-update frame with the job's id refetches the workspace to completed", async () => {
    let jobState: Record<string, unknown> = QUEUED_JOB();
    const completeJob = STATIC_JOB();
    vi.stubGlobal(
      "fetch",
      makeStub({ runId: RUN, job: () => jobState, observations: OBSERVATIONS, findings: FINDINGS }),
    );
    window.history.pushState({}, "", `/analysis/${RUN}`);
    const { router: freshRouter } = await import("../appRouter");
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <RouterProvider router={freshRouter} />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(screen.getByText("Cancel job")).toBeTruthy(), { timeout: 5000 });
    // The executor finishes: the persisted row flips, and the frame pushes
    // that transition over the shared stream.
    jobState = completeJob;
    FakeEventSource.instances[0].fire("run-update", {
      run_id: RUN, events: 0, completed: true, job_id: RUN, job_status: "completed", progress: 100,
    });
    // The workspace invalidates its queries for this job → refetch → the
    // completed observations render without any manual navigation.
    await waitFor(() => expect(screen.getAllByText("completed").length).toBeGreaterThan(0), { timeout: 3000 });
    await waitFor(() => expect(screen.getByText("C:\\Windows\\System32\\cmd.exe")).toBeTruthy(), { timeout: 3000 });
    expect(screen.queryByText("Cancel job")).toBeNull();
  });
});
