// P1.5 — Realtime analyst experience: wire the findings queue, the
// investigations list, and the investigation workspace onto the EXISTING
// SSE contract (alert frames for new detections; run-update frames with
// investigation_id / finding_id for investigation lifecycle + attach/detach).
// No new event type, no backend changes — these three surfaces previously
// only refreshed on their own mutations.
//
// Each test renders the routed page with a fake EventSource, counts refetches
// to the surface's query URL, fires the relevant frame, and asserts the
// targeted invalidation: the named surface refetches, a frame naming a
// DIFFERENT investigation does not touch the workspace.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { RouterProvider } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_FETCH = globalThis.fetch;

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

const ok = (data: unknown, status = 200) => ({ ok: status < 400, status, json: async () => data });

function shellStub(counters: { queue?: () => unknown; list?: () => unknown; detail?: () => unknown }) {
  return vi.fn((input: RequestInfo | URL) => {
    const u = String(input);
    if (u.includes("/auth/me"))
      return Promise.resolve(ok({ enabled: true, authenticated: true, role: "analyst", read_only: false, credential_mode: "hash", expires_at: null }));
    // /rules/meta BEFORE /meta (substring collision: the meta branch would
    // swallow the rules-meta URL and return an object, breaking the page).
    if (u.includes("/rules/meta")) return Promise.resolve(ok([]));
    if (u.includes("/meta")) return Promise.resolve(ok({ first_run: false, demo_mode: false, version: "test" }));
    if (u.includes("/platform")) return Promise.resolve(ok({ os: "linux", name: "Linux", release: "6.7", machine: "x86_64", python: "3.12", collector: "auditd" }));
    if (u.includes("/health")) return Promise.resolve(ok(true));
    if (u.includes("/campaigns") || u.includes("/events")) return Promise.resolve(ok([]));
    if (u.includes("/runs")) return Promise.resolve(ok([]));
    if (u.includes("/alerts/queue")) return Promise.resolve(ok(counters.queue ? counters.queue() : { total: 0, limit: 50, offset: 0, alerts: [] }));
    if (u.includes("/alerts")) return Promise.resolve(ok([]));
    // GET /investigations/{id} (detail) BEFORE the list URL which is /investigations?.
    if (u.includes("/investigations/")) return Promise.resolve(ok(counters.detail ? counters.detail() : { id: "inv1", title: "C2 beaconing", status: "active", severity: "malicious", conclusion: null, created_by: "analyst", created_at: "2026-08-18T08:00:00Z", updated_at: "2026-08-18T08:30:00Z", closed_at: null, finding_count: 1, ref_count: 1, tags: [], findings: [], refs: [], notes: [] }));
    if (u.includes("/investigations")) return Promise.resolve(ok(counters.list ? counters.list() : { total: 0, limit: 100, offset: 0, investigations: [] }));
    return Promise.resolve(ok({}));
  });
}

function renderAt(path: string, fetchStub: (input: RequestInfo | URL) => Promise<unknown>) {
  window.history.pushState({}, "", path);
  vi.resetModules();
  vi.stubGlobal("fetch", fetchStub);
  return import("../appRouter").then(({ router: freshRouter }) =>
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <RouterProvider router={freshRouter} />
      </QueryClientProvider>,
    ),
  );
}

describe("P1.5 realtime analyst surfaces (SSE)", () => {
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

  it("an alert frame refetches the findings queue and the statusbar", async () => {
    let queueCalls = 0;
    const stub = shellStub({ queue: () => {
      queueCalls += 1;
      return { total: 1, limit: 50, offset: 0, alerts: [{ id: 1, rule_name: "beaconing", severity: "malicious", status: "open", run_id: "r1", host_ids: ["archlinux"], related_pids: [] }] };
    } });
    await renderAt("/findings", stub);
    // Initial render fires the queue query.
    await waitFor(() => expect(queueCalls).toBeGreaterThan(0));
    const before = queueCalls;
    // A new detection lands: the backend publishes an alert frame.
    FakeEventSource.instances[0].fire("alert", {
      rule_id: "rule-1", rule_name: "beaconing", severity: "malicious", run_id: "r1", details: "beaconing to 203.0.113.88", triggered_at: "2026-08-18T09:00:00Z",
    });
    await waitFor(() => expect(queueCalls).toBeGreaterThan(before));
  });

  it("a run-update naming a finding refetches the queue (attach/detach moved a link)", async () => {
    let queueCalls = 0;
    const stub = shellStub({ queue: () => {
      queueCalls += 1;
      return { total: 0, limit: 50, offset: 0, alerts: [] };
    } });
    await renderAt("/findings", stub);
    await waitFor(() => expect(queueCalls).toBeGreaterThan(0));
    const before = queueCalls;
    FakeEventSource.instances[0].fire("run-update", {
      run_id: "r1", events: 0, investigation_id: "inv1", finding_id: 42,
    });
    await waitFor(() => expect(queueCalls).toBeGreaterThan(before));
  });

  it("an investigation frame refetches the investigations list (case created/closed elsewhere)", async () => {
    let listCalls = 0;
    const stub = shellStub({ list: () => {
      listCalls += 1;
      return { total: 1, limit: 100, offset: 0, investigations: [{ id: "inv1", title: "C2 beaconing", status: "active", severity: "malicious", conclusion: null, created_by: "analyst", created_at: "2026-08-18T08:00:00Z", updated_at: "2026-08-18T08:30:00Z", closed_at: null, finding_count: 1, ref_count: 1, tags: [] }] };
    } });
    await renderAt("/investigations", stub);
    await waitFor(() => expect(listCalls).toBeGreaterThan(0));
    const before = listCalls;
    // A case was reopened from the CLI: lifecycle frame.
    FakeEventSource.instances[0].fire("run-update", { run_id: "", events: 0, investigation_id: "inv1" });
    await waitFor(() => expect(listCalls).toBeGreaterThan(before));
  });

  it("a frame naming THIS case refetches the investigation workspace", async () => {
    let detailCalls = 0;
    const stub = shellStub({ detail: () => {
      detailCalls += 1;
      return { id: "inv1", title: "C2 beaconing", status: "active", severity: "malicious", conclusion: null, created_by: "analyst", created_at: "2026-08-18T08:00:00Z", updated_at: "2026-08-18T08:30:00Z", closed_at: null, finding_count: 1, ref_count: 1, tags: [], findings: [], refs: [], notes: [] };
    } });
    await renderAt("/investigations/inv1", stub);
    await waitFor(() => expect(screen.getByText("C2 beaconing")).toBeTruthy());
    const before = detailCalls;
    // A finding was attached from the run-detail triage panel.
    FakeEventSource.instances[0].fire("run-update", { run_id: "r1", events: 0, investigation_id: "inv1", finding_id: 42 });
    await waitFor(() => expect(detailCalls).toBeGreaterThan(before));
  });

  it("a frame naming a DIFFERENT case does NOT refetch the open workspace (targeted invalidation)", async () => {
    let detailCalls = 0;
    const stub = shellStub({ detail: () => {
      detailCalls += 1;
      return { id: "inv1", title: "C2 beaconing", status: "active", severity: "malicious", conclusion: null, created_by: "analyst", created_at: "2026-08-18T08:00:00Z", updated_at: "2026-08-18T08:30:00Z", closed_at: null, finding_count: 1, ref_count: 1, tags: [], findings: [], refs: [], notes: [] };
    } });
    await renderAt("/investigations/inv1", stub);
    await waitFor(() => expect(screen.getByText("C2 beaconing")).toBeTruthy());
    const before = detailCalls;
    // Another case changed — inv1 must not refetch.
    FakeEventSource.instances[0].fire("run-update", { run_id: "r2", events: 0, investigation_id: "inv-other" });
    await new Promise((r) => setTimeout(r, 300));
    expect(detailCalls).toBe(before);
  });
});
