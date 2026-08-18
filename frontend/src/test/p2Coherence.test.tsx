// P2 — Analyst-surface coherence pass: every place a host id appears should
// deep-link into the P1.4 `/hosts/{hostId}` aggregate-timeline workspace
// (the agents page already models the pattern: workspace link + a runs-list
// filter), and every finding carrying an `investigation_id` (P0.3 attach)
// should surface its case link so an analyst can move finding → case
// without leaving the queue.
//
// Pinned here:
//  - findings queue: host chip → /hosts/{h}; case chip → /investigations/{id}
//  - events feed:    host chip → /hosts/{host_id} ("local" stays plain text)
//  - run detail:     host chip → /hosts/{h} workspace + a secondary runs link
//  - history page:   the ?host= filter chip links into the host workspace

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { RouterProvider } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const ORIGINAL_FETCH = globalThis.fetch;

const ok = (data: unknown, status = 200) => ({ ok: status < 400, status, json: async () => data });

const HOST_ID = "agent-archlinux";

const queueAlert = {
  id: 41,
  run_id: "run1",
  sample_name: "evil.exe",
  rule_id: "rule-beacon",
  rule_name: "beaconing",
  severity: "malicious",
  triggered_at: "2026-08-18T08:00:00Z",
  status: "open",
  status_comment: null,
  status_at: null,
  assignee: null,
  related_pid: null,
  related_ip: "203.0.113.88",
  related_pids: [],
  host_ids: [HOST_ID],
  details: "beaconing to 203.0.113.88",
  investigation_id: "inv-c2",
};

const runDetail = {
  run: {
    run_id: "run1",
    sample_name: "evil.exe",
    platform: "windows",
    session_type: "analysis",
    source: "sandbox:anyrun",
    host_ids: [HOST_ID],
    started_at: "2026-08-18T08:00:00Z",
    completed_at: "2026-08-18T08:00:10Z",
    process_count: 4,
    unique_ips: 2,
    alert_count: 1,
    highest_severity: "malicious",
    risk_score: 71,
  },
  alerts: [],
  events: [],
  iocs: [],
  processes: [],
  notes: [],
  process_tree: [],
  network_connections: [],
  timeline: [],
};

function shellStub(overrides: Record<string, unknown> = {}) {
  return vi.fn((input: RequestInfo | URL) => {
    const u = String(input);
    if (u.includes("/auth/me"))
      return Promise.resolve(ok({ enabled: true, authenticated: true, role: "analyst", read_only: false, credential_mode: "hash", expires_at: null }));
    if (u.includes("/rules/suppressions")) return Promise.resolve(ok([]));
    if (u.includes("/rules/meta")) return Promise.resolve(ok([]));
    if (u.includes("/meta")) return Promise.resolve(ok({ first_run: false, demo_mode: false, version: "test" }));
    if (u.includes("/platform")) return Promise.resolve(ok({ os: "linux", name: "Linux", release: "6.7", machine: "x86_64", python: "3.12", collector: "auditd" }));
    if (u.includes("/health")) return Promise.resolve(ok(true));
    if (u.includes("/campaigns")) return Promise.resolve(ok([]));
    if (u.includes("/alerts/queue"))
      return Promise.resolve(ok(overrides.queue ?? { total: 1, limit: 50, offset: 0, alerts: [queueAlert] }));
    if (u.includes("/alerts")) return Promise.resolve(ok([]));
    if (u.includes("/events/counts"))
      return Promise.resolve(ok({ total: 0, types: { all: 0, process_create: 0, network_connection: 0, file_write: 0, registry_write: 0 }, channels: { total: 0, live: 0, sandbox: 0, webapp: 0, cli: 0 } }));
    if (u.includes("/events/channel-counts")) return Promise.resolve(ok([]));
    if (u.includes("/events")) return Promise.resolve(ok(overrides.events ?? { total: 1, limit: 100, offset: 0, events: [] }));
    if (u.includes("/runs/run1/notes")) return Promise.resolve(ok([]));
    if (u.includes("/runs/")) return Promise.resolve(ok(overrides.run ?? runDetail));
    if (u.includes("/runs")) return Promise.resolve(ok([]));
    return Promise.resolve(ok(overrides.fallback ?? {}));
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

// The routed pages render under the full app shell + lazy route chunks — the
// same load class P1.4 hit (default 1000ms waitFor expired under the parallel
// pool on a contended machine). Follow that convention: generous explicit
// timeouts on every waitFor so this suite stays deterministic.
const ROUTED_TIMEOUT = 5000;

function linkHrefs(): string[] {
  return Array.from(document.querySelectorAll("a"))
    .map((a) => a.getAttribute("href"))
    .filter((h): h is string => !!h);
}

describe("P2 analyst-surface coherence", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.resetModules();
    vi.stubGlobal("EventSource", class { addEventListener() {} close() {} });
  });
  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("findings queue: host chip deep-links to the host workspace", async () => {
    await renderAt("/findings", shellStub());
    await waitFor(() => expect(linkHrefs()).toContain(`/hosts/${HOST_ID}`), { timeout: ROUTED_TIMEOUT });
    // The link carries the aggregate-timeline title, proving it is the
    // workspace entry, not a run-list filter.
    const hostLink = Array.from(document.querySelectorAll("a")).find((a) => a.getAttribute("href") === `/hosts/${HOST_ID}`);
    expect(hostLink?.getAttribute("title")).toContain("aggregate timeline");
  });

  it("findings queue: an attached finding surfaces its case link", async () => {
    await renderAt("/findings", shellStub());
    await waitFor(() => expect(linkHrefs()).toContain("/investigations/inv-c2"), { timeout: ROUTED_TIMEOUT });
    expect(screen.getByText(/case inv-c2/)).toBeTruthy();
  });

  it("findings queue: findings without a case render no case link", async () => {
    const stub = shellStub({
      queue: { total: 1, limit: 50, offset: 0, alerts: [{ ...queueAlert, investigation_id: null }] },
    });
    await renderAt("/findings", stub);
    await waitFor(() => expect(screen.getByText("beaconing to 203.0.113.88")).toBeTruthy(), { timeout: ROUTED_TIMEOUT });
    expect(linkHrefs().filter((h) => h.startsWith("/investigations/"))).toHaveLength(0);
  });

  it("events feed: host chip deep-links to the host workspace; local stays text", async () => {
    const stub = shellStub({
      events: {
        total: 2,
        limit: 100,
        offset: 0,
        events: [
          { id: 1, event_type: "network_connection", timestamp: "2026-08-18T08:00:00Z", host_id: HOST_ID, sample_name: "evil.exe", run_id: "run1", pid: 1, ppid: 0, process_name: "evil.exe", command_line: "evil.exe -c", dest_ip: "203.0.113.88", dest_port: 443, file_path: null, registry_key: null, severity: "malicious", source: "sandbox:anyrun", synthetic: false },
          { id: 2, event_type: "process_create", timestamp: "2026-08-18T08:00:01Z", host_id: null, sample_name: "local-run", run_id: "run2", pid: 2, ppid: 1, process_name: "sh", command_line: "sh -c whoami", dest_ip: null, dest_port: null, file_path: null, registry_key: null, severity: "suspicious", source: "live", synthetic: false },
        ],
      },
    });
    await renderAt("/events", stub);
    await waitFor(() => expect(linkHrefs()).toContain(`/hosts/${HOST_ID}`), { timeout: ROUTED_TIMEOUT });
    // The null-host row renders "local" as plain text — no host workspace link.
    expect(screen.getByText("local")).toBeTruthy();
    expect(linkHrefs()).not.toContain("/hosts/local");
  });

  it("run detail: host chip leads to the workspace, with a runs-list secondary", async () => {
    await renderAt("/runs/run1", shellStub());
    await waitFor(() => expect(linkHrefs()).toContain(`/hosts/${HOST_ID}`), { timeout: ROUTED_TIMEOUT });
    await waitFor(() => expect(linkHrefs()).toContain(`/history?host=${HOST_ID}`), { timeout: ROUTED_TIMEOUT });
    // The workspace link is the primary (first) chip; the runs filter is the
    // secondary "runs" chip — both reachable from the header.
    expect(screen.getByText("runs")).toBeTruthy();
  });

  it("history page: the active host filter chip links into the host workspace", async () => {
    await renderAt("/history?host=agent-archlinux", shellStub({ runs: { total: 0, limit: 50, offset: 0, runs: [] } }));
    await waitFor(() => expect(linkHrefs()).toContain("/hosts/agent-archlinux"), { timeout: ROUTED_TIMEOUT });
  });
});
