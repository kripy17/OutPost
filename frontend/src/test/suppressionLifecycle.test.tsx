// The full suppression lifecycle, as an e2e regression test — this is the
// live walk (add → appears in the shared list → remove → every surface
// reflects it) turned into a test. What it pins:
//
//  1. The run-detail alert row's one-click "suppress" POSTs a RUN-scoped
//     suppression, and the shared ["suppressions"] query refetch flips the
//     row into the ✓ suppressed chip WHILE the bottom SuppressionPanel
//     simultaneously shows "1 for this run" with a restore row — one
//     mutation, two surfaces, one refetch.
//  2. "restore" in the panel DELETEs it, and both surfaces flip back.
//  3. The queue sweep (Findings page) POSTs a VALUE-scoped suppression into
//     the SAME store the run-detail surfaces read — the shared key + its
//     invalidation is the contract that keeps every triage surface in sync.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AlertBanner from "../components/AlertBanner/AlertBanner";
import { SuppressionPanel } from "../components/TriagePanels/TriagePanels";
import type { Alert, QueueAlert, QueueResponse, Suppression } from "../types";
import FindingsPage from "../routes/findings";

const RUN = "r1";
const SAMPLE = "detonate-demo.sh";

function alertFixture(over: Partial<Alert> = {}): Alert {
  return {
    id: 1,
    run_id: RUN,
    rule_id: "beaconing",
    rule_name: "Beaconing to a fixed destination",
    severity: "suspicious",
    triggered_at: "2026-08-16T10:00:00Z",
    related_pid: 1234,
    related_ip: "203.0.113.88",
    related_pids: [1234],
    details: "3 beacon intervals to 203.0.113.88 (variance 0.12s)",
    status: "open",
    status_comment: null,
    status_at: null,
    ...over,
  };
}

function queueAlertFixture(over: Partial<QueueAlert> = {}): QueueAlert {
  return {
    id: 1,
    run_id: RUN,
    sample_name: SAMPLE,
    rule_id: "beaconing",
    rule_name: "Beaconing to a fixed destination",
    severity: "suspicious",
    triggered_at: "2026-08-16T10:00:00Z",
    status: "open",
    status_comment: null,
    status_at: null,
    assignee: null,
    related_pid: 1234,
    related_ip: "203.0.113.88",
    related_pids: [1234],
    host_ids: ["agent-archlinux"],
    details: "3 beacon intervals to 203.0.113.88 (variance 0.12s)",
    ...over,
  };
}

/** Stateful fetch mock with a suppression store, mirroring the real backend:
 *  POSTs append, GETs return the list, DELETEs remove by id. The queue and
 *  rule-meta endpoints are seeded so both pages render without real I/O. */
function stubFetch(initialSuppressions: Suppression[] = []) {
  const store: Suppression[] = [...initialSuppressions];
  const calls: { method: string; url: string; body?: string }[] = [];
  let nextId = initialSuppressions.length + 1;

  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      const u = String(url);
      const body = typeof init?.body === "string" ? init.body : undefined;
      calls.push({ method, url: u, body });

      const ok = (data: unknown, status = 200) => ({
        ok: status >= 200 && status < 300,
        status,
        json: async () => data,
      });

      if (u.includes("/rules/suppressions")) {
        if (method === "POST") {
          const p = JSON.parse(body ?? "{}") as { rule_id: string; reason: string; run_id: string | null; value: string | null };
          const created: Suppression = {
            id: nextId++,
            rule_id: p.rule_id,
            run_id: p.run_id,
            value: p.value,
            reason: p.reason || null,
            created_at: "2026-08-16T12:00:00Z",
          };
          store.push(created);
          return Promise.resolve(ok(created, 201));
        }
        if (method === "DELETE") {
          const id = Number(u.match(/\/rules\/suppressions\/(\d+)$/)?.[1]);
          const idx = store.findIndex((s) => s.id === id);
          if (idx >= 0) store.splice(idx, 1);
          return Promise.resolve(ok({}, 204));
        }
        return Promise.resolve(ok([...store]));
      }
      if (u.includes("/alerts/queue")) {
        const q: QueueResponse = {
          total: 1,
          open: 1,
          acknowledged: 0,
          resolved: 0,
          sort: "aging",
          limit: 25,
          offset: 0,
          alerts: [queueAlertFixture()],
        };
        return Promise.resolve(ok(q));
      }
      if (u.includes("/rules/meta")) {
        return Promise.resolve(
          ok([
            {
              rule_id: "beaconing",
              rule_name: "Beaconing to a fixed destination",
              tactic: "Command and Control",
              technique: "T1071",
              weight: 60,
            },
          ]),
        );
      }
      return Promise.resolve(ok({}));
    }),
  );
  return { store, calls };
}

function renderRunDetailSurfaces(store: Suppression[], calls: { method: string; url: string; body?: string }[]) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const alerts = [alertFixture()];
  render(
    <QueryClientProvider client={queryClient}>
      {/* AlertBanner renders pid-jump Links to the process view. */}
      <MemoryRouter initialEntries={[`/runs/${RUN}`]}>
        <AlertBanner
          alerts={alerts}
          triage
          runId={RUN}
          sampleName={SAMPLE}
          onStatus={vi.fn()}
          onBulkStatus={vi.fn()}
        />
        <SuppressionPanel runId={RUN} alerts={alerts} sampleName={SAMPLE} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { queryClient, alerts, store, calls };
}

describe("suppression lifecycle — run-detail surfaces (row + panel)", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("adds from the alert row, shows in both surfaces, removes from the panel, and both flip back", async () => {
    const { store, calls } = stubFetch();
    renderRunDetailSurfaces(store, calls);

    // Initial: the row offers suppress; the panel reports nothing active.
    // (The panel's fired-rule chip shares a similar title — pin the row
    // button by its "— stop it from firing on future batches" suffix.)
    const rowBtn = await screen.findByTitle(/Suppress Beaconing to a fixed destination for this run — stop it from firing/);
    expect(screen.getByText("0 for this run")).toBeInTheDocument();
    expect(screen.queryByText("suppressed")).not.toBeInTheDocument();

    // One click on the row → run-scoped POST → both surfaces flip together.
    // "suppressed" appears TWICE — the row's ✓ chip AND the panel's list
    // row — which is exactly the shared-key sync this test pins.
    fireEvent.click(rowBtn);
    await waitFor(
      () => {
        expect(screen.getByText("1 for this run")).toBeInTheDocument();
        expect(screen.getAllByText("suppressed").length).toBeGreaterThanOrEqual(2);
        expect(screen.getByText("beaconing ✓")).toBeInTheDocument();
      },
      { timeout: 2000 },
    );
    const post = calls.find((c) => c.method === "POST");
    expect(post).toBeTruthy();
    expect(JSON.parse(post!.body ?? "{}")).toMatchObject({ rule_id: "beaconing", run_id: RUN, value: null });
    expect(store).toHaveLength(1);
    // The row's suppress button is gone (the chip replaced it).
    expect(screen.queryByTitle(/Suppress Beaconing to a fixed destination for this run — stop it from firing/)).not.toBeInTheDocument();

    // Restore from the panel → DELETE → both surfaces flip back.
    fireEvent.click(screen.getByRole("button", { name: "restore" }));
    await waitFor(
      () => {
        expect(screen.getByText("0 for this run")).toBeInTheDocument();
        expect(screen.getByTitle(/Suppress Beaconing to a fixed destination for this run — stop it from firing/)).toBeInTheDocument();
      },
      { timeout: 2000 },
    );
    expect(screen.queryByText("suppressed")).not.toBeInTheDocument();
    expect(calls.some((c) => c.method === "DELETE" && /\/rules\/suppressions\/1$/.test(c.url))).toBe(true);
    expect(store).toHaveLength(0);
  });
});

describe("suppression lifecycle — queue sweep writes the shared store", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("the Findings page's suppress lands in the same list the run-detail panel reads", async () => {
    const { store, calls } = stubFetch();
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const alerts = [alertFixture()];
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/findings"]}>
          <FindingsPage />
          {/* The run-detail surface reading the SAME ["suppressions"] key. */}
          <SuppressionPanel runId={RUN} alerts={alerts} sampleName={SAMPLE} />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    // The queue row renders its suppress action scoped to the sample/C2.
    const queueRowBtn = await screen.findByTitle(/Suppress beaconing for detonate-demo\.sh/);
    expect(screen.getByText("0 for this run")).toBeInTheDocument();

    fireEvent.click(queueRowBtn);
    await waitFor(
      () => {
        // The queue's own feedback…
        expect(screen.getByText(/Suppressed 1 rule scope\(s\)/)).toBeInTheDocument();
        // …and the run-detail panel now sees the value-scoped suppression.
        expect(screen.getByText("1 for this run")).toBeInTheDocument();
      },
      { timeout: 2000 },
    );
    const post = calls.find((c) => c.method === "POST");
    expect(post).toBeTruthy();
    // Queue sweep suppresses GLOBAL value-scoped (run_id null, value = sample).
    expect(JSON.parse(post!.body ?? "{}")).toMatchObject({ rule_id: "beaconing", run_id: null, value: SAMPLE });
    expect(store).toHaveLength(1);
    // The panel lists the value scope chip → detonate-demo.sh.
    expect(screen.getByText(`→ ${SAMPLE}`)).toBeInTheDocument();
  });
});
