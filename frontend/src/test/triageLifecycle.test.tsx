// The alert-triage lifecycle, as an e2e regression test — the third lifecycle
// test alongside suppressionLifecycle and allowlistLifecycle. It drives the
// REAL AlertBanner (run-detail triage mode) through the REAL updateAlertStatus
// API against a stateful fetch mock standing in for the backend, so the
// whole analyst workflow is pinned:
//
//  1. open → acknowledged (with a comment): the pill flips Acked, the comment
//     renders on the card, the header open-count drops, and the action row
//     swaps Ack/Mark FP for Resolve/Reopen.
//  2. acknowledged → resolved: pill Resolved, only Reopen remains.
//  3. resolved → open (reopen): the full cycle closes — pill back to Open
//     with Ack/Resolve/Mark FP restored.
//  4. The resolve-direct shortcut (open → resolved, skipping ack) and the
//     header's "all triaged" state.
// Each transition asserts the exact PATCH payload (status + comment), so the
// comment-plumbing contract — the part most likely to regress silently — is
// pinned end to end.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { useState } from "react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AlertBanner from "../components/AlertBanner/AlertBanner";
import { bulkUpdateAlertStatus, updateAlertStatus } from "../lib/api";
import type { Alert, AlertStatus, RuleMeta } from "../types";

const RUN = "r1";
const SAMPLE = "detonate-demo.sh";

function alertFixture(id: number, over: Partial<Alert> = {}): Alert {
  return {
    id,
    run_id: RUN,
    rule_id: id === 1 ? "beaconing" : "masquerading",
    rule_name: id === 1 ? "Beaconing to a fixed destination" : "Process masquerading as a system binary",
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

const RULE_META: RuleMeta[] = [
  { rule_id: "beaconing", rule_name: "Beaconing to a fixed destination", technique: "T1071", tactic: "Command and Control", weight: 60, severity: "suspicious" },
  { rule_id: "masquerading", rule_name: "Process masquerading as a system binary", technique: "T1036", tactic: "Defense Evasion", weight: 70, severity: "suspicious" },
];

/** Stateful fetch mock with an alert store, mirroring the backend: PATCH
 *  /alerts/{id} strips the comment (empty → null) and returns the updated
 *  alert — exactly routes_alerts.update_alert_status. The store is what the
 *  harness re-reads, so each transition persists like a real round-trip. */
function stubFetch(initialAlerts: Alert[]) {
  const store: Alert[] = [...initialAlerts];
  const calls: { method: string; url: string; body?: string }[] = [];
  const nextId = Math.max(...store.map((a) => a.id ?? 0), 0) + 1;

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

      if (u.includes("/alerts/") && method === "PATCH") {
        const p = JSON.parse(body ?? "{}") as { status: AlertStatus; comment?: string };
        const id = Number(u.match(/\/alerts\/(\d+)$/)?.[1]);
        const idx = store.findIndex((a) => a.id === id);
        // Backend: comment = (body.comment or "").strip() or None.
        const comment = (p.comment ?? "").trim() || null;
        const updated: Alert = {
          ...store[idx],
          status: p.status,
          status_comment: comment,
          status_at: "2026-08-16T13:00:00Z",
        };
        store[idx] = updated;
        return Promise.resolve(ok(updated));
      }
      if (u.includes("/alerts/bulk") && method === "POST") {
        // Mirror bulk_update_alert_status: one transition across many ids,
        // comment stripped (empty → NULL), returns the updated count.
        const p = JSON.parse(body ?? "{}") as { ids: number[]; status: AlertStatus; comment?: string };
        const comment = (p.comment ?? "").trim() || null;
        for (const id of p.ids) {
          const idx = store.findIndex((a) => a.id === id);
          if (idx >= 0) {
            store[idx] = { ...store[idx], status: p.status, status_comment: comment, status_at: "2026-08-16T13:00:00Z" };
          }
        }
        return Promise.resolve(ok({ updated: p.ids.length }));
      }
      if (u.includes("/rules/meta")) {
        return Promise.resolve(ok(RULE_META));
      }
      if (u.includes("/rules/suppressions")) {
        return Promise.resolve(ok([]));
      }
      if (u.includes("/alerts")) {
        return Promise.resolve(ok([]));
      }
      return Promise.resolve(ok({}));
    }),
  );
  return { store, calls, nextId };
}

/** The run-detail parent, compressed: it holds the alert list in state (the
 *  backend row store) and onStatus round-trips through the REAL api.ts PATCH
 *  before re-rendering — the same shape runDetail's onAlertStatus uses, minus
 *  the run-query refetch (state here stands in for it). */
function TriageHarness({ initialAlerts, storeRef }: { initialAlerts: Alert[]; storeRef: Alert[] }) {
  const [alerts, setAlerts] = useState(initialAlerts);
  const onStatus = (alertId: number, status: AlertStatus, comment?: string) => {
    void updateAlertStatus(alertId, status, comment).then((updated) => {
      setAlerts((prev) => prev.map((a) => (a.id === alertId ? updated : a)));
    });
  };
  // Bulk triage — the run-detail onBulkAlertStatus mirror: POST /alerts/bulk
  // through the real client, then RE-READ the store the way runDetail's
  // invalidation refetches the run rows (the bulk response is only
  // {updated: n}, so the UI state must come from the backend side). This
  // makes the bulk test genuinely pin the round-trip: if the backend never
  // applies the transition, the refetched rows still say open.
  const onBulkStatus = (ids: number[], status: AlertStatus) => {
    void bulkUpdateAlertStatus(ids, status).then(() => {
      setAlerts([...storeRef]);
    });
  };
  return <AlertBanner alerts={alerts} triage runId={RUN} sampleName={SAMPLE} onStatus={onStatus} onBulkStatus={onBulkStatus} />;
}

/** Scope queries to one alert card by its rule name. */
const card = (ruleName: string) => within(screen.getByText(ruleName).closest(".rounded-lg") as HTMLElement);

/** The banner header line — "2 alerts — 1 open". The open-count sits in a
 *  nested <span>, so node-text matchers can't see the whole line; the header
 *  <p> is the only text-sm element whose full textContent is the line. */
const header = (line: string) =>
  screen.getByText((_c, el) => !!el?.classList?.contains("text-sm") && (el.textContent ?? "").replace(/\s+/g, " ").trim() === line);

function renderTriage(alerts: Alert[]) {
  const stub = stubFetch(alerts);
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/runs/${RUN}`]}>
        <TriageHarness initialAlerts={alerts} storeRef={stub.store} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...stub, queryClient };
}

describe("alert triage lifecycle — run-detail panel", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("acks with a comment, resolves, reopens — pill, buttons, header, and PATCH payloads at every step", async () => {
    const { calls, store } = renderTriage([alertFixture(1), alertFixture(2)]);

    // Initial: both open — pill, full action row, header count.
    await screen.findAllByRole("button", { name: "Ack" });
    expect(header("2 alerts — 2 open")).toBeInTheDocument();
    expect(card("Beaconing to a fixed destination").getByText("Open")).toBeInTheDocument();
    expect(card("Beaconing to a fixed destination").getByRole("button", { name: "Ack" })).toBeInTheDocument();
    expect(card("Beaconing to a fixed destination").getByRole("button", { name: "Resolve" })).toBeInTheDocument();

    // ── ack with a comment ────────────────────────────────────────────────
    const c1 = card("Beaconing to a fixed destination");
    fireEvent.change(c1.getByPlaceholderText("Optional comment…"), { target: { value: "seen, will resolve" } });
    fireEvent.click(c1.getByRole("button", { name: "Ack" }));

    await waitFor(
      () => {
        // Pill flips, comment rides along, action row swaps, header drops.
        expect(card("Beaconing to a fixed destination").getByText("Acked")).toBeInTheDocument();
        expect(card("Beaconing to a fixed destination").getByText("“seen, will resolve”")).toBeInTheDocument();
        expect(header("2 alerts — 1 open")).toBeInTheDocument();
        expect(card("Beaconing to a fixed destination").queryByRole("button", { name: "Ack" })).not.toBeInTheDocument();
        expect(card("Beaconing to a fixed destination").getByRole("button", { name: "Reopen" })).toBeInTheDocument();
      },
      { timeout: 2000 },
    );
    const ackPatch = calls.find((c) => c.method === "PATCH" && /\/alerts\/1$/.test(c.url));
    expect(JSON.parse(ackPatch!.body ?? "{}")).toMatchObject({ status: "acknowledged", comment: "seen, will resolve" });
    expect(store.find((a) => a.id === 1)?.status).toBe("acknowledged");

    // ── resolve the acked alert (draft was consumed — empty comment) ──────
    fireEvent.click(card("Beaconing to a fixed destination").getByRole("button", { name: "Resolve" }));
    await waitFor(
      () => {
        expect(card("Beaconing to a fixed destination").getByText("Resolved")).toBeInTheDocument();
        expect(card("Beaconing to a fixed destination").queryByRole("button", { name: "Resolve" })).not.toBeInTheDocument();
        expect(card("Beaconing to a fixed destination").getByRole("button", { name: "Reopen" })).toBeInTheDocument();
      },
      { timeout: 2000 },
    );
    const resolvePatch = calls.find((c) => c.method === "PATCH" && /\/alerts\/1$/.test(c.url) && (c.body ?? "").includes("resolved"));
    expect(JSON.parse(resolvePatch!.body ?? "{}")).toMatchObject({ status: "resolved", comment: "" });

    // ── resolve-direct shortcut on the second alert (skip ack) ────────────
    fireEvent.click(card("Process masquerading as a system binary").getByRole("button", { name: "Resolve" }));
    await waitFor(
      () => {
        // Both now resolved → the header's explicit "all triaged" state.
        expect(header("2 alerts — all triaged")).toBeInTheDocument();
        expect(card("Process masquerading as a system binary").getByText("Resolved")).toBeInTheDocument();
        expect(card("Process masquerading as a system binary").queryByRole("button", { name: "Ack" })).not.toBeInTheDocument();
      },
      { timeout: 2000 },
    );
    const directPatch = calls.find((c) => c.method === "PATCH" && /\/alerts\/2$/.test(c.url));
    expect(JSON.parse(directPatch!.body ?? "{}")).toMatchObject({ status: "resolved", comment: "" });

    // ── reopen one — the full cycle closes ────────────────────────────────
    fireEvent.click(card("Process masquerading as a system binary").getByRole("button", { name: "Reopen" }));
    await waitFor(
      () => {
        expect(header("2 alerts — 1 open")).toBeInTheDocument();
        expect(card("Process masquerading as a system binary").getByText("Open")).toBeInTheDocument();
        // The full open action row is back (Mark FP is gated on the
        // onFalsePositive prop the harness doesn't pass — outside this
        // lifecycle's scope).
        expect(card("Process masquerading as a system binary").getByRole("button", { name: "Ack" })).toBeInTheDocument();
        expect(card("Process masquerading as a system binary").getByRole("button", { name: "Resolve" })).toBeInTheDocument();
      },
      { timeout: 2000 },
    );
    const reopenPatch = calls.find((c) => c.method === "PATCH" && /\/alerts\/2$/.test(c.url) && (c.body ?? "").includes("open"));
    expect(JSON.parse(reopenPatch!.body ?? "{}")).toMatchObject({ status: "open", comment: "" });
    expect(store.find((a) => a.id === 2)?.status).toBe("open");

    // The bare resolve CLEARED the ack comment — the backend records the
    // comment at each transition (empty → NULL), so resolving wipes the
    // prior one. That is the real contract this pins: a comment is attached
    // to the transition that carried it, not accumulated on the alert.
    expect(card("Beaconing to a fixed destination").queryByText("“seen, will resolve”")).not.toBeInTheDocument();
  });

  it("reopen from resolved works on an alert that was never acked (open → resolved → open)", async () => {
    const { calls, store } = renderTriage([alertFixture(3, { rule_id: "beaconing", rule_name: "Beaconing to a fixed destination" })]);

    await screen.findByRole("button", { name: "Resolve" });
    expect(header("1 alert — 1 open")).toBeInTheDocument();

    // Resolve directly from open.
    fireEvent.click(card("Beaconing to a fixed destination").getByRole("button", { name: "Resolve" }));
    await waitFor(() => expect(header("1 alert — all triaged")).toBeInTheDocument(), { timeout: 2000 });
    expect(card("Beaconing to a fixed destination").getByRole("button", { name: "Reopen" })).toBeInTheDocument();

    // Reopen → back to the open action row.
    fireEvent.click(card("Beaconing to a fixed destination").getByRole("button", { name: "Reopen" }));
    await waitFor(
      () => {
        expect(header("1 alert — 1 open")).toBeInTheDocument();
        expect(card("Beaconing to a fixed destination").getByRole("button", { name: "Ack" })).toBeInTheDocument();
      },
      { timeout: 2000 },
    );
    const resolvePatch = calls.find((c) => c.method === "PATCH" && (c.body ?? "").includes("resolved"));
    const reopenPatch = calls.find((c) => c.method === "PATCH" && (c.body ?? "").includes("\"open\""));
    expect(JSON.parse(resolvePatch!.body ?? "{}")).toMatchObject({ status: "resolved", comment: "" });
    expect(JSON.parse(reopenPatch!.body ?? "{}")).toMatchObject({ status: "open", comment: "" });
    expect(store[0].status).toBe("open");
  });

  it("bulk-acks both alerts from the bulk bar — header, pills, and the /alerts/bulk payload", async () => {
    const { calls, store } = renderTriage([alertFixture(1), alertFixture(2)]);

    await screen.findAllByRole("button", { name: "Ack" });
    expect(header("2 alerts — 2 open")).toBeInTheDocument();

    // Enter bulk mode — each card gains a select checkbox.
    fireEvent.click(screen.getByRole("button", { name: "Bulk" }));
    fireEvent.click(screen.getByRole("button", { name: "Select Beaconing to a fixed destination for bulk triage" }));
    fireEvent.click(screen.getByRole("button", { name: "Select Process masquerading as a system binary for bulk triage" }));
    // The bulk bar reports the selection before the transition.
    expect(screen.getByText(/2 selected · 2 open/)).toBeInTheDocument();

    // One click transitions BOTH alerts — the header hits all-triaged and
    // both pills flip in the same mutation.
    fireEvent.click(screen.getByRole("button", { name: "Ack all" }));
    await waitFor(
      () => {
        expect(header("2 alerts — all triaged")).toBeInTheDocument();
        expect(card("Beaconing to a fixed destination").getByText("Acked")).toBeInTheDocument();
        expect(card("Process masquerading as a system binary").getByText("Acked")).toBeInTheDocument();
        // The bulk bar consumed the selection.
        expect(screen.queryByRole("button", { name: "Ack all" })).not.toBeInTheDocument();
      },
      { timeout: 2000 },
    );

    // POST /alerts/bulk (bulkUpdateAlertStatus uses POST, not PATCH) carries
    // both ids + the empty comment the backend strips to NULL.
    const bulkPost = calls.find((c) => c.method === "POST" && /\/alerts\/bulk$/.test(c.url));
    expect(bulkPost).toBeTruthy();
    expect(JSON.parse(bulkPost!.body ?? "{}")).toMatchObject({ ids: [1, 2], status: "acknowledged", comment: "" });
    expect(store.filter((a) => a.status === "acknowledged")).toHaveLength(2);
    // No per-alert PATCH fired for the bulk'd alerts — one request, two rows.
    expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(0);
  });
});
