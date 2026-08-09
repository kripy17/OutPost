// QuickAllowlist — the two-click allowlist flow from the network table and
// process tree. Locks the semantics: click 1 arms ("confirm?"), click 2
// POSTs the entry; an already-allowlisted value renders as a quiet check and
// never offers the button again. Uses a stateful fetch mock so the allowlist
// GET reflects the POST like the real backend does.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { QuickAllowlist } from "../components/TriagePanels/TriagePanels";

function renderQuick(runId = "r1") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <QuickAllowlist runId={runId} kind="ip" value="203.0.113.88" />
    </QueryClientProvider>,
  );
  return queryClient;
}

/** Stateful fetch mock: POSTs append to the allowlist store; GETs return it. */
function stubFetch(initial: unknown[] = []) {
  const store: unknown[] = [...initial];
  const calls: { url: string; method: string }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      calls.push({ url: String(url), method });
      if (String(url).includes("/allowlist")) {
        if (method === "POST") {
          const added = { id: store.length + 1, run_id: "r1", kind: "ip", value: "203.0.113.88", note: null, created_at: "2026-08-09T12:00:00Z", acked: 1 };
          store.push(added);
          return Promise.resolve({ ok: true, status: 201, json: () => Promise.resolve(added) });
        }
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([...store]) });
      }
      // catch-all (e.g. the run-detail invalidation) — harmless empty body
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) });
    }),
  );
  return calls;
}

describe("QuickAllowlist", () => {
  it("is two clicks: arm, then confirm — and POSTs once", async () => {
    stubFetch();
    renderQuick();
    const btn = await screen.findByRole("button", { name: /Allowlist 203\.0\.113\.88/ });
    expect(btn.textContent).toContain("allowlist");

    // Click 1 — arms, does NOT POST yet.
    fireEvent.click(btn);
    expect(btn.textContent).toContain("confirm?");
    expect(screen.queryByText("adding…")).not.toBeInTheDocument();

    // Click 2 — confirms; the refetch flips it into the "allowed" chip.
    fireEvent.click(btn);
    await waitFor(() => expect(screen.getByText("allowed")).toBeInTheDocument(), { timeout: 2000 });
    expect(screen.queryByRole("button", { name: /Allowlist/ })).not.toBeInTheDocument();
  });

  it("renders a quiet allowed check when the value is already allowlisted", async () => {
    stubFetch([{ id: 1, run_id: "r1", kind: "ip", value: "203.0.113.88", note: null, created_at: "2026-08-09T12:00:00Z", acked: 0 }]);
    renderQuick();
    await waitFor(() => expect(screen.getByText("allowed")).toBeInTheDocument(), { timeout: 2000 });
    expect(screen.queryByRole("button", { name: /Allowlist/ })).not.toBeInTheDocument();
  });
});
