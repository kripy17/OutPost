// The full per-run IOC allowlist lifecycle, as an e2e regression test — the
// mirror of suppressionLifecycle.test.tsx for the allowlist surface. What it
// pins:
//
//  1. QuickAllowlist's two-click quick-add (click 1 arms "confirm?", click 2
//     POSTs) lands a RUN-scoped entry, and the shared ["allowlist", runId]
//     refetch flips BOTH surfaces at once: the row's "allowed" check chip
//     AND the AllowlistPanel's "1 entry" with the row. One mutation, two
//     surfaces, one refetch.
//  2. "Remove" in the panel DELETEs it, and both surfaces flip back.
//  3. The process-tree surface (kind=process) writes into the SAME store the
//     network-table surface (kind=ip) and the panel read — and the shared
//     key is scoped per kind+value, so one quick-add only flips its own
//     button while the panel shows the union.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AllowlistPanel, QuickAllowlist } from "../components/TriagePanels/TriagePanels";
import type { AllowlistEntry, AllowlistKind } from "../types";

const RUN = "r1";
const C2 = "203.0.113.88";

/** Stateful fetch mock with an allowlist store, mirroring the real backend:
 *  GETs return the list, POSTs append (201 + the new entry), DELETEs remove
 *  by id. The store lives in the module closure so every surface sharing the
 *  ["allowlist", runId] key reads the same data, exactly like the backend. */
function stubFetch(initialEntries: AllowlistEntry[] = []) {
  const store: AllowlistEntry[] = [...initialEntries];
  const calls: { method: string; url: string; body?: string }[] = [];
  let nextId = initialEntries.length + 1;

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

      if (u.includes("/allowlist")) {
        if (method === "POST") {
          const p = JSON.parse(body ?? "{}") as { kind: AllowlistKind; value: string; note: string };
          const created: AllowlistEntry = {
            id: nextId++,
            run_id: RUN,
            kind: p.kind,
            value: p.value,
            note: p.note || null,
            created_at: "2026-08-16T12:00:00Z",
            acked: 0,
          };
          store.push(created);
          return Promise.resolve(ok(created, 201));
        }
        if (method === "DELETE") {
          const id = Number(u.match(/\/allowlist\/(\d+)$/)?.[1]);
          const idx = store.findIndex((e) => e.id === id);
          if (idx >= 0) store.splice(idx, 1);
          return Promise.resolve(ok({}, 204));
        }
        return Promise.resolve(ok([...store]));
      }
      return Promise.resolve(ok({}));
    }),
  );
  return { store, calls };
}

function renderAllowlistSurfaces(stub: ReturnType<typeof stubFetch>) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/runs/${RUN}`]}>
        {/* Network-table quick-add (kind=ip) + the bottom panel. */}
        <QuickAllowlist runId={RUN} kind="ip" value={C2} />
        <AllowlistPanel runId={RUN} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return stub;
}

describe("allowlist lifecycle — run-detail surfaces (row quick-add + panel)", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("two-click quick-adds from the row, shows in both surfaces, removes from the panel, and both flip back", async () => {
    const { store, calls } = renderAllowlistSurfaces(stubFetch());

    // Initial: the row offers the two-click allowlist; the panel reports none.
    const rowBtn = await screen.findByRole("button", { name: `Allowlist ${C2} for this run` });
    expect(screen.getByText("0 entries")).toBeInTheDocument();
    expect(screen.queryByTitle(/Allowlisted for this run/)).not.toBeInTheDocument();

    // Click 1 arms the button ("confirm?"); click 2 POSTs.
    fireEvent.click(rowBtn);
    expect(screen.getByRole("button", { name: `Allowlist ${C2} for this run` })).toHaveTextContent("confirm?");
    fireEvent.click(rowBtn);

    // The shared ["allowlist", runId] refetch flips BOTH surfaces at once:
    // the row's "allowed" check chip AND the panel's entry list.
    await waitFor(
      () => {
        expect(screen.getByTitle(`Allowlisted for this run — matching alerts suppressed (ip: ${C2})`)).toBeInTheDocument();
        expect(screen.getByText("1 entry")).toBeInTheDocument();
        expect(screen.getByText(C2)).toBeInTheDocument();
        expect(screen.getByText("quick-add from network table")).toBeInTheDocument();
      },
      { timeout: 2000 },
    );
    const post = calls.find((c) => c.method === "POST");
    expect(post).toBeTruthy();
    expect(JSON.parse(post!.body ?? "{}")).toMatchObject({ kind: "ip", value: C2, note: "quick-add from network table" });
    expect(store).toHaveLength(1);
    // The row's button is gone — the "allowed" chip replaced it.
    expect(screen.queryByRole("button", { name: `Allowlist ${C2} for this run` })).not.toBeInTheDocument();

    // Remove from the panel → DELETE → both surfaces flip back.
    fireEvent.click(screen.getByRole("button", { name: `Remove ${C2} from the allowlist` }));
    await waitFor(
      () => {
        expect(screen.getByText("0 entries")).toBeInTheDocument();
        expect(screen.getByRole("button", { name: `Allowlist ${C2} for this run` })).toBeInTheDocument();
      },
      { timeout: 2000 },
    );
    expect(screen.queryByTitle(/Allowlisted for this run/)).not.toBeInTheDocument();
    expect(calls.some((c) => c.method === "DELETE" && /\/runs\/r1\/allowlist\/1$/.test(c.url))).toBe(true);
    expect(store).toHaveLength(0);
  });
});

describe("allowlist lifecycle — process-tree and network-table surfaces share one store", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("a quick-add from the process tree lands in the same list the ip surface and panel read, scoped per kind+value", async () => {
    const { store, calls } = stubFetch();
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={[`/runs/${RUN}`]}>
          {/* Network-table surface (ip) + process-tree surface (process) + panel. */}
          <QuickAllowlist runId={RUN} kind="ip" value={C2} />
          <QuickAllowlist runId={RUN} kind="process" value="bash" />
          <AllowlistPanel runId={RUN} />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    const ipBtn = await screen.findByRole("button", { name: `Allowlist ${C2} for this run` });
    const procBtn = screen.getByRole("button", { name: "Allowlist bash for this run" });
    expect(screen.getByText("0 entries")).toBeInTheDocument();

    // Two-click quick-add via the process-tree button.
    fireEvent.click(procBtn);
    fireEvent.click(procBtn);
    await waitFor(
      () => {
        expect(screen.getByTitle("Allowlisted for this run — matching alerts suppressed (process: bash)")).toBeInTheDocument();
        expect(screen.getByText("1 entry")).toBeInTheDocument();
        expect(screen.getByText("quick-add from process tree")).toBeInTheDocument();
      },
      { timeout: 2000 },
    );
    const post = calls.find((c) => c.method === "POST");
    expect(JSON.parse(post!.body ?? "{}")).toMatchObject({ kind: "process", value: "bash", note: "quick-add from process tree" });
    expect(store).toHaveLength(1);
    // Kind discrimination: a process entry must NOT flip the ip surface's
    // button — the shared key is scoped per (kind, value).
    expect(ipBtn).toBeInTheDocument();
    expect(ipBtn).toHaveTextContent("allowlist");

    // Now the ip surface quick-adds too — one shared list, two rows.
    fireEvent.click(ipBtn);
    fireEvent.click(ipBtn);
    await waitFor(
      () => {
        expect(screen.getByTitle(`Allowlisted for this run — matching alerts suppressed (ip: ${C2})`)).toBeInTheDocument();
        expect(screen.getByText("2 entries")).toBeInTheDocument();
      },
      { timeout: 2000 },
    );
    expect(store).toHaveLength(2);

    // Remove the process entry from the panel → only the process button
    // flips back; the ip surface stays allowed (a different entry).
    fireEvent.click(screen.getByRole("button", { name: "Remove bash from the allowlist" }));
    await waitFor(
      () => {
        expect(screen.getByText("1 entry")).toBeInTheDocument();
        expect(screen.getByRole("button", { name: "Allowlist bash for this run" })).toBeInTheDocument();
        expect(screen.getByTitle(`Allowlisted for this run — matching alerts suppressed (ip: ${C2})`)).toBeInTheDocument();
      },
      { timeout: 2000 },
    );
    expect(store).toHaveLength(1);
    expect(calls.some((c) => c.method === "DELETE" && /\/runs\/r1\/allowlist\/1$/.test(c.url))).toBe(true);
  });
});
