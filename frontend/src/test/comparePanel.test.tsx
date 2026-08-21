// ComparePanel preset resolution — regression test for the synthetic-hidden
// preset bug. A `?a=&b=` compare jump can point at runs the archive hides by
// default (seeds / webapp-demo detonations), so the panel fetches those runs
// directly. Locks the semantics: a preset missing from the `runs` prop still
// renders in both selects and the diff fires; presets already present never
// trigger an extra fetch.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import ComparePanel from "../components/ComparePanel/ComparePanel";
import type { RunSummary } from "../types";

const HIDDEN_A = "358d8e3fae41"; // detonate-demo (synthetic, hidden from archive)
const HIDDEN_B = "c1094445bc9e"; // detonate-demo (synthetic, hidden from archive)

function run(id: string, sample: string, extra: Partial<RunSummary> = {}): RunSummary {
  return {
    run_id: id,
    sample_name: sample,
    platform: "linux",
    session_type: "analysis",
    source: "webapp-demo",
    started_at: "2026-08-10T10:00:00Z",
    completed_at: "2026-08-10T10:05:00Z",
    process_count: 6,
    unique_ips: 1,
    alert_count: 9,
    highest_severity: "malicious",
    risk_score: 100,
    ...extra,
  };
}

/** Stateful fetch mock: /runs/{id} (getRunDetail) serves the hidden presets,
 *  /runs/{a}/compare/{b} serves the diff, everything else is a quiet 200. */
function stubFetch(detailById: Record<string, RunSummary>) {
  const calls: string[] = [];
  const ok = (data: unknown) => ({ ok: true, status: 200, json: () => Promise.resolve(data) });
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      const u = String(url);
      calls.push(u);
      if (u.includes("/compare/")) {
        return Promise.resolve(
          ok({
            run_a: { run_id: HIDDEN_A, sample_name: "detonate-demo.sh" },
            run_b: { run_id: HIDDEN_B, sample_name: "detonate-demo.sh" },
            processes: { only_a: [], only_b: [], shared: ["bash", "curl", "getent", "sh", "uname", "whoami"] },
            ips: { only_a: [], only_b: [], shared: ["203.0.113.88"] },
          }),
        );
      }
      const m = u.match(/\/runs\/([0-9a-f]{12})$/);
      if (m && detailById[m[1]]) {
        return Promise.resolve(
          ok({ run: detailById[m[1]], process_tree: [], network_connections: [], timeline: [], alerts: [] }),
        );
      }
      return Promise.resolve(ok({}));
    }),
  );
  return calls;
}

function renderPanel(runs: RunSummary[], a = "", b = "") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <ComparePanel runs={runs} initialA={a} initialB={b} />
    </QueryClientProvider>,
  );
  return queryClient;
}

describe("ComparePanel preset resolution", () => {
  it("fetches synthetic-hidden presets and renders them in both selects + the diff", async () => {
    const calls = stubFetch({ [HIDDEN_A]: run(HIDDEN_A, "detonate-demo.sh"), [HIDDEN_B]: run(HIDDEN_B, "detonate-demo.sh") });
    // The archive (default synthetic-hidden view) does NOT contain the pair.
    renderPanel([run("704eb2d397ab", "host-soak-2")], HIDDEN_A, HIDDEN_B);

    // Both hidden presets were resolved via getRunDetail — the core fix.
    // (Host-agnostic: the vitest env may override VITE_API_URL.)
    await waitFor(() => {
      expect(calls.some((c) => c.endsWith(`/runs/${HIDDEN_A}`))).toBe(true);
      expect(calls.some((c) => c.endsWith(`/runs/${HIDDEN_B}`))).toBe(true);
    });

    // The selects now offer the preset pair (previously they rendered empty).
    // Each option appears once per select (A and B), so expect two each.
    const optionAs = await screen.findAllByRole("option", { name: `detonate-demo.sh · ${HIDDEN_A.slice(0, 8)}` });
    const optionBs = await screen.findAllByRole("option", { name: `detonate-demo.sh · ${HIDDEN_B.slice(0, 8)}` });
    expect(optionAs).toHaveLength(2);
    expect(optionBs).toHaveLength(2);

    // The selects are actually pre-selected to the preset pair, and the diff
    // fired: shared processes render in the three-column comparison.
    const selectA = screen.getByLabelText("Pick session A") as HTMLSelectElement;
    const selectB = screen.getByLabelText("Pick session B") as HTMLSelectElement;
    await waitFor(() => {
      expect(selectA.value).toBe(HIDDEN_A);
      expect(selectB.value).toBe(HIDDEN_B);
    });
    expect(await screen.findByText("bash")).toBeInTheDocument();
    expect(screen.getByText("curl")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.88")).toBeInTheDocument();
  });

  it("does not fetch presets that are already in the archive list", async () => {
    const calls = stubFetch({});
    const visible = run("704eb2d397ab", "host-soak-2");
    renderPanel([visible, run(HIDDEN_A, "detonate-demo.sh")], HIDDEN_A, "704eb2d397ab");

    // The diff still fires…
    await waitFor(() => {
      expect(calls.some((c) => c.includes("/compare/"))).toBe(true);
    });
    // …but no getRunDetail call was made — the preset was already known.
    expect(calls.filter((c) => /\/runs\/[0-9a-f]{12}$/.test(c))).toHaveLength(0);
  });
});
