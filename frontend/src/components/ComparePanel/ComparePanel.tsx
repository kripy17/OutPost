import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { compareRuns, getRunDetail } from "../../lib/api";
import type { RunSummary } from "../../types";
import { Panel } from "../ui";

/** Compare two sessions — the former /compare page folded into the archive.
 *  Pick any two runs and see what processes/IPs each has that the other
 *  doesn't (variant A vs variant B, before vs after a patch, …). */
export default function ComparePanel({
  runs,
  initialA = "",
  initialB = "",
}: {
  runs: RunSummary[];
  initialA?: string;
  initialB?: string;
}) {
  const [a, setA] = useState(initialA);
  const [b, setB] = useState(initialB);
  const { data, isFetching } = useQuery({
    queryKey: ["compare", a, b],
    queryFn: () => compareRuns(a, b),
    enabled: a !== "" && b !== "" && a !== b,
  });
  // A preset pair may be synthetic-hidden from the archive list (seeds /
  // webapp detonations) — fetch those runs directly so the selects can show
  // them instead of rendering an empty value for a preset that did fire.
  const knownIds = useMemo(() => new Set(runs.map((r) => r.run_id)), [runs]);
  const missingPresets = useMemo(
    () => [initialA, initialB].filter((id) => id && !knownIds.has(id)),
    [initialA, initialB, knownIds],
  );
  const { data: presetRuns = [] } = useQuery({
    queryKey: ["runs", "compare-presets", missingPresets],
    queryFn: async () => {
      const details = await Promise.all(missingPresets.map((id) => getRunDetail(id)));
      return details.map((d) => d.run).filter((r) => r);
    },
    enabled: missingPresets.length > 0,
  });
  const options = useMemo(() => {
    const merged = new Map<string, RunSummary>();
    for (const r of runs) merged.set(r.run_id, r);
    for (const r of presetRuns) merged.set(r.run_id, r);
    return [...merged.values()];
  }, [runs, presetRuns]);

  const col = (kind: "a" | "shared" | "b", items: string[]) => {
    const tone =
      kind === "a"
        ? "border-risk-malicious/30 bg-risk-malicious/5 text-risk-malicious"
        : kind === "b"
          ? "border-accent/30 bg-accent/5 text-accent"
          : "border-border-subtle bg-bg-elevated/40 text-text-muted";
    return (
      <div className="min-w-0">
        <p className={`mb-1.5 font-mono text-[9px] font-semibold uppercase tracking-wider ${tone} !bg-transparent !border-0`}>
          {kind === "a" ? "only A" : kind === "b" ? "only B" : "shared"}{" "}
          <span className="text-text-faint">({items.length})</span>
        </p>
        {items.length === 0 ? (
          <p className="font-mono text-[10px] text-text-faint">—</p>
        ) : (
          <ul className="space-y-1">
            {items.slice(0, 12).map((v) => (
              <li key={v} className={`truncate rounded border px-2 py-1 font-mono text-[10px] ${tone}`} title={v}>
                {v}
              </li>
            ))}
            {items.length > 12 && <li className="font-mono text-[10px] text-text-faint">+{items.length - 12} more</li>}
          </ul>
        )}
      </div>
    );
  };

  return (
    <Panel kicker="Analysis · diff" title="Compare two sessions" className="mt-8">
      <div className="flex flex-wrap items-end gap-3">
        {(["A", "B"] as const).map((side) => (
          <label key={side} className="block min-w-52 flex-1">
            <span className="kicker mb-1 block">Session {side}</span>
            <select
              value={side === "A" ? a : b}
              onChange={(e) => (side === "A" ? setA(e.target.value) : setB(e.target.value))}
              className="w-full rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 font-mono text-xs text-text-primary transition-colors focus:border-accent/60 focus:outline-none"
              aria-label={`Pick session ${side}`}
            >
              <option value="">— pick a session —</option>
              {options.map((r) => (
                <option key={r.run_id} value={r.run_id}>
                  {r.sample_name} · {r.run_id.slice(0, 8)}
                </option>
              ))}
            </select>
          </label>
        ))}
        {isFetching && <span className="pb-2 text-xs text-text-muted">comparing…</span>}
      </div>
      {a !== "" && b !== "" && a === b && (
        <p className="mt-3 text-xs text-risk-malicious">Pick two different sessions.</p>
      )}
      {data && (
        <div className="mt-5 grid grid-cols-1 gap-5 sm:grid-cols-2">
          <div>
            <p className="kicker mb-2">Processes</p>
            <div className="grid grid-cols-3 gap-3">
              {col("a", data.processes.only_a)}
              {col("shared", data.processes.shared)}
              {col("b", data.processes.only_b)}
            </div>
          </div>
          <div>
            <p className="kicker mb-2">IPs</p>
            <div className="grid grid-cols-3 gap-3">
              {col("a", data.ips.only_a)}
              {col("shared", data.ips.shared)}
              {col("b", data.ips.only_b)}
            </div>
          </div>
        </div>
      )}
    </Panel>
  );
}
