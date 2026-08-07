import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Panel, PageHeader } from "../components/ui";
import { compareRuns, getRuns } from "../lib/api";

function DiffTable({
  title,
  data,
}: {
  title: string;
  data: { only_a: string[]; only_b: string[]; shared: string[] };
}) {
  const rows = Math.max(data.only_a.length, data.shared.length, data.only_b.length);
  if (rows === 0) return null;
  return (
    <Panel kicker="Diff" title={title}>
      <div className="grid grid-cols-3 gap-3">
        <div className="min-w-0">
          <p className="mb-2 text-[10px] uppercase tracking-wider text-risk-malicious">Only in A</p>
          <ul className="space-y-1">
            {data.only_a.map((v) => (
              <li key={v} className="truncate font-mono text-xs text-text-primary" title={v}>
                {v}
              </li>
            ))}
          </ul>
        </div>
        <div className="min-w-0">
          <p className="mb-2 text-[10px] uppercase tracking-wider text-risk-clean">Shared</p>
          <ul className="space-y-1">
            {data.shared.map((v) => (
              <li key={v} className="truncate font-mono text-xs text-text-muted" title={v}>
                {v}
              </li>
            ))}
          </ul>
        </div>
        <div className="min-w-0">
          <p className="mb-2 text-[10px] uppercase tracking-wider text-accent-amber">Only in B</p>
          <ul className="space-y-1">
            {data.only_b.map((v) => (
              <li key={v} className="truncate font-mono text-xs text-text-primary" title={v}>
                {v}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Panel>
  );
}

export default function ComparePage() {
  const { data: runs = [] } = useQuery({ queryKey: ["runs"], queryFn: () => getRuns() });
  const [a, setA] = useState("");
  const [b, setB] = useState("");

  const { data, isFetching } = useQuery({
    queryKey: ["compare", a, b],
    queryFn: () => compareRuns(a, b),
    enabled: a !== "" && b !== "" && a !== b,
  });

  const select = (value: string, onChange: (v: string) => void) => (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-full max-w-xs rounded border border-border-subtle bg-bg-surface px-3 py-2 font-mono text-xs text-text-primary transition-colors duration-150 focus:border-accent-amber/60 focus:outline-none"
    >
      <option value="">— pick a run —</option>
      {runs.map((r) => (
        <option key={r.run_id} value={r.run_id}>
          {r.sample_name} · {r.run_id.slice(0, 8)}
        </option>
      ))}
    </select>
  );

  return (
    <div className="mx-auto max-w-5xl px-6 py-10">
      <PageHeader
        kicker="Intelligence · compare"
        title={
          <>
            Compare runs <span className="font-normal text-text-muted">— what changed between two sessions?</span>
          </>
        }
        lede="Diff two variants of the same sample, or the same sample before and after a patch."
      />

      <div className="mt-6 flex flex-wrap items-center gap-3">
        {select(a, setA)}
        <span className="text-xs text-text-faint">vs</span>
        {select(b, setB)}
        {isFetching && <span className="text-xs text-text-muted">comparing…</span>}
      </div>

      {a !== "" && b !== "" && a === b && (
        <p className="mt-4 text-xs text-risk-malicious">Pick two different runs.</p>
      )}

      {data && (
        <div className="mt-8 space-y-6">
          <p className="text-xs text-text-muted">
            <span className="font-mono text-text-primary">{data.run_a.sample_name}</span> ({data.run_a.run_id.slice(0, 8)})
            vs <span className="font-mono text-text-primary">{data.run_b.sample_name}</span> ({data.run_b.run_id.slice(0, 8)})
          </p>
          <DiffTable title="Processes" data={data.processes} />
          <DiffTable title="IPs" data={data.ips} />
        </div>
      )}
    </div>
  );
}
