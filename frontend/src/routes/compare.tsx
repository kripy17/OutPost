import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../components/Icon";
import { Panel, PageHeader } from "../components/ui";
import { compareRuns, getRuns } from "../lib/api";
import { riskBand } from "../lib/constants";

function RunPick({
  value,
  onChange,
  runs,
  side,
}: {
  value: string;
  onChange: (v: string) => void;
  runs: { run_id: string; sample_name: string }[];
  side: "A" | "B";
}) {
  const tone = side === "A" ? "text-risk-malicious border-risk-malicious/50" : "text-accent border-accent/50";
  return (
    <label className="flex min-w-0 flex-1 items-center gap-2">
      <span className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-md border font-mono text-[11px] font-bold ${tone}`}>
        {side}
      </span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full min-w-0 rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 font-mono text-xs text-text-primary transition-colors duration-150 focus:border-accent/60 focus:outline-none"
        aria-label={`Pick run ${side}`}
      >
        <option value="">— pick a run —</option>
        {runs.map((r) => (
          <option key={r.run_id} value={r.run_id}>
            {r.sample_name} · {r.run_id.slice(0, 8)}
          </option>
        ))}
      </select>
    </label>
  );
}

function DeltaCol({ kind, title, items }: { kind: "a" | "shared" | "b"; title: string; items: string[] }) {
  const styles = {
    a: { head: "text-risk-malicious", icon: "x" as const, iconTone: "text-risk-malicious", chip: "border-risk-malicious/40 bg-risk-malicious/10" },
    shared: { head: "text-risk-clean", icon: "check" as const, iconTone: "text-risk-clean", chip: "border-risk-clean/30 bg-risk-clean/5" },
    b: { head: "text-accent", icon: "plus" as const, iconTone: "text-accent", chip: "border-accent/40 bg-accent/10" },
  }[kind];
  return (
    <div className="min-w-0">
      <p className={`mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider ${styles.head}`}>
        <Icon name={styles.icon} size={11} className={styles.iconTone} />
        {title}
        <span className="ml-1 rounded border border-border-subtle px-1 font-mono text-[9px] normal-case text-text-faint">{items.length}</span>
      </p>
      {items.length === 0 ? (
        <p className="font-mono text-[11px] text-text-faint">—</p>
      ) : (
        <ul className="space-y-1">
          {items.map((v) => (
            <li
              key={v}
              className={`truncate rounded border px-2 py-1 font-mono text-[11px] ${styles.chip} ${
                kind === "a" ? "text-risk-malicious" : kind === "b" ? "text-accent" : "text-text-muted"
              }`}
              title={v}
            >
              {v}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function DiffTable({
  title,
  data,
}: {
  title: string;
  data: { only_a: string[]; only_b: string[]; shared: string[] };
}) {
  if (data.only_a.length + data.only_b.length + data.shared.length === 0) return null;
  return (
    <Panel
      kicker="Diff"
      title={title}
      right={
        <span className="font-mono text-[10px] text-text-faint">
          {data.shared.length} shared · {data.only_a.length} only A · {data.only_b.length} only B
        </span>
      }
    >
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-3">
        <DeltaCol kind="a" title="Only in A" items={data.only_a} />
        <DeltaCol kind="shared" title="Shared" items={data.shared} />
        <DeltaCol kind="b" title="Only in B" items={data.only_b} />
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

  const runA = runs.find((r) => r.run_id === a);
  const runB = runs.find((r) => r.run_id === b);

  const summaryCard = (r: typeof runA, side: "A" | "B") => {
    if (!r) return null;
    const band = riskBand(r.risk_score);
    return (
      <Link
        to={`/runs/${r.run_id}`}
        className={`panel tile flex-1 rounded-xl p-4 ${side === "A" ? "border-l-2 border-l-risk-malicious" : "border-l-2 border-l-accent"}`}
      >
        <p className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wide text-text-faint">
          {side === "A" ? <Icon name="x" size={10} className="text-risk-malicious" /> : <Icon name="plus" size={10} className="text-accent" />}
          sample {side}
        </p>
        <p className="mt-1 truncate font-mono text-sm font-semibold text-text-primary">{r.sample_name}</p>
        <p className="mt-0.5 font-mono text-[10px] text-text-faint">{r.run_id.slice(0, 12)}</p>
        <div className="mt-2 flex flex-wrap items-center gap-3 font-mono text-[11px] text-text-muted">
          <span className={r.highest_severity === "malicious" ? "text-risk-malicious" : r.highest_severity === "suspicious" ? "text-risk-suspicious" : "text-risk-clean"}>
            {r.highest_severity ?? "clean"}
          </span>
          <span>risk {r.risk_score ?? 0}</span>
          <span className={band.color}>{band.label}</span>
          <span>{r.alert_count} alerts</span>
        </div>
      </Link>
    );
  };

  return (
    <div className="mx-auto max-w-5xl px-5 py-8 lg:px-8">
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
        <RunPick value={a} onChange={setA} runs={runs} side="A" />
        <span className="flex items-center gap-1 font-mono text-xs text-text-faint">
          <Icon name="compare" size={13} /> vs
        </span>
        <RunPick value={b} onChange={setB} runs={runs} side="B" />
        {isFetching && <span className="text-xs text-text-muted">comparing…</span>}
      </div>

      {a !== "" && b !== "" && a === b && (
        <p className="mt-4 inline-flex items-center gap-1.5 text-xs text-risk-malicious">
          <Icon name="alert" size={12} />
          Pick two different runs.
        </p>
      )}

      {data && (runA || runB) && (
        <div className="mt-8 space-y-6">
          <div className="flex flex-col gap-3 sm:flex-row">
            {summaryCard(runA, "A")}
            {summaryCard(runB, "B")}
          </div>
          <DiffTable title="Processes" data={data.processes} />
          <DiffTable title="IPs" data={data.ips} />
        </div>
      )}
    </div>
  );
}
