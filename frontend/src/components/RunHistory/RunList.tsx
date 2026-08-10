import type { RunSummary } from "../../types";
import RunCard from "./RunCard";

export default function RunList({ runs, highlightId = null }: { runs: RunSummary[]; highlightId?: string | null }) {
  if (runs.length === 0) {
    return (
      <div className="rounded-lg border border-border-subtle bg-bg-surface p-10 text-center">
        <p className="text-sm text-text-muted">
          No sessions yet — start one with <span className="font-mono text-accent">outpost watch</span> or{" "}
          <span className="font-mono text-accent">outpost run &lt;sample&gt;</span>.
        </p>
      </div>
    );
  }

  return (
    <div className="panel overflow-hidden">
      <div className="grid grid-cols-[1fr_auto] items-center gap-4 border-b border-border-subtle bg-bg-elevated/60 px-4 py-2 text-xs font-semibold text-text-muted">
        <span className="font-mono">Sample</span>
        <span className="pr-2 font-mono">procs · ips · alerts · risk · severity · started</span>
      </div>
      {runs.map((run) => (
        <RunCard key={run.run_id} run={run} highlighted={run.run_id === highlightId} />
      ))}
    </div>
  );
}
