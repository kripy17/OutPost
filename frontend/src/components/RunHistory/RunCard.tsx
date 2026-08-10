import { Link, useNavigate } from "react-router-dom";
import { Icon, platformIconName } from "../Icon";
import { Chip, SourceBadge } from "../ui";
import { riskBand } from "../../lib/constants";
import type { RunSummary } from "../../types";

function PlatformIcon({ platform }: { platform: RunSummary["platform"] }) {
  return (
    <span className="inline-flex w-8 items-center justify-center text-[13px] text-text-muted" title={platform}>
      <Icon name={platformIconName(platform)} size={14} />
    </span>
  );
}

function SeverityBadge({ summary }: { summary: RunSummary }) {
  const sev = summary.highest_severity ?? "clean";
  const tone = sev === "malicious" ? "malicious" : sev === "suspicious" ? "suspicious" : "clean";
  return (
    <Chip tone={tone} dot glow>
      {sev}
    </Chip>
  );
}

function RiskBadge({ score }: { score: number }) {
  const s = score ?? 0;
  const band = riskBand(s);
  const tone = band.label === "critical" ? "malicious" : band.label === "elevated" ? "suspicious" : "clean";
  return (
    <Chip tone={tone} title={`Risk score ${s}/100 — ${band.label}`}>
      risk {s}
    </Chip>
  );
}

export default function RunCard({ run, highlighted = false }: { run: RunSummary; highlighted?: boolean }) {
  const inProgress = run.completed_at === null;
  const navigate = useNavigate();
  return (
    <Link
      to={`/runs/${run.run_id}`}
      aria-current={highlighted ? "true" : undefined}
      className={`group relative grid grid-cols-[1fr_auto] items-center gap-4 border-b border-border-subtle px-4 py-3 transition-colors duration-150 last:border-b-0 hover:bg-bg-elevated/50 ${
        highlighted ? "bg-accent/5" : "bg-bg-surface"
      }`}
    >
      {/* Accent bar — hover or keyboard selection marks the row as the target. */}
      <span
        className={`absolute left-0 top-0 h-full w-0.5 rounded-r bg-accent transition-opacity duration-150 ${
          highlighted ? "opacity-70" : "opacity-0 group-hover:opacity-70"
        }`}
      />
      <div className="flex min-w-0 items-center gap-3">
        <PlatformIcon platform={run.platform} />
        <span className="truncate font-mono text-sm text-text-primary">{run.sample_name}</span>
        <SourceBadge source={run.source} />
        {run.host_ids?.map((host) => (
          <button
            key={host}
            type="button"
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              navigate(`/history?host=${encodeURIComponent(host)}`);
            }}
            title={`Filter the archive to host ${host}`}
            className="inline-flex cursor-pointer items-center gap-1 rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[11px] text-text-muted transition-colors hover:border-accent/40 hover:text-accent"
          >
            <Icon name="network" size={11} />
            {host}
          </button>
        ))}
        {inProgress && (
          <span className="animate-outpost-pulse text-xs text-accent" title="Still tracing">
            ● tracing
          </span>
        )}
      </div>
      <div className="flex items-center gap-4 font-mono text-xs tabular-nums text-text-muted">
        <span>{run.process_count} procs</span>
        <span>{run.unique_ips} ips</span>
        <span>{run.alert_count} alerts</span>
        <RiskBadge score={run.risk_score} />
        <SeverityBadge summary={run} />
        <span className="hidden text-text-faint md:inline">{run.started_at.slice(0, 19).replace("T", " ")}</span>
        <span className="text-text-faint transition-transform duration-150 group-hover:translate-x-0.5">
          <Icon name="arrowRight" size={13} />
        </span>
      </div>
    </Link>
  );
}
