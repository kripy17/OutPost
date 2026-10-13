import { useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../Icon";
import { Chip } from "../ui";
import type { AnalysisJob, AnalysisStatus } from "../../types";

interface DynamicRunHeaderProps {
  job: AnalysisJob;
  onCancelJob: () => void;
  isCancelling: boolean;
  onRerun?: () => void;
  droppedArtifactsCount?: number;
}

const STATUS_TONE: Record<AnalysisStatus, "muted" | "accent" | "clean" | "malicious"> = {
  queued: "muted",
  running: "accent",
  completed: "clean",
  failed: "malicious",
  canceled: "muted",
};

export function DynamicRunHeader({
  job,
  onCancelJob,
  isCancelling,
  onRerun,
  droppedArtifactsCount = 0,
}: DynamicRunHeaderProps) {
  const [copiedId, setCopiedId] = useState(false);

  const handleCopyId = () => {
    void navigator.clipboard.writeText(job.run_id);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 1800);
  };

  const isCancellable = job.status === "queued" || job.status === "running";
  const exitCode = typeof job.result?.exit_code === "number" ? job.result.exit_code : null;
  const isolationDriver = (job.result?.isolation_driver as string) || (job.backend === "isolated-outpost" ? "bubblewrap" : job.backend);

  // Compute duration
  let durationStr = "—";
  if (job.started_at && job.finished_at) {
    const diffMs = Math.max(0, new Date(job.finished_at).getTime() - new Date(job.started_at).getTime());
    const secs = Math.round(diffMs / 1000);
    durationStr = secs < 60 ? `${secs}s` : `${Math.floor(secs / 60)}m ${secs % 60}s`;
  } else if (job.status === "running" && job.started_at) {
    const diffMs = Math.max(0, Date.now() - new Date(job.started_at).getTime());
    durationStr = `${Math.round(diffMs / 1000)}s live`;
  }

  return (
    <div className="border-b border-border-subtle bg-bg-surface/50 pb-4 font-sans">
      {/* Breadcrumb Navigation */}
      <nav aria-label="Breadcrumb" className="mb-2.5 flex items-center gap-1.5 font-mono text-[11px] text-text-faint">
        <Link to="/analysis" className="text-text-muted hover:text-accent transition-colors">
          Dynamic Analysis
        </Link>
        <span>/</span>
        <Link to="/analysis" className="text-text-muted hover:text-accent transition-colors">
          Runs
        </Link>
        <span>/</span>
        <span className="font-semibold text-text-primary truncate max-w-[240px]" title={job.run_id}>
          {job.run_id}
        </span>
      </nav>

      {/* Main Identity & Actions Row */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Left: Identity Cluster */}
        <div className="flex flex-wrap items-center gap-2.5 min-w-0">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border-subtle bg-bg-base text-accent">
            <Icon name={job.backend === "static" ? "box" : "zap"} size={18} />
          </div>

          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="truncate font-mono text-base font-bold text-text-primary" title={job.sample_name || job.run_id}>
                {job.sample_name ?? `job ${job.run_id.slice(0, 12)}`}
              </h1>
              <span className="inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-base px-2 py-0.5 font-mono text-[10px] text-text-muted">
                <span>{job.backend}</span>
                <span className="text-text-faint">({isolationDriver})</span>
              </span>
              <button
                onClick={handleCopyId}
                className="press inline-flex items-center gap-1 rounded bg-bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-text-faint hover:text-text-primary transition"
                title="Copy Run ID"
              >
                <span>{job.run_id.slice(0, 10)}</span>
                <Icon name={copiedId ? "check" : "copy"} size={10} className={copiedId ? "text-emerald-400" : ""} />
              </button>
            </div>
          </div>

          <Chip tone={STATUS_TONE[job.status]} dot>
            {job.status}
          </Chip>

          {exitCode !== null && (
            <span
              className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold ${
                exitCode === 0
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                  : "border-amber-500/40 bg-amber-500/10 text-amber-400"
              }`}
              title={exitCode === 0 ? "Clean execution exit" : `Process exited with code ${exitCode}`}
            >
              Exit Code {exitCode}
            </span>
          )}

          <span className="rounded bg-bg-elevated px-2 py-0.5 font-mono text-[10px] text-text-faint tabular-nums">
            {durationStr}
          </span>
        </div>

        {/* Right: Actions Cluster */}
        <div className="flex flex-wrap items-center gap-2">
          <Link
            to={`/investigations?create=1&title=${encodeURIComponent(`Incident Dossier — ${job.sample_name || job.run_id}`)}&evidence_type=run&evidence_id=${encodeURIComponent(job.run_id)}`}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-sans text-xs font-semibold text-text-primary hover:border-accent hover:text-accent transition shadow-xs"
            title="Escalate run findings into formal investigation"
          >
            <Icon name="shield" size={12} />
            <span>Escalate Case</span>
          </Link>

          <a
            href={`/api/runs/${job.run_id}/export?format=stix`}
            target="_blank"
            rel="noopener noreferrer"
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-sans text-xs font-semibold text-text-primary hover:border-accent hover:text-accent transition shadow-xs"
            title="Export STIX 2.1 threat intelligence bundle"
          >
            <Icon name="download" size={12} />
            <span>Export STIX</span>
          </a>

          {droppedArtifactsCount > 0 && (
            <a
              href={`/api/sandbox/artifacts/${job.run_id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 font-sans text-xs font-semibold text-accent hover:bg-accent/20 transition shadow-xs"
              title="Download dropped forensic payload bundle"
            >
              <Icon name="box" size={12} />
              <span>Artifacts ({droppedArtifactsCount})</span>
            </a>
          )}

          {isCancellable && (
            <button
              onClick={onCancelJob}
              disabled={isCancelling}
              className="press btn inline-flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 font-sans text-xs font-semibold text-rose-400 hover:bg-rose-500/20 disabled:opacity-50 transition shadow-xs"
              title="Cancel ongoing detonation"
            >
              <Icon name="x" size={12} />
              <span>{isCancelling ? "Canceling…" : "Cancel job"}</span>
            </button>
          )}

          {job.status === "completed" && onRerun && (
            <button
              onClick={onRerun}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-sans text-xs font-semibold text-text-primary hover:border-accent hover:text-accent transition shadow-xs"
              title="Re-run detonation on this sample"
            >
              <Icon name="refresh" size={12} />
              <span>Re-run</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
