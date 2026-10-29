import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../Icon";
import { Chip } from "../ui";
import { toneFill, toneForSeverity } from "../../lib/fillPatterns";
import type { AnalysisJob, AnalysisStatus } from "../../types";

interface ExecutionRunsTableProps {
  jobs: AnalysisJob[];
  isLoading: boolean;
  isError: boolean;
  onCancelJob: (runId: string) => void;
  cancellingId?: string | null;
  statusFilter: string;
  backendFilter: string;
  searchFilter: string;
  severityFilter: string;
  onRetry?: () => void;
}

const STATUS_TONE: Record<AnalysisStatus, "muted" | "accent" | "clean" | "malicious"> = {
  queued: "muted",
  running: "accent",
  completed: "clean",
  failed: "malicious",
  canceled: "muted",
};

export function ExecutionRunsTable({
  jobs,
  isLoading,
  isError,
  onCancelJob,
  cancellingId,
  statusFilter,
  backendFilter,
  searchFilter,
  severityFilter,
  onRetry,
}: ExecutionRunsTableProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [sortField, setSortField] = useState<"started_at" | "risk_score" | "events" | "sample_name">("started_at");
  const [sortAsc, setSortAsc] = useState(false);

  const handleCopyRunId = (runId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    void navigator.clipboard.writeText(runId);
    setCopiedId(runId);
    setTimeout(() => setCopiedId(null), 1800);
  };

  const filteredJobs = useMemo(() => {
    return jobs.filter((job) => {
      // Status filter
      if (statusFilter && job.status !== statusFilter) return false;

      // Backend / driver filter
      if (backendFilter && job.backend !== backendFilter) return false;

      // Severity / risk filter
      if (severityFilter === "malicious" && job.risk_score < 7) return false;
      if (severityFilter === "suspicious" && (job.risk_score < 4 || job.risk_score >= 7)) return false;
      if (severityFilter === "clean" && job.risk_score >= 4) return false;

      // Free text search (sample name, SHA-256, run ID)
      if (searchFilter.trim()) {
        const query = searchFilter.toLowerCase();
        const nameMatch = job.sample_name?.toLowerCase().includes(query) ?? false;
        const idMatch = job.run_id.toLowerCase().includes(query);
        const backendMatch = job.backend.toLowerCase().includes(query);
        if (!nameMatch && !idMatch && !backendMatch) return false;
      }

      return true;
    }).sort((a, b) => {
      let valA: any = a[sortField];
      let valB: any = b[sortField];

      if (sortField === "started_at") {
        valA = a.started_at ? new Date(a.started_at).getTime() : 0;
        valB = b.started_at ? new Date(b.started_at).getTime() : 0;
      } else if (sortField === "sample_name") {
        valA = (a.sample_name || a.run_id).toLowerCase();
        valB = (b.sample_name || b.run_id).toLowerCase();
      }

      if (valA < valB) return sortAsc ? -1 : 1;
      if (valA > valB) return sortAsc ? 1 : -1;
      return 0;
    });
  }, [jobs, statusFilter, backendFilter, severityFilter, searchFilter, sortField, sortAsc]);

  const toggleSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortAsc((prev) => !prev);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  if (isLoading) {
    return (
      <div className="rounded-xl border border-border-subtle bg-bg-surface p-12 text-center font-mono text-xs text-text-muted">
        <Icon name="refresh" size={16} className="mx-auto mb-2 animate-spin text-accent" />
        <p>Loading execution runs from vault…</p>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-8 text-center font-mono text-xs text-rose-400 space-y-3">
        <Icon name="alert" size={20} className="mx-auto text-rose-400" />
        <div>
          <p className="font-bold text-sm text-text-primary">Execution Runs API Unreachable</p>
          <p className="mt-1 text-text-muted">
            Failed to query execution runs API. Ensure the OutPost backend service is running on port 8001.
          </p>
        </div>
        {onRetry && (
          <div className="pt-2">
            <button
              onClick={onRetry}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/15 px-3 py-1.5 font-bold text-accent hover:bg-accent/25 transition"
            >
              <Icon name="refresh" size={13} />
              <span>Retry Query</span>
            </button>
          </div>
        )}
      </div>
    );
  }

  if (filteredJobs.length === 0) {
    return (
      <div className="rounded-xl border border-border-subtle bg-bg-surface/60 p-12 text-center font-mono text-xs text-text-muted">
        <Icon name="box" size={24} className="mx-auto mb-3 text-text-faint" />
        <p className="font-bold text-text-primary">No Matching Execution Runs</p>
        <p className="mt-1 text-text-faint max-w-md mx-auto">
          {searchFilter || statusFilter || backendFilter || severityFilter
            ? "No analysis jobs match your current search and filter criteria. Adjust the filter parameters or reset to view all runs."
            : "No analysis jobs have been executed yet. Detonate a vault binary or run static analysis to view the operational execution queue."}
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-surface shadow-xs">
      <table className="w-full text-left font-mono text-xs">
        <thead>
          <tr className="border-b border-border-subtle bg-bg-base/70 text-[10px] uppercase text-text-faint font-semibold tracking-wider">
            <th className="py-2.5 px-3">Severity</th>
            <th className="py-2.5 px-3 cursor-pointer hover:text-text-primary" onClick={() => toggleSort("started_at")}>
              <div className="flex items-center gap-1">
                <span>Run ID</span>
                {sortField === "started_at" && (
                  <Icon name="chevronDown" size={10} className={`text-accent transition-transform ${sortAsc ? "rotate-180" : ""}`} />
                )}
              </div>
            </th>
            <th className="py-2.5 px-3 cursor-pointer hover:text-text-primary" onClick={() => toggleSort("sample_name")}>
              <div className="flex items-center gap-1">
                <span>Target Sample</span>
                {sortField === "sample_name" && (
                  <Icon name="chevronDown" size={10} className={`text-accent transition-transform ${sortAsc ? "rotate-180" : ""}`} />
                )}
              </div>
            </th>
            <th className="py-2.5 px-3">Driver / Isolation</th>
            <th className="py-2.5 px-3">Status</th>
            <th className="py-2.5 px-3">Exit Code</th>
            <th className="py-2.5 px-3 cursor-pointer hover:text-text-primary text-right" onClick={() => toggleSort("events")}>
              <div className="flex items-center justify-end gap-1">
                <span>Findings &amp; Events</span>
                {sortField === "events" && (
                  <Icon name="chevronDown" size={10} className={`text-accent transition-transform ${sortAsc ? "rotate-180" : ""}`} />
                )}
              </div>
            </th>
            <th className="py-2.5 px-3 cursor-pointer hover:text-text-primary text-right" onClick={() => toggleSort("risk_score")}>
              <div className="flex items-center justify-end gap-1">
                <span>Threat Score</span>
                {sortField === "risk_score" && (
                  <Icon name="chevronDown" size={10} className={`text-accent transition-transform ${sortAsc ? "rotate-180" : ""}`} />
                )}
              </div>
            </th>
            <th className="py-2.5 px-3">Started (UTC)</th>
            <th className="py-2.5 px-3 text-right">Quick Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border-subtle/50 text-[11px]">
          {filteredJobs.map((job) => {
            const sev = job.risk_score >= 7 ? "malicious" : job.risk_score >= 4 ? "suspicious" : "clean";
            const exitCode = typeof job.result?.exit_code === "number" ? job.result.exit_code : null;
            const isolationDriver = (job.result?.isolation_driver as string) || (job.backend === "isolated-outpost" ? "bubblewrap" : job.backend);
            const isCancellable = job.status === "queued" || job.status === "running";

            // Format duration
            let durationStr = "—";
            if (job.started_at && job.finished_at) {
              const diffMs = Math.max(0, new Date(job.finished_at).getTime() - new Date(job.started_at).getTime());
              const secs = Math.round(diffMs / 1000);
              durationStr = secs < 60 ? `${secs}s` : `${Math.floor(secs / 60)}m ${secs % 60}s`;
            } else if (job.status === "running" && job.started_at) {
              const diffMs = Math.max(0, Date.now() - new Date(job.started_at).getTime());
              durationStr = `${Math.round(diffMs / 1000)}s (live)`;
            }

            return (
              <tr
                key={job.run_id}
                className="group hover:bg-bg-elevated/40 transition-colors"
              >
                {/* Severity indicator */}
                <td className="py-2 px-3 whitespace-nowrap">
                  <div className="flex items-center gap-1.5">
                    <span
                      className="h-2 w-2 shrink-0 rounded-full"
                      style={
                        job.status === "completed"
                          ? sev === "malicious" || sev === "suspicious"
                            ? toneFill(toneForSeverity(sev))
                            : toneFill("low")
                          : { background: "var(--border-subtle)" }
                      }
                      title={`Severity: ${sev}`}
                      aria-hidden
                    />
                    <span className="text-[10px] uppercase font-semibold text-text-faint">
                      {job.status === "completed" ? sev : "—"}
                    </span>
                  </div>
                </td>

                {/* Run ID with copy button */}
                <td className="py-2 px-3 whitespace-nowrap">
                  <div className="flex items-center gap-1.5">
                    <Link
                      to={`/analysis/${job.run_id}`}
                      className="font-mono text-accent hover:underline font-bold text-xs"
                      title={`Open execution dossier for ${job.run_id}`}
                    >
                      {job.run_id.slice(0, 10)}
                    </Link>
                    <button
                      onClick={(e) => handleCopyRunId(job.run_id, e)}
                      className="press rounded p-0.5 text-text-faint hover:text-text-primary transition"
                      title="Copy full Run ID"
                    >
                      <Icon name={copiedId === job.run_id ? "check" : "copy"} size={10} className={copiedId === job.run_id ? "text-emerald-400" : ""} />
                    </button>
                  </div>
                </td>

                {/* Target sample */}
                <td className="py-2 px-3 max-w-[220px]">
                  <div className="min-w-0">
                    <p className="truncate font-semibold text-text-primary" title={job.sample_name || job.run_id}>
                      {job.sample_name || `job_${job.run_id.slice(0, 8)}`}
                    </p>
                    <span className="text-[10px] text-text-faint">
                      {job.sample_name?.endsWith(".exe") || job.sample_name?.endsWith(".dll")
                        ? "PE Binary"
                        : job.sample_name?.endsWith(".sh") || job.sample_name?.endsWith(".py")
                          ? "Script Payload"
                          : "Raw Artifact"}
                    </span>
                  </div>
                </td>

                {/* Driver / Isolation */}
                <td className="py-2 px-3 whitespace-nowrap">
                  <div className="flex flex-col gap-0.5">
                    <span className="inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-[10px] text-text-primary font-semibold">
                      <Icon
                        name={isolationDriver.includes("bwrap") || isolationDriver.includes("bubblewrap") ? "shield" : isolationDriver.includes("container") ? "box" : "terminal"}
                        size={10}
                        className="text-accent"
                      />
                      <span>{isolationDriver}</span>
                    </span>
                    <span className="text-[9px] text-text-faint uppercase tracking-wider">
                      {job.backend === "static" ? "Safe Static" : "Isolated Detonation"}
                    </span>
                  </div>
                </td>

                {/* Status */}
                <td className="py-2 px-3 whitespace-nowrap">
                  <div className="flex items-center gap-2">
                    <Chip tone={STATUS_TONE[job.status]} dot>
                      {job.status}
                    </Chip>
                    {job.status === "running" && (
                      <span className="text-[10px] text-text-faint tabular-nums animate-pulse">
                        {job.progress}%
                      </span>
                    )}
                  </div>
                </td>

                {/* Exit Code & Duration */}
                <td className="py-2 px-3 whitespace-nowrap">
                  <div className="flex flex-col gap-0.5 font-mono text-[10px]">
                    {exitCode !== null ? (
                      <span
                        className={`font-bold ${exitCode === 0 ? "text-emerald-400" : "text-amber-400"}`}
                        title={exitCode === 0 ? "Exited cleanly (code 0)" : `Exited with error code ${exitCode}`}
                      >
                        code {exitCode}
                      </span>
                    ) : (
                      <span className="text-text-faint">—</span>
                    )}
                    <span className="text-text-faint">{durationStr}</span>
                  </div>
                </td>

                {/* Findings & Events count */}
                <td className="py-2 px-3 whitespace-nowrap text-right">
                  <div className="flex flex-col items-end gap-0.5 tabular-nums">
                    <span className={job.alerts > 0 ? "font-bold text-rose-400" : "text-text-muted"}>
                      {job.alerts} alert{job.alerts === 1 ? "" : "s"}
                    </span>
                    <span className="text-[10px] text-text-faint">
                      {job.events} event{job.events === 1 ? "" : "s"}
                    </span>
                  </div>
                </td>

                {/* Risk score */}
                <td className="py-2 px-3 whitespace-nowrap text-right">
                  <div className="flex items-center justify-end gap-1.5 tabular-nums">
                    <span
                      className={`text-sm font-bold ${
                        job.risk_score >= 7 ? "text-rose-400" : job.risk_score >= 4 ? "text-amber-400" : "text-emerald-400"
                      }`}
                    >
                      {job.risk_score}
                    </span>
                    <span className="text-[10px] text-text-faint">/ 10</span>
                  </div>
                </td>

                {/* Started at */}
                <td className="py-2 px-3 whitespace-nowrap text-text-muted tabular-nums">
                  {job.started_at ? (
                    <div>
                      <span>{job.started_at.slice(0, 10)}</span>
                      <span className="block text-[10px] text-text-faint">{job.started_at.slice(11, 19)} UTC</span>
                    </div>
                  ) : (
                    <span className="text-text-faint">Queued</span>
                  )}
                </td>

                {/* Quick actions */}
                <td className="py-2 px-3 whitespace-nowrap text-right">
                  <div className="flex items-center justify-end gap-2">
                    <Link
                      to={`/analysis/${job.run_id}`}
                      className="press rounded border border-border-subtle bg-bg-surface px-2 py-1 text-[10px] font-semibold text-text-primary hover:border-accent hover:text-accent transition shadow-xs"
                      title="Inspect full execution dossier"
                    >
                      Inspect
                    </Link>
                    {isCancellable && (
                      <button
                        onClick={() => onCancelJob(job.run_id)}
                        disabled={cancellingId === job.run_id}
                        className="press rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-[10px] font-semibold text-rose-400 hover:bg-rose-500/20 disabled:opacity-50 transition"
                        title="Cancel ongoing execution job"
                      >
                        {cancellingId === job.run_id ? "Canceling…" : "Cancel"}
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
