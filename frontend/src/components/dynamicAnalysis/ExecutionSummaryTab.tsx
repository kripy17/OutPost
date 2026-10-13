import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Icon } from "../Icon";
import { Chip, Panel } from "../ui";
import { SampleMitreMatrix } from "../SampleMitreMatrix";
import { setAlertInvestigation } from "../../lib/api";
import { toneFill, toneForSeverity } from "../../lib/fillPatterns";
import type { AnalysisJob, Finding } from "../../types";

interface ExecutionSummaryTabProps {
  job: AnalysisJob;
  findings: Finding[];
  investigations: Array<{ id: string; title: string }>;
  onSelectTab?: (tab: string) => void;
}

export function ExecutionSummaryTab({
  job,
  findings,
  investigations,
  onSelectTab,
}: ExecutionSummaryTabProps) {
  const queryClient = useQueryClient();

  const attach = useMutation({
    mutationFn: ({ findingId, investigationId, status }: { findingId: number; investigationId: string | null; status?: string }) =>
      setAlertInvestigation(findingId, investigationId, (status as any) || "open"),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["analysis"] });
      void queryClient.invalidateQueries({ queryKey: ["investigations"] });
    },
  });

  const riskScore = job.risk_score ?? 0;
  const isMalicious = riskScore >= 7 || findings.some((f) => f.severity === "malicious");
  const isSuspicious = riskScore >= 4 || findings.some((f) => f.severity === "suspicious");

  const verdictLabel = isMalicious
    ? "MALICIOUS SPECIMEN"
    : isSuspicious
      ? "SUSPICIOUS BEHAVIOR"
      : "BENIGN / CLEAN EXECUTION";

  const exitCode = typeof job.result?.exit_code === "number" ? job.result.exit_code : null;
  const terminationReason = exitCode === 0
    ? "Process completed normally (Exit code 0)"
    : exitCode !== null
      ? `Process terminated with error code ${exitCode}`
      : job.status === "completed"
        ? "Normal execution completion"
        : "Execution pending or in progress";

  return (
    <div className="space-y-6 font-sans">
      {/* Dynamic Execution Assessment Banner */}
      <div
        className={`rounded-2xl border p-5 transition shadow-xs ${
          isMalicious
            ? "border-rose-500/40 bg-rose-500/10 ring-1 ring-rose-500/20"
            : isSuspicious
              ? "border-amber-500/40 bg-amber-500/10 ring-1 ring-amber-500/20"
              : "border-emerald-500/40 bg-emerald-500/10 ring-1 ring-emerald-500/20"
        }`}
      >
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div
              className={`flex h-12 w-12 items-center justify-center rounded-xl border ${
                isMalicious
                  ? "border-rose-500/50 bg-rose-500/20 text-rose-400"
                  : isSuspicious
                    ? "border-amber-500/50 bg-amber-500/20 text-amber-400"
                    : "border-emerald-500/50 bg-emerald-500/20 text-emerald-400"
              }`}
            >
              <Icon name={isMalicious ? "alert" : isSuspicious ? "zap" : "shield"} size={22} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span
                  className={`font-bold uppercase tracking-wider text-sm ${
                    isMalicious ? "text-rose-400" : isSuspicious ? "text-amber-400" : "text-emerald-400"
                  }`}
                >
                  {verdictLabel}
                </span>
                <span className="rounded bg-bg-surface/80 border border-border-subtle px-2 py-0.5 font-mono text-[10px] text-text-muted">
                  Dynamic Runtime Assessment
                </span>
              </div>
              <p className="mt-1 font-mono text-xs text-text-muted leading-relaxed">
                Observed runtime behavior under <span className="font-semibold text-text-primary">{job.backend}</span> isolation.
                Evaluated against {findings.length} alert rules and compound process trees without host compromise.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-6 font-mono text-right">
            <div>
              <span className="text-[10px] uppercase tracking-wider text-text-faint block font-semibold">
                Threat Score
              </span>
              <div className="flex items-baseline justify-end gap-1 mt-0.5">
                <span
                  className={`text-2xl font-black ${
                    isMalicious ? "text-rose-400" : isSuspicious ? "text-amber-400" : "text-emerald-400"
                  }`}
                >
                  Level {riskScore}
                </span>
                <span className="text-xs text-text-faint">/ 10</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Execution Timeline & Facts Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 font-mono text-xs">
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-1">
          <span className="text-[10px] uppercase text-text-faint block font-semibold">Execution Started</span>
          <p className="font-bold text-text-primary">
            {job.started_at ? job.started_at.slice(11, 19) + " UTC" : "Not started"}
          </p>
          <p className="text-[10px] text-text-faint">{job.started_at ? job.started_at.slice(0, 10) : "—"}</p>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-1">
          <span className="text-[10px] uppercase text-text-faint block font-semibold">Execution Finished</span>
          <p className="font-bold text-text-primary">
            {job.finished_at ? job.finished_at.slice(11, 19) + " UTC" : job.status}
          </p>
          <p className="text-[10px] text-text-faint">{job.finished_at ? job.finished_at.slice(0, 10) : "Active"}</p>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-1">
          <span className="text-[10px] uppercase text-text-faint block font-semibold">Termination Reason</span>
          <p className="font-bold text-text-primary truncate" title={terminationReason}>
            {exitCode !== null ? `Exit code ${exitCode}` : terminationReason}
          </p>
          <p className="text-[10px] text-text-faint truncate">{terminationReason}</p>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-1">
          <span className="text-[10px] uppercase text-text-faint block font-semibold">Observed Activity</span>
          <p className="font-bold text-accent">
            {job.events} Events · {job.alerts} Alerts
          </p>
          <p className="text-[10px] text-text-faint">
            {onSelectTab && (
              <button
                onClick={() => onSelectTab("events")}
                className="text-accent underline hover:text-accent/80 transition"
              >
                Inspect event stream →
              </button>
            )}
          </p>
        </div>
      </div>

      {/* Findings Requiring Inspection Table */}
      <Panel
        kicker="Correlated Detections"
        title="Findings &amp; Behavioral Alerts on this Run"
        right={
          <span className="font-mono text-xs text-text-faint tabular-nums">
            {findings.length} alert{findings.length === 1 ? "" : "s"} triggered
          </span>
        }
      >
        {findings.length === 0 ? (
          <div className="p-6 text-center font-mono text-xs text-text-muted">
            <p className="font-semibold text-text-primary">No Behavioral Alerts Triggered</p>
            <p className="text-text-faint mt-1">
              Zero OutPost behavioral detection rules fired during the monitored execution window.
            </p>
          </div>
        ) : (
          <ul className="divide-y divide-border-subtle/50 font-mono text-xs">
            {findings.map((finding) => {
              const attached = investigations.find((i) => i.id === finding.investigation_id);
              return (
                <li
                  key={finding.id}
                  className="flex flex-wrap items-start justify-between gap-3 p-3 hover:bg-bg-elevated/30 transition-colors"
                >
                  <div className="flex items-start gap-2.5 min-w-0 flex-1">
                    <span
                      className="mt-1.5 h-2 w-2 shrink-0 rounded-full"
                      style={toneFill(toneForSeverity(finding.severity))}
                      aria-hidden
                    />
                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-bold text-text-primary text-[12px]">{finding.rule_name}</span>
                        <Chip tone={finding.severity === "malicious" ? "malicious" : "suspicious"}>
                          {finding.severity}
                        </Chip>
                        <span className="rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-[9px] uppercase tracking-wider text-text-faint">
                          {finding.status}
                        </span>
                      </div>
                      <p className="text-text-muted text-[11px] leading-relaxed">{finding.details}</p>
                      <div className="flex flex-wrap items-center gap-3 text-[10px] text-text-faint">
                        <span>Alert #{finding.id}</span>
                        <span>Triggered: {finding.triggered_at}</span>
                        {finding.related_pid && <span>PID: {finding.related_pid}</span>}
                        {finding.related_ip && <span>Target IP: {finding.related_ip}</span>}
                      </div>
                    </div>
                  </div>

                  {/* Investigation Picker / Detach */}
                  <div className="shrink-0 flex items-center gap-2">
                    {attached ? (
                      <div className="flex items-center gap-1.5">
                        <Link
                          to={`/investigations/${attached.id}`}
                          className="rounded border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] font-semibold text-accent hover:underline"
                          title={attached.title}
                        >
                          {attached.title.length > 24 ? `${attached.title.slice(0, 24)}…` : attached.title}
                        </Link>
                        <button
                          onClick={() => attach.mutate({ findingId: finding.id!, investigationId: null })}
                          disabled={attach.isPending}
                          className="press rounded border border-border-subtle bg-bg-surface px-1.5 py-0.5 text-[9px] text-text-muted hover:text-text-primary transition"
                          title="Detach finding from investigation"
                        >
                          detach
                        </button>
                      </div>
                    ) : (
                      <select
                        className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-[10px] font-mono outline-none focus:border-accent"
                        value=""
                        disabled={attach.isPending}
                        onChange={(e) => {
                          if (e.target.value) {
                            attach.mutate({
                              findingId: finding.id!,
                              investigationId: e.target.value,
                              status: finding.status,
                            });
                          }
                        }}
                      >
                        <option value="">Attach to investigation…</option>
                        {investigations.map((inv) => (
                          <option key={inv.id} value={inv.id}>
                            {inv.title}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Panel>

      {/* MITRE ATT&CK Matrix Alignment */}
      <SampleMitreMatrix findings={findings} />
    </div>
  );
}
