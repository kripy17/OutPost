// Analysis workspace — the per-job view over the P0.2 persisted job + the
// P0.7 run-update stream.
//
// Operational workstation for deep runtime telemetry, compound process lineage,
// network socket inspection, dropped forensic artifacts, and MITRE matrix correlation.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Icon, type IconName } from "../components/Icon";
import { PageHeader, Panel, Stat } from "../components/ui";
import {
  cancelAnalysisJob,
  getAnalysisFindings,
  getAnalysisJob,
  getAnalysisObservations,
  listInvestigations,
  listSandboxArtifacts,
} from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import { DynamicRunHeader } from "../components/dynamicAnalysis/DynamicRunHeader";
import { ExecutionSummaryTab } from "../components/dynamicAnalysis/ExecutionSummaryTab";
import { ProcessActivityTab } from "../components/dynamicAnalysis/ProcessActivityTab";
import { NetworkActivityTab } from "../components/dynamicAnalysis/NetworkActivityTab";
import { FileSystemArtifactsTab } from "../components/dynamicAnalysis/FileSystemArtifactsTab";
import { BehavioralEventsTab } from "../components/dynamicAnalysis/BehavioralEventsTab";

export default function AnalysisDetailPage() {
  const { runId } = useParams<{ runId: string }>();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<string>("summary");
  const [cancelError, setCancelError] = useState<string | null>(null);

  // Real-time updates subscription: invalidates queries on run-update SSE frames
  useEventStream(
    () => {},
    undefined,
    (r) => {
      if (r.job_id && r.job_id === runId) {
        void queryClient.invalidateQueries({ queryKey: ["analysis", runId] });
      }
    },
  );

  const job = useQuery({
    queryKey: ["analysis", runId],
    queryFn: () => getAnalysisJob(runId!),
    enabled: Boolean(runId),
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      return s === "queued" || s === "running" ? 5_000 : false;
    },
  });

  const observations = useQuery({
    queryKey: ["analysis", runId, "observations"],
    queryFn: () => getAnalysisObservations(runId!),
    enabled: Boolean(runId) && job.data?.status === "completed",
  });

  const findings = useQuery({
    queryKey: ["analysis", runId, "findings"],
    queryFn: () => getAnalysisFindings(runId!),
    enabled: Boolean(runId) && job.data?.status === "completed",
  });

  const investigations = useQuery({
    queryKey: ["investigations", "attach"],
    queryFn: () => listInvestigations({ limit: 50 }),
  });

  const artifacts = useQuery({
    queryKey: ["sandbox", "artifacts", runId],
    queryFn: () => listSandboxArtifacts(runId!),
    enabled: Boolean(runId) && job.data?.status === "completed" && job.data?.backend !== "static",
  });

  const cancel = useMutation({
    mutationFn: () => cancelAnalysisJob(runId!),
    onSuccess: (updated) => {
      setCancelError(null);
      void queryClient.invalidateQueries({ queryKey: ["analysis"] });
      queryClient.setQueryData(["analysis", runId], updated);
    },
    onError: (e) => setCancelError(e instanceof Error ? e.message : "Cancel failed"),
  });

  if (job.isLoading) {
    return (
      <div>
        <PageHeader kicker="Analysis workspace" title="Loading job…" />
        <Panel><p className="py-6 text-center text-sm text-text-muted">Loading analysis job…</p></Panel>
      </div>
    );
  }

  if (job.isError || !job.data) {
    return (
      <div className="mx-auto max-w-4xl px-6 py-12">
        <PageHeader kicker="Analysis workspace · 404" title="Job not found" />
        <Panel>
          <p className="py-4 text-center text-sm text-text-muted">
            Unknown analysis job <span className="font-mono text-text-primary">{runId}</span> — it may have been pruned or not yet queued.
          </p>
          <div className="mt-2 text-center">
            <Link to="/analysis" className="press inline-flex items-center gap-1.5 font-mono text-xs text-accent underline">
              <Icon name="chevronLeft" size={12} />
              Return to Analysis &amp; Detonations
            </Link>
          </div>
        </Panel>
      </div>
    );
  }

  const j = job.data;
  const isStatic = j.backend === "static";
  const active = j.status === "queued" || j.status === "running";
  const observationsList = Array.isArray(observations.data?.observations) ? observations.data.observations : [];
  const findingsList = Array.isArray(findings.data) ? findings.data : [];
  const artifactsList = Array.isArray(artifacts.data) ? artifacts.data : [];

  // Compute telemetry metrics for tab badges
  const pidsCount = new Set(observationsList.filter((o) => o.pid).map((o) => o.pid)).size;
  const networkCount = observationsList.filter((o) => o.dest_ip || o.event_type === "network_connection").length;
  const fileCount = observationsList.filter((o) => o.file_path || o.event_type === "file_write").length + artifactsList.length;

  const dynamicTabs: Array<{ id: string; label: string; count?: string; icon: IconName }> = [
    { id: "summary", label: "Execution Summary", count: findingsList.length > 0 ? `${findingsList.length} alerts` : undefined, icon: "shield" },
    { id: "process_tree", label: "Process Tree", count: pidsCount > 0 ? `${pidsCount} PIDs` : undefined, icon: "terminal" },
    { id: "network", label: "Network Sockets", count: networkCount > 0 ? `${networkCount}` : undefined, icon: "activity" },
    { id: "artifacts", label: "Files & Artifacts", count: fileCount > 0 ? `${fileCount}` : undefined, icon: "box" },
    { id: "events", label: "Behavioral Events", count: observationsList.length > 0 ? `${observationsList.length}` : undefined, icon: "clock" },
  ];

  const staticTabs: Array<{ id: string; label: string; count?: string; icon: IconName }> = [
    { id: "summary", label: "Triage Summary & Indicators", count: findingsList.length > 0 ? `${findingsList.length} alerts` : undefined, icon: "shield" },
    { id: "events", label: "Extracted Strings & Symbols", count: observationsList.length > 0 ? `${observationsList.length}` : undefined, icon: "box" },
  ];

  const tabs = isStatic ? staticTabs : dynamicTabs;

  return (
    <div className="space-y-6">
      {/* Dynamic Run Header */}
      <DynamicRunHeader
        job={j}
        onCancelJob={() => cancel.mutate()}
        isCancelling={cancel.isPending}
        onRerun={() => navigate("/analysis")}
        droppedArtifactsCount={artifactsList.length}
      />

      {cancelError && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-400 font-mono">
          {cancelError}
        </div>
      )}

      {/* Primary KPI Stats Strip */}
      <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4 font-mono">
        <Stat label="Progress" value={`${j.progress}%`} tone={j.status === "failed" ? "malicious" : "accent"} />
        <Stat label="Events" value={j.events} />
        <Stat label="Alerts" value={j.alerts} tone={j.alerts > 0 ? "malicious" : "default"} />
        <Stat label="Risk score" value={j.risk_score} tone={j.risk_score >= 7 ? "malicious" : "default"} />
      </dl>

      {/* Active Progress Bar (Running / Queued) */}
      {active && (
        <Panel className="mb-6">
          <div className="mb-1 flex items-center justify-between text-[11px]">
            <span className="font-medium text-text-muted">
              {j.status === "queued" ? "Queued — waiting for an executor" : "Running execution flight recorder"}
            </span>
            <span className="font-mono tabular-nums text-text-faint">{j.progress}%</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-bg-inset">
            <div
              className="h-full rounded-full bg-accent/70 transition-[width] duration-500"
              style={{ width: `${Math.max(2, j.progress)}%` }}
            />
          </div>
          <p className="mt-2 text-[11px] text-text-faint">
            {j.started_at ? `started ${j.started_at}` : "not started"} · the run-update stream pushes each transition to this page live.
          </p>
        </Panel>
      )}

      {/* Terminal State Panels */}
      {j.status === "failed" && (
        <Panel className="mb-6" title="Job failed" kicker="terminal state">
          <p className="text-sm text-risk-malicious">{j.error ?? "The job failed without a recorded error."}</p>
        </Panel>
      )}

      {j.status === "canceled" && (
        <Panel className="mb-6" title="Job canceled" kicker="terminal state">
          <p className="text-sm text-text-muted">This job was canceled before completion{j.finished_at ? ` (${j.finished_at})` : ""}.</p>
        </Panel>
      )}

      {active && (
        <Panel title="Results pending" kicker="terminal states only">
          <p className="text-sm text-text-muted">
            Observations and findings render once the job reaches <span className="font-mono">completed</span>. The persisted row
            ({j.run_id}) is the source of truth across restarts.
          </p>
        </Panel>
      )}

      {/* Completed Job Workspace Tabs */}
      {j.status === "completed" && (
        <div className="space-y-6">
          {/* Workstation Navigation Tab Bar */}
          <div className="flex flex-wrap items-center gap-1.5 border-b border-border-subtle pb-2">
            {tabs.map((tab) => {
              const isSelected = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`press flex items-center gap-2 rounded-xl px-3.5 py-2 text-xs font-sans font-semibold transition ${
                    isSelected
                      ? "bg-accent/15 text-accent border border-accent/40 shadow-xs"
                      : "text-text-muted hover:text-text-primary hover:bg-bg-elevated/40 border border-transparent"
                  }`}
                >
                  <Icon name={tab.icon} size={14} className={isSelected ? "text-accent" : "text-text-faint"} />
                  <span>{tab.label}</span>
                  {tab.count && (
                    <span className={`rounded-full px-1.5 py-0.2 font-mono text-[9px] tabular-nums ${
                      isSelected ? "bg-accent/20 text-accent font-bold" : "bg-bg-elevated text-text-faint"
                    }`}>
                      {tab.count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Tab Panel Viewports */}
          {activeTab === "summary" && (
            <div className="space-y-6">
              <ExecutionSummaryTab
                job={j}
                findings={findingsList}
                investigations={investigations.data?.investigations ?? []}
                onSelectTab={(tabKey) => setActiveTab(tabKey)}
              />

              {/* For static triage jobs, render static byte observations directly in summary for unified triage */}
              {isStatic && (
                <BehavioralEventsTab
                  observations={observationsList}
                  isStatic={true}
                />
              )}
            </div>
          )}

          {activeTab === "process_tree" && (
            <ProcessActivityTab
              observations={observationsList}
              runId={j.run_id}
            />
          )}

          {activeTab === "network" && (
            <NetworkActivityTab
              observations={observationsList}
              runId={j.run_id}
            />
          )}

          {activeTab === "artifacts" && (
            <FileSystemArtifactsTab
              observations={observationsList}
              runId={j.run_id}
            />
          )}

          {activeTab === "events" && (
            <BehavioralEventsTab
              observations={observationsList}
              isStatic={isStatic}
            />
          )}
        </div>
      )}
    </div>
  );
}
