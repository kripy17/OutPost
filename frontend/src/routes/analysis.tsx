// Analysis — the P1.2 workflow surface over the P0.2 persisted jobs API.
//
// Operational workstation for artifact static triage and isolated dynamic
// sandbox detonation. Real-time telemetry, compound process lineage,
// network socket containment, and forensic artifacts archive.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/ui";
import {
  cancelAnalysisJob,
  createAnalysisJob,
  getSandboxDrivers,
  getSandboxEnvironment,
  getSamples,
  listAnalysisJobs,
} from "../lib/api";
import type { AnalysisBackend, AnalysisStatus } from "../types";
import { ExecutionRunsTable } from "../components/dynamicAnalysis/ExecutionRunsTable";
import { LaunchRunDrawer } from "../components/dynamicAnalysis/LaunchRunDrawer";

const STATUS_TABS: { value: AnalysisStatus | ""; label: string }[] = [
  { value: "", label: "All" },
  { value: "queued", label: "Queued" },
  { value: "running", label: "Running" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed" },
  { value: "canceled", label: "Canceled" },
];

const BACKENDS: { value: AnalysisBackend; label: string; hint: string; available?: boolean }[] = [
  { value: "static", label: "Static Triage", hint: "Synchronous deep triage over stored bytes — strings, IOCs, PE/ELF sections & entropy", available: true },
  { value: "isolated-outpost", label: "Isolated Dynamic Sandbox", hint: "Native sandbox execution with live process tracing, socket containment, and dropped artifacts", available: true },
];

export default function AnalysisPage() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [status, setStatus] = useState<AnalysisStatus | "">("");
  const [backend, setBackend] = useState<AnalysisBackend | "">("");
  const [searchFilter, setSearchFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [creating, setCreating] = useState(false);
  const [cancellingId, setCancellingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["analysis", status, backend],
    queryFn: () => listAnalysisJobs({ status: status || undefined, backend: backend || undefined, limit: 100 }),
  });

  const samples = useQuery({
    queryKey: ["samples", "launch"],
    queryFn: () => getSamples({ limit: 100 }),
  });

  const drivers = useQuery({
    queryKey: ["sandbox", "drivers"],
    queryFn: () => getSandboxDrivers(),
  });

  const sandboxEnv = useQuery({
    queryKey: ["sandbox", "environment"],
    queryFn: () => getSandboxEnvironment(),
  });

  const launch = useMutation({
    mutationFn: (params: {
      backend: AnalysisBackend;
      sample_id?: string;
      sample_name?: string;
      platform?: any;
      timeout_seconds?: number;
      isolation_driver?: string;
    }) =>
      createAnalysisJob({
        backend: params.backend,
        sample_id: params.sample_id,
        sample_name: params.sample_name,
        platform: params.backend === "static" ? undefined : params.platform,
        timeout_seconds: params.backend === "static" ? undefined : params.timeout_seconds,
      }),
    onSuccess: (job) => {
      setCreating(false);
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ["analysis"] });
      navigate(`/analysis/${job.run_id}`);
    },
    onError: (e) => {
      setError(e instanceof Error ? e.message : "Launch failed");
    },
  });

  const cancelJob = useMutation({
    mutationFn: (runId: string) => cancelAnalysisJob(runId),
    onMutate: (runId) => {
      setCancellingId(runId);
    },
    onSettled: () => {
      setCancellingId(null);
      void queryClient.invalidateQueries({ queryKey: ["analysis"] });
    },
  });

  const tabs = useMemo(
    () =>
      STATUS_TABS.map((t) => ({
        ...t,
        count: t.value === "" ? data?.total ?? 0 : data?.jobs.filter((j) => j.status === t.value).length,
      })),
    [data],
  );

  const availableDrivers = Array.isArray(drivers.data) ? drivers.data : [];
  const readyDriversCount = availableDrivers.filter((d) => d.available).length;

  return (
    <div className="space-y-6">
      <PageHeader
        kicker="Artifact analysis & detonation"
        title="Analysis Jobs & Background Tasks"
        lede="Submit vault artifacts for safe static triage or native isolated dynamic sandbox detonation. Follow background execution progress, process trees, and correlated alerts in real time."
        actions={
          <button className="btn btn-primary" onClick={() => setCreating(true)}>
            <Icon name="plus" size={14} /> New analysis
          </button>
        }
      />

      {/* Sandbox Driver & Containment Environment Strip */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border-subtle bg-bg-surface/50 px-4 py-2.5 font-mono text-xs">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            <span className="text-[11px] font-semibold text-text-primary">Execution Environment:</span>
          </div>
          <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
            <span className="rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-text-muted">
              Static Byte Engine: <strong className="text-emerald-400">Online</strong>
            </span>
            <span className="rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-text-muted">
              Micro-Sandbox Drivers: <strong className="text-accent">{readyDriversCount > 0 ? `${readyDriversCount} Ready` : "Active"}</strong>
            </span>
            <span className="rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-text-muted">
              Network Isolation: <strong className="text-text-primary">Airgap (--unshare-net)</strong>
            </span>
            {sandboxEnv.data?.dev_probe_only && (
              <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-amber-300">
                Not running inside a VM: sample analysis disabled; only built-in probes can run
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3 text-[10px] text-text-faint">
          <span>Active Queue: <strong className="text-text-primary tabular-nums">{data?.jobs.filter((j) => j.status === "queued" || j.status === "running").length ?? 0}</strong></span>
          <span>Total Vault Runs: <strong className="text-text-primary tabular-nums">{data?.total ?? 0}</strong></span>
        </div>
      </div>

      {/* Search & Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap gap-1">
          {tabs.map((t) => (
            <button
              key={t.value}
              onClick={() => setStatus(t.value)}
              className={`rounded-full border px-3 py-1 text-[11px] font-sans font-semibold transition-colors shadow-xs ${
                status === t.value
                  ? "border-accent/50 bg-accent/10 text-accent ring-1 ring-accent/30"
                  : "border-border-subtle text-text-muted hover:border-accent/30"
              }`}
            >
              {t.label}
              {t.count !== undefined && <span className="ml-1 font-mono tabular-nums text-text-faint">({t.count})</span>}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            placeholder="Search run, sample, SHA256…"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="w-48 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-[11px] text-text-primary placeholder:text-text-faint outline-none focus:border-accent/50"
          />

          <select
            className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-[11px] outline-none focus:border-accent/50"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="">All severities</option>
            <option value="malicious">Malicious (Score &ge; 7)</option>
            <option value="suspicious">Suspicious (Score 4–6)</option>
            <option value="clean">Clean (Score &le; 3)</option>
          </select>

          <select
            className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-[11px] outline-none focus:border-accent/50"
            value={backend}
            onChange={(e) => setBackend(e.target.value as AnalysisBackend | "")}
          >
            <option value="">All backends</option>
            {BACKENDS.filter((b) => b.available !== false).map((b) => (
              <option key={b.value} value={b.value}>
                {b.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Execution Runs Table */}
      <ExecutionRunsTable
        jobs={data?.jobs ?? []}
        isLoading={isLoading}
        isError={isError}
        onCancelJob={(runId) => cancelJob.mutate(runId)}
        cancellingId={cancellingId}
        statusFilter={status}
        backendFilter={backend}
        searchFilter={searchFilter}
        severityFilter={severityFilter}
      />

      {/* Launch Run Modal Drawer */}
      <LaunchRunDrawer
        isOpen={creating}
        onClose={() => {
          setCreating(false);
          setError(null);
        }}
        onLaunch={(params) => launch.mutate(params)}
        isLaunching={launch.isPending}
        samples={samples.data?.samples ?? []}
        drivers={availableDrivers}
        devProbeOnly={sandboxEnv.data?.dev_probe_only}
        error={error}
      />
    </div>
  );
}
