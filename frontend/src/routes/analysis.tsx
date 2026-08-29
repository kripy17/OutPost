// Analysis — the P1.2 workflow surface over the P0.2 persisted jobs API.
//
// Two halves on one page: a launch panel (backend + sample/artifact selection,
// job creation) and the job archive (status/backend filters + per-job rows
// linking into the workspace). The backend contract is the source of truth —
// no new endpoints here; this consumes POST/GET /analysis exactly as P0.2
// defined them. `isolated-outpost` is deliberately NOT offered as a launch
// option: the backend returns 501 for it (reserved enum, no execution env),
// and listing it as if it worked would be a fabricated capability.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Icon } from "../components/Icon";
import { Chip, PageHeader, Panel } from "../components/ui";
import { createAnalysisJob, getSamples, listAnalysisJobs } from "../lib/api";
import { toneFill, toneForSeverity } from "../lib/fillPatterns";
import type { AnalysisBackend, AnalysisJob, AnalysisStatus } from "../types";

const STATUS_TABS: { value: AnalysisStatus | ""; label: string }[] = [
  { value: "", label: "All" },
  { value: "queued", label: "Queued" },
  { value: "running", label: "Running" },
  { value: "completed", label: "Completed" },
  { value: "failed", label: "Failed" },
  { value: "canceled", label: "Canceled" },
];

const BACKENDS: { value: AnalysisBackend; label: string; hint: string; available?: boolean }[] = [
  { value: "static", label: "Static", hint: "Synchronous triage over the stored bytes — strings, IOCs, PE/ELF metadata" },
  { value: "external-provider", label: "External provider", hint: "Detonate via Any.Run / Triage / Joe Sandbox — or the built-in demo provider" },
  { value: "watched-host", label: "Watched host", hint: "Execution backend not configured — no host executor exists yet (501)", available: false },
  { value: "isolated-outpost", label: "Isolated OutPost", hint: "Reserved — no isolated execution environment exists yet (501)", available: false },
];

const PROVIDERS = ["auto", "demo", "anyrun", "triage", "joe"] as const;

const STATUS_TONE: Record<AnalysisStatus, "muted" | "accent" | "clean" | "malicious"> = {
  queued: "muted",
  running: "accent",
  completed: "clean",
  failed: "malicious",
  canceled: "muted",
};

function statusTone(status: AnalysisStatus) {
  return STATUS_TONE[status];
}

function JobRow({ job }: { job: AnalysisJob }) {
  const sev = job.risk_score >= 7 ? "malicious" : job.risk_score >= 4 ? "suspicious" : null;
  return (
    <li className="group flex items-start gap-3 rounded-xl border border-border-subtle bg-bg-surface px-4 py-3 transition-colors duration-150 hover:border-accent/30">
      <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={sev ? toneFill(toneForSeverity(sev)) : { background: "var(--border-subtle)" }} aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <Link to={`/analysis/${job.run_id}`} className="press truncate text-[13px] font-semibold text-text-primary hover:text-accent">
            {job.sample_name ?? `job ${job.run_id.slice(0, 8)}`}
          </Link>
          <span className="rounded border border-border-subtle px-1 py-px font-mono text-[9px] uppercase tracking-wide text-text-faint">
            {job.backend}
          </span>
          <Chip tone={statusTone(job.status)} dot>
            {job.status}
          </Chip>
          <span className="ml-auto inline-flex items-center gap-2.5 font-mono text-[10px] tabular-nums text-text-faint">
            <span title="Run id">
              <Icon name="external" size={9} className="opacity-60" /> {job.run_id.slice(0, 12)}
            </span>
            <span title="Progress">{job.progress}%</span>
          </span>
        </div>
        {job.backend !== "static" && job.status !== "completed" && job.status !== "canceled" && (
          <div className="mt-2 h-1 w-full overflow-hidden rounded-full bg-bg-inset">
            <div
              className="h-full rounded-full bg-accent/70 transition-[width] duration-500"
              style={{ width: `${Math.max(2, job.progress)}%` }}
            />
          </div>
        )}
        <p className="mt-1 font-mono text-[10px] text-text-faint">
          {job.events} events · {job.alerts} alerts · risk {job.risk_score}
          {job.finished_at ? ` · finished ${job.finished_at}` : job.started_at ? ` · started ${job.started_at}` : ""}
        </p>
      </div>
    </li>
  );
}

export default function AnalysisPage() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [status, setStatus] = useState<AnalysisStatus | "">("");
  const [backend, setBackend] = useState<AnalysisBackend | "">("");
  const [creating, setCreating] = useState(false);

  // Launch form state.
  const [launchBackend, setLaunchBackend] = useState<AnalysisBackend>("static");
  const [provider, setProvider] = useState<string>("demo");
  const [sampleId, setSampleId] = useState("");
  const [sampleName, setSampleName] = useState("");
  const [timeoutSeconds, setTimeoutSeconds] = useState("120");
  const [manualName, setManualName] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["analysis", status, backend],
    queryFn: () => listAnalysisJobs({ status: status || undefined, backend: backend || undefined, limit: 100 }),
  });

  // The launch sample picker reads the sample library (GET /samples) — the
  // P0 artifact mapping. Synthetic-only binaries are hidden by default.
  const samples = useQuery({
    queryKey: ["samples", "launch"],
    queryFn: () => getSamples({ limit: 100 }),
  });

  const launch = useMutation({
    mutationFn: () =>
      createAnalysisJob({
        backend: launchBackend,
        sample_id: sampleId || undefined,
        sample_name: manualName || !sampleId ? sampleName.trim() || undefined : undefined,
        timeout_seconds: launchBackend === "static" ? undefined : Number(timeoutSeconds) || undefined,
        provider: launchBackend === "external-provider" ? provider : undefined,
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

  const selectedSample = samples.data?.samples.find((s) => s.sample_id === sampleId);
  const resolvedPlatform = selectedSample?.detected_platform !== "unknown" ? selectedSample?.detected_platform : undefined;

  const tabs = useMemo(
    () =>
      STATUS_TABS.map((t) => ({
        ...t,
        count: t.value === "" ? data?.total ?? 0 : undefined,
      })),
    [data],
  );

  return (
    <div>
      <PageHeader
        kicker="Artifact analysis"
        title="Analysis"
        lede="Submit an artifact for static triage or provider-backed detonation and follow the job through its persisted lifecycle — results land as observations and findings. Watched-host and isolated backends stay honestly unavailable (501) until their execution environments exist."
        actions={
          <button className="btn btn-primary" onClick={() => setCreating((v) => !v)}>
            <Icon name="plus" size={14} /> New analysis
          </button>
        }
      />

      {creating && (
        <Panel title="New analysis" kicker="POST /analysis" className="mb-6">
          <div className="space-y-4">
            <div>
              <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-text-muted">Backend</label>
              <div className="grid gap-2 sm:grid-cols-2">
                {BACKENDS.map((b) => (
                  <button
                    key={b.value}
                    onClick={() => setLaunchBackend(b.value)}
                    disabled={b.available === false}
                    className={`rounded-xl border px-3 py-2.5 text-left transition-colors ${
                      launchBackend === b.value
                        ? "border-accent/50 bg-accent/10"
                        : b.available === false
                          ? "cursor-not-allowed border-border-subtle opacity-50"
                          : "border-border-subtle hover:border-accent/30"
                    }`}
                  >
                    <span className="block text-[12px] font-semibold text-text-primary">{b.label}</span>
                    <span className="mt-0.5 block text-[10px] leading-snug text-text-faint">{b.hint}</span>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-text-muted">Artifact</label>
              {!manualName && (
                <select
                  className="w-full rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 text-sm outline-none focus:border-accent/50"
                  value={sampleId}
                  onChange={(e) => setSampleId(e.target.value)}
                >
                  <option value="">— select from the sample library —</option>
                  {samples.data?.samples.map((s) => (
                    <option key={s.sample_id} value={s.sample_id}>
                      {s.original_name} · {s.detected_platform} · {s.sha256.slice(0, 12)}…
                    </option>
                  ))}
                </select>
              )}
              <div className="mt-2 flex items-center gap-2">
                <label className="flex items-center gap-1.5 text-[11px] text-text-muted">
                  <input type="checkbox" checked={manualName} onChange={(e) => setManualName(e.target.checked)} className="accent-[var(--accent)]" />
                  Manual sample name
                </label>
                {sampleId && resolvedPlatform && (
                  <span className="rounded border border-border-subtle px-1.5 py-px font-mono text-[9px] uppercase tracking-wide text-text-faint">
                    platform {resolvedPlatform}
                  </span>
                )}
              </div>
              {manualName && (
                <input
                  className="mt-2 w-full rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 text-sm outline-none focus:border-accent/50"
                  placeholder="e.g. artifact.bin"
                  value={sampleName}
                  onChange={(e) => setSampleName(e.target.value)}
                />
              )}
            </div>

            {launchBackend === "external-provider" && (
              <div className="max-w-40">
                <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-text-muted">Provider</label>
                <select
                  className="w-full rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 text-sm outline-none focus:border-accent/50"
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                >
                  {PROVIDERS.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
                <p className="mt-1 text-[10px] leading-snug text-text-faint">
                  live providers need their API key env var; demo needs nothing
                </p>
              </div>
            )}

            {launchBackend !== "static" && (
              <div className="max-w-40">
                <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-text-muted">
                  Timeout <span className="normal-case text-text-faint">(seconds)</span>
                </label>
                <input
                  type="number"
                  min={1}
                  className="w-full rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 text-sm outline-none focus:border-accent/50"
                  value={timeoutSeconds}
                  onChange={(e) => setTimeoutSeconds(e.target.value)}
                />
              </div>
            )}

            {error && <p className="text-xs text-risk-malicious">{error}</p>}

            <div className="flex items-center gap-2">
              <button
                className="btn btn-primary"
                disabled={
                  launch.isPending ||
                  (!sampleId && !(manualName && sampleName.trim()))
                }
                onClick={() => launch.mutate()}
              >
                {launch.isPending ? "Launching…" : "Launch analysis"}
              </button>
              <button className="btn" onClick={() => setCreating(false)}>
                Cancel
              </button>
            </div>
          </div>
        </Panel>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap gap-1">
          {tabs.map((t) => (
            <button
              key={t.value}
              onClick={() => setStatus(t.value)}
              className={`rounded-full border px-3 py-1 text-[11px] font-medium transition-colors ${
                status === t.value
                  ? "border-accent/50 bg-accent/10 text-accent"
                  : "border-border-subtle text-text-muted hover:border-accent/30"
              }`}
            >
              {t.label}
              {t.count !== undefined && <span className="ml-1 font-mono tabular-nums text-text-faint">{t.count}</span>}
            </button>
          ))}
        </div>
        <select
          className="ml-auto rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 text-[11px] outline-none focus:border-accent/50"
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

      {isLoading ? (
        <Panel><p className="py-6 text-center text-sm text-text-muted">Loading analysis jobs…</p></Panel>
      ) : isError ? (
        <Panel><p className="py-6 text-center text-sm text-risk-malicious">Failed to load analysis jobs</p></Panel>
      ) : (data?.jobs.length ?? 0) === 0 ? (
        <Panel>
          <p className="py-6 text-center text-sm text-text-muted">
            No analysis jobs{status ? ` in ${status}` : ""}{backend ? ` · ${backend}` : ""}. Launch one above to see its persisted lifecycle here.
          </p>
        </Panel>
      ) : (
        <ul className="space-y-2">
          {data!.jobs.map((job) => (
            <JobRow key={job.run_id} job={job} />
          ))}
        </ul>
      )}
    </div>
  );
}
