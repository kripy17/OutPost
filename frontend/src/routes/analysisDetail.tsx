// Analysis workspace — the per-job view over the P0.2 persisted job + the
// P0.7 run-update stream.
//
// One run_id doubles as the job id. The page reads GET /analysis/{run_id}
// (status/progress/derived stats) plus the observations and findings
// sub-resources, and subscribes to the existing run-update SSE frames: when
// a frame arrives with job_id === this run, the job/observations/findings
// queries invalidate so the workspace tracks the persisted state live.
// Cancellation only appears for queued/running jobs — the backend rejects
// terminal states with 422, and the UI surfaces that honestly.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Chip, PageHeader, Panel, Stat } from "../components/ui";
import {
  cancelAnalysisJob,
  getAnalysisFindings,
  getAnalysisJob,
  getAnalysisObservations,
  listInvestigations,
  setAlertInvestigation,
} from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import { toneFill, toneForSeverity } from "../lib/fillPatterns";
import type { AnalysisObservation, AnalysisStatus, Finding } from "../types";

const STATUS_TONE: Record<AnalysisStatus, "muted" | "accent" | "clean" | "malicious"> = {
  queued: "muted",
  running: "accent",
  completed: "clean",
  failed: "malicious",
  canceled: "muted",
};

const EVENT_TYPE_LABEL: Record<string, string> = {
  process_create: "process",
  network_connection: "network",
  file_write: "file",
  registry_write: "registry",
};

/** One observations row. Static jobs produce {kind, data} pairs from the
 *  stored analysis result; dynamic jobs produce raw event rows (no kind
 *  wrapper — P0 defers the observations table). */
function ObservationRow({ obs }: { obs: AnalysisObservation }) {
  if (obs.kind === "strings" && Array.isArray(obs.data)) {
    const strings = obs.data as string[];
    return (
      <div>
        <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-text-faint">strings</p>
        <div className="max-h-56 overflow-y-auto rounded-lg border border-border-subtle bg-bg-inset p-3 font-mono text-[11px] leading-relaxed text-text-muted">
          {strings.length === 0 ? <span className="text-text-faint">none</span> : strings.map((s) => <div key={s}>{s}</div>)}
        </div>
      </div>
    );
  }
  if (obs.kind === "iocs" && obs.data && typeof obs.data === "object") {
    const iocs = obs.data as Record<string, string[]>;
    const cats = Object.entries(iocs).filter(([, v]) => v.length > 0);
    if (cats.length === 0) return null;
    return (
      <div>
        <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-text-faint">iocs</p>
        <div className="space-y-1.5">
          {cats.map(([cat, values]) => (
            <div key={cat} className="flex flex-wrap items-baseline gap-1.5">
              <span className="w-16 shrink-0 font-mono text-[10px] uppercase text-text-faint">{cat}</span>
              <span className="flex flex-wrap gap-1">
                {values.slice(0, 24).map((v) => (
                  <span key={v} className="rounded border border-border-subtle bg-bg-elevated px-1.5 py-px font-mono text-[10px] text-text-muted">
                    {v}
                  </span>
                ))}
                {values.length > 24 && (
                  <span className="font-mono text-[10px] text-text-faint">+{values.length - 24} more</span>
                )}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  }
  if ((obs.kind === "pe" || obs.kind === "elf") && obs.data && typeof obs.data === "object") {
    const meta = obs.data as Record<string, unknown>;
    return (
      <div>
        <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-text-faint">{obs.kind}</p>
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 rounded-lg border border-border-subtle bg-bg-inset p-3 sm:grid-cols-3">
          {Object.entries(meta)
            .filter(([k]) => k !== "sections")
            .map(([k, v]) => (
              <div key={k} className="min-w-0">
                <dt className="text-[10px] uppercase tracking-wide text-text-faint">{k}</dt>
                <dd className="truncate font-mono text-[11px] text-text-muted">{String(v ?? "—")}</dd>
              </div>
            ))}
        </dl>
      </div>
    );
  }
  // Honest note rows — e.g. static jobs whose bytes were never stored
  // ("no stored bytes — re-upload to run static analysis"). A note must
  // render, never be swallowed.
  if (obs.kind === "note" && typeof obs.data === "string") {
    return (
      <p className="rounded-lg border border-border-subtle bg-bg-inset px-3 py-2 text-[12px] text-text-muted">
        {obs.data}
      </p>
    );
  }
  // Event-row fallback (dynamic backends): the backend hands back the run's
  // events verbatim — same shape the Event Log renders.
  if (obs.timestamp || obs.event_type) {
    return (
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 rounded-lg border border-border-subtle bg-bg-inset px-3 py-2 font-mono text-[11px] text-text-muted">
        <span className="text-text-faint">{obs.timestamp?.slice(11, 19) ?? ""}</span>
        <span className="rounded border border-border-subtle px-1 text-[9px] uppercase text-text-faint">
          {EVENT_TYPE_LABEL[obs.event_type ?? ""] ?? obs.event_type ?? "event"}
        </span>
        <span>{obs.process_name ?? "—"}</span>
        {obs.dest_ip && <span className="text-accent">{obs.dest_ip}</span>}
        {obs.file_path && <span className="truncate text-text-faint">{obs.file_path}</span>}
        {obs.registry_key && <span className="truncate text-text-faint">{obs.registry_key}</span>}
      </div>
    );
  }
  return null;
}

function FindingRow({
  finding,
  investigations,
}: {
  finding: Finding;
  investigations: { id: string; title: string }[];
}) {
  const queryClient = useQueryClient();
  const attach = useMutation({
    mutationFn: (investigationId: string | null) =>
      setAlertInvestigation(finding.id!, investigationId, finding.status),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["analysis"] });
      void queryClient.invalidateQueries({ queryKey: ["investigations"] });
    },
  });

  const attached = investigations.find((i) => i.id === finding.investigation_id);

  return (
    <li className="flex flex-wrap items-start gap-3 rounded-xl border border-border-subtle bg-bg-surface px-4 py-3">
      <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={toneFill(toneForSeverity(finding.severity))} aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <span className="text-[12px] font-semibold text-text-primary">{finding.rule_name}</span>
          <Chip tone={finding.severity === "malicious" ? "malicious" : "suspicious"}>{finding.severity}</Chip>
          <span className="rounded border border-border-subtle px-1 py-px font-mono text-[9px] uppercase tracking-wide text-text-faint">
            {finding.status}
          </span>
        </div>
        <p className="mt-0.5 text-[11px] leading-snug text-text-muted">{finding.details}</p>
        <p className="mt-0.5 font-mono text-[9px] text-text-faint">
          #{finding.id} · {finding.triggered_at}
        </p>
      </div>
      <div className="flex shrink-0 flex-col items-end gap-1">
        {attached ? (
          <div className="flex items-center gap-1.5">
            <Link to={`/investigations/${attached.id}`} className="rounded border border-accent/40 bg-accent/10 px-1.5 py-px text-[9px] font-medium text-accent hover:underline" title={attached.title}>
              {attached.title.length > 28 ? `${attached.title.slice(0, 28)}…` : attached.title}
            </Link>
            <button
              className="press rounded border border-border-subtle px-1.5 py-px text-[9px] text-text-faint hover:text-text-primary"
              disabled={attach.isPending}
              onClick={() => attach.mutate(null)}
              title="Detach from investigation"
            >
              detach
            </button>
          </div>
        ) : (
          <select
            className="max-w-44 rounded-lg border border-border-subtle bg-bg-surface px-2 py-1 text-[10px] outline-none focus:border-accent/50"
            value=""
            disabled={attach.isPending}
            onChange={(e) => {
              if (e.target.value) attach.mutate(e.target.value);
            }}
          >
            <option value="">Attach to investigation…</option>
            {investigations.map((i) => (
              <option key={i.id} value={i.id}>
                {i.title}
              </option>
            ))}
          </select>
        )}
      </div>
    </li>
  );
}

export default function AnalysisDetailPage() {
  const { runId } = useParams<{ runId: string }>();
  const queryClient = useQueryClient();
  const [cancelError, setCancelError] = useState<string | null>(null);

  // P0.7 realtime: the workspace subscribes to the shared run-update stream
  // and invalidates its queries when a frame names this job. Reconnect never
  // duplicates state — the persisted row is the source of truth; a late
  // subscriber just refetches.
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
    enabled: !!runId,
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      return s === "queued" || s === "running" ? 5_000 : false;
    },
  });

  const observations = useQuery({
    queryKey: ["analysis", runId, "observations"],
    queryFn: () => getAnalysisObservations(runId!),
    enabled: !!runId && job.data?.status === "completed",
  });

  const findings = useQuery({
    queryKey: ["analysis", runId, "findings"],
    queryFn: () => getAnalysisFindings(runId!),
    enabled: !!runId && job.data?.status === "completed",
  });

  // The attach picker's options — the existing investigation list (P1.1).
  const investigations = useQuery({
    queryKey: ["investigations", "attach"],
    queryFn: () => listInvestigations({ limit: 50 }),
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
      <div>
        <PageHeader kicker="Analysis workspace" title="Job not found" />
        <Panel>
          <p className="py-6 text-center text-sm text-risk-malicious">
            Unknown analysis job{runId ? ` ${runId}` : ""} — it may have been pruned.
          </p>
        </Panel>
      </div>
    );
  }

  const j = job.data;
  const cancellable = j.status === "queued" || j.status === "running";
  const active = j.status === "queued" || j.status === "running";
  const observationsList = observations.data?.observations ?? [];
  const findingsList = findings.data ?? [];
  const isStatic = j.backend === "static";
  const eventRows = observationsList.filter((o) => !o.kind && o.timestamp);
  const shownEvents = eventRows.slice(0, 200);
  const kindRows = observationsList.filter((o) => o.kind);

  return (
    <div>
      <PageHeader
        kicker="Analysis workspace"
        title={j.sample_name ?? `job ${j.run_id.slice(0, 12)}`}
        lede={`${j.backend} backend · run ${j.run_id}`}
        actions={
          <>
            <Chip tone={j.backend === "static" ? "accent" : "muted"}>{j.backend}</Chip>
            <Chip tone={STATUS_TONE[j.status]} dot>
              {j.status}
            </Chip>
            {cancellable && (
              <button className="btn" disabled={cancel.isPending} onClick={() => cancel.mutate()}>
                {cancel.isPending ? "Canceling…" : "Cancel job"}
              </button>
            )}
          </>
        }
      />

      {cancelError && <p className="mb-4 text-xs text-risk-malicious">{cancelError}</p>}

      <dl className="mb-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label="Progress" value={`${j.progress}%`} tone={j.status === "failed" ? "malicious" : "accent"} />
        <Stat label="Events" value={j.events} />
        <Stat label="Alerts" value={j.alerts} tone={j.alerts > 0 ? "malicious" : "default"} />
        <Stat label="Risk score" value={j.risk_score} tone={j.risk_score >= 7 ? "malicious" : "default"} />
      </dl>

      {active && (
        <Panel className="mb-6">
          <div className="mb-1 flex items-center justify-between text-[11px]">
            <span className="font-medium text-text-muted">
              {j.status === "queued" ? "Queued — waiting for an executor" : "Running"}
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

      {j.status === "completed" && (
        <>
          <Panel title={isStatic ? "Observations" : "Events"} kicker={isStatic ? "static analysis result" : "run events"} className="mb-6">
            {observations.isLoading ? (
              <p className="py-4 text-center text-sm text-text-muted">Loading observations…</p>
            ) : observations.isError ? (
              <p className="py-4 text-center text-sm text-risk-malicious">Failed to load observations</p>
            ) : observationsList.length === 0 ? (
              <p className="py-4 text-center text-sm text-text-muted">No observations recorded for this job.</p>
            ) : (
              <div className="space-y-4">
                {isStatic ? (
                  kindRows.length > 0 ? kindRows.map((o, i) => <ObservationRow key={i} obs={o} />) : (
                    <p className="py-2 text-center text-sm text-text-muted">Static analysis produced no observations.</p>
                  )
                ) : (
                  <>
                    <div className="space-y-1.5">
                      {shownEvents.map((o, i) => (
                        <ObservationRow key={`${o.id ?? i}-${i}`} obs={o} />
                      ))}
                    </div>
                    {eventRows.length > 200 && (
                      <p className="text-[11px] text-text-faint">Showing {shownEvents.length} of {eventRows.length} events — open the Event Log for the full feed.</p>
                    )}
                  </>
                )}
              </div>
            )}
          </Panel>

          <Panel title="Findings" kicker="alerts on this run" className="mb-6">
            {findings.isLoading ? (
              <p className="py-4 text-center text-sm text-text-muted">Loading findings…</p>
            ) : findingsList.length === 0 ? (
              <p className="py-4 text-center text-sm text-text-muted">No findings attached to this run.</p>
            ) : (
              <ul className="space-y-2">
                {findingsList.map((f) => (
                  <FindingRow key={f.id} finding={f} investigations={investigations.data?.investigations ?? []} />
                ))}
              </ul>
            )}
          </Panel>
        </>
      )}

      {(j.status === "queued" || j.status === "running") && (
        <Panel title="Results pending" kicker="terminal states only">
          <p className="text-sm text-text-muted">
            Observations and findings render once the job reaches <span className="font-mono">completed</span>. The persisted row
            ({j.run_id}) is the source of truth across restarts.
          </p>
        </Panel>
      )}
    </div>
  );
}
