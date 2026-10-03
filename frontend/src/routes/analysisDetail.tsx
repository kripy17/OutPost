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
import { Icon } from "../components/Icon";
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
  const [stringFilter, setStringFilter] = useState("");
  const [copiedStrings, setCopiedStrings] = useState(false);

  if (obs.kind === "strings" && Array.isArray(obs.data)) {
    const rawStrings = obs.data as string[];
    const filtered = stringFilter.trim()
      ? rawStrings.filter((s) => s.toLowerCase().includes(stringFilter.toLowerCase()))
      : rawStrings;

    const copyAll = () => {
      void navigator.clipboard.writeText(rawStrings.join("\n"));
      setCopiedStrings(true);
      setTimeout(() => setCopiedStrings(false), 2000);
    };

    return (
      <div className="rounded-xl border border-border-subtle bg-bg-surface overflow-hidden shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-subtle bg-bg-elevated/40 px-4 py-3">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs font-bold uppercase tracking-wider text-text-primary">
              Extracted &amp; Deobfuscated Strings
            </span>
            <span className="rounded-full border border-border-subtle bg-bg-base px-2 py-0.5 font-mono text-[10px] text-text-faint">
              {rawStrings.length} strings
            </span>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative">
              <input
                type="text"
                placeholder="Filter strings..."
                value={stringFilter}
                onChange={(e) => setStringFilter(e.target.value)}
                className="w-48 rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 font-mono text-[11px] text-text-primary placeholder:text-text-faint focus:border-accent focus:outline-none"
              />
            </div>
            <button
              onClick={copyAll}
              className="press rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 font-mono text-[11px] text-text-secondary hover:text-text-primary hover:border-accent/40 transition"
            >
              {copiedStrings ? "Copied ✓" : "Copy All"}
            </button>
          </div>
        </div>
        <div className="max-h-72 overflow-y-auto p-4 font-mono text-[11px] leading-relaxed text-text-primary bg-bg-base/90 divide-y divide-border-subtle/30">
          {filtered.length === 0 ? (
            <span className="text-text-faint">
              {rawStrings.length === 0 ? "none" : "No matching strings"}
            </span>
          ) : (
            filtered.map((s, idx) => (
              <div key={`${s}-${idx}`} className="py-1 flex items-start gap-3 hover:bg-bg-elevated/40 transition">
                <span className="text-text-faint tabular-nums w-8 text-right select-none opacity-50">
                  {idx + 1}
                </span>
                <span className="break-all font-mono select-all text-text-primary">{s}</span>
              </div>
            ))
          )}
        </div>
      </div>
    );
  }

  if (obs.kind === "iocs" && obs.data && typeof obs.data === "object") {
    const iocs = obs.data as Record<string, string[]>;
    const cats = Object.entries(iocs).filter(([, v]) => v.length > 0);
    if (cats.length === 0) return null;

    return (
      <div className="rounded-xl border border-border-subtle bg-bg-surface overflow-hidden shadow-xs">
        <div className="border-b border-border-subtle bg-bg-elevated/40 px-4 py-3 flex items-center justify-between">
          <span className="font-mono text-xs font-bold uppercase tracking-wider text-text-primary">
            Extracted Indicators of Compromise (IOCs)
          </span>
          <span className="text-[10px] font-mono text-text-faint">Network &amp; Host Forensics</span>
        </div>
        <div className="p-4 space-y-4">
          {cats.map(([cat, values]) => (
            <div key={cat} className="space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-accent">
                  {cat} ({values.length})
                </span>
              </div>
              <div className="flex flex-wrap gap-2">
                {values.map((v) => (
                  <div
                    key={v}
                    className="inline-flex items-center gap-2 rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 font-mono text-[11px] text-text-primary hover:border-accent/40 transition group"
                  >
                    <span className="select-all font-semibold">{v}</span>
                    <Link
                      to={`/watchlist`}
                      className="text-[9px] uppercase tracking-wider rounded border border-border-subtle bg-bg-surface px-1.5 py-0.5 text-text-faint hover:text-accent hover:border-accent/50"
                      title="Add to Watchlist"
                    >
                      Watchlist
                    </Link>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if ((obs.kind === "pe" || obs.kind === "elf") && obs.data && typeof obs.data === "object") {
    const meta = obs.data as Record<string, unknown>;
    const imports = Array.isArray(meta.imports) ? (meta.imports as string[]) : [];

    return (
      <div className="rounded-xl border border-border-subtle bg-bg-surface overflow-hidden shadow-xs space-y-4 p-4">
        <div>
          <span className="font-mono text-xs font-bold uppercase tracking-wider text-text-primary">
            Binary Header &amp; Executable Architecture ({obs.kind.toUpperCase()})
          </span>
          <dl className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4 font-mono text-xs">
            {Object.entries(meta)
              .filter(([k]) => k !== "sections" && k !== "imports")
              .map(([k, v]) => (
                <div key={k} className="rounded-lg border border-border-subtle bg-bg-base p-2.5">
                  <dt className="text-[10px] uppercase tracking-wider text-text-faint font-semibold">{k}</dt>
                  <dd className="mt-1 truncate font-mono text-[11px] font-bold text-text-primary">
                    {String(v ?? "—")}
                  </dd>
                </div>
              ))}
          </dl>
        </div>

        {imports.length > 0 && (
          <div className="border-t border-border-subtle/60 pt-3">
            <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-text-faint">
              Imported Libraries &amp; API Dependencies ({imports.length})
            </span>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {imports.map((imp) => (
                <span
                  key={imp}
                  className="rounded-md border border-border-subtle bg-bg-base px-2 py-0.5 font-mono text-[11px] text-text-secondary select-all"
                >
                  {imp}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  if (obs.kind === "note" && typeof obs.data === "string") {
    return (
      <div className="rounded-xl border border-border-subtle bg-bg-surface p-4 text-xs font-mono text-text-muted">
        {obs.data}
      </div>
    );
  }

  if (obs.timestamp || obs.event_type) {
    return (
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 rounded-lg border border-border-subtle bg-bg-base/80 px-3 py-2 font-mono text-[11px] text-text-muted">
        <span className="text-text-faint">{obs.timestamp?.slice(11, 19) ?? ""}</span>
        <span className="rounded border border-border-subtle px-1 text-[9px] uppercase text-text-faint">
          {EVENT_TYPE_LABEL[obs.event_type ?? ""] ?? obs.event_type ?? "event"}
        </span>
        <span className="font-semibold text-text-primary">{obs.process_name ?? "—"}</span>
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
          <p className="py-6 text-center text-sm text-[#C4453B]">
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
    <div className="mx-auto max-w-[1440px] px-6 py-8 lg:px-8 space-y-6">
      <PageHeader
        kicker="Analysis workspace"
        title={j.sample_name ?? `job ${j.run_id.slice(0, 12)}`}
        lede={`${j.backend} backend · run ${j.run_id}`}
        actions={
          <>
            <Link
              to={`/investigations?create=1&title=${encodeURIComponent(`Analysis Job — ${j.sample_name || j.run_id}`)}&evidence_type=run&evidence_id=${encodeURIComponent(runId ?? "")}`}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 font-mono text-[11px] font-semibold text-accent hover:bg-accent/20"
              title="Escalate this analysis job into a formal incident dossier"
            >
              Escalate Case
            </Link>
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

      {/* Executive Threat Verdict Banner */}
      {j.status === "completed" && (
        <div className={`rounded-2xl border p-5 backdrop-blur-sm shadow-sm font-mono ${
          j.risk_score >= 7
            ? "border-risk-malicious/50 bg-risk-malicious/10"
            : j.risk_score >= 4
              ? "border-risk-suspicious/50 bg-risk-suspicious/10"
              : "border-risk-clean/40 bg-risk-clean/10"
        }`}>
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <span className={`flex h-12 w-12 items-center justify-center rounded-xl border text-xl ${
                j.risk_score >= 7
                  ? "border-risk-malicious/60 bg-risk-malicious/20 text-risk-malicious"
                  : j.risk_score >= 4
                    ? "border-risk-suspicious/60 bg-risk-suspicious/20 text-risk-suspicious"
                    : "border-risk-clean/60 bg-risk-clean/20 text-risk-clean"
              }`}>
                <Icon name={j.risk_score >= 7 ? "alert" : j.risk_score >= 4 ? "zap" : "shield"} size={22} />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <span className={`text-base font-bold uppercase tracking-wide ${
                    j.risk_score >= 7 ? "text-risk-malicious" : j.risk_score >= 4 ? "text-risk-suspicious" : "text-risk-clean"
                  }`}>
                    {j.risk_score >= 7 ? "MALICIOUS SPECIMEN" : j.risk_score >= 4 ? "SUSPICIOUS BEHAVIOR" : "BENIGN / CLEAN"}
                  </span>
                  <span className="rounded bg-bg-surface/80 border border-border-subtle px-2 py-0.5 text-[10px] text-text-muted">
                    Automated Triage Verdict
                  </span>
                </div>
                <p className="text-xs text-text-muted mt-0.5">
                  Static analysis &amp; heuristic triage evaluated against 38 MITRE ATT&amp;CK rules.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <div className="text-right">
                <span className="text-[10px] uppercase tracking-wider text-text-faint block">Threat Score</span>
                <span className={`text-2xl font-bold ${
                  j.risk_score >= 7 ? "text-risk-malicious" : j.risk_score >= 4 ? "text-risk-suspicious" : "text-risk-clean"
                }`}>
                  Level {j.risk_score} / 10
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {cancelError && <p className="mb-4 text-xs text-[#C4453B]">{cancelError}</p>}

      <dl className="mb-6 grid grid-cols-2 gap-4 sm:grid-cols-4 font-mono">
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
          <p className="text-sm text-[#C4453B]">{j.error ?? "The job failed without a recorded error."}</p>
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
              <p className="py-4 text-center text-sm text-[#C4453B]">Failed to load observations</p>
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
