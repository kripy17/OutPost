import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { Chip, PageHeader, Panel } from "../components/ui";
import {
  addInvestigationNote,
  addInvestigationRef,
  closeInvestigation,
  getInvestigation,
  patchInvestigation,
  removeInvestigationRef,
  reopenInvestigation,
  setAlertInvestigation,
  synthesizeInvestigation,
  getInvestigationExportUrl,
} from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import { toneFill, toneForSeverity } from "../lib/fillPatterns";
import type { AlertStatus, InvestigationNarrativeResult, InvestigationRefType, InvestigationStatus } from "../types";
import DataProvenanceBadge from "../components/DataProvenanceBadge";
import NetworkContextModal from "../components/NetworkContextModal";
import ProcessContextModal from "../components/ProcessContextModal";
import InvestigationEvidenceGraph from "../components/InvestigationEvidenceGraph";

const REF_TYPES: InvestigationRefType[] = ["run", "host", "ioc", "artifact", "campaign"];
const STATUSES: InvestigationStatus[] = ["created", "triage", "active", "contained", "resolved"];

function StatusPill({ status }: { status: InvestigationStatus }) {
  return (
    <span className={`rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
      status === "closed" ? "border-border-subtle text-text-muted" : "border-accent/40 bg-accent/10 text-accent"
    }`}>
      {status}
    </span>
  );
}

export default function InvestigationDetailPage() {
  const { investigationId = "" } = useParams();
  const queryClient = useQueryClient();
  const [noteText, setNoteText] = useState("");
  const [refType, setRefType] = useState<InvestigationRefType>("run");
  const [refId, setRefId] = useState("");
  const [conclusion, setConclusion] = useState("");
  const [showClose, setShowClose] = useState(false);
  const [inspectIp, setInspectIp] = useState<string | null>(null);
  const [inspectPid, setInspectPid] = useState<number | null>(null);
  const [narrative, setNarrative] = useState<InvestigationNarrativeResult | null>(null);
  const [synthesizing, setSynthesizing] = useState(false);
  const [completedRemediations, setCompletedRemediations] = useState<Record<string, boolean>>({});

  const handleSynthesize = async () => {
    setSynthesizing(true);
    try {
      const res = await synthesizeInvestigation(investigationId);
      setNarrative(res);
    } catch (e) {
      console.error(e);
    } finally {
      setSynthesizing(false);
    }
  };

  const { data: inv, isLoading, isError } = useQuery({
    queryKey: ["investigation", investigationId],
    queryFn: () => getInvestigation(investigationId),
    enabled: investigationId.length > 0,
  });

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["investigation", investigationId] });

  // P1.5 realtime: a run-update naming THIS case (finding attached/detached
  // from the run-detail triage panel, closed/reopened from the CLI, a note
  // or ref added elsewhere) refreshes the workspace immediately — the
  // derived severity/counts and findings panel stay live without polling.
  // The DB row is the source of truth on reconnect; local mutations still
  // invalidate as before.
  useEventStream(
    () => undefined,
    undefined,
    (r) => {
      if (r.investigation_id === investigationId) {
        invalidate();
      }
    },
  );

  const addNote = useMutation({
    mutationFn: () => addInvestigationNote(investigationId, { note: noteText.trim() }),
    onSuccess: () => {
      setNoteText("");
      invalidate();
    },
  });

  const addRef = useMutation({
    mutationFn: () => addInvestigationRef(investigationId, { ref_type: refType, ref_id: refId.trim() }),
    onSuccess: () => {
      setRefId("");
      invalidate();
    },
    onError: () => invalidate(), // surface backend validation (e.g. unknown ref)
  });

  const removeRef = useMutation({
    mutationFn: (refIdToRemove: string) => removeInvestigationRef(investigationId, refIdToRemove),
    onSuccess: invalidate,
  });

  const detachFinding = useMutation({
    mutationFn: (args: { alertId: number; currentStatus: AlertStatus }) =>
      setAlertInvestigation(args.alertId, null, args.currentStatus),
    onSuccess: invalidate,
  });

  const close = useMutation({
    mutationFn: () => closeInvestigation(investigationId, { conclusion: conclusion.trim() }),
    onSuccess: () => {
      setShowClose(false);
      setConclusion("");
      invalidate();
    },
  });

  const reopen = useMutation({ mutationFn: () => reopenInvestigation(investigationId), onSuccess: invalidate });

  const updateStatus = useMutation({
    mutationFn: (status: InvestigationStatus) => patchInvestigation(investigationId, { status }),
    onSuccess: invalidate,
  });

  if (isLoading) {
    return <Panel><p className="py-10 text-center text-sm text-text-muted">Loading investigation…</p></Panel>;
  }
  if (isError || !inv) {
    return (
      <Panel>
        <p className="py-10 text-center text-sm text-[#C4453B]">Investigation not found</p>
        <p className="pb-6 text-center"><Link to="/investigations" className="text-accent hover:underline">← All investigations</Link></p>
      </Panel>
    );
  }

  const sev = inv.severity;

  const handleExportIncidentReport = (format: "markdown" | "json" = "markdown") => {
    if (!inv) return;
    const downloadUrl = getInvestigationExportUrl(inv.id, format);
    const a = document.createElement("a");
    a.href = downloadUrl;
    a.download = `outpost-incident-brief-${inv.id}.${format === "markdown" ? "md" : "json"}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  return (
    <div className="mx-auto max-w-5xl px-6 py-8">
      <PageHeader
        kicker="Incident Response · Case File"
        title={inv.title}
        lede={
          inv.conclusion
            ? inv.conclusion
            : "An optional case anchor — attach findings, evidence refs, and notes as the analysis progresses."
        }
        actions={
          <>
            <button
              className="btn btn-primary"
              disabled={synthesizing}
              onClick={() => void handleSynthesize()}
            >
              <Icon name={synthesizing ? "refresh" : "terminal"} size={13} className={`mr-1.5 inline ${synthesizing ? "animate-spin" : ""}`} />
              {synthesizing ? "Synthesizing…" : "Synthesize Narrative"}
            </button>
            <div className="inline-flex rounded-lg border border-border-subtle bg-bg-surface overflow-hidden">
              <button
                className="px-3 py-1.5 text-xs font-semibold text-text hover:bg-bg-elevated transition flex items-center gap-1.5"
                onClick={() => handleExportIncidentReport("markdown")}
                title="Download Incident Response Brief (.md)"
              >
                <Icon name="download" size={12} className="text-accent" />
                <span>Export Brief (.md)</span>
              </button>
              <div className="w-[1px] bg-border-subtle" />
              <button
                className="px-2.5 py-1.5 text-xs font-semibold text-text-muted hover:text-text hover:bg-bg-elevated transition"
                onClick={() => handleExportIncidentReport("json")}
                title="Download Structured Case Dossier (.json)"
              >
                JSON
              </button>
            </div>
            {inv.status !== "closed" ? (
              <button className="btn" onClick={() => setShowClose((v) => !v)}>
                Close case
              </button>
            ) : (
              <button className="btn" disabled={reopen.isPending} onClick={() => reopen.mutate()}>
                {reopen.isPending ? "Reopening…" : "Reopen case"}
              </button>
            )}
            <Link to="/investigations" className="btn">
              ← All
            </Link>
          </>
        }
      />

      {/* Header stats + status */}
      <Panel className="mb-6">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-medium uppercase tracking-wide text-text-muted">Status</span>
            <StatusPill status={inv.status} />
            {inv.status !== "closed" && (
              <select
                className="rounded border border-border-subtle bg-bg-surface px-1.5 py-0.5 text-[11px] outline-none focus:border-accent/50"
                value={inv.status}
                onChange={(e) => updateStatus.mutate(e.target.value as InvestigationStatus)}
                aria-label="Move investigation status"
              >
                {STATUSES.filter((s) => s !== "closed").map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            )}
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-medium uppercase tracking-wide text-text-muted">Severity</span>
            {sev ? (
              <span className="inline-flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full" style={toneFill(toneForSeverity(sev))} aria-hidden />
                <span className="text-xs font-medium">{sev}</span>
              </span>
            ) : (
              <span className="text-xs text-text-faint">none (no findings)</span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-medium uppercase tracking-wide text-text-muted">Findings</span>
            <span className="font-mono text-xs tabular-nums">{inv.finding_count}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-medium uppercase tracking-wide text-text-muted">Refs</span>
            <span className="font-mono text-xs tabular-nums">{inv.ref_count}</span>
          </div>
          <div className="ml-auto flex items-center gap-2 font-mono text-[10px] text-text-faint">
            <span>created {inv.created_at}</span>
            {inv.closed_at && <span>· closed {inv.closed_at}</span>}
          </div>
        </div>
        {inv.tags.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-1.5">
            {inv.tags.map((t) => (
              <Chip key={t} tone="accent">{t}</Chip>
            ))}
          </div>
        )}
        {showClose && inv.status !== "closed" && (
          <div className="mt-4 rounded-lg border border-border-subtle bg-bg-inset p-3">
            <label className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-text-muted">
              Conclusion (required to close)
            </label>
            <textarea
              className="w-full rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 text-sm outline-none focus:border-accent/50"
              rows={3}
              value={conclusion}
              onChange={(e) => setConclusion(e.target.value)}
              placeholder="What did this investigation establish?"
            />
            <div className="mt-2 flex items-center gap-2">
              <button
                className="btn btn-primary"
                disabled={!conclusion.trim() || close.isPending}
                onClick={() => close.mutate()}
              >
                {close.isPending ? "Closing…" : "Close with conclusion"}
              </button>
              <button className="btn" onClick={() => setShowClose(false)}>Cancel</button>
            </div>
          </div>
        )}
      </Panel>

      {/* Synthesized Incident Narrative & Remediation Action Card */}
      {narrative && (
        <Panel kicker="AI Incident Response Copilot · Synthesis" title="Executive Incident Narrative & Containment Plan" className="mb-6">
          <div className="space-y-4">
            <div className="rounded-xl border border-accent/30 bg-accent/5 p-4">
              <span className="font-mono text-[10px] uppercase font-bold text-accent">Executive Summary</span>
              <p className="mt-1 text-xs leading-relaxed text-text-primary">{narrative.executive_summary}</p>
              {narrative.tactics_involved.length > 0 && (
                <div className="mt-3 flex flex-wrap items-center gap-1.5">
                  <span className="font-mono text-[10px] text-text-faint uppercase">Kill-Chain Phases:</span>
                  {narrative.tactics_involved.map((tac) => (
                    <span key={tac} className="rounded border border-accent/40 bg-accent/15 px-2 py-0.5 font-mono text-[10px] font-bold text-accent">
                      {tac}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Attack causality sequence */}
            {narrative.causality_timeline.length > 0 && (
              <div className="space-y-2">
                <span className="font-mono text-[10px] uppercase font-bold text-text-faint">Attack Causality Sequence:</span>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {narrative.causality_timeline.map((c) => (
                    <div key={c.step} className="rounded-lg border border-border-subtle bg-bg-surface p-2.5 font-mono text-xs">
                      <div className="flex items-center justify-between text-text-muted">
                        <span className="font-bold text-text-primary">#{c.step} · {c.rule}</span>
                        <span className={`text-[9px] uppercase font-bold ${c.severity === "malicious" ? "text-rose-400" : "text-amber-400"}`}>{c.severity}</span>
                      </div>
                      <p className="mt-1 text-[11px] truncate text-text-muted" title={c.details}>{c.details}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Prescribed Remediation Checklist */}
            <div className="space-y-2 border-t border-border-subtle pt-3">
              <span className="font-mono text-[10px] uppercase font-bold text-text-faint">Incident Containment & Remediation Checklist:</span>
              <div className="space-y-1.5">
                {narrative.remediation_checklist.map((item, idx) => {
                  const isChecked = !!completedRemediations[item];
                  return (
                    <label
                      key={idx}
                      className={`flex items-start gap-2.5 rounded-lg border p-2.5 font-mono text-xs cursor-pointer transition ${
                        isChecked
                          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300 line-through"
                          : "border-border-subtle bg-bg-surface text-text-primary hover:border-accent/40"
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => setCompletedRemediations((prev) => ({ ...prev, [item]: !prev[item] }))}
                        className="mt-0.5 h-3.5 w-3.5 accent-[var(--accent)]"
                      />
                      <span className="flex-1">{item}</span>
                    </label>
                  );
                })}
              </div>
            </div>
          </div>
        </Panel>
      )}

      {/* Incident Visual Evidence Graph */}
      <Panel
        kicker="Incident Response · Evidence Correlation Graph"
        title="Interactive Incident Correlation & Attack Graph"
        right={
          <span className="font-mono text-[10px] text-text-faint">
            Correlating Case, Hosts, Runs, Findings & Extracted IOCs
          </span>
        }
        className="mb-6"
      >
        <InvestigationEvidenceGraph
          investigation={inv}
          onSelectNode={(type, id) => {
            if (type === "ioc" && id.includes(".")) {
              setInspectIp(id);
            }
          }}
        />
      </Panel>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[3fr_2fr]">
        {/* Findings */}
        <div className="min-w-0 space-y-6">
          <Panel
            kicker="Canonical findings model (alerts)"
            title={`Attached findings · ${inv.findings.length}`}
            right={<span className="font-mono text-[10px] text-text-faint">detach never touches triage state</span>}
          >
            {inv.findings.length === 0 ? (
              <p className="py-4 text-center text-sm text-text-muted">
                No findings attached. Attach one from the Findings queue via the case link, or a run's alert rows.
              </p>
            ) : (
              <ul className="space-y-2">
                {inv.findings.map((f) => (
                  <li key={f.id} className="flex items-start gap-3 rounded-xl border border-border-subtle bg-bg-surface px-3 py-2.5">
                    <span
                      className="mt-1 h-2 w-2 shrink-0 rounded-full"
                      style={toneFill(toneForSeverity(f.severity))}
                      title={f.severity}
                      aria-hidden
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                        <Link to={`/runs/${f.run_id}`} className="press text-[12px] font-semibold text-text-primary hover:text-accent">
                          {f.rule_name}
                        </Link>
                        <span className="rounded border border-border-subtle px-1 py-px font-mono text-[9px] uppercase text-text-faint">{f.rule_id}</span>
                        <DataProvenanceBadge source="live" />
                        <span className="ml-auto font-mono text-[10px] text-text-faint">{f.status}</span>
                      </div>
                      <p className="mt-0.5 truncate font-mono text-[11px] text-text-muted" title={f.details}>{f.details}</p>
                    </div>
                    <button
                      className="press text-[10px] text-text-faint hover:text-accent"
                      title="Detach this finding from the investigation"
                      disabled={detachFinding.isPending}
                      onClick={() => f.id !== null && detachFinding.mutate({ alertId: f.id, currentStatus: f.status })}
                    >
                      <Icon name="x" size={12} />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          {/* Refs */}
          <Panel kicker="Evidence · references, not copies" title={`Refs · ${inv.refs.length}`}>
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <select
                className="rounded border border-border-subtle bg-bg-surface px-2 py-1.5 text-xs outline-none focus:border-accent/50"
                value={refType}
                onChange={(e) => setRefType(e.target.value as InvestigationRefType)}
                aria-label="Ref type"
              >
                {REF_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
              <input
                className="min-w-0 flex-1 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 text-xs outline-none focus:border-accent/50"
                placeholder={`${refType} id`}
                value={refId}
                onChange={(e) => setRefId(e.target.value)}
              />
              <button className="btn btn-primary" disabled={!refId.trim() || addRef.isPending} onClick={() => addRef.mutate()}>
                <Icon name="plus" size={12} /> Add
              </button>
            </div>
            {addRef.isError && <p className="mb-2 text-[11px] text-[#C4453B]">Ref rejected — unknown {refType} id?</p>}
            {inv.refs.length === 0 ? (
              <p className="py-3 text-center text-sm text-text-muted">No evidence refs yet.</p>
            ) : (
              <ul className="space-y-1.5">
                {inv.refs.map((r) => {
                  const refLink =
                    r.ref_type === "run" ? `/runs/${r.ref_id}` :
                    r.ref_type === "host" ? `/hosts/${encodeURIComponent(r.ref_id)}` :
                    r.ref_type === "ioc" ? `/search?q=${encodeURIComponent(r.ref_id)}` :
                    null;
                  const isIp = r.ref_type === "ioc" && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(r.ref_id);
                  return (
                  <li key={`${r.ref_type}:${r.ref_id}`} className="flex items-center gap-2 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5">
                    <span className="rounded border border-border-subtle px-1 py-px font-mono text-[9px] uppercase text-text-faint">{r.ref_type}</span>
                    {refLink ? (
                      <Link to={refLink} className="min-w-0 flex-1 truncate font-mono text-[11px] text-text-primary hover:text-accent">{r.ref_id}</Link>
                    ) : (
                      <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-text-primary">{r.ref_id}</span>
                    )}
                    {isIp && (
                      <button
                        onClick={() => setInspectIp(r.ref_id)}
                        className="press inline-flex items-center gap-1 rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-accent hover:bg-accent/20"
                        title={`Investigate network context for ${r.ref_id}`}
                      >
                        <Icon name="activity" size={10} />
                        Context
                      </button>
                    )}
                    <span className="font-mono text-[9px] text-text-faint">{r.added_at}</span>
                    <button
                      className="press text-text-faint hover:text-[#C4453B]"
                      title="Remove ref"
                      disabled={removeRef.isPending}
                      onClick={() => removeRef.mutate(r.ref_id)}
                    >
                      <Icon name="x" size={11} />
                    </button>
                  </li>
                  );
                })}
              </ul>
            )}
          </Panel>
        </div>

        {/* Notes */}
        <div className="min-w-0">
          <Panel kicker="Analyst notes" title={`Notes · ${inv.notes.length}`}>
            <div className="mb-3">
              <textarea
                className="w-full rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 text-sm outline-none focus:border-accent/50"
                rows={3}
                value={noteText}
                onChange={(e) => setNoteText(e.target.value)}
                placeholder="Observations, hypotheses, next steps…"
              />
              <button
                className="btn btn-primary mt-2"
                disabled={!noteText.trim() || addNote.isPending}
                onClick={() => addNote.mutate()}
              >
                {addNote.isPending ? "Adding…" : "Add note"}
              </button>
            </div>
            {inv.notes.length === 0 ? (
              <p className="py-3 text-center text-sm text-text-muted">No notes yet.</p>
            ) : (
              <ul className="space-y-2">
                {inv.notes.map((n) => (
                  <li key={n.id} className="rounded-lg border border-border-subtle bg-bg-surface px-3 py-2">
                    <p className="whitespace-pre-wrap text-[12px] leading-relaxed text-text-primary">{n.note}</p>
                    <p className="mt-1.5 font-mono text-[9px] text-text-faint">{n.actor} · {n.created_at}</p>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>

      {inspectIp !== null && (
        <NetworkContextModal ip={inspectIp} onClose={() => setInspectIp(null)} />
      )}
      {inspectPid !== null && (
        <ProcessContextModal pid={inspectPid} onClose={() => setInspectPid(null)} />
      )}
    </div>
  );
}
