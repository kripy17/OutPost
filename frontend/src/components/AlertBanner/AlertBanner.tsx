import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Icon } from "../Icon";
import { toneFill, toneForSeverity } from "../../lib/fillPatterns";
import { addSuppression, getRuleMeta, getSuppressions, setTuning } from "../../lib/api";
import { suppressedRuleIds } from "../TriagePanels/suppressions";
import type { Alert, AlertStatus, FpResponse, FpSuggestion } from "../../types";
import { openDuration, sortAlertsForTriage, type TriageSort } from "./triage";

/** Tiny inline check glyph for bulk-select checkboxes (avoids an SVG import). */
function IconCheckMini() {
  return (
    <svg viewBox="0 0 24 24" width="1em" height="1em" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="m5 12.5 5 5 9-11" />
    </svg>
  );
}

const STATUS_META: Record<AlertStatus, { label: string; cls: string }> = {
  open: { label: "Open", cls: "border-risk-suspicious/50 text-risk-suspicious bg-risk-suspicious/10" },
  acknowledged: { label: "Acked", cls: "border-accent/50 text-accent bg-accent/10" },
  resolved: { label: "Resolved", cls: "border-risk-clean/50 text-risk-clean bg-risk-clean/10" },
};

/**
 * Alert cards for a run. With `triage` enabled (run-detail page), each card
 * gains the analyst-workflow controls: a status pill, an optional comment,
 * and Ack / Resolve / Reopen buttons that call `onStatus`.
 */
export default function AlertBanner({
  alerts,
  triage = false,
  runId,
  sampleName,
  onStatus,
  onBulkStatus,
  onFalsePositive,
}: {
  alerts: Alert[];
  triage?: boolean;
  /** Run-scoped suppression target (run-detail page) — enables the one-click
   *  "suppress this rule" action on each alert row. */
  runId?: string;
  /** Sample name, for resolving global VALUE-scoped suppressions (shared
   *  derivation with the bottom SuppressionPanel). */
  sampleName?: string | null;
  onStatus?: (alertId: number, status: AlertStatus, comment?: string) => void;
  /** Bulk triage (select many alerts → one Ack/Resolve). Triage mode only. */
  onBulkStatus?: (ids: number[], status: AlertStatus, comment?: string) => void;
  /** Mark an alert as a false positive. Should resolve the alert, bump the
   *  rule's FP counter, and return the actionable suggestions. */
  onFalsePositive?: (alertId: number, comment?: string) => Promise<FpResponse> | void;
}) {
  // ATT&CK map (roadmap 1.3) — one fetch, shared by every alert card.
  // Static metadata — cache forever so monitor polling never refetches it.
  const { data: meta } = useQuery({
    queryKey: ["rules-meta"],
    queryFn: getRuleMeta,
    staleTime: Infinity,
  });
  const byRule = new Map((meta ?? []).map((m) => [m.rule_id, m]));
  // Suppressions effective for this run — the same shared query + derivation
  // the bottom SuppressionPanel reads, so the per-row button and the panel
  // can never disagree. Only fetched in triage mode (monitor never asks).
  const queryClient = useQueryClient();
  const { data: suppressions = [] } = useQuery({
    queryKey: ["suppressions"],
    queryFn: getSuppressions,
    enabled: triage && !!runId,
    staleTime: 30_000,
  });
  const suppressedRules = runId ? suppressedRuleIds(suppressions, runId, sampleName) : new Set<string>();
  const [suppressing, setSuppressing] = useState<Record<string, boolean>>({});
  const suppressRule = async (ruleId: string) => {
    if (!runId || suppressing[ruleId]) return;
    setSuppressing((s) => ({ ...s, [ruleId]: true }));
    try {
      await addSuppression(ruleId, undefined, runId);
      void queryClient.invalidateQueries({ queryKey: ["suppressions"] });
    } finally {
      setSuppressing((s) => ({ ...s, [ruleId]: false }));
    }
  };
  // Per-alert comment drafts (only used in triage mode). Cleared once the
  // transition is submitted — the comment is consumed into the request.
  const [drafts, setDrafts] = useState<Record<number, string>>({});
  // Triage sort mode (triage only): "aging" surfaces longest-open alerts first.
  const [sortMode, setSortMode] = useState<TriageSort>("time");
  // Bulk selection (triage mode only): a Set of selected alert ids. Empty
  // disables the bulk bar; the bar Ack/Resolves every selected alert at once.
  const [bulkSelect, setBulkSelect] = useState<Set<number>>(new Set());
  const [bulkMode, setBulkMode] = useState(false);
  // FP feedback loop: per-alert mark-FP state (busy, returned suggestions).
  const [fpBusy, setFpBusy] = useState<Record<number, boolean>>({});
  const [fpResp, setFpResp] = useState<Record<number, FpResponse>>({});
  // Suggestions already applied (one-click buttons) — `${alertId}:${index}`.
  const [fpApplied, setFpApplied] = useState<Set<string>>(new Set());
  const markFp = async (alertId: number, comment?: string) => {
    if (fpBusy[alertId]) return;
    setFpBusy((b) => ({ ...b, [alertId]: true }));
    try {
      const resp = await onFalsePositive?.(alertId, comment ?? "");
      if (resp) setFpResp((r) => ({ ...r, [alertId]: resp }));
    } finally {
      setFpBusy((b) => ({ ...b, [alertId]: false }));
    }
  };
  const applySuggestion = async (alertId: number, s: FpSuggestion) => {
    if (s.kind === "threshold" && s.param && s.suggested !== undefined) {
      await setTuning(s.param, String(s.suggested)).catch(() => undefined);
    } else if (s.kind === "suppress" && s.rule_id && s.run_id) {
      await addSuppression(s.rule_id, undefined, s.run_id).catch(() => undefined);
    }
    setFpApplied((prev) => new Set(prev).add(`${alertId}:${fpResp[alertId]?.suggestions.indexOf(s) ?? 0}`));
  };
  const submitTriage = (alertId: number, status: AlertStatus, comment?: string) => {
    onStatus?.(alertId, status, comment);
    setDrafts((d) => ({ ...d, [alertId]: "" }));
  };
  const submitBulk = (status: AlertStatus) => {
    const ids = [...bulkSelect].filter((id) => id !== null && id !== undefined) as number[];
    if (ids.length === 0) return;
    onBulkStatus?.(ids, status);
    setBulkSelect(new Set());
  };
  const toggleBulk = (id: number) => {
    setBulkSelect((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const selectable = triage && onBulkStatus !== undefined && alerts.some((a) => a.id !== null && a.id !== undefined);
  const selectedCount = bulkSelect.size;
  const selectedOpen = alerts.filter((a) => a.id !== null && a.id !== undefined && bulkSelect.has(a.id as number) && a.status === "open").length;
  // Triage sort — must run before the empty-check early return (hook order).
  const shown = useMemo(() => sortAlertsForTriage(alerts, sortMode), [alerts, sortMode]);
  const now = Date.now();

  if (alerts.length === 0) {
    return (
      <div className="rounded-lg border border-risk-clean/30 bg-bg-surface px-4 py-3">
        <p className="text-sm">
          <span className="font-semibold text-risk-clean">● Clean</span>{" "}
          <span className="text-text-muted">— no detection rules fired in this session.</span>
        </p>
      </div>
    );
  }

  const malicious = alerts.filter((a) => a.severity === "malicious").length;
  const open = alerts.filter((a) => a.status === "open").length;

  return (
    <div className="space-y-2">
      <div className="rounded-t-lg border border-risk-malicious/50 bg-bg-elevated px-4 py-3">
        <div className="flex flex-wrap items-center gap-3">
          <p className="text-sm font-semibold text-risk-malicious">
            {alerts.length} alert{alerts.length > 1 ? "s" : ""}
            {malicious > 0 && ` — ${malicious} malicious`}
            {triage && open > 0 && <span className="text-risk-suspicious"> — {open} open</span>}
            {triage && open === 0 && <span className="text-risk-clean"> — all triaged</span>}
          </p>
          {triage && (
            <span
              role="group"
              aria-label="Triage sort"
              className="ml-auto flex items-center gap-0.5 rounded-lg border border-border-subtle bg-bg-elevated/40 p-0.5 font-mono text-[10px]"
            >
              {(["time", "aging"] as const).map((m) => (
                <button
                  key={m}
                  onClick={() => setSortMode(m)}
                  aria-pressed={sortMode === m}
                  className={`press rounded-md px-2 py-0.5 transition-colors duration-150 ${
                    sortMode === m ? "bg-accent/15 font-semibold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                  title={m === "aging" ? "Open alerts first — longest open at the top" : "Chronological order"}
                >
                  {m}
                </button>
              ))}
            </span>
          )}
          {selectable && (
            <span className="ml-auto flex items-center gap-2">
              {bulkMode && selectedCount > 0 && (
                <>
                  <span className="font-mono text-[10px] text-text-faint">
                    {selectedCount} selected{selectedOpen > 0 && ` · ${selectedOpen} open`}
                  </span>
                  <button
                    onClick={() => submitBulk("acknowledged")}
                    className="press rounded border border-accent/50 px-2 py-0.5 font-mono text-[10px] text-accent transition-colors hover:bg-accent/10"
                  >
                    Ack all
                  </button>
                  <button
                    onClick={() => submitBulk("resolved")}
                    className="press rounded border border-risk-clean/50 px-2 py-0.5 font-mono text-[10px] text-risk-clean transition-colors hover:bg-risk-clean/10"
                  >
                    Resolve all
                  </button>
                  <button
                    onClick={() => setBulkSelect(new Set())}
                    className="press rounded border border-border-subtle px-2 py-0.5 font-mono text-[10px] text-text-muted transition-colors hover:text-text-primary"
                    aria-label="Clear selection"
                  >
                    Clear
                  </button>
                </>
              )}
              <button
                onClick={() => {
                  setBulkMode((v) => !v);
                  setBulkSelect(new Set());
                }}
                aria-pressed={bulkMode}
                className={`press rounded border px-2 py-0.5 font-mono text-[10px] transition-colors ${
                  bulkMode
                    ? "border-accent/60 bg-accent/10 text-accent"
                    : "border-border-subtle text-text-muted hover:text-text-primary"
                }`}
              >
                {bulkMode ? "Bulk on" : "Bulk"}
              </button>
            </span>
          )}
        </div>
      </div>
      {shown.map((alert) => {
        const rule = byRule.get(alert.rule_id);
        const accent = alert.severity === "malicious" ? "border-l-risk-malicious" : "border-l-risk-suspicious";
        const statusMeta = STATUS_META[alert.status];
        const aid = alert.id;
        return (
          <div
            key={aid ?? `${alert.rule_id}-${alert.triggered_at}`}
            className={`rounded-lg border border-border-subtle border-l-2 bg-bg-surface p-3 transition-colors duration-150 hover:bg-bg-elevated/40 ${accent} ${
              bulkMode && aid !== null && bulkSelect.has(aid) ? "border-accent/70 shadow-[var(--glow-accent)]" : ""
            }`}
          >
            <div className="flex flex-wrap items-center gap-2">
              {bulkMode && aid !== null && (
                <button
                  onClick={() => toggleBulk(aid)}
                  aria-pressed={bulkSelect.has(aid)}
                  aria-label={`Select ${alert.rule_name} for bulk triage`}
                  className={`press flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors ${
                    bulkSelect.has(aid) ? "border-accent/70 bg-accent/20 text-accent" : "border-border-subtle text-transparent hover:border-accent/50"
                  }`}
                >
                  <IconCheckMini />
                </button>
              )}
              {/* Pattern-encoded severity dot (deck-wide fill language). */}
              <span className="h-2 w-2 rounded-full" style={toneFill(toneForSeverity(alert.severity))} aria-hidden />
              <span className="text-sm font-medium text-text-primary">{alert.rule_name}</span>
              <span className="font-mono text-xs text-text-faint">{alert.rule_id}</span>
              {rule && (
                <span
                  className="rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[10px] text-text-muted"
                  title={`MITRE ATT&CK ${rule.technique_name ? `${rule.technique} · ${rule.technique_name}` : rule.tactic}`}
                >
                  {rule.technique} · {rule.technique_name ?? rule.tactic}
                </span>
              )}
              {/* Process jump (Event-Manager parity): alerts that name a
                  process link straight to everything that PID did. A recon
                  sweep lists every enumerating PID at once. */}
              {(() => {
                const pids = alert.related_pids ?? [];
                const recon = alert.rule_id === "enumeration-burst" && pids.length > 1;
                const pid = alert.related_pid ?? pids[0] ?? null;
                if (recon) {
                  return (
                    <Link
                      to={`/events?pid=${pids.join(",")}`}
                      className="press inline-flex items-center gap-1 rounded border border-risk-suspicious/50 bg-risk-suspicious/10 px-1.5 py-0.5 font-mono text-[10px] text-risk-suspicious transition-colors duration-150 hover:border-risk-suspicious hover:bg-risk-suspicious/15"
                      title={`Recon sweep — ${pids.length} enumerating processes — jump to the process view`}
                    >
                      <Icon name="process" size={10} />
                      recon actors · {pids.length}
                    </Link>
                  );
                }
                return pid ? (
                  <Link
                    to={`/events?pid=${pid}`}
                    className="press inline-flex items-center gap-1 rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[10px] text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
                    title={`Everything process ${pid} did (${alert.rule_name}) — jump to the process view`}
                  >
                    <Icon name="process" size={10} />
                    pid {pid}
                  </Link>
                ) : null;
              })()}
              {triage && aid !== null && (
                <span className={`rounded-full border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wide ${statusMeta.cls}`}>
                  {statusMeta.label}
                </span>
              )}
              <span className="ml-auto flex items-center gap-2 font-mono text-xs text-text-muted">
                {triage && (
                  <span
                    className={`rounded-full border px-1.5 py-0.5 text-[9px] ${
                      alert.status === "open"
                        ? "border-risk-suspicious/40 bg-risk-suspicious/10 text-risk-suspicious"
                        : "border-border-subtle text-text-faint"
                    }`}
                    title={`Fired ${alert.triggered_at} UTC`}
                  >
                    {openDuration(alert, now) ?? "triaged"}
                  </span>
                )}
                {alert.triggered_at.slice(11, 19)} UTC
              </span>
            </div>
            <p className="mt-1.5 pl-4 font-mono text-xs text-text-muted">{alert.details}</p>
            {rule?.remediation?.length ? (
              <details className="group mt-1.5 pl-4">
                <summary className="cursor-pointer select-none font-mono text-[10px] text-accent transition-colors hover:text-accent/80">
                  What to do <span className="text-text-faint">→</span>
                </summary>
                <ul className="mt-1.5 space-y-1">
                  {rule.remediation.map((step, i) => (
                    <li key={i} className="flex items-start gap-1.5 font-mono text-[10px] leading-relaxed text-text-muted">
                      <span className="mt-0.5 h-1 w-1 shrink-0 rounded-full bg-accent/70" />
                      {step}
                    </li>
                  ))}
                </ul>
              </details>
            ) : null}
            {alert.status_comment && (
              <p className="mt-1 pl-4 font-mono text-[10px] italic text-text-faint">
                “{alert.status_comment}”
              </p>
            )}
            {triage && aid !== null && onStatus && (
              <div className="mt-2 flex flex-wrap items-center gap-2 pl-4">
                <input
                  value={drafts[aid] ?? ""}
                  onChange={(e) => setDrafts((d) => ({ ...d, [aid]: e.target.value }))}
                  placeholder="Optional comment…"
                  className="min-w-0 flex-1 rounded border border-border-subtle bg-bg-elevated/40 px-2 py-1 font-mono text-[10px] text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
                />
                {/* One-click run-scoped suppression — no scrolling to the
                    bottom panel. The refetched "suppressions" query flips
                    this into the quiet ✓ chip, which IS the feedback. */}
                {runId && alert.rule_id ? (
                  suppressedRules.has(alert.rule_id) ? (
                    <span
                      className="inline-flex items-center gap-1 rounded border border-risk-clean/40 bg-risk-clean/10 px-2 py-1 font-mono text-[10px] text-risk-clean"
                      title={`${alert.rule_name} suppressed for this run — restore it in the Rule suppressions panel below`}
                    >
                      <Icon name="check" size={9} />
                      suppressed
                    </span>
                  ) : (
                    <button
                      onClick={() => void suppressRule(alert.rule_id)}
                      disabled={suppressing[alert.rule_id]}
                      title={`Suppress ${alert.rule_name} for this run — stop it from firing on future batches`}
                      className="press rounded border border-border-subtle px-2 py-1 font-mono text-[10px] text-text-faint transition-colors hover:border-risk-malicious/50 hover:text-risk-malicious disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {suppressing[alert.rule_id] ? "suppressing…" : "suppress"}
                    </button>
                  )
                ) : null}
                {alert.status === "open" && (
                  <>
                    <button
                      onClick={() => submitTriage(aid, "acknowledged", drafts[aid] ?? "")}
                      className="press rounded border border-accent/50 px-2 py-1 font-mono text-[10px] text-accent transition-colors hover:bg-accent/10"
                    >
                      Ack
                    </button>
                    <button
                      onClick={() => submitTriage(aid, "resolved", drafts[aid] ?? "")}
                      className="press rounded border border-risk-clean/50 px-2 py-1 font-mono text-[10px] text-risk-clean transition-colors hover:bg-risk-clean/10"
                    >
                      Resolve
                    </button>
                    {onFalsePositive && (
                      <button
                        onClick={() => void markFp(aid, drafts[aid] ?? "")}
                        disabled={fpBusy[aid]}
                        title="Resolve as a false positive — feeds the rule's FP counter and suggests tuning/suppression"
                        className="press rounded border border-risk-suspicious/50 px-2 py-1 font-mono text-[10px] text-risk-suspicious transition-colors hover:bg-risk-suspicious/10 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        {fpBusy[aid] ? "Marking…" : "Mark FP"}
                      </button>
                    )}
                  </>
                )}
                {fpResp[aid] && (
                  <div className="flex w-full flex-wrap items-center gap-2 rounded border border-risk-suspicious/30 bg-risk-suspicious/5 px-2 py-1.5">
                    <span className="font-mono text-[10px] text-text-faint">
                      FP#{fpResp[aid].fp_count} for {fpResp[aid].rule_id} — suggested follow-ups:
                    </span>
                    {fpResp[aid].suggestions.map((s, i) => {
                      const done = fpApplied.has(`${aid}:${i}`);
                      return (
                        <button
                          key={`${s.kind}-${i}`}
                          onClick={() => void applySuggestion(aid, s)}
                          disabled={done}
                          className={`press rounded border px-2 py-0.5 font-mono text-[10px] transition-colors disabled:cursor-default ${
                            done
                              ? "border-risk-clean/40 text-risk-clean"
                              : "border-border-subtle text-text-muted hover:border-accent/60 hover:text-accent"
                          }`}
                          title={s.detail}
                        >
                          {done
                            ? "✓ applied"
                            : s.kind === "threshold"
                              ? `Raise ${s.param} → ${s.suggested}`
                              : "Suppress for this run"}
                        </button>
                      );
                    })}
                  </div>
                )}
                {alert.status === "acknowledged" && (
                  <>
                    <button
                      onClick={() => submitTriage(aid, "resolved", drafts[aid] ?? "")}
                      className="press rounded border border-risk-clean/50 px-2 py-1 font-mono text-[10px] text-risk-clean transition-colors hover:bg-risk-clean/10"
                    >
                      Resolve
                    </button>
                    <button
                      onClick={() => submitTriage(aid, "open", drafts[aid] ?? "")}
                      className="press rounded border border-border-subtle px-2 py-1 font-mono text-[10px] text-text-muted transition-colors hover:text-text-primary"
                    >
                      Reopen
                    </button>
                  </>
                )}
                {alert.status === "resolved" && (
                  <button
                    onClick={() => submitTriage(aid, "open", drafts[aid] ?? "")}
                    className="press rounded border border-border-subtle px-2 py-1 font-mono text-[10px] text-text-muted transition-colors hover:text-text-primary"
                  >
                    Reopen
                  </button>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
