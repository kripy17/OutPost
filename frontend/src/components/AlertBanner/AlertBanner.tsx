import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { SEVERITY_BG } from "../../lib/constants";
import { getRuleMeta } from "../../lib/api";
import type { Alert, AlertStatus } from "../../types";

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
  onStatus,
  onBulkStatus,
}: {
  alerts: Alert[];
  triage?: boolean;
  onStatus?: (alertId: number, status: AlertStatus, comment?: string) => void;
  /** Bulk triage (select many alerts → one Ack/Resolve). Triage mode only. */
  onBulkStatus?: (ids: number[], status: AlertStatus, comment?: string) => void;
}) {
  // ATT&CK map (roadmap 1.3) — one fetch, shared by every alert card.
  // Static metadata — cache forever so monitor polling never refetches it.
  const { data: meta } = useQuery({
    queryKey: ["rules-meta"],
    queryFn: getRuleMeta,
    staleTime: Infinity,
  });
  const byRule = new Map((meta ?? []).map((m) => [m.rule_id, m]));
  // Per-alert comment drafts (only used in triage mode). Cleared once the
  // transition is submitted — the comment is consumed into the request.
  const [drafts, setDrafts] = useState<Record<number, string>>({});
  // Bulk selection (triage mode only): a Set of selected alert ids. Empty
  // disables the bulk bar; the bar Ack/Resolves every selected alert at once.
  const [bulkSelect, setBulkSelect] = useState<Set<number>>(new Set());
  const [bulkMode, setBulkMode] = useState(false);
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
      {alerts.map((alert) => {
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
              <span className={`h-2 w-2 rounded-full ${SEVERITY_BG[alert.severity]}`} />
              <span className="text-sm font-medium text-text-primary">{alert.rule_name}</span>
              <span className="font-mono text-xs text-text-faint">{alert.rule_id}</span>
              {rule && (
                <span
                  className="rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[10px] text-text-muted"
                  title={`MITRE ATT&CK ${rule.tactic}`}
                >
                  {rule.technique} · {rule.tactic}
                </span>
              )}
              {triage && aid !== null && (
                <span className={`rounded-full border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wide ${statusMeta.cls}`}>
                  {statusMeta.label}
                </span>
              )}
              <span className="ml-auto font-mono text-xs text-text-muted">
                {alert.triggered_at.slice(11, 19)} UTC
              </span>
            </div>
            <p className="mt-1.5 pl-4 font-mono text-xs text-text-muted">{alert.details}</p>
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
                  </>
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
