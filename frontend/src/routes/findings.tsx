import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { PageHeader, Panel } from "../components/ui";
import { bulkUpdateAlertStatus, getAlertQueue, getRuleMeta } from "../lib/api";
import { SEVERITY_BG, SEVERITY_COLORS, SEVERITY_LABEL } from "../lib/constants";
import type { AlertStatus, QueueAlert, Severity } from "../types";
import { ageLabel, PAGE, STATUS_TABS, statusTabCount } from "./findingsHelpers";

function FindingRow({
  a,
  selected,
  onToggle,
  ruleNames,
}: {
  a: QueueAlert;
  selected: boolean;
  onToggle: (id: number) => void;
  ruleNames: Map<string, string>;
}) {
  const sev = a.severity as Severity;
  return (
    <li
      className={`group flex items-start gap-3 rounded-xl border bg-bg-surface px-4 py-3 transition-colors duration-150 ${
        selected ? "border-accent/50 bg-accent/5" : "border-border-subtle hover:border-accent/30"
      }`}
    >
      <input
        type="checkbox"
        checked={selected}
        onChange={() => onToggle(a.id)}
        aria-label={`Select ${a.rule_name} finding`}
        className="mt-1 h-3.5 w-3.5 shrink-0 accent-[var(--accent)]"
      />
      <span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${SEVERITY_BG[sev]}`} title={SEVERITY_LABEL[sev]} aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <span className={`text-[13px] font-semibold ${SEVERITY_COLORS[sev]}`}>
            {ruleNames.get(a.rule_id) ?? a.rule_name}
          </span>
          <span className="rounded border border-border-subtle px-1 py-px font-mono text-[9px] uppercase tracking-wide text-text-faint">
            {a.rule_id}
          </span>
          <span
            className="ml-auto rounded-full border border-border-subtle px-1.5 py-px font-mono text-[10px] tabular-nums text-text-faint"
            title={`Triggered ${a.triggered_at}`}
          >
            {ageLabel(a.triggered_at)} ago
          </span>
        </div>
        <p className="mt-0.5 truncate font-mono text-[11px] text-text-muted" title={a.details}>
          {a.details}
        </p>
        <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-text-faint">
          <Link to={`/runs/${a.run_id}`} className="press inline-flex items-center gap-1 font-mono font-medium text-accent hover:underline">
            {a.sample_name}
            <Icon name="external" size={9} className="opacity-60" />
          </Link>
          {a.host_ids.filter(Boolean).map((h) => (
            <span key={h} className="inline-flex items-center gap-1 font-mono">
              <Icon name="terminal" size={9} className="opacity-60" />
              {h}
            </span>
          ))}
          {a.related_ip && (
            <Link to={`/search?q=${encodeURIComponent(a.related_ip)}`} className="press font-mono text-accent hover:underline">
              {a.related_ip}
            </Link>
          )}
          {a.related_pids.filter(Boolean).length > 0 && (
            <Link to={`/events?pid=${a.related_pids.join(",")}`} className="press font-mono hover:text-accent">
              pid {a.related_pids.join(",")}
            </Link>
          )}
          {a.assignee && <span className="font-mono">→ {a.assignee}</span>}
          {a.status !== "open" && (
            <span className="font-mono uppercase tracking-wide">
              {a.status}
              {a.status_comment ? ` — ${a.status_comment}` : ""}
            </span>
          )}
        </div>
      </div>
    </li>
  );
}

export default function FindingsPage() {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const status = (searchParams.get("status") as "open" | "acknowledged" | "resolved" | "all") ?? "open";
  const sort = (searchParams.get("sort") as "aging" | "newest") ?? "aging";
  const sev = (searchParams.get("severity") as Severity | "") ?? "";
  const q = searchParams.get("q") ?? "";
  const [submittedQ, setSubmittedQ] = useState(q);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const setParam = (k: string, v: string) => {
    const next = new URLSearchParams(searchParams);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== "offset") next.delete("offset");
    setSearchParams(next, { replace: true });
  };

  const { data, isLoading, isError } = useQuery({
    queryKey: ["alerts", "queue", status, sort, sev, submittedQ, offset],
    queryFn: () =>
      getAlertQueue({
        status,
        severity: sev || undefined,
        q: submittedQ || undefined,
        sort,
        limit: PAGE,
        offset,
      }),
  });
  const { data: ruleMeta } = useQuery({ queryKey: ["rules", "meta"], queryFn: getRuleMeta });
  const ruleNames = useMemo(() => {
    const m = new Map<string, string>();
    for (const r of ruleMeta ?? []) m.set(r.rule_id, r.rule_name);
    return m;
  }, [ruleMeta]);

  const alerts = data?.alerts ?? [];
  const onPage = alerts.map((a) => a.id);

  const toggle = (id: number) =>
    setSelected((cur) => {
      const n = new Set(cur);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  const bulk = async (nextStatus: AlertStatus) => {
    const ids = [...selected];
    if (ids.length === 0) return;
    setBusy(true);
    setMsg(null);
    try {
      const res = await bulkUpdateAlertStatus(ids, nextStatus);
      setMsg({ ok: true, text: `${res.updated} finding(s) marked ${nextStatus}.` });
      setSelected(new Set());
      await queryClient.invalidateQueries({ queryKey: ["alerts", "queue"] });
      await queryClient.invalidateQueries({ queryKey: ["statusbar"] });
    } catch {
      setMsg({ ok: false, text: "Bulk update failed — is the backend running?" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-[1200px] px-5 py-8 lg:px-8">
      <PageHeader
        kicker="Operations · findings"
        title={
          <>
            Open findings <span className="font-normal text-text-muted">— triage queue across every run</span>
          </>
        }
        lede="Every alert still needing attention, oldest first (SLA pressure). Acknowledge while you investigate, resolve when you're done — bulk-select to clear a page in one pass."
      />

      {/* Status tabs with live counts */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        {STATUS_TABS.map((t) => {
          // Badges are live totals across the active non-status filters; the
          // "All" badge sums the three status buckets (data.total is scoped
          // to the active view for pagination).
          const count = statusTabCount(t.v, data);
          return (
            <button
              key={t.v}
              onClick={() => setParam("status", t.v === "open" ? "" : t.v)}
              aria-pressed={status === t.v}
              className={`press inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 font-mono text-[11px] transition-colors duration-150 ${
                status === t.v ? "border-accent/50 bg-accent/10 font-medium text-accent" : "border-border-subtle text-text-muted hover:bg-bg-elevated hover:text-text-primary"
              }`}
            >
              {t.label}
              <span className="rounded-full border border-border-subtle bg-bg-elevated/60 px-1.5 font-mono text-[9px] tabular-nums text-text-faint">
                {count ?? "…"}
              </span>
            </button>
          );
        })}

        <div className="ml-auto flex items-center gap-2">
          <select
            value={sev}
            onChange={(e) => setParam("severity", e.target.value)}
            className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary outline-none transition-colors focus:border-accent/60"
            aria-label="Filter by severity"
          >
            <option value="">All severities</option>
            <option value="malicious">Malicious</option>
            <option value="suspicious">Suspicious</option>
          </select>
          <div className="flex items-center overflow-hidden rounded-lg border border-border-subtle" role="group" aria-label="Sort findings">
            <button
              onClick={() => setParam("sort", sort === "aging" ? "newest" : "aging")}
              aria-pressed={sort === "aging"}
              className={`px-3 py-1.5 font-mono text-[11px] transition-colors duration-150 ${
                sort === "aging" ? "bg-accent/10 font-medium text-accent" : "text-text-muted hover:bg-bg-elevated hover:text-text-primary"
              }`}
              title={sort === "aging" ? "Oldest first — findings that have waited longest surface first" : "Newest first"}
            >
              {sort === "aging" ? "Oldest first" : "Newest first"}
            </button>
          </div>
          <form
            className="flex items-center gap-1.5"
            onSubmit={(e) => {
              e.preventDefault();
              setSubmittedQ(q.trim());
              setOffset(0);
            }}
          >
            <input
              value={q}
              onChange={(e) => setParam("q", e.target.value)}
              placeholder="sample, rule, detail…"
              className="w-44 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary placeholder:text-text-faint outline-none transition-colors focus:border-accent/60"
              aria-label="Search findings"
            />
            <button type="submit" className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle px-2.5 py-1.5 font-mono text-[11px] text-text-muted transition-colors hover:border-accent/60 hover:text-accent">
              <Icon name="search" size={11} />
            </button>
          </form>
        </div>
      </div>

      {/* Bulk action bar */}
      {(selected.size > 0 || msg) && (
        <div className="mb-4 flex flex-wrap items-center gap-2 rounded-lg border border-accent/40 bg-accent/5 px-3 py-2">
          <span className="font-mono text-xs font-semibold text-accent">{selected.size} selected</span>
          <button
            onClick={() => void bulk("acknowledged")}
            disabled={busy || selected.size === 0}
            className="press rounded-md border border-border-subtle bg-bg-surface px-2.5 py-1 font-mono text-[11px] text-text-primary transition-colors hover:border-accent/60 disabled:opacity-40"
          >
            Ack {selected.size > 0 ? `(${selected.size})` : ""}
          </button>
          <button
            onClick={() => void bulk("resolved")}
            disabled={busy || selected.size === 0}
            className="press rounded-md border border-risk-clean/40 bg-risk-clean/10 px-2.5 py-1 font-mono text-[11px] text-risk-clean transition-colors hover:border-risk-clean/70 disabled:opacity-40"
          >
            Resolve
          </button>
          {selected.size > 0 && (
            <button onClick={() => setSelected(new Set())} className="press ml-auto font-mono text-[10px] text-text-faint hover:text-text-primary" title="Clear selection">
              clear
            </button>
          )}
          {msg && <span className={`font-mono text-[11px] ${msg.ok ? "text-risk-clean" : "text-risk-malicious"}`}>{msg.text}</span>}
        </div>
      )}

      <Panel
        title={status === "open" ? "Open findings" : `${status[0].toUpperCase()}${status.slice(1)} findings`}
        right={
          alerts.length > 0 ? (
            <span className="font-mono text-[10px] text-text-faint">
              {offset + 1}–{Math.min(offset + PAGE, data?.total ?? 0)} of {data?.total ?? 0}
            </span>
          ) : undefined
        }
      >
        {isLoading && (
          <div className="space-y-2 p-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="skeleton h-14 w-full" />
            ))}
          </div>
        )}
        {isError && <p className="p-6 text-sm text-risk-malicious">Couldn't load findings — is the OutPost backend running?</p>}
        {!isLoading && !isError && alerts.length === 0 && (
          <div className="p-10 text-center">
            <Icon name="check" size={26} className="mx-auto text-risk-clean" />
            <p className="mt-3 text-sm text-text-muted">
              {status === "open" ? "No open findings — the queue is clear." : "Nothing matches these filters."}
            </p>
            {(sev || submittedQ) && (
              <button
                onClick={() => {
                  setParam("severity", "");
                  setParam("q", "");
                  setSubmittedQ("");
                }}
                className="press mt-4 inline-flex items-center gap-1.5 rounded-lg border border-accent/50 px-3 py-1.5 font-mono text-xs text-accent transition-colors hover:bg-accent/10"
              >
                <Icon name="x" size={11} />
                Clear filters
              </button>
            )}
          </div>
        )}
        {!isLoading && !isError && alerts.length > 0 && (
          <div className="p-3">
            <div className="mb-2 flex items-center justify-between px-1">
              <button
                onClick={() => {
                  const all = onPage.length === 0 ? [] : onPage.every((id) => selected.has(id)) ? [] : onPage;
                  setSelected(new Set(all));
                }}
                className="press font-mono text-[10px] text-text-faint hover:text-text-primary"
              >
                {onPage.length > 0 && onPage.every((id) => selected.has(id)) ? "Clear page selection" : "Select this page"}
              </button>
              {selected.size > onPage.length && (
                <span className="font-mono text-[10px] text-text-faint">+{selected.size - onPage.length} from other pages</span>
              )}
            </div>
            <ul className="space-y-2">
              {alerts.map((a) => (
                <FindingRow key={a.id} a={a} selected={selected.has(a.id)} onToggle={toggle} ruleNames={ruleNames} />
              ))}
            </ul>
            {(data?.total ?? 0) > PAGE && (
              <div className="mt-4 flex items-center justify-between border-t border-border-subtle pt-3">
                <button
                  onClick={() => setOffset(Math.max(0, offset - PAGE))}
                  disabled={offset === 0}
                  className="press inline-flex items-center gap-1 rounded-md border border-border-subtle px-2.5 py-1 font-mono text-[11px] text-text-muted transition-colors hover:border-accent/60 disabled:opacity-40"
                >
                  <Icon name="chevronLeft" size={11} /> Prev
                </button>
                <span className="font-mono text-[10px] text-text-faint">
                  page {Math.floor(offset / PAGE) + 1} / {Math.max(1, Math.ceil((data?.total ?? 0) / PAGE))}
                </span>
                <button
                  onClick={() => setOffset(offset + PAGE)}
                  disabled={offset + PAGE >= (data?.total ?? 0)}
                  className="press inline-flex items-center gap-1 rounded-md border border-border-subtle px-2.5 py-1 font-mono text-[11px] text-text-muted transition-colors hover:border-accent/60 disabled:opacity-40"
                >
                  Next <Icon name="chevronRight" size={11} />
                </button>
              </div>
            )}
          </div>
        )}
      </Panel>
    </div>
  );
}
