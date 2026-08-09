// Triage queue — the analyst's day-to-day work list.
//
// Every alert across every run, filtered the way an analyst thinks: by status,
// rule, host, severity, campaign, or free text. Defaults to *aging* order so
// the alert that's been open longest surfaces first (SLA pressure), with bulk
// ack/resolve for sweeps and one-click assignment. Alerts link back to their
// run detail; resolved/FP rows drop out of the open view.

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Icon } from "../components/Icon";
import { PageHeader, Panel } from "../components/ui";
import { assignAlert, bulkUpdateAlertStatus, getAgents, getAlertQueue, getRuleFp } from "../lib/api";
import type { QueueAlert } from "../types";

function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h`;
  return `${Math.floor(hrs / 24)}d`;
}

function severityTone(sev: string) {
  return sev === "malicious" ? "text-risk-malicious border-risk-malicious/40 bg-risk-malicious/10" : "text-risk-suspicious border-risk-suspicious/40 bg-risk-suspicious/10";
}

const STATUS_LABEL: Record<string, string> = {
  open: "open",
  acknowledged: "acked",
  resolved: "resolved",
};

function QueueRow({
  alert,
  selected,
  onToggle,
  onAssign,
  onStatus,
}: {
  alert: QueueAlert;
  selected: boolean;
  onToggle: (id: number) => void;
  onAssign: (id: number, assignee: string) => void;
  onStatus: (id: number, status: "acknowledged" | "resolved") => void;
}) {
  const ageSecs = Math.max(0, (Date.now() - new Date(alert.triggered_at).getTime()) / 1000);
  const overdue = alert.status === "open" && ageSecs > 24 * 3600;
  const fp = (alert.status_comment ?? "").startsWith("FP");
  return (
    <li
      className={`rounded-xl border bg-bg-surface transition-colors ${
        overdue ? "border-risk-malicious/50" : "border-border-subtle hover:border-accent/40"
      }`}
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-3">
        <input
          type="checkbox"
          checked={selected}
          onChange={() => onToggle(alert.id)}
          aria-label={`select alert ${alert.id}`}
          className="h-3.5 w-3.5 accent-[var(--accent)]"
        />
        <span className={`w-20 shrink-0 rounded-full border px-2 py-px text-center font-mono text-[10px] ${severityTone(alert.severity)}`}>
          {alert.severity}
        </span>
        <span
          className={`rounded-full border px-2 py-px font-mono text-[10px] ${
            alert.status === "open"
              ? "border-border-subtle text-text-muted"
              : alert.status === "acknowledged"
                ? "border-accent/40 bg-accent/10 text-accent"
                : "border-signal/40 bg-signal/10 text-signal"
          }`}
        >
          {fp ? "fp" : STATUS_LABEL[alert.status]}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
            <Link
              to={`/runs/${alert.run_id}`}
              className="font-mono text-[13px] font-semibold text-text-primary hover:text-accent"
              title={alert.details}
            >
              {alert.rule_name}
            </Link>
            <span className="font-mono text-[10px] text-text-faint">{alert.rule_id}</span>
          </div>
          <p className="mt-0.5 flex flex-wrap items-center gap-x-2 font-mono text-[11px] text-text-faint">
            <Link to={`/runs/${alert.run_id}`} className="hover:text-accent">
              {alert.sample_name}
            </Link>
            {alert.host_ids.map((h) => (
              <Link key={h} to={`/events?q=${encodeURIComponent(h)}`} className="hover:text-accent">
                {h}
              </Link>
            ))}
            {alert.related_ip && (
              <Link to={`/search?q=${encodeURIComponent(alert.related_ip)}`} className="hover:text-accent">
                {alert.related_ip}
              </Link>
            )}
            {alert.related_pid && <span>pid {alert.related_pid}</span>}
          </p>
        </div>
        <span
          className={`shrink-0 font-mono text-[11px] tabular-nums ${
            overdue ? "font-semibold text-risk-malicious" : "text-text-faint"
          }`}
          title={`open for ${Math.floor(ageSecs)}s`}
        >
          {overdue && <Icon name="alert" size={11} className="mr-1 inline" />}
          {relativeTime(alert.triggered_at)}
        </span>
        <select
          value={alert.assignee ?? ""}
          onChange={(e) => onAssign(alert.id, e.target.value)}
          aria-label={`assign alert ${alert.id}`}
          className="shrink-0 rounded-lg border border-border-subtle bg-bg-elevated px-2 py-1 font-mono text-[11px] text-text-muted outline-none focus:border-accent/60"
        >
          <option value="">unassigned</option>
          <option value="you">you</option>
          <option value="sofi">sofi</option>
          <option value="max">max</option>
        </select>
        {alert.status !== "resolved" && (
          <div className="flex shrink-0 items-center gap-1.5">
            {alert.status === "open" && (
              <button
                onClick={() => onStatus(alert.id, "acknowledged")}
                className="press rounded-lg border border-border-subtle px-2 py-1 font-mono text-[10px] text-text-muted hover:border-accent/60 hover:text-accent"
              >
                ack
              </button>
            )}
            <button
              onClick={() => onStatus(alert.id, "resolved")}
              className="press rounded-lg border border-border-subtle px-2 py-1 font-mono text-[10px] text-text-muted hover:border-signal/60 hover:text-signal"
            >
              resolve
            </button>
          </div>
        )}
      </div>
    </li>
  );
}

export default function TriagePage() {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState("open");
  const [ruleId, setRuleId] = useState("");
  const [hostId, setHostId] = useState("");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const [sort, setSort] = useState("aging");
  const [selected, setSelected] = useState<Set<number>>(new Set());

  const { data, isLoading, isError } = useQuery({
    queryKey: ["queue", status, ruleId, hostId, severity, q, sort],
    queryFn: () => getAlertQueue({ status, rule_id: ruleId, host_id: hostId, severity, q, sort, limit: 100 }),
    refetchInterval: 20_000,
  });
  // Header status counts are global (status=all) — the row query's envelope
  // is filter-scoped and would show 0 acked/resolved in the open view.
  const { data: counts } = useQuery({
    queryKey: ["queue-counts"],
    queryFn: () => getAlertQueue({ status: "all", limit: 1 }),
    refetchInterval: 20_000,
  });
  const { data: rulesData } = useQuery({ queryKey: ["rules-fp"], queryFn: getRuleFp });
  const { data: agentsData } = useQuery({ queryKey: ["agents"], queryFn: getAgents });

  const ruleOptions = useMemo(() => {
    const fromFp = rulesData?.rules.map((r) => r.rule_id) ?? [];
    const fromQueue = data?.alerts.map((a) => a.rule_id) ?? [];
    return Array.from(new Set([...fromFp, ...fromQueue])).sort();
  }, [rulesData, data]);

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["queue"] });

  const assignMut = useMutation({
    mutationFn: ({ id, assignee }: { id: number; assignee: string }) => assignAlert(id, assignee),
    onSuccess: invalidate,
  });
  const statusMut = useMutation({
    mutationFn: ({ ids, st }: { ids: number[]; st: "acknowledged" | "resolved" }) =>
      bulkUpdateAlertStatus(ids, st),
    onSuccess: () => {
      setSelected(new Set());
      invalidate();
    },
  });

  const toggle = (id: number) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const alertRows = data?.alerts ?? [];
  const allSelected = alertRows.length > 0 && alertRows.every((a) => selected.has(a.id));

  return (
    <div className="mx-auto max-w-[1200px] px-5 py-8 lg:px-8">
      <PageHeader
        kicker="Operations · analyst workflow"
        title={
          <>
            Triage <span className="font-normal text-text-muted">— the alert work list</span>
          </>
        }
        lede="Every finding across every run, sorted so the longest-open alert surfaces first. Sweep the noise with bulk ack/resolve, claim alerts by assigning them, and let the queue shrink."
        actions={
          <span className="flex items-center gap-2 font-mono text-[11px] text-text-faint">
            <span className="inline-flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-risk-malicious" /> {counts?.open ?? "…"} open
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-accent" /> {counts?.acknowledged ?? 0} acked
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-signal" /> {counts?.resolved ?? 0} resolved
            </span>
          </span>
        }
      />

      {/* Filter bar */}
      <Panel kicker="Queue" title="Filters">
        <div className="flex flex-wrap items-center gap-2">
          {["open", "acknowledged", "resolved", "all"].map((s) => (
            <button
              key={s}
              onClick={() => {
                setStatus(s);
                setSelected(new Set());
              }}
              aria-pressed={status === s}
              className={`press rounded-lg border px-3 py-1.5 font-mono text-[11px] transition-colors ${
                status === s ? "border-accent/60 bg-accent/10 text-accent" : "border-border-subtle text-text-muted hover:text-text-primary"
              }`}
            >
              {s}
            </button>
          ))}
          <select
            value={ruleId}
            onChange={(e) => setRuleId(e.target.value)}
            className="rounded-lg border border-border-subtle bg-bg-elevated px-2 py-1.5 font-mono text-[11px] text-text-muted outline-none focus:border-accent/60"
            aria-label="filter by rule"
          >
            <option value="">all rules</option>
            {ruleOptions.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <select
            value={hostId}
            onChange={(e) => setHostId(e.target.value)}
            className="rounded-lg border border-border-subtle bg-bg-elevated px-2 py-1.5 font-mono text-[11px] text-text-muted outline-none focus:border-accent/60"
            aria-label="filter by host"
          >
            <option value="">all hosts</option>
            {(agentsData?.agents ?? []).map((a) => (
              <option key={a.host_id} value={a.host_id}>
                {a.host_id}
              </option>
            ))}
          </select>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="rounded-lg border border-border-subtle bg-bg-elevated px-2 py-1.5 font-mono text-[11px] text-text-muted outline-none focus:border-accent/60"
            aria-label="filter by severity"
          >
            <option value="">all severities</option>
            <option value="malicious">malicious</option>
            <option value="suspicious">suspicious</option>
          </select>
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="search sample · rule · details · IP"
            className="min-w-[200px] flex-1 rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-[11px] text-text-primary outline-none placeholder:text-text-faint focus:border-accent/60"
          />
          <button
            onClick={() => setSort((s) => (s === "aging" ? "newest" : "aging"))}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-[11px] text-text-muted hover:border-accent/60 hover:text-accent"
            title={sort === "aging" ? "Oldest open first (SLA pressure)" : "Newest first"}
          >
            <Icon name={sort === "aging" ? "clock" : "activity"} size={12} />
            {sort === "aging" ? "aging (oldest first)" : "newest"}
          </button>
        </div>

        {/* Bulk bar — appears when anything is selected */}
        {selected.size > 0 && (
          <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-border-subtle pt-3">
            <span className="font-mono text-[11px] text-text-muted">
              {selected.size} selected
            </span>
            <input
              type="checkbox"
              checked={allSelected}
              onChange={() =>
                setSelected(allSelected ? new Set() : new Set(alertRows.map((a) => a.id)))
              }
              aria-label="select all on page"
              className="h-3.5 w-3.5 accent-[var(--accent)]"
            />
            <button
              onClick={() => statusMut.mutate({ ids: [...selected], st: "acknowledged" })}
              className="press rounded-lg border border-accent/50 bg-accent/10 px-3 py-1.5 font-mono text-[11px] text-accent hover:bg-accent/20"
            >
              Ack selected
            </button>
            <button
              onClick={() => statusMut.mutate({ ids: [...selected], st: "resolved" })}
              className="press rounded-lg border border-signal/50 bg-signal/10 px-3 py-1.5 font-mono text-[11px] text-signal hover:bg-signal/20"
            >
              Resolve selected
            </button>
            <span className="font-mono text-[10px] text-text-faint">sweeps land in the audit trail</span>
          </div>
        )}
      </Panel>

      {/* The list */}
      {isLoading && (
        <div className="mt-4 space-y-2.5">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="skeleton h-14 w-full" />
          ))}
        </div>
      )}
      {isError && (
        <p className="mt-4 rounded-lg border border-risk-malicious/40 bg-bg-surface p-4 text-sm text-risk-malicious">
          Couldn't reach the queue — is the backend running?
        </p>
      )}
      {!isLoading && !isError && alertRows.length === 0 && (
        <Panel kicker="Queue" title={status === "open" ? "Queue is clear" : "Nothing here"}>
          <div className="py-8 text-center">
            <Icon name="shield" size={26} className="mx-auto text-text-faint" />
            <p className="mt-3 text-sm text-text-muted">
              {status === "open"
                ? "No open alerts — every finding has been triaged."
                : `No ${status} alerts match the current filters.`}
            </p>
          </div>
        </Panel>
      )}
      {alertRows.length > 0 && (
        <ul className="mt-4 space-y-2.5">
          {alertRows.map((a) => (
            <QueueRow
              key={a.id}
              alert={a}
              selected={selected.has(a.id)}
              onToggle={toggle}
              onAssign={(id, assignee) => assignMut.mutate({ id, assignee })}
              onStatus={(id, st) => statusMut.mutate({ ids: [id], st })}
            />
          ))}
        </ul>
      )}
      <p className="mt-3 text-right font-mono text-[10px] text-text-faint">
        {data?.total ?? 0} match{data?.total === 1 ? "" : "es"} · showing first {alertRows.length}
      </p>
    </div>
  );
}
