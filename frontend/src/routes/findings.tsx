import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { DataProvenanceBadge } from "../components/DataProvenanceBadge";
import { PageHeader, Panel } from "../components/ui";
import { addSuppression, bulkUpdateAlertStatus, getAlertQueue, getRuleMeta } from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import { SEVERITY_COLORS, SEVERITY_LABEL } from "../lib/constants";
import { toneFill, toneForSeverity } from "../lib/fillPatterns";
import type { AlertStatus, QueueAlert, Severity } from "../types";
import ProcessContextModal from "../components/ProcessContextModal";
import NetworkContextModal from "../components/NetworkContextModal";
import {
  ageLabel,
  PAGE,
  provenanceChips,
  provenanceLabel,
  readSavedProvenance,
  STATUS_TABS,
  statusTabCount,
  writeSavedProvenance,
} from "./findingsHelpers";

function FindingRow({
  a,
  selected,
  onToggle,
  ruleNames,
  onSuppress,
  suppressing,
  onInspectIp,
  onInspectPid,
}: {
  a: QueueAlert;
  selected: boolean;
  onToggle: (id: number) => void;
  ruleNames: Map<string, string>;
  onSuppress: (a: QueueAlert) => void;
  suppressing: boolean;
  onInspectIp?: (ip: string) => void;
  onInspectPid?: (pid: number) => void;
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
      {/* Pattern-encoded severity dot (deck-wide fill language). */}
      <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={toneFill(toneForSeverity(sev))} title={SEVERITY_LABEL[sev]} aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <span className={`text-[13px] font-semibold ${SEVERITY_COLORS[sev]}`}>
            {ruleNames.get(a.rule_id) ?? a.rule_name}
          </span>
          <span className="rounded border border-border-subtle px-1 py-px font-mono text-[9px] uppercase tracking-wide text-text-faint">
            {a.rule_id}
          </span>
          <DataProvenanceBadge source={a.run_source || a.source || "live"} />
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
            <Link
              key={h}
              to={`/hosts/${encodeURIComponent(h)}`}
              className="press inline-flex items-center gap-1 font-mono text-text-muted hover:text-accent"
              title={`The aggregate timeline — everything OutPost knows about ${h}`}
            >
              <Icon name="terminal" size={9} className="opacity-60" />
              {h}
            </Link>
          ))}
          {a.related_ip && (
            <span className="inline-flex items-center gap-1">
              <Link to={`/search?q=${encodeURIComponent(a.related_ip)}`} className="press font-mono text-accent hover:underline">
                {a.related_ip}
              </Link>
              {onInspectIp && (
                <button
                  onClick={() => onInspectIp(a.related_ip as string)}
                  className="press inline-flex items-center gap-0.5 rounded border border-accent/40 bg-accent/10 px-1 py-px font-mono text-[9px] text-accent hover:bg-accent/20"
                  title={`Inspect network context for ${a.related_ip}`}
                >
                  <Icon name="activity" size={9} />
                  Context
                </button>
              )}
            </span>
          )}
          {a.related_pids.filter(Boolean).length > 0 && (
            <span className="inline-flex items-center gap-1">
              <Link to={`/events?pid=${a.related_pids.join(",")}`} className="press font-mono hover:text-accent">
                pid {a.related_pids.join(",")}
              </Link>
              {onInspectPid && a.related_pids[0] && (
                <button
                  onClick={() => onInspectPid(a.related_pids[0])}
                  className="press inline-flex items-center gap-0.5 rounded border border-border-subtle bg-bg-elevated/60 px-1 py-px font-mono text-[9px] text-text-muted hover:border-accent/40 hover:text-accent"
                  title={`Inspect process context for PID ${a.related_pids[0]}`}
                >
                  <Icon name="terminal" size={9} />
                  PID
                </button>
              )}
            </span>
          )}
          {a.investigation_id && (
            <Link
              to={`/investigations/${encodeURIComponent(a.investigation_id)}`}
              className="press inline-flex items-center gap-1 font-mono text-text-muted hover:text-accent"
              title={`Attached to the investigation ${a.investigation_id}`}
            >
              <Icon name="notes" size={9} className="opacity-60" />
              case {a.investigation_id.slice(0, 12)}
            </Link>
          )}
          {a.assignee && <span className="font-mono">→ {a.assignee}</span>}
          {a.status !== "open" && (
            <span className="font-mono uppercase tracking-wide">
              {a.status}
              {a.status_comment ? ` — ${a.status_comment}` : ""}
            </span>
          )}
          {(a.sample_name || a.related_ip) && (
            <button
              onClick={() => onSuppress(a)}
              disabled={suppressing}
              className="press ml-auto font-mono text-[9px] uppercase tracking-wide text-text-faint transition-colors hover:text-risk-malicious disabled:opacity-40"
              title={`Suppress ${a.rule_id} for ${a.sample_name || a.related_ip} — future runs of this sample/C2 stop firing it`}
            >
              {suppressing ? "…" : "suppress"}
            </button>
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
  // Provenance split (real hosts vs synthetic/demo) — mirrors the History
  // archive's default hide-synthetic behavior, so demo noise can be hidden
  // or selected for a bulk ack without hand-picking sample names. An explicit
  // ?provenance= wins; otherwise each status tab's saved preference applies
  // ("real hosts first" survives navigation like the search draft).
  const provParam = searchParams.get("provenance");
  const provenance: "" | "real" | "synthetic" =
    provParam === "real" || provParam === "synthetic" ? provParam : readSavedProvenance(status);
  const q = searchParams.get("q") ?? "";
  const [submittedQ, setSubmittedQ] = useState(q);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [busy, setBusy] = useState(false);
  const [inspectIp, setInspectIp] = useState<string | null>(null);
  const [inspectPid, setInspectPid] = useState<number | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const setParam = (k: string, v: string) => {
    const next = new URLSearchParams(searchParams);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== "offset") next.delete("offset");
    setSearchParams(next, { replace: true });
  };

  // Changing provenance updates the URL AND remembers it for the active tab.
  const setProvenance = (v: string) => {
    writeSavedProvenance(status, (v === "real" || v === "synthetic" ? v : "") as "" | "real" | "synthetic");
    setParam("provenance", v);
  };

  // Switching tabs applies THAT tab's saved preference (each status keeps its
  // own split), folding it into one navigation so nothing gets lost.
  const switchStatus = (v: string) => {
    const saved = readSavedProvenance(v);
    const next = new URLSearchParams(searchParams);
    if (saved) next.set("provenance", saved);
    else next.delete("provenance");
    next.set("status", v === "open" ? "" : v);
    next.delete("offset");
    setSearchParams(next, { replace: true });
  };

  const { data, isLoading, isError } = useQuery({
    queryKey: ["alerts", "queue", status, sort, sev, provenance, submittedQ, offset],
    queryFn: () =>
      getAlertQueue({
        status,
        severity: sev || undefined,
        provenance: provenance || undefined,
        q: submittedQ || undefined,
        sort,
        limit: PAGE,
        offset,
      }),
  });

  // P1.5 realtime: the queue is a live surface — a fired alert (new
  // detection) or a run-update naming a finding (attach/detach moved its
  // investigation link) refreshes the sweep immediately. The DB row stays
  // the source of truth on reconnect; the queue's own mutations invalidate
  // as before (push is an enhancement over the default refetch, never a
  // dependency).
  useEventStream(
    () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts", "queue"] });
      void queryClient.invalidateQueries({ queryKey: ["statusbar"] });
    },
    undefined,
    (r) => {
      if (r.finding_id !== undefined) {
        void queryClient.invalidateQueries({ queryKey: ["alerts", "queue"] });
      }
    },
  );
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

  // Select EVERY alert matching the active filters (across pages) — the
  // bulk-ack lever for a provenance-filtered demo sweep: filter to synthetic,
  // "Select all N matching", Ack. The queue API caps at 200/page, so this
  // walks offsets until it has collected the whole filtered set.
  const selectAllMatching = async () => {
    setBusy(true);
    try {
      const ids = new Set<number>();
      const limit = 200;
      let offset = 0;
      let total = Infinity;
      while (offset < total) {
        const page = await getAlertQueue({
          status,
          severity: sev || undefined,
          provenance: provenance || undefined,
          q: submittedQ || undefined,
          sort,
          limit,
          offset,
        });
        total = page.total;
        for (const a of page.alerts) ids.add(a.id);
        if (page.alerts.length === 0) break;
        offset += limit;
      }
      setSelected(ids);
      setMsg({ ok: true, text: `Selected all ${ids.size} matching finding(s).` });
    } catch {
      setMsg({ ok: false, text: "Couldn't select all matching — is the backend running?" });
    } finally {
      setBusy(false);
    }
  };

  // The value scope a suppression targets from the sweep: the run's sample
  // name (detonate-demo.sh etc.) when present, else the alert's related IP
  // (the C2). This is what makes the suppression future-proof — it applies
  // to every subsequent run of that sample / touch of that IP, not just the
  // alerts on screen.
  const suppressScope = (a: QueueAlert): string | null => {
    const sample = (a.sample_name || "").trim();
    if (sample) return sample;
    const ip = (a.related_ip || "").trim();
    return ip || null;
  };

  const [suppressingId, setSuppressingId] = useState<number | null>(null);

  const suppress = async (targets: QueueAlert[]) => {
    const seen = new Set<string>();
    const plans: { ruleId: string; scope: string }[] = [];
    for (const a of targets) {
      const scope = suppressScope(a);
      if (!scope) continue;
      const key = `${a.rule_id}\u0000${scope}`;
      if (seen.has(key)) continue;
      seen.add(key);
      plans.push({ ruleId: a.rule_id, scope });
    }
    if (plans.length === 0) {
      setMsg({ ok: false, text: "None of the selected findings have a sample name or IP to scope a suppression to." });
      return;
    }
    setBusy(true);
    setMsg(null);
    try {
      for (const p of plans) {
        await addSuppression(p.ruleId, "suppressed from queue sweep", undefined, p.scope);
      }
      setMsg({
        ok: true,
        text: `Suppressed ${plans.length} rule scope(s) — future matching runs stop firing (${plans.map((p) => p.ruleId).join(", ")}).`,
      });
      setSelected(new Set());
      await queryClient.invalidateQueries({ queryKey: ["alerts", "queue"] });
      await queryClient.invalidateQueries({ queryKey: ["suppressions"] });
    } catch {
      setMsg({ ok: false, text: "Suppression failed — is the backend running?" });
    } finally {
      setBusy(false);
      setSuppressingId(null);
    }
  };

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
              onClick={() => switchStatus(t.v)}
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
            value={provenance}
            onChange={(e) => setProvenance(e.target.value)}
            className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary outline-none transition-colors focus:border-accent/60"
            aria-label="Filter by provenance"
            title="Real = host/sandbox telemetry · Synthetic = seed/webapp-demo runs — demo noise can be hidden or acked in bulk"
          >
            <option value="">All provenance</option>
            <option value="real">Real hosts</option>
            <option value="synthetic">Synthetic / demo</option>
          </select>
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

      {/* Saved-split chips — the same per-tab vocabulary as Settings, so an
          analyst sees what each tab will show (and what the active tab IS
          showing) without leaving the sweep. Hidden when nothing is saved
          and the active tab has no explicit override. */}
      {provenanceChips(status, provenance).some((c) => c.value) && (
        <div className="mb-4 flex flex-wrap items-center gap-1.5" aria-label="Saved provenance split per status tab">
          <span className="font-mono text-[10px] uppercase tracking-wide text-text-faint">Saved splits:</span>
          {provenanceChips(status, provenance).map((c) => (
            <span
              key={c.tab}
              className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono text-[10px] ${
                c.active
                  ? "border-accent/60 bg-accent/10 text-accent"
                  : "border-border-subtle bg-bg-elevated/40 text-text-muted"
              }`}
              title={`${c.label} tab: ${provenanceLabel(c.value)}${c.active ? " (active view)" : " (saved)"}`}
            >
              <span className="uppercase tracking-wide">{c.label}</span>
              <span>{provenanceLabel(c.value)}</span>
            </span>
          ))}
        </div>
      )}

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
          <button
            onClick={() => void suppress(alerts.filter((a) => selected.has(a.id)))}
            disabled={busy || selected.size === 0}
            className="press rounded-md border border-border-subtle bg-bg-surface px-2.5 py-1 font-mono text-[11px] text-text-muted transition-colors hover:border-risk-malicious/60 hover:text-risk-malicious disabled:opacity-40"
            title="Suppress each selected rule for its sample or C2 — future matching runs stop firing it"
          >
            Suppress
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
              {(data?.total ?? 0) > onPage.length && selected.size < (data?.total ?? 0) && (
                <button
                  onClick={() => void selectAllMatching()}
                  disabled={busy}
                  className="press font-mono text-[10px] text-text-faint transition-colors hover:text-accent disabled:opacity-40"
                  title="Select every alert matching the active filters (across all pages) — one step before a bulk ack"
                >
                  Select all {data?.total ?? 0} matching
                </button>
              )}
              {selected.size > onPage.length && (
                <span className="font-mono text-[10px] text-text-faint">+{selected.size - onPage.length} from other pages</span>
              )}
            </div>
            <ul className="space-y-2">
              {alerts.map((a) => (
                <FindingRow
                  key={a.id}
                  a={a}
                  selected={selected.has(a.id)}
                  onToggle={toggle}
                  ruleNames={ruleNames}
                  onSuppress={(target) => {
                    setSuppressingId(target.id);
                    void suppress([target]);
                  }}
                  suppressing={suppressingId === a.id}
                  onInspectIp={setInspectIp}
                  onInspectPid={setInspectPid}
                />
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

      {inspectIp !== null && (
        <NetworkContextModal ip={inspectIp} onClose={() => setInspectIp(null)} />
      )}
      {inspectPid !== null && (
        <ProcessContextModal pid={inspectPid} onClose={() => setInspectPid(null)} />
      )}
    </div>
  );
}
