import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { MouseEvent as ReactMouseEvent, ReactNode } from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Deferred } from "../components/Deferred/Deferred";
import { Icon } from "../components/Icon";
import { platformIconName } from "../components/iconMeta";
import { PageHeader, Panel } from "../components/ui";
import { ageBucket, collapseFindings, intelFreshness, intelKeyHealth, openSince, overviewRunParams, sortFindingsRiskFirst } from "./overviewHelpers";
import { copyToClipboard } from "../lib/clipboard";
import { SEVERITY_BG } from "../lib/constants";
import { BASE_URL, getAgents, getCampaigns, getHealth, getHostXRaySnapshot, getIntelFreshness, getIntelKeys, getMeta, getPlatform, getProcessSummary, getRecentAlerts, getRuleMeta, getRuns, getXRayTargetCatalog, listInvestigations, resetStore } from "../lib/api";
import { useEventStream } from "../lib/useEventStream";

// Compact relative time for the host panel's auth-context tooltips (the
// Agents page keeps its own copy — same convention).
function _rel(iso: string): string {
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
import type { ProcessSummary, RunSummary, Severity } from "../types";

/* ──────────────────────────────────────────────────────────────────────── */
// Threat posture — the console header. Three visual primitives instead of a
// stat strip: a risk gauge, a severity donut, and a risk-over-time trend.
// The trend is aggregated by sample (one bar per binary, sized by peak) so
// the console reads which samples are worst at a glance; per-session detail
// lives on History (click a bar to jump there pre-filtered). The primitives
// live in components/Posture/Posture.tsx.
/* ──────────────────────────────────────────────────────────────────────── */

function PostureHeader({
  runs,
  campaigns,
  totalAlerts,
}: {
  runs: RunSummary[];
  campaigns: number;
  totalAlerts: number;
}) {
  const { data: fleet } = useQuery({ queryKey: ["agents"], queryFn: () => getAgents(), staleTime: 15_000 });
  const onlineAgents = (fleet?.agents ?? []).filter((a) => a.online).length;
  const malicious = runs.filter((r) => r.highest_severity === "malicious").length;
  const suspicious = runs.filter((r) => r.highest_severity === "suspicious").length;
  const clean = runs.length - malicious - suspicious;

  return (
    <section className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3" aria-label="Operational telemetry summary">
      {/* Telemetry Health */}
      <div className="flex flex-col justify-between rounded-2xl border border-border-subtle bg-bg-surface/80 p-5 backdrop-blur-md transition-all duration-200 hover:border-accent/40">
        <div className="flex items-center justify-between">
          <span className="font-mono text-[11px] uppercase tracking-wider text-text-faint">Host Telemetry</span>
          <span className="flex items-center gap-1.5 font-mono text-[10px] text-risk-clean">
            <span className="h-1.5 w-1.5 rounded-full bg-risk-clean animate-pulse" />
            ingestion active
          </span>
        </div>
        <div className="my-3 flex items-baseline gap-3">
          <span className="font-mono text-3xl font-bold tracking-tight text-text-primary">{runs.length}</span>
          <span className="text-xs text-text-muted">monitored sessions</span>
        </div>
        <div className="flex flex-wrap items-center gap-3 border-t border-border-subtle/60 pt-3 font-mono text-[11px] text-text-muted">
          <span>{fleet?.agents?.length ?? 1} host{fleet?.agents?.length === 1 ? "" : "s"} enrolled</span>
          <span className="text-text-faint">·</span>
          <span className="text-risk-clean">{onlineAgents || 1} online</span>
        </div>
      </div>

      {/* Detections & Findings */}
      <div className="flex flex-col justify-between rounded-2xl border border-border-subtle bg-bg-surface/80 p-5 backdrop-blur-md transition-all duration-200 hover:border-risk-suspicious/40">
        <div className="flex items-center justify-between">
          <span className="font-mono text-[11px] uppercase tracking-wider text-text-faint">Detection Queue</span>
          <Link to="/findings" className="font-mono text-[10px] text-accent hover:underline">
            triage queue →
          </Link>
        </div>
        <div className="my-3 flex items-baseline gap-3">
          <span className="font-mono text-3xl font-bold tracking-tight text-text-primary">{totalAlerts}</span>
          <span className="text-xs text-text-muted">active alerts</span>
        </div>
        <div className="flex items-center gap-2 border-t border-border-subtle/60 pt-3 font-mono text-[11px]">
          <span className="inline-flex items-center gap-1 rounded bg-risk-malicious/15 px-2 py-0.5 font-semibold text-risk-malicious">
            {malicious} critical/malicious
          </span>
          <span className="inline-flex items-center gap-1 rounded bg-risk-suspicious/15 px-2 py-0.5 font-semibold text-risk-suspicious">
            {suspicious} suspicious
          </span>
        </div>
      </div>

      {/* Investigations & Campaigns */}
      <div className="flex flex-col justify-between rounded-2xl border border-border-subtle bg-bg-surface/80 p-5 backdrop-blur-md transition-all duration-200 hover:border-accent/40 sm:col-span-2 lg:col-span-1">
        <div className="flex items-center justify-between">
          <span className="font-mono text-[11px] uppercase tracking-wider text-text-faint">Investigations</span>
          <Link to="/investigations" className="font-mono text-[10px] text-accent hover:underline">
            case files →
          </Link>
        </div>
        <div className="my-3 flex items-baseline gap-3">
          <span className="font-mono text-3xl font-bold tracking-tight text-text-primary">{campaigns}</span>
          <span className="text-xs text-text-muted">active campaigns</span>
        </div>
        <div className="flex items-center justify-between border-t border-border-subtle/60 pt-3 font-mono text-[11px] text-text-muted">
          <span>{clean} clean baseline runs</span>
          <span className="text-text-faint">SLA tracked</span>
        </div>
      </div>
    </section>
  );
}

/* ──────────────────────────────────────────────────────────────────────── */
// Live findings feed — SSE push + duplicate collapse
/* ──────────────────────────────────────────────────────────────────────── */

function FindingsFeed() {
  const queryClient = useQueryClient();
  const [sevFilter, setSevFilter] = useState<Severity | "all">("all");
  // Process-jump hover preview: a fixed-position card next to the link showing
  // the process's identity (name + command line), platform, activity and alert
  // counts, and its run — fetched lazily on hover with a short debounce.
  const [preview, setPreview] = useState<{ x: number; y: number; data: ProcessSummary } | null>(null);
  const previewTimer = useRef<number | null>(null);
  const showPreview = (e: ReactMouseEvent<HTMLAnchorElement>, pid: number) => {
    if (previewTimer.current !== null) window.clearTimeout(previewTimer.current);
    const r = e.currentTarget.getBoundingClientRect();
    previewTimer.current = window.setTimeout(() => {
      void getProcessSummary(pid)
        .then((data) =>
          setPreview({
            x: Math.max(8, Math.min(r.left, window.innerWidth - 336)),
            y: Math.max(8, Math.min(r.bottom + 8, window.innerHeight - 180)),
            data,
          }),
        )
        .catch(() => setPreview(null));
    }, 250);
  };
  const hidePreview = () => {
    if (previewTimer.current !== null) window.clearTimeout(previewTimer.current);
    setPreview(null);
  };
  const { data: alerts = [], isLoading, isError } = useQuery({
    queryKey: ["alerts", "recent"],
    queryFn: () => getRecentAlerts(24, "real"),
    refetchInterval: 10_000,
  });
  const { data: meta } = useQuery({ queryKey: ["rules-meta"], queryFn: getRuleMeta, staleTime: Infinity });
  const byRule = useMemo(() => new Map((meta ?? []).map((m) => [m.rule_id, m])), [meta]);

  // Live push: a fired alert refetches the feed immediately (SSE carries no
  // sample_name, so the query stays the single source of truth). The poll is
  // the fallback; push just makes it instant.
  useEventStream(() => {
    void queryClient.invalidateQueries({ queryKey: ["alerts", "recent"] });
  });

  // Flash rows that weren't in the previous snapshot (new findings ring in).
  const prevKeys = useRef<Set<string>>(new Set());
  const [freshKeys, setFreshKeys] = useState<Set<string>>(new Set());
  useEffect(() => {
    const keys = new Set(collapseFindings(alerts).map((g) => g.key));
    const fresh = new Set<string>();
    for (const k of keys) if (!prevKeys.current.has(k)) fresh.add(k);
    prevKeys.current = keys;
    if (fresh.size === 0) return;
    setFreshKeys(fresh);
    const t = setTimeout(() => setFreshKeys(new Set()), 2500);
    return () => clearTimeout(t);
  }, [alerts]);

  const groups = useMemo(() => {
    const collapsed = collapseFindings(alerts);
    const filtered = sevFilter === "all" ? collapsed : collapsed.filter((g) => g.first.severity === sevFilter);
    return sortFindingsRiskFirst(filtered, byRule);
  }, [alerts, sevFilter, byRule]);

  const now = Date.now();

  return (
    <Panel
      kicker="Live feed"
      title="Findings"
      right={
        <div className="flex items-center gap-3">
          <div className="flex overflow-hidden rounded-md border border-border-subtle font-mono text-[10px]">
            {(["all", "malicious", "suspicious"] as const).map((s) => (
              <button
                key={s}
                onClick={() => setSevFilter(s)}
                className={`px-2 py-1 transition-colors ${
                  sevFilter === s
                    ? s === "malicious"
                      ? "bg-risk-malicious/20 text-risk-malicious"
                      : s === "suspicious"
                        ? "bg-risk-suspicious/20 text-risk-suspicious"
                        : "bg-accent/15 text-accent"
                    : "text-text-faint hover:text-text-muted"
                }`}
              >
                {s === "all" ? "all" : s.slice(0, 3)}
              </button>
            ))}
          </div>
          <span className="inline-flex items-center gap-1.5 font-mono text-[10px] text-signal">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-signal" aria-hidden />
            live · SSE
          </span>
        </div>
      }
    >
      {isLoading && <SkeletonList rows={4} />}
      {isError && (
        <p className="rounded-md border border-risk-malicious/40 px-3 py-2 text-xs text-risk-malicious">
          Backend unreachable — is it running?
        </p>
      )}
      {!isLoading && !isError && groups.length === 0 && (
        <div className="py-8 text-center font-mono text-sm text-text-muted">
          <p className="font-semibold text-text-primary">Monitoring active — 0 findings detected</p>
          <p className="mt-1 text-xs text-text-faint">No security heuristics or IOC alerts have triggered across ingested host telemetry.</p>
        </div>
      )}

      <ol className="space-y-2">
        {groups.map((g) => {
          const a = g.first;
          const rule = byRule.get(a.rule_id);
          const isFresh = freshKeys.has(g.key);
          return (
            <li
              key={g.key}
              className={`group relative overflow-hidden rounded-lg border border-border-subtle bg-bg-elevated/40 pl-3 transition-all duration-150 hover:border-accent/40 hover:shadow-[var(--shadow-raised)] ${
                isFresh ? "animate-outpost-pulse border-accent/50" : ""
              }`}
            >
              <span className={`absolute inset-y-0 left-0 w-1 ${SEVERITY_BG[a.severity]}`} aria-hidden />
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1 px-3.5 py-3">
                {/* Clicking the sample jumps to the process-centric view when
                    the alert names a process (Event-Manager parity): everything
                    that PID did, filtered live. A recon sweep lists every
                    enumerating PID at once. Alerts without a process keep
                    linking to the run. */}
                {(() => {
                  const pids = a.related_pids ?? [];
                  const pid = a.related_pid ?? pids[0] ?? null;
                  if (a.rule_id === "enumeration-burst" && pids.length > 1) {
                    return (
                      <Link
                        to={`/events?pid=${pids.join(",")}`}
                        onMouseEnter={(e) => showPreview(e, pids[0])}
                        onMouseLeave={hidePreview}
                        className="press inline-flex items-center gap-1.5 font-mono text-xs font-medium text-risk-suspicious hover:underline"
                        title={`Recon sweep — ${pids.length} enumerating processes (${a.sample_name}) — jump to the process view`}
                      >
                        {a.sample_name}
                        <Icon name="process" size={11} className="opacity-80" />
                        <span className="rounded border border-risk-suspicious/50 bg-risk-suspicious/10 px-1 py-px text-[9px] uppercase tracking-wide">
                          recon · {pids.length}
                        </span>
                      </Link>
                    );
                  }
                  return pid ? (
                    <Link
                      to={`/events?pid=${pid}`}
                      onMouseEnter={(e) => showPreview(e, pid)}
                      onMouseLeave={hidePreview}
                      className="press inline-flex items-center gap-1.5 font-mono text-xs font-medium text-text-primary hover:text-accent"
                      title={`Everything process ${pid} did (${a.sample_name}) — jump to the process view`}
                    >
                      {a.sample_name}
                      <Icon name="process" size={11} className="text-text-faint transition-colors group-hover:text-accent" />
                    </Link>
                  ) : (
                    <Link to={`/runs/${a.run_id}`} className="press font-mono text-xs font-medium text-text-primary hover:text-accent">
                      {a.sample_name}
                    </Link>
                  );
                })()}
                {g.count > 1 && (
                  <span
                    className="rounded-full border border-border-subtle bg-bg-elevated/70 px-1.5 py-px font-mono text-[10px] tabular-nums text-text-muted"
                    title={`${g.count} identical findings across ${g.runs.size} run${g.runs.size === 1 ? "" : "s"} in the last 5 minutes`}
                  >
                    ×{g.count}
                  </span>
                )}
                <span className="text-xs text-text-muted">{a.rule_name}</span>
                {rule && (
                  <span
                    className="rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[10px] text-text-faint"
                    title={`MITRE ATT&CK ${rule.tactic}`}
                  >
                    {rule.technique} · {rule.tactic}
                  </span>
                )}
                <span className="ml-auto flex items-center gap-2 font-mono text-[10px] tabular-nums">
                  {a.status === "open" && (
                    <span
                      className={`rounded-full border px-1.5 py-px ${
                        ageBucket(a, now) === 2
                          ? "border-risk-malicious/40 bg-risk-malicious/10 text-risk-malicious"
                          : ageBucket(a, now) === 1
                            ? "border-risk-suspicious/40 bg-risk-suspicious/10 text-risk-suspicious"
                            : "border-border-subtle text-text-faint"
                      }`}
                      title={a.status_at ? `Open since ${a.triggered_at}` : "Open — awaiting triage"}
                    >
                      {openSince(a, now)}
                    </span>
                  )}
                  {a.status !== "open" && (
                    <span className="text-text-faint">{a.status}</span>
                  )}
                  <span className="flex items-center gap-1 text-text-faint">
                    <Icon name={a.severity === "malicious" ? "alert" : "zap"} size={11} className={a.severity === "malicious" ? "text-risk-malicious" : "text-risk-suspicious"} />
                    {a.triggered_at.slice(11, 19)} UTC
                  </span>
                </span>
              </div>
              <p className="truncate px-3.5 pb-3 font-mono text-[11px] text-text-muted" title={a.details}>
                {a.details}
              </p>
            </li>
          );
        })}
      </ol>

      {/* Process-jump hover preview — fixed-position card at the link's spot. */}
      {preview && (
        <div
          role="tooltip"
          className="pointer-events-none fixed z-50 w-80 overflow-hidden rounded-xl border border-border-subtle bg-bg-surface shadow-[var(--shadow-raised)]"
          style={{ left: preview.x, top: preview.y }}
        >
          <div className="flex items-center gap-2 border-b border-border-subtle bg-bg-elevated/40 px-3 py-2">
            <Icon name="process" size={13} className="shrink-0 text-accent" />
            <span className="truncate font-mono text-xs font-semibold text-text-primary">
              {preview.data.process_name ?? `pid ${preview.data.pid}`}
            </span>
            <span className="ml-auto shrink-0 font-mono text-[10px] text-text-faint">pid {preview.data.pid}</span>
          </div>
          <div className="space-y-2 px-3 py-2.5">
            {preview.data.command_line && (
              <p className="truncate font-mono text-[10px] text-text-muted" title={preview.data.command_line}>
                {preview.data.command_line}
              </p>
            )}
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[10px] text-text-faint">
              <span className="inline-flex items-center gap-1">
                <Icon name={platformIconName(preview.data.platform)} size={10} />
                {preview.data.platform}
              </span>
              <span>
                {preview.data.event_count} event{preview.data.event_count === 1 ? "" : "s"}
              </span>
              {(preview.data.children?.length ?? 0) > 0 && (
                <span>
                  {preview.data.children!.length} child{preview.data.children!.length === 1 ? "" : "ren"}
                </span>
              )}
              {(preview.data.network_connections?.length ?? 0) > 0 && (
                <span>
                  {preview.data.network_connections!.length} socket{preview.data.network_connections!.length === 1 ? "" : "s"}
                </span>
              )}
              <span className={preview.data.alert_count > 0 ? "text-risk-suspicious font-semibold" : ""}>
                {preview.data.alert_count} alert{preview.data.alert_count === 1 ? "" : "s"}
              </span>
            </div>
            <Link
              to={`/runs/${preview.data.run_id}`}
              className="press inline-flex items-center gap-1 font-mono text-[10px] text-accent hover:underline"
            >
              {preview.data.sample_name}
              <Icon name="external" size={9} className="opacity-60" />
            </Link>
          </div>
        </div>
      )}
    </Panel>
  );
}

function SkeletonList({ rows }: { rows: number }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-3 rounded-lg border border-border-subtle p-3">
          <span className="skeleton h-2 w-2 rounded-full" />
          <span className="skeleton h-3 w-36" />
          <span className="skeleton h-3 w-48" />
        </div>
      ))}
    </div>
  );
}

function ActiveInvestigationsPanel() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["investigations", "active"],
    queryFn: () => listInvestigations({ limit: 4 }),
  });

  const investigations = data?.investigations ?? [];

  if (isLoading) return <p className="text-sm text-text-muted">Loading cases…</p>;
  if (isError) return <p className="text-xs text-risk-malicious">Couldn't load investigations.</p>;

  return (
    <Panel
      kicker="Case workspace"
      title="Active investigations"
      right={
        <Link to="/investigations" className="press inline-flex items-center gap-1 font-mono text-[10px] text-accent hover:underline">
          all cases <Icon name="arrowRight" size={11} />
        </Link>
      }
    >
      {investigations.length === 0 ? (
        <div className="py-6 text-center">
          <p className="font-mono text-xs text-text-muted">No open investigation cases.</p>
          <p className="mt-1 text-[11px] text-text-faint">
            Create an investigation from the findings queue or investigate suspicious telemetry.
          </p>
          <Link
            to="/investigations"
            className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-elevated px-3 py-1.5 font-mono text-xs text-text-muted hover:border-accent/40 hover:text-accent"
          >
            <Icon name="plus" size={12} />
            New investigation
          </Link>
        </div>
      ) : (
        <div className="space-y-2">
          {investigations.map((inv) => (
            <Link
              key={inv.id}
              to={`/investigations/${inv.id}`}
              className="group block rounded-xl border border-border-subtle/70 bg-bg-elevated/40 p-3 transition-colors hover:border-accent/50 hover:bg-bg-elevated"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-sans text-xs font-semibold text-text-primary group-hover:text-accent">
                  {inv.title}
                </span>
                <span
                  className={`shrink-0 rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wide ${
                    inv.status === "active" || inv.status === "triage"
                      ? "border-risk-suspicious/40 text-risk-suspicious"
                      : inv.status === "created"
                        ? "border-accent/40 text-accent"
                        : "border-border-subtle text-text-faint"
                  }`}
                >
                  {inv.status}
                </span>
              </div>
              <div className="mt-1.5 flex flex-wrap items-center gap-2 font-mono text-[10px] text-text-faint">
                <span>{inv.id}</span>
                <span>·</span>
                <span>updated {inv.updated_at ? _rel(inv.updated_at) : "recently"}</span>
                {inv.tags && inv.tags.length > 0 && (
                  <div className="flex gap-1">
                    {inv.tags.slice(0, 2).map((t) => (
                      <span key={t} className="rounded bg-bg-surface px-1 text-[9px] text-text-muted">
                        #{t}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </Link>
          ))}
        </div>
      )}
    </Panel>
  );
}

/* ──────────────────────────────────────────────────────────────────────── */
// Action strip — quick actions + host system, one compact bar at the bottom
/* ──────────────────────────────────────────────────────────────────────── */

const ACTIONS: { to: string; label: string; desc: string; icon: ReactNode }[] = [
  { to: "/monitor", label: "Detonate sample", desc: "Dynamic analysis on the auto-detected host OS", icon: <Icon name="play" size={14} /> },
  { to: "/events", label: "Event log", desc: "Browse every activity like a system log viewer", icon: <Icon name="list" size={14} /> },
  { to: "/history", label: "Compare sessions", desc: "Pick two runs from History and diff them", icon: <Icon name="compare" size={14} /> },
  { to: "/watchlist", label: "Watchlist", desc: "Track known-bad infrastructure", icon: <Icon name="star" size={14} /> },
];

function ActionStrip() {
  const { data: plat } = useQuery({ queryKey: ["platform"], queryFn: getPlatform, staleTime: Infinity });
  const { data: alive } = useQuery({ queryKey: ["health"], queryFn: getHealth, refetchInterval: 10_000 });

  const glyph = plat ? (plat.os === "windows" ? "windows" : plat.os === "macos" ? "mac" : "linux") : "terminal";
  const label = plat ? plat.name || plat.os : "detecting…";

  return (
    <section className="panel mt-6" aria-label="Actions and environment">
      <div className="flex flex-col gap-4 p-4 lg:flex-row lg:items-center lg:gap-6">
        {/* Quick actions — compact inline buttons, descriptions on hover */}
        <div className="flex flex-wrap items-center gap-2">
          {ACTIONS.map((a) => (
            <Link
              key={a.to}
              to={a.to}
              title={a.desc}
              className="press group inline-flex items-center gap-2 rounded-lg border border-border-subtle bg-bg-elevated/40 px-3 py-2 text-xs font-medium text-text-muted transition-all duration-150 hover:border-accent/40 hover:text-text-primary hover:shadow-[var(--shadow-raised)]"
            >
              <span className="text-accent">{a.icon}</span>
              {a.label}
              <Icon
                name="arrowRight"
                size={11}
                className="text-text-faint transition-all duration-150 group-hover:translate-x-0.5 group-hover:text-accent"
              />
            </Link>
          ))}
        </div>

        {/* Host system — one compact readout, auto-detected */}
        <div className="flex items-center gap-3 border-t border-border-subtle pt-4 lg:ml-auto lg:border-l lg:border-t-0 lg:pl-6 lg:pt-0">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-accent/10 text-accent">
            <Icon name={glyph} size={15} />
          </span>
          <div className="min-w-0">
            <p className="truncate text-xs font-semibold text-text-primary">{label}</p>
            <p className="truncate font-mono text-[10px] text-text-faint">
              {plat ? `${plat.os} ${plat.release} · ${plat.machine}` : "detecting…"}
            </p>
          </div>
          <span className="rounded border border-accent/40 bg-bg-elevated/50 px-1.5 py-0.5 font-mono text-[10px] text-accent">
            {plat?.collector ?? "—"}
          </span>
          <span
            className={`flex items-center gap-1.5 text-[10px] font-medium ${alive ? "text-risk-clean" : "text-risk-malicious"}`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${alive ? "animate-pulse bg-risk-clean" : "bg-risk-malicious"}`} />
            {alive ? "online" : "offline"}
          </span>
        </div>
      </div>
    </section>
  );
}

/* ──────────────────────────────────────────────────────────────────────── */
// Auto-OS front door — the vision's first question: "is THIS host being
// monitored?" The backend detects its own OS (no picker anywhere); this
// panel compares its hostname to the fleet and, when no agent is attached,
// leads with the one-command agent bootstrap instead of the detonation lab.
// macOS hosts get nothing (Windows/Linux focus).
/* ──────────────────────────────────────────────────────────────────────── */

function IntelKeyHealth() {
  const { data } = useQuery({ queryKey: ["intel-keys"], queryFn: getIntelKeys, staleTime: 60_000, refetchInterval: 120_000 });
  const keys = data?.keys ?? [];
  const health = intelKeyHealth(keys);
  if (health.tone === "none") return null;
  const cls =
    health.tone === "stale"
      ? "border-risk-suspicious/40 bg-risk-suspicious/10 text-risk-suspicious"
      : "border-risk-clean/40 bg-risk-clean/10 text-risk-clean";
  return (
    <Link
      to="/settings"
      className={`mb-5 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border px-3 py-2 font-mono text-[10px] transition-colors duration-150 hover:brightness-110 ${cls}`}
      title="Threat-intel keys — configure, test, and rotate in Settings"
    >
      <Icon name="shield" size={11} />
      {health.items.join(" · ")}
      <span className="ml-auto inline-flex items-center gap-1 text-text-faint">
        intel keys <Icon name="arrowRight" size={10} />
      </span>
    </Link>
  );
}

function HostForensicsRadarPanel() {
  const { data: snapshot } = useQuery({
    queryKey: ["xray", "snapshot"],
    queryFn: getHostXRaySnapshot,
    refetchInterval: 10_000,
  });
  const { data: catalog } = useQuery({
    queryKey: ["xray", "catalog"],
    queryFn: getXRayTargetCatalog,
    refetchInterval: 15_000,
  });

  const procCount = snapshot?.process_count ?? 0;
  const socketCount = snapshot?.socket_count ?? 0;
  const cpuPct = snapshot?.metrics?.cpu_percent ?? 0;
  const memMb = snapshot?.metrics?.memory_used_mb ?? 0;
  const memTotal = snapshot?.metrics?.memory_total_mb ?? 1;
  const memPct = Math.min(100, Math.round((memMb / memTotal) * 100));

  return (
    <section className="panel mb-6 border border-border-subtle bg-bg-surface/80 backdrop-blur-md p-5 rounded-2xl" aria-label="Host Forensics Real-Time Radar">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-subtle pb-3">
        <div className="flex items-center gap-2.5">
          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-accent/15 text-accent">
            <Icon name="box" size={15} />
          </span>
          <div>
            <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-text-primary">
              Host Forensics Real-Time Telemetry Pulse
            </h3>
            <p className="text-[11px] text-text-muted">
              Live kernel procfs & hardware device observation across host endpoints
            </p>
          </div>
        </div>
        <Link
          to="/events"
          className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 font-mono text-xs font-semibold text-accent hover:bg-accent/20 transition"
        >
          <span>Open Host Forensics</span>
          <Icon name="arrowRight" size={11} />
        </Link>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-6">
        <div className="rounded-xl border border-border-subtle bg-bg-elevated/40 p-3 text-center">
          <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">Host CPU Load</span>
          <div className="mt-1 font-mono text-xl font-bold text-text-primary">{cpuPct}%</div>
          <span className="text-[10px] text-text-muted">baseline</span>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-elevated/40 p-3 text-center">
          <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">Memory Active</span>
          <div className="mt-1 font-mono text-xl font-bold text-text-primary">{memMb} MB</div>
          <span className="text-[10px] text-text-muted">{memPct}% allocated</span>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-elevated/40 p-3 text-center">
          <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">Live Processes</span>
          <div className="mt-1 font-mono text-xl font-bold text-accent">{procCount}</div>
          <span className="text-[10px] text-text-muted">procfs tracks</span>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-elevated/40 p-3 text-center">
          <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">Listening Sockets</span>
          <div className="mt-1 font-mono text-xl font-bold text-emerald-400">{socketCount}</div>
          <span className="text-[10px] text-text-muted">IP bindings</span>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-elevated/40 p-3 text-center">
          <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">GPU Render Clients</span>
          <div className="mt-1 font-mono text-xl font-bold text-purple-400">{catalog?.quick_inspect?.gpu ?? 0}</div>
          <span className="text-[10px] text-text-muted">render nodes</span>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-elevated/40 p-3 text-center">
          <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">Audio / Mic Sensors</span>
          <div className="mt-1 font-mono text-xl font-bold text-amber-400">
            {(catalog?.quick_inspect?.microphone ?? 0) + (catalog?.quick_inspect?.audio ?? 0)}
          </div>
          <span className="text-[10px] text-text-muted">active streams</span>
        </div>
      </div>
    </section>
  );
}

function MitreTacticalProgressionPanel() {
  const tactics = [
    { id: "TA0001", name: "Initial Access", color: "bg-blue-500/20 text-blue-300 border-blue-500/30", count: 2 },
    { id: "TA0002", name: "Execution", color: "bg-amber-500/20 text-amber-300 border-amber-500/30", count: 4 },
    { id: "TA0003", name: "Persistence", color: "bg-orange-500/20 text-orange-300 border-orange-500/30", count: 3 },
    { id: "TA0004", name: "Priv Escalation", color: "bg-red-500/20 text-red-300 border-red-500/30", count: 1 },
    { id: "TA0005", name: "Defense Evasion", color: "bg-rose-500/20 text-rose-300 border-rose-500/30", count: 5 },
    { id: "TA0006", name: "Credential Access", color: "bg-purple-500/20 text-purple-300 border-purple-500/30", count: 2 },
    { id: "TA0011", name: "Command & Control", color: "bg-indigo-500/20 text-indigo-300 border-indigo-500/30", count: 3 },
  ];

  return (
    <section className="panel mb-6 border border-border-subtle bg-bg-surface/80 backdrop-blur-md p-5 rounded-2xl" aria-label="MITRE Kill Chain Progression">
      <div className="flex items-center justify-between border-b border-border-subtle pb-3">
        <div className="flex items-center gap-2">
          <Icon name="target" size={15} className="text-accent" />
          <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-text-primary">
            MITRE ATT&CK Kill-Chain Tactical Distribution
          </h3>
        </div>
        <Link to="/coverage" className="font-mono text-[11px] text-accent hover:underline flex items-center gap-1">
          <span>Enterprise Heatmap</span>
          <Icon name="arrowRight" size={11} />
        </Link>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7">
        {tactics.map((t) => (
          <Link
            key={t.id}
            to={`/coverage?tactic=${t.id}`}
            className={`rounded-xl border p-3 text-center transition hover:brightness-125 cursor-pointer ${t.color}`}
          >
            <div className="font-mono text-[10px] opacity-70">{t.id}</div>
            <div className="mt-1 font-bold text-xs truncate">{t.name}</div>
            <div className="mt-2 font-mono text-sm font-bold">{t.count} techniques</div>
          </Link>
        ))}
      </div>
    </section>
  );
}

// Intel cache freshness — the one-line sibling of IntelKeyHealth: oldest
// verdict age + stale count fleet-wide, amber when any verdict is past the
// TTL. Links to Settings (where the stale-only sweep lives). Cheap: one
// aggregate query, no external calls.
function IntelFreshness() {
  const { data } = useQuery({
    queryKey: ["intel-freshness"],
    queryFn: getIntelFreshness,
    staleTime: 60_000,
    refetchInterval: 120_000,
  });
  if (!data) return null;
  const h = intelFreshness(data);
  if (h.tone === "none" || !h.line) return null;
  const cls =
    h.tone === "stale"
      ? "border-risk-suspicious/40 bg-risk-suspicious/10 text-risk-suspicious"
      : "border-border-subtle text-text-faint";
      return (
    <Link
      to="/settings"
      className={`mb-5 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border px-3 py-2 font-mono text-[10px] transition-colors duration-150 hover:brightness-110 ${cls}`}
      title="Enrichment cache age across the fleet — refresh stale verdicts in Settings (stale-only sweep)"
    >
      <Icon name="refresh" size={11} />
      {h.line}
      <span className="ml-auto inline-flex items-center gap-1 text-text-faint">
        intel cache <Icon name="arrowRight" size={10} />
      </span>
    </Link>
  );
}

function HostMonitorPanel() {
  const queryClient = useQueryClient();
  const { data: plat } = useQuery({ queryKey: ["platform"], queryFn: getPlatform, staleTime: Infinity });
  const { data: fleet } = useQuery({
    queryKey: ["agents"],
    queryFn: () => getAgents(),
    staleTime: 15_000,
    refetchInterval: 30_000,
  });
  const [copied, setCopied] = useState(false);

  useEventStream(
    () => undefined,
    undefined,
    undefined,
    (f) => {
      if (f.host_id === plat?.hostname) {
        void queryClient.invalidateQueries({ queryKey: ["agents"] });
      }
    },
  );

  if (!plat) return null;
  if (plat.os === "macos") return null;

  const agent = (fleet?.agents ?? []).find((a) => a.host_id === plat.hostname);
  const monitored = agent !== undefined;
  const collector = plat.os === "windows" ? "collectors\\windows\\collector_win.py" : "collectors/linux/collector_linux.py";
  const agentCmd = `python ${collector} --backend-url ${BASE_URL} --mode live`;
  const glyph = plat.os === "windows" ? "windows" : "linux";

  return (
    <div
      className={`mb-6 relative overflow-hidden rounded-2xl border p-4 backdrop-blur-xl transition-all duration-200 ${
        monitored
          ? "border-risk-clean/30 bg-gradient-to-r from-risk-clean/10 via-bg-surface/90 to-bg-surface/90 shadow-[0_4px_24px_-4px_rgba(63,167,150,0.15)]"
          : "border-risk-suspicious/30 bg-gradient-to-r from-risk-suspicious/10 via-bg-surface/90 to-bg-surface/90 shadow-[0_4px_24px_-4px_rgba(217,164,65,0.15)]"
      }`}
      aria-label="This host's monitor status"
    >
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <span
            className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border ${
              monitored
                ? "border-risk-clean/40 bg-risk-clean/15 text-risk-clean shadow-[var(--glow-clean)]"
                : "border-risk-suspicious/40 bg-risk-suspicious/15 text-risk-suspicious shadow-[var(--glow-amber)]"
            }`}
          >
            <Icon name={glyph} size={20} />
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-2.5">
              <span className="relative flex h-2.5 w-2.5">
                <span
                  className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-75 ${
                    monitored ? "bg-risk-clean" : "bg-risk-suspicious"
                  }`}
                />
                <span
                  className={`relative inline-flex h-2.5 w-2.5 rounded-full ${
                    monitored ? "bg-risk-clean" : "bg-risk-suspicious"
                  }`}
                />
              </span>
              <p className="font-sans text-sm font-semibold tracking-tight text-text-primary">
                {monitored ? `Host Monitored — ${agent?.online ? "Agent Active" : "Agent Standby"}` : "Host Not Monitored Yet"}
              </p>
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-1 font-mono text-[11px] text-text-muted">
              <span className="font-medium text-text-primary">{plat.hostname}</span>
              <span className="text-text-faint">·</span>
              <span>{plat.os} {plat.release}</span>
              <span className="text-text-faint">·</span>
              <span className="rounded bg-bg-elevated/70 px-1.5 py-0.5 text-text-faint">{plat.collector}</span>
              {monitored && agent && (
                <>
                  <span className="text-text-faint">·</span>
                  {agent.identity === "collector" ? (
                    <Link
                      to="/agents?identity=collector"
                      className="inline-flex items-center gap-1 rounded border border-risk-clean/40 bg-risk-clean/10 px-1.5 py-0.5 text-[10px] font-medium text-risk-clean transition-colors hover:bg-risk-clean/20"
                      title={`Real host agent · channels: ${agent.channels?.join(", ") || "—"}`}
                    >
                      <Icon name="activity" size={10} />
                      collector
                    </Link>
                  ) : (
                    <Link
                      to="/agents?identity=webapp"
                      className="inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-elevated/60 px-1.5 py-0.5 text-[10px] text-text-muted hover:text-text-primary"
                    >
                      <Icon name="terminal" size={10} />
                      webapp
                    </Link>
                  )}
                  {agent.channels?.map((c) => (
                    <span
                      key={c}
                      className="rounded border border-border-subtle bg-bg-elevated/60 px-1.5 py-0.5 text-[10px] text-text-muted"
                    >
                      {c}
                    </span>
                  ))}
                  {agent.last_auth_role && (
                    <span
                      className="rounded border border-border-subtle bg-bg-elevated/60 px-1.5 py-0.5 text-[10px] text-text-muted"
                      title={`Authenticated as ${agent.last_auth_role}${agent.last_auth_at ? ` (${_rel(agent.last_auth_at)})` : ""}`}
                    >
                      auth: {agent.last_auth_role === "agent" ? "agent token" : agent.last_auth_role}
                    </span>
                  )}
                </>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {!monitored && (
            <button
              onClick={() => {
                void copyToClipboard(agentCmd);
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-elevated/60 px-3 py-2 font-mono text-xs text-text-muted transition-colors hover:border-accent/60 hover:text-accent"
              title="Copy collector command"
            >
              <Icon name={copied ? "check" : "copy"} size={12} />
              {copied ? "copied" : "copy agent cmd"}
            </button>
          )}
          <Link
            to="/events"
            className="press inline-flex items-center gap-2 rounded-lg border border-accent/60 bg-accent/15 px-4 py-2 font-mono text-xs font-semibold text-accent shadow-[var(--glow-accent)] transition-all hover:bg-accent/25"
          >
            <Icon name="activity" size={13} />
            Watch live stream
          </Link>
        </div>
      </div>
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────────────── */
// Demo-mode banner — seeded data labeled honestly, never masquerading as
// real host telemetry. Dismissed per-browser (localStorage).
/* ──────────────────────────────────────────────────────────────────────── */

const DEMO_DISMISS_KEY = "outpost-demo-dismissed";

function DemoBanner() {
  const queryClient = useQueryClient();
  const { data: meta } = useQuery({ queryKey: ["meta"], queryFn: getMeta, staleTime: 30_000 });
  const [dismissed, setDismissed] = useState(() => {
    try {
      return localStorage.getItem(DEMO_DISMISS_KEY) === "1";
    } catch {
      return false;
    }
  });
  const [purging, setPurging] = useState(false);

  if (!meta?.demo_mode || dismissed) return null;

  return (
    <div className="mb-5 flex flex-wrap items-center justify-between gap-x-3 gap-y-2 rounded-xl border border-risk-suspicious/40 bg-risk-suspicious/10 px-4 py-3">
      <div className="flex min-w-0 flex-1 items-center gap-2">
        <span className="inline-flex items-center gap-1.5 font-mono text-xs font-semibold text-risk-suspicious">
          <Icon name="zap" size={13} />
          Demo data
        </span>
        <p className="min-w-0 flex-1 text-xs leading-relaxed text-text-muted">
          These sessions are seeded demo samples. Ship real telemetry with{" "}
          <code className="font-mono text-text-primary">outpost agent run</code> or purge demo data to work with a clean store.
        </p>
      </div>
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={purging}
          onClick={async () => {
            setPurging(true);
            try {
              await resetStore();
              await queryClient.invalidateQueries();
            } finally {
              setPurging(false);
            }
          }}
          className="press inline-flex items-center gap-1 rounded-md border border-risk-malicious/50 bg-risk-malicious/15 px-2.5 py-1 font-mono text-xs font-semibold text-risk-malicious transition-colors hover:bg-risk-malicious/25 disabled:opacity-50"
          title="Wipe seeded demo data from the database"
        >
          <Icon name="x" size={11} />
          {purging ? "Purging..." : "Purge demo data"}
        </button>
        <button
          onClick={() => {
            try {
              localStorage.setItem(DEMO_DISMISS_KEY, "1");
            } catch {
              /* ignore */
            }
            setDismissed(true);
          }}
          className="press inline-flex items-center gap-1 rounded border border-border-subtle px-2 py-1 font-mono text-[10px] text-text-muted transition-colors hover:border-risk-suspicious/60 hover:text-risk-suspicious"
          aria-label="Dismiss demo banner"
        >
          <Icon name="x" size={10} />
          dismiss
        </button>
      </div>
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────────────── */
// Page
/* ──────────────────────────────────────────────────────────────────────── */

export default function OverviewPage() {
  // Archive parity: soak-named collector baselines (soak-…) are hidden so
  // the dashboard's trend, session count, and severity mix read as real
  // telemetry first — same default as the History page (see overviewRunParams).
  const { data: runs = [], isLoading, isError } = useQuery({ queryKey: ["runs"], queryFn: () => getRuns(overviewRunParams()) });
  const { data: campaigns = [] } = useQuery({ queryKey: ["campaigns"], queryFn: () => getCampaigns() });

  const totalAlerts = runs.reduce((n, r) => n + r.alert_count, 0);

  return (
    <div className="mx-auto max-w-[1400px] px-5 py-8 lg:px-8">
      <PageHeader
        kicker="Workspace · overview"
        title={
          <>
            OutPost <span className="font-normal text-text-muted">— behavioral monitor</span>
          </>
        }
        lede="Unified behavioral security telemetry, live fleet pulse, and prioritized SOC detection queue across monitored endpoints."
        actions={
          <div className="flex items-center gap-2">
            <Link
              to="/events"
              className="press inline-flex items-center gap-1.5 rounded-xl border border-accent/60 bg-accent/15 px-3.5 py-2 font-mono text-xs font-semibold text-accent transition-all duration-150 hover:bg-accent/25 hover:shadow-[var(--glow-accent)]"
            >
              <Icon name="list" size={13} />
              Event Manager
            </Link>
            <Link
              to="/monitor"
              className="press inline-flex items-center gap-1.5 rounded-xl border border-border-subtle bg-bg-elevated px-3.5 py-2 font-mono text-xs font-medium text-text-muted transition-all duration-150 hover:border-accent/40 hover:text-text-primary"
            >
              <Icon name="activity" size={13} />
              Simulation Lab
            </Link>
          </div>
        }
      />

      <DemoBanner />
      <Deferred>
        <HostMonitorPanel />
        {/* Intel posture: configured keys + rotation age, and cache freshness. */}
        <IntelKeyHealth />
        <IntelFreshness />
      </Deferred>

      {!isLoading && !isError && runs.length === 0 && (
        <Panel kicker="Telemetry status" title="No telemetry received">
          <div className="py-8 text-center font-mono text-sm text-text-muted">
            <p className="font-semibold text-text-primary">0 monitored sessions active</p>
            <p className="mt-1 text-xs text-text-faint">
              Connect a Linux or Windows agent collector, or launch the Simulation Lab to generate security events.
            </p>
            <div className="mt-4 flex justify-center gap-3">
              <Link to="/events" className="btn btn-primary text-xs">
                Open Event Manager
              </Link>
              <Link to="/monitor" className="btn text-xs">
                Open Simulation Lab
              </Link>
            </div>
          </div>
        </Panel>
      )}

      {!isLoading && !isError && runs.length > 0 && (
        <PostureHeader runs={runs} campaigns={campaigns.length} totalAlerts={totalAlerts} />
      )}

      {/* Host X-Ray Real-time Telemetry Radar & MITRE Kill Chain Progression */}
      <Deferred>
        <HostForensicsRadarPanel />
        <MitreTacticalProgressionPanel />
      </Deferred>
      {isLoading && (
        <div className="space-y-4">
          <div className="skeleton h-40 w-full" />
        </div>
      )}

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-[1.6fr_1fr]">
        <Deferred>
          <FindingsFeed />
        </Deferred>
        <Deferred>
          <ActiveInvestigationsPanel />
        </Deferred>
      </div>

      {/* Actions + environment, one compact strip. The dashboard is exactly:
          posture, live findings (+ hunt), and this action bar. */}
      <Deferred>
        <ActionStrip />
      </Deferred>
    </div>
  );
}
