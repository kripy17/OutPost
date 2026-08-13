import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { MouseEvent as ReactMouseEvent, ReactNode } from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../components/Icon";
import { platformIconName } from "../components/iconMeta";
import { RiskGauge, RiskTrendBars, SeverityDonut, type RiskTrendBar } from "../components/Posture/Posture";
import { Chip, PageHeader, Panel } from "../components/ui";
import { ageBucket, aggregateTrend, collapseFindings, intelFreshness, intelKeyHealth, openSince, overviewRunParams, sortFindingsRiskFirst } from "./overviewHelpers";
import { copyToClipboard } from "../lib/clipboard";
import { SEVERITY_BG } from "../lib/constants";
import { BASE_URL, getAgents, getCampaigns, getHealth, getIntelFreshness, getIntelKeys, getMeta, getPlatform, getProcessSummary, getRecentAlerts, getRuleMeta, getRuns } from "../lib/api";
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
import type { Campaign, ProcessSummary, RunSummary, Severity } from "../types";

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
  trendBars,
  campaigns,
  totalAlerts,
}: {
  runs: RunSummary[];
  trendBars: RiskTrendBar[];
  campaigns: number;
  totalAlerts: number;
}) {
  const peak = Math.max(0, ...runs.map((r) => r.risk_score ?? 0));
  const malicious = runs.filter((r) => r.highest_severity === "malicious").length;
  const suspicious = runs.filter((r) => r.highest_severity === "suspicious").length;
  const clean = runs.length - malicious - suspicious;

  return (
    <section className="panel overflow-hidden">
      <div className="grid divide-y divide-border-subtle lg:grid-cols-[1.05fr_0.95fr_1.4fr] lg:divide-x lg:divide-y-0">
        <div className="flex items-center justify-center px-6 py-6">
          <RiskGauge score={peak} />
        </div>
        <div className="flex items-center justify-center px-6 py-6">
          <SeverityDonut malicious={malicious} suspicious={suspicious} clean={clean} />
        </div>
        <div className="flex flex-col justify-center gap-4 px-6 py-6">
          <RiskTrendBars bars={trendBars} />
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-border-subtle pt-3 text-[12px]">
            <span className="flex items-center gap-1.5 text-text-muted">
              <Icon name="grid" size={13} className="text-text-faint" />
              <span className="font-semibold tabular-nums text-text-primary">{runs.length}</span> sessions
            </span>
            <span className="flex items-center gap-1.5 text-text-muted">
              <Icon name="zap" size={13} className="text-risk-suspicious" />
              <span className="font-semibold tabular-nums text-text-primary">{totalAlerts}</span> alerts
            </span>
            <span className="flex items-center gap-1.5 text-text-muted">
              <Icon name="flag" size={13} className="text-accent" />
              <span className="font-semibold tabular-nums text-text-primary">{campaigns}</span> campaigns
            </span>
          </div>
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
    queryFn: () => getRecentAlerts(24),
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
    setFreshKeys(fresh);
    if (fresh.size === 0) return;
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
        <p className="py-8 text-center text-sm text-text-muted">No findings yet — detonate a sample from Monitor.</p>
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
              <span className={preview.data.alert_count > 0 ? "text-risk-suspicious" : ""}>
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

/* ──────────────────────────────────────────────────────────────────────── */
// Campaign spotlight
/* ──────────────────────────────────────────────────────────────────────── */

function rankCampaign(c: Campaign): number {
  const shared = c.iocs.ips.filter((i) => i.runs >= 2).length;
  return c.runs.length * 10 + Math.min(shared, 5) + c.runs.reduce((n, r) => n + r.alert_count, 0);
}

function CampaignSpotlight() {
  const { data: campaigns = [], isLoading, isError } = useQuery({ queryKey: ["campaigns"], queryFn: () => getCampaigns() });

  if (isLoading) return <p className="text-sm text-text-muted">Grouping runs…</p>;
  if (isError) return <p className="text-xs text-risk-malicious">Couldn't load campaigns.</p>;
  if (campaigns.length === 0) {
    return (
      <Panel kicker="Hunt" title="Campaign spotlight">
        <p className="text-sm text-text-muted">Two or more runs connecting to the same IP form a campaign automatically.</p>
      </Panel>
    );
  }

  const top = [...campaigns].sort((a, b) => rankCampaign(b) - rankCampaign(a))[0];
  const rep = top.reputation;
  const sharedIps = top.iocs.ips.filter((i) => i.runs >= 2).slice(0, 3);
  const topRuns = [...top.runs].sort((a, b) => b.alert_count - a.alert_count).slice(0, 3);

  return (
    <Panel
      kicker="Hunt"
      title="Campaign spotlight"
      right={
        <Link to="/campaigns" className="press inline-flex items-center gap-1 font-mono text-[10px] text-accent hover:underline">
          all campaigns <Icon name="arrowRight" size={11} />
        </Link>
      }
    >
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <Icon name="network" size={14} className="text-accent" />
          <span className="font-mono text-sm font-semibold text-text-primary">{top.key}</span>
          <Chip tone={rep === "malicious" ? "malicious" : "suspicious"} dot glow>
            {top.watchlist ? "★ " : ""}
            {rep ?? "unknown"}
            {top.watchlist_label ? ` — ${top.watchlist_label}` : ""}
          </Chip>
          <span className="font-mono text-[10px] text-text-faint">
            {top.runs.length} run{top.runs.length === 1 ? "" : "s"}
          </span>
        </div>

        <ul className="space-y-1">
          {topRuns.map((r) => (
            <li key={r.run_id}>
              <Link
                to={`/runs/${r.run_id}`}
                className="group flex items-baseline gap-2 rounded-md border border-transparent px-2 py-1 transition-colors hover:border-border-subtle hover:bg-bg-elevated"
              >
                <span className="font-mono text-xs text-text-primary">{r.sample_name}</span>
                <span className="ml-auto font-mono text-[10px] text-text-faint">
                  {r.alert_count} alert{r.alert_count === 1 ? "" : "s"}
                </span>
                <span
                  className={`text-xs ${r.highest_severity === "malicious" ? "text-risk-malicious" : "text-risk-suspicious"}`}
                >
                  ●
                </span>
              </Link>
            </li>
          ))}
        </ul>

        {sharedIps.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 border-t border-border-subtle pt-2">
            <span className="text-[11px] font-semibold uppercase tracking-wide text-text-muted">shared C2</span>
            {sharedIps.map((i) => (
              <span
                key={i.value}
                className="rounded border border-accent/40 bg-bg-elevated/50 px-2 py-0.5 font-mono text-[11px] text-accent"
              >
                {i.value}
                <span className="ml-1 text-[10px] text-text-faint">×{i.runs}</span>
              </span>
            ))}
          </div>
        )}
      </div>
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
  const { data: fleet } =useQuery({
    queryKey: ["agents"],
    queryFn: () => getAgents(), staleTime: 15_000, refetchInterval: 30_000 });
  const [copied, setCopied] = useState(false);

  // Live fleet: a heartbeat from this host flips the panel to "monitored"
  // the moment it lands (e.g. the operator runs `outpost agent run`) — no
  // waiting for the 30 s poll.
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
  if (plat.os === "macos") return null; // no collector ships for macOS

  const agent = (fleet?.agents ?? []).find((a) => a.host_id === plat.hostname);
  const monitored = agent !== undefined;
  const collector = plat.os === "windows" ? "collectors\\windows\\collector_win.py" : "collectors/linux/collector_linux.py";
  const agentCmd = `python ${collector} --backend-url ${BASE_URL} --mode live`;
  const glyph = plat.os === "windows" ? "windows" : "linux";

  return (
    <div
      className={`mb-5 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-xl border px-4 py-3 ${
        monitored ? "border-risk-clean/40 bg-risk-clean/10" : "border-risk-suspicious/40 bg-risk-suspicious/10"
      }`}
      aria-label="This host's monitor status"
    >
      <span
        className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${
          monitored ? "bg-risk-clean/15 text-risk-clean" : "bg-risk-suspicious/15 text-risk-suspicious"
        }`}
      >
        <Icon name={glyph} size={16} />
      </span>
      <div className="min-w-0">
        <p className={`font-mono text-xs font-semibold ${monitored ? "text-risk-clean" : "text-risk-suspicious"}`}>
          {monitored ? `This host is monitored — ${agent?.online ? "agent online" : "agent silent"}` : "This host isn't monitored yet"}
        </p>
        <p className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[10px] text-text-muted">
          <span className="truncate">
            {plat.hostname} · {plat.os} {plat.release} · {plat.collector}
          </span>
          {monitored && agent && (
            <>
              {agent.identity === "collector" ? (
                <Link
                  to="/agents?identity=collector"
                  className="inline-flex items-center gap-1 rounded border border-risk-clean/40 bg-risk-clean/10 px-1.5 py-px text-[10px] text-risk-clean transition-colors duration-150 hover:border-risk-clean/70 hover:bg-risk-clean/20"
                  title={`Real host agent${agent.heartbeat_version ? ` · ${agent.heartbeat_version}` : ""} · channels: ${agent.channels?.join(", ") || "—"} · last auth: ${agent.last_auth_role ?? "—"}${agent.last_auth_at ? ` ${_rel(agent.last_auth_at)}` : ""} — open the collector fleet`}
                >
                  <Icon name="activity" size={9} />
                  collector
                </Link>
              ) : (
                <Link
                  to="/agents?identity=webapp"
                  className="inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-elevated/50 px-1.5 py-px text-[10px] text-text-faint transition-colors duration-150 hover:border-border-subtle hover:bg-bg-elevated hover:text-text-muted"
                  title="No agent heartbeat — events came from this machine (webapp detonations, sandbox runs) — open the webapp hosts"
                >
                  <Icon name="terminal" size={9} />
                  webapp detonation
                </Link>
              )}
              {agent.identity === "collector" &&
                (agent.channels ?? [])
                  .filter((c) => c !== "webapp")
                  .map((c) => (
                    <span
                      key={c}
                      className={`inline-flex items-center gap-1 rounded border px-1.5 py-px font-mono text-[10px] ${
                        c === "auditd"
                          ? "border-risk-clean/30 bg-risk-clean/5 text-risk-clean/90"
                          : c === "sysmon"
                            ? "border-accent/30 bg-accent/5 text-accent/90"
                            : "border-border-subtle bg-bg-elevated/50 text-text-muted"
                      }`}
                      title={`Telemetry channel: ${c === "auditd" ? "Linux audit daemon events (execve, connect, file writes)" : c === "sysmon" ? "Windows Sysmon events (process create, network, file, registry)" : "Custom collector channel"} — streamed live from this host`}
                    >
                      <Icon name="activity" size={9} />
                      {c}
                    </span>
                  ))}
              {agent.last_auth_role && (
                <span
                  className={`inline-flex items-center gap-1 rounded border px-1.5 py-px text-[10px] ${
                    agent.last_auth_role === "agent"
                      ? "border-accent/40 bg-accent/10 text-accent"
                      : agent.last_auth_role === "local"
                        ? "border-border-subtle bg-bg-elevated/50 text-text-faint"
                        : "border-border-subtle bg-bg-elevated/50 text-text-muted"
                  }`}
                  title={`Authenticated ${agent.last_auth_role === "agent" ? "via the shared OUTPOST_AGENT_TOKEN" : agent.last_auth_role === "local" ? "without a credential (auth off / open mode)" : `as the ${agent.last_auth_role} role`}${agent.last_auth_at ? ` · ${_rel(agent.last_auth_at)}` : ""}`}
                >
                  auth: {agent.last_auth_role === "agent" ? "agent token" : agent.last_auth_role}
                </span>
              )}
            </>
          )}
          <span className="text-text-faint">
            {monitored && agent?.silent
              ? "— heartbeat lost, agent may be down"
              : monitored
                ? "— live events stream into the Monitor"
                : "— run the agent to stream its activity live"}
          </span>
        </p>
      </div>
      {monitored ? (
        <Link
          to="/monitor"
          className="press ml-auto inline-flex items-center gap-1.5 rounded-lg border border-risk-clean/50 bg-risk-clean/10 px-3 py-1.5 font-mono text-xs text-risk-clean transition-all duration-150 hover:shadow-[var(--glow-clean)]"
        >
          <Icon name="activity" size={12} />
          Watch live
        </Link>
      ) : (
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <code className="overflow-x-auto rounded-lg border border-border-subtle bg-bg-elevated/40 px-2.5 py-1.5 font-mono text-[10px] text-text-primary">
            {agentCmd}
          </code>
          <button
            onClick={() =>
              void copyToClipboard(agentCmd).then(() => {
                setCopied(true);
                setTimeout(() => setCopied(false), 1600);
              })
            }
            className="press inline-flex items-center gap-1 rounded-lg border border-risk-suspicious/50 px-2.5 py-1.5 font-mono text-[10px] text-risk-suspicious transition-colors duration-150 hover:bg-risk-suspicious/10"
          >
            <Icon name={copied ? "check" : "copy"} size={11} />
            {copied ? "copied" : "copy agent command"}
          </button>
          <Link
            to="/monitor"
            className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle px-2.5 py-1.5 font-mono text-[10px] text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
          >
            <Icon name="arrowRight" size={11} />
            Live Monitor
          </Link>
        </div>
      )}
    </div>
  );
}

/* ──────────────────────────────────────────────────────────────────────── */
// Demo-mode banner — seeded data labeled honestly, never masquerading as
// real host telemetry. Dismissed per-browser (localStorage).
/* ──────────────────────────────────────────────────────────────────────── */

const DEMO_DISMISS_KEY = "outpost-demo-dismissed";

function DemoBanner() {
  const { data: meta } = useQuery({ queryKey: ["meta"], queryFn: getMeta, staleTime: 30_000 });
  const [dismissed, setDismissed] = useState(() => {
    try {
      return localStorage.getItem(DEMO_DISMISS_KEY) === "1";
    } catch {
      return false;
    }
  });

  if (!meta?.demo_mode || dismissed) return null;

  return (
    <div className="mb-5 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-risk-suspicious/40 bg-risk-suspicious/10 px-4 py-3">
      <span className="inline-flex items-center gap-1.5 font-mono text-xs font-semibold text-risk-suspicious">
        <Icon name="zap" size={13} />
        Demo data
      </span>
      <p className="min-w-0 flex-1 text-xs leading-relaxed text-text-muted">
        These sessions are seeded samples so you can explore the console — not real host telemetry. Ship live events
        from this machine with{" "}
        <code className="font-mono text-text-primary">outpost agent run</code> (or{" "}
        <code className="font-mono text-text-primary">outpost agent install</code> for a persistent service).
      </p>
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
  const trendBars = useMemo(() => aggregateTrend(runs), [runs]);

  return (
    <div className="mx-auto max-w-[1400px] px-5 py-8 lg:px-8">
      <PageHeader
        kicker="Workspace · overview"
        title={
          <>
            OutPost <span className="font-normal text-text-muted">— behavioral monitor</span>
          </>
        }
        lede="Detect suspicious activity on this machine, watch detonations land in real time, and track shared infrastructure across every session."
        actions={
          <Link
            to="/monitor"
            className="press inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-xs font-semibold text-bg-base transition-all duration-150 hover:bg-accent-soft hover:shadow-[var(--glow-accent)]"
          >
            <Icon name="play" size={13} />
            Detonate
          </Link>
        }
      />

      <DemoBanner />
      <HostMonitorPanel />
      {/* Intel posture: configured keys + rotation age, and cache freshness. */}
      <IntelKeyHealth />
      <IntelFreshness />

      {!isLoading && !isError && (
        <>
          <PostureHeader runs={runs} trendBars={trendBars} campaigns={campaigns.length} totalAlerts={totalAlerts} />
          {/* One-line trend affordance — the analytical bars live in History now. */}
          <p className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[10px] text-text-faint">
            <Icon name="activity" size={12} className="text-accent" />
            <span>Risk timeline &amp; detection volume moved to</span>
            <Link
              to="/history"
              className="press inline-flex items-center gap-1 font-semibold text-accent hover:underline"
            >
              History <Icon name="arrowRight" size={11} />
            </Link>
          </p>
        </>
      )}
      {isLoading && (
        <div className="space-y-4">
          <div className="skeleton h-40 w-full" />
        </div>
      )}

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-[1.6fr_1fr]">
        <FindingsFeed />
        <CampaignSpotlight />
      </div>

      {/* Actions + environment, one compact strip. The dashboard is exactly:
          posture, live findings (+ hunt), and this action bar. */}
      <ActionStrip />
    </div>
  );
}
