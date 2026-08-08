import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../components/Icon";
import { RiskGauge, RiskSparkline, SeverityDonut } from "../components/Posture/Posture";
import { Chip, PageHeader, Panel } from "../components/ui";
import { SEVERITY_BG } from "../lib/constants";
import { getCampaigns, getHealth, getPlatform, getRecentAlerts, getRuleMeta, getRuns } from "../lib/api";
import type { Campaign, GlobalAlert, RunSummary } from "../types";

/* ──────────────────────────────────────────────────────────────────────── */
// Threat posture — the console header. Three visual primitives instead of a
// stat strip: a risk gauge, a severity donut, and a risk-over-time sparkline.
// The primitives live in components/Posture/Posture.tsx (shared with the
// Theme Lab so palettes can be previewed side by side).
/* ──────────────────────────────────────────────────────────────────────── */

function PostureHeader({ runs, campaigns, totalAlerts }: { runs: RunSummary[]; campaigns: number; totalAlerts: number }) {
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
          <RiskSparkline runs={runs} />
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
// Live findings feed
/* ──────────────────────────────────────────────────────────────────────── */

function FindingsFeed() {
  const { data: alerts = [], isLoading, isError } = useQuery({
    queryKey: ["alerts", "recent"],
    queryFn: () => getRecentAlerts(12),
    refetchInterval: 10_000,
  });
  const { data: meta } = useQuery({ queryKey: ["rules-meta"], queryFn: getRuleMeta, staleTime: Infinity });
  const byRule = new Map((meta ?? []).map((m) => [m.rule_id, m]));

  return (
    <Panel
      kicker="Live feed"
      title="Findings"
      right={<span className="font-mono text-[10px] text-text-faint">auto-refresh · 10s</span>}
    >
      {isLoading && <SkeletonList rows={4} />}
      {isError && (
        <p className="rounded-md border border-risk-malicious/40 px-3 py-2 text-xs text-risk-malicious">
          Backend unreachable — is it running?
        </p>
      )}
      {!isLoading && !isError && alerts.length === 0 && (
        <p className="py-8 text-center text-sm text-text-muted">No findings yet — detonate a sample from Monitor.</p>
      )}

      <ol className="space-y-2">
        {alerts.map((a: GlobalAlert) => {
          const rule = byRule.get(a.rule_id);
          return (
            <li
              key={a.id ?? `${a.run_id}-${a.rule_id}-${a.triggered_at}`}
              className="group relative overflow-hidden rounded-lg border border-border-subtle bg-bg-elevated/40 pl-3 transition-all duration-150 hover:border-accent/40 hover:shadow-[var(--shadow-raised)]"
            >
              <span className={`absolute inset-y-0 left-0 w-1 ${SEVERITY_BG[a.severity]}`} aria-hidden />
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1 px-3.5 py-3">
                <Link to={`/runs/${a.run_id}`} className="press font-mono text-xs font-medium text-text-primary hover:text-accent">
                  {a.sample_name}
                </Link>
                <span className="text-xs text-text-muted">{a.rule_name}</span>
                {rule && (
                  <span
                    className="rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[10px] text-text-faint"
                    title={`MITRE ATT&CK ${rule.tactic}`}
                  >
                    {rule.technique} · {rule.tactic}
                  </span>
                )}
                <span className="ml-auto flex items-center gap-1 font-mono text-[10px] tabular-nums text-text-faint">
                  <Icon name={a.severity === "malicious" ? "alert" : "zap"} size={11} className={a.severity === "malicious" ? "text-risk-malicious" : "text-risk-suspicious"} />
                  {a.triggered_at.slice(11, 19)} UTC
                </span>
              </div>
              <p className="truncate px-3.5 pb-3 font-mono text-[11px] text-text-muted" title={a.details}>
                {a.details}
              </p>
            </li>
          );
        })}
      </ol>
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
  const { data: campaigns = [], isLoading, isError } = useQuery({ queryKey: ["campaigns"], queryFn: getCampaigns });

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
  { to: "/compare", label: "Compare runs", desc: "Diff two samples side by side", icon: <Icon name="compare" size={14} /> },
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
// Page
/* ──────────────────────────────────────────────────────────────────────── */

export default function OverviewPage() {
  const { data: runs = [], isLoading, isError } = useQuery({ queryKey: ["runs"], queryFn: () => getRuns() });
  const { data: campaigns = [] } = useQuery({ queryKey: ["campaigns"], queryFn: getCampaigns });

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

      {!isLoading && !isError && (
        <>
          <PostureHeader runs={runs} campaigns={campaigns.length} totalAlerts={totalAlerts} />
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
