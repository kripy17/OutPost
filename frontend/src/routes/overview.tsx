import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import DetectionVolume from "../components/DetectionVolume/DetectionVolume";
import RiskTimeline from "../components/RiskTimeline/RiskTimeline";
import { Chip, PageHeader, Panel, Stat } from "../components/ui";
import { SEVERITY_BG } from "../lib/constants";
import { getCampaigns, getRecentAlerts, getRuleMeta, getRuns } from "../lib/api";
import type { Campaign } from "../types";

// ---------------------------------------------------------------------------
// Stat strip — one deck panel, divided like a ticker tape.
// ---------------------------------------------------------------------------

function StatStrip({
  runs,
  campaigns,
  malicious,
  totalAlerts,
  totalRisk,
}: {
  runs: number;
  campaigns: number;
  malicious: number;
  totalAlerts: number;
  totalRisk: number;
}) {
  return (
    <Panel className="overflow-hidden" pad={false}>
      <dl className="grid grid-cols-2 divide-border-subtle sm:grid-cols-3 md:grid-cols-5 md:divide-x">
        <div className="px-5 py-4">
          <Stat label="sessions" value={runs} icon={<span aria-hidden>⬡</span>} />
        </div>
        <div className="px-5 py-4">
          <Stat label="alerts" value={totalAlerts} icon={<span aria-hidden>⚠</span>} />
        </div>
        <div className="px-5 py-4">
          <Stat label="malicious" value={malicious} tone="malicious" icon={<span aria-hidden>✕</span>} />
        </div>
        <div className="px-5 py-4">
          <Stat label="campaigns" value={campaigns} tone="accent" icon={<span aria-hidden>⛨</span>} />
        </div>
        <div className="px-5 py-4">
          <Stat label="cumulative risk" value={totalRisk} icon={<span aria-hidden>▤</span>} sub="all sessions" />
        </div>
      </dl>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Live findings feed
// ---------------------------------------------------------------------------

function FindingsFeed() {
  const { data: alerts = [], isLoading, isError } = useQuery({
    queryKey: ["alerts", "recent"],
    queryFn: () => getRecentAlerts(12),
    refetchInterval: 10_000, // the console refreshes itself
  });
  const { data: meta } = useQuery({ queryKey: ["rules-meta"], queryFn: getRuleMeta, staleTime: Infinity });
  const byRule = new Map((meta ?? []).map((m) => [m.rule_id, m]));

  return (
    <Panel
      kicker="Live feed"
      title="Findings"
      right={<span className="font-mono text-[10px] text-text-faint">auto-refresh · 10s</span>}
    >
      {isLoading && <p className="py-8 text-center text-sm text-text-muted">Watching the feed…</p>}
      {isError && (
        <p className="rounded-md border border-risk-malicious/40 px-3 py-2 text-xs text-risk-malicious">
          Backend unreachable — is it running?
        </p>
      )}

      {!isLoading && !isError && alerts.length === 0 && (
        <p className="py-8 text-center text-sm text-text-muted">No findings yet — detonate a sample from Monitor.</p>
      )}

      <ol className="space-y-2">
        {alerts.map((a) => {
          const rule = byRule.get(a.rule_id);
          return (
            <li
              key={a.id ?? `${a.run_id}-${a.rule_id}-${a.triggered_at}`}
              className="group rounded-lg border border-border-subtle bg-bg-elevated/40 px-3 py-2.5 transition-all duration-150 hover:border-accent-amber/40 hover:shadow-[var(--shadow-raised)]"
            >
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span className={`h-2 w-2 shrink-0 rounded-full ${SEVERITY_BG[a.severity]}`} />
                <Link to={`/runs/${a.run_id}`} className="press font-mono text-xs font-medium text-text-primary hover:text-accent-amber">
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
                <span className="ml-auto font-mono text-[10px] tabular-nums text-text-faint">
                  {a.triggered_at.slice(11, 19)} UTC
                </span>
              </div>
              <p className="mt-1 truncate pl-4 font-mono text-[11px] text-text-muted" title={a.details}>
                {a.details}
              </p>
            </li>
          );
        })}
      </ol>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Campaign spotlight
// ---------------------------------------------------------------------------

function rankCampaign(c: Campaign): number {
  // Most infrastructure shared + most alerts → highest signal.
  const shared = c.iocs.ips.filter((i) => i.runs >= 2).length;
  return c.runs.length * 10 + Math.min(shared, 5) + c.runs.reduce((n, r) => n + r.alert_count, 0);
}

function CampaignSpotlight() {
  const { data: campaigns = [], isLoading, isError } = useQuery({
    queryKey: ["campaigns"],
    queryFn: getCampaigns,
  });

  if (isLoading) return <p className="text-sm text-text-muted">Grouping runs…</p>;
  if (isError) return <p className="text-xs text-risk-malicious">Couldn't load campaigns.</p>;
  if (campaigns.length === 0) {
    return (
      <Panel kicker="Hunt" title="Campaign spotlight">
        <p className="text-sm text-text-muted">
          No campaigns yet — two or more runs connecting to the same IP form one automatically.
        </p>
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
        <Link to="/campaigns" className="press font-mono text-[10px] text-accent-amber hover:underline">
          all campaigns →
        </Link>
      }
    >
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
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
                className="flex items-baseline gap-2 rounded-md border border-transparent px-2 py-1 transition-colors hover:border-border-subtle hover:bg-bg-elevated"
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
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-[10px] uppercase tracking-widest text-text-faint">shared C2</span>
            {sharedIps.map((i) => (
              <span
                key={i.value}
                className="rounded border border-accent-amber/40 bg-bg-elevated/50 px-2 py-0.5 font-mono text-[11px] text-accent-amber"
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

// ---------------------------------------------------------------------------
// Quick actions — command buttons
// ---------------------------------------------------------------------------

const ACTIONS = [
  { to: "/monitor", label: "Detonate sample", desc: "Live analysis on Windows or Linux", glyph: "▶" },
  { to: "/search", label: "IOC search", desc: "Every run that touched an IP, file, or key", glyph: "⌕" },
  { to: "/compare", label: "Compare runs", desc: "Diff two samples side by side", glyph: "⇄" },
  { to: "/watchlist", label: "Watchlist", desc: "Track known-bad infrastructure", glyph: "★" },
];

function QuickActions() {
  return (
    <Panel kicker="Operate" title="Quick actions">
      <div className="grid grid-cols-2 gap-2">
        {ACTIONS.map((a) => (
          <Link
            key={a.to}
            to={a.to}
            className="press group rounded-lg border border-border-subtle bg-bg-elevated/40 p-3 transition-all duration-150 hover:border-accent-amber/50 hover:shadow-[var(--shadow-raised)]"
          >
            <span className="flex items-center justify-between">
              <span className="font-mono text-sm text-accent-amber">{a.glyph}</span>
              <span className="font-mono text-[10px] text-text-faint opacity-0 transition-opacity duration-150 group-hover:opacity-100">
                →
              </span>
            </span>
            <span className="mt-1 block text-xs font-medium text-text-primary group-hover:text-accent-amber">
              {a.label}
            </span>
            <span className="mt-0.5 block text-[10px] leading-snug text-text-faint">{a.desc}</span>
          </Link>
        ))}
      </div>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function OverviewPage() {
  const { data: runs = [], isLoading, isError } = useQuery({ queryKey: ["runs"], queryFn: () => getRuns() });
  const { data: campaigns = [] } = useQuery({ queryKey: ["campaigns"], queryFn: getCampaigns });

  const totalAlerts = runs.reduce((n, r) => n + r.alert_count, 0);
  const malicious = runs.filter((r) => r.highest_severity === "malicious").length;
  const totalRisk = runs.reduce((n, r) => n + (r.risk_score ?? 0), 0);

  return (
    <div className="mx-auto max-w-7xl px-6 py-10 lg:px-10">
      <PageHeader
        kicker="Security operations"
        title={
          <>
            OutPost <span className="font-normal text-text-muted">— command deck</span>
          </>
        }
        lede="Detonate samples, watch detections land, and track shared infrastructure across every session."
        actions={
          <Link
            to="/monitor"
            className="press inline-flex items-center gap-2 rounded-lg bg-accent-amber px-3.5 py-2 font-mono text-xs font-semibold text-black transition-all duration-150 hover:bg-accent-amber-soft hover:shadow-[var(--glow-amber)]"
          >
            ▶ Detonate
          </Link>
        }
      />

      {!isLoading && !isError && (
        <StatStrip
          runs={runs.length}
          campaigns={campaigns.length}
          malicious={malicious}
          totalAlerts={totalAlerts}
          totalRisk={totalRisk}
        />
      )}

      {!isLoading && !isError && (
        <div className="mb-6 mt-6 grid grid-cols-1 gap-6 xl:grid-cols-[1.7fr_1fr]">
          <RiskTimeline runs={runs} />
          <DetectionVolume />
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1.6fr_1fr]">
        <FindingsFeed />
        <div className="space-y-6">
          <CampaignSpotlight />
          <QuickActions />
        </div>
      </div>
    </div>
  );
}
