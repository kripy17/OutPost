import { useQuery } from "@tanstack/react-query";
import type { MouseEvent as ReactMouseEvent } from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import ExportButton from "../components/ExportButton/ExportButton";
import { Icon } from "../components/Icon";
import { EVENT_ICON, platformIconName } from "../components/iconMeta";
import { eventDetail, TYPE_STYLE } from "../components/TimelineView/timeline";
import { PageHeader } from "../components/ui";
import { CAMPAIGN_SORTS, clusterBars, reputationFill, sortCampaigns, topMembers, topologyClusters, type CampaignSort, type ClusterBar } from "./campaignsHelpers";
import { getCampaigns, getCampaignStix, getFootprintTopology } from "../lib/api";
import type { Campaign, CampaignIoc, Reputation, Severity } from "../types";

const MAX_TIMELINE = 40;
const MAX_CHIPS = 10;

const SEV_DOT: Record<Severity, string> = {
  malicious: "text-risk-malicious",
  suspicious: "text-risk-suspicious",
};

const IOC_GROUPS: { key: keyof Campaign["iocs"]; label: string; icon: "network" | "registry" | "file" | "process" }[] = [
  { key: "ips", label: "IPs", icon: "network" },
  { key: "registry_keys", label: "Registry keys", icon: "registry" },
  { key: "file_paths", label: "File paths", icon: "file" },
  { key: "processes", label: "Processes", icon: "process" },
];

function fmt(ts: string | null): string {
  return ts ? ts.slice(0, 19).replace("T", " ") : "—";
}

function ReputationBadge({ campaign }: { campaign: Campaign }) {
  const rep = campaign.reputation;
  const style =
    rep === "malicious"
      ? "border-risk-malicious/50 text-risk-malicious"
      : "border-risk-suspicious/50 text-risk-suspicious";
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide ${style}`}>
      {campaign.watchlist && <Icon name="star" size={9} />}
      {rep ?? "unknown"}
      {campaign.watchlist_label ? ` — ${campaign.watchlist_label}` : ""}
    </span>
  );
}

function IocChip({ ioc, tone }: { ioc: CampaignIoc; tone: "accent" | "suspicious" | "clean" | "muted" }) {
  const cls = {
    accent: "border-accent/40 text-accent",
    suspicious: "border-risk-suspicious/40 text-risk-suspicious",
    clean: "border-risk-clean/40 text-risk-clean",
    muted: "border-border-subtle text-text-muted",
  }[tone];
  // One-click hunt pivot: every chip is an IOC, so it jumps straight to the
  // IOC search pre-filled with that value.
  return (
    <Link
      to={`/search?q=${encodeURIComponent(ioc.value)}`}
      className={`truncate rounded-md border bg-bg-elevated/40 px-2 py-0.5 font-mono text-[11px] transition-colors duration-150 hover:border-accent/60 hover:text-accent ${cls}`}
      title={`${ioc.value} — seen in ${ioc.runs} run(s). Click to search it.`}
    >
      {ioc.value}
      <span className="ml-1.5 text-[10px] opacity-70">×{ioc.runs}</span>
    </Link>
  );
}

function CampaignCard({ campaign }: { campaign: Campaign }) {
  const shown = campaign.timeline.slice(0, MAX_TIMELINE);
  const total = campaign.timeline_total ?? campaign.timeline.length;
  const hidden = total - shown.length;
  const iconTone: Record<string, "accent" | "suspicious" | "clean" | "muted"> = {
    ips: "accent",
    registry_keys: "suspicious",
    file_paths: "clean",
    processes: "muted",
  };

  return (
    <article className="tile overflow-hidden rounded-2xl border border-border-subtle bg-bg-surface">
      {/* header */}
      <header className="flex flex-wrap items-center gap-3 border-b border-border-subtle bg-bg-elevated/30 px-5 py-4">
        <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-accent/30 bg-accent/10 text-accent">
          <Icon name="network" size={17} />
        </span>
        <span className="font-mono text-lg font-semibold tracking-tight text-text-primary">{campaign.key}</span>
        <span className="rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[10px] uppercase text-text-faint">
          {campaign.runs.length} sample{campaign.runs.length === 1 ? "" : "s"}
        </span>
        <ReputationBadge campaign={campaign} />
        <span className="ml-auto flex items-center gap-3">
          {campaign.runs.length >= 2 && (
            <Link
              to={`/history?a=${campaign.runs[0].run_id}&b=${campaign.runs[1].run_id}`}
              className="press inline-flex items-center gap-1.5 rounded border border-border-subtle px-2.5 py-1 font-mono text-[11px] text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
              title="Diff the two newest samples in this campaign (processes/IPs each has that the other doesn't)"
            >
              <Icon name="compare" size={11} />
              Compare 2 newest
            </Link>
          )}
          <ExportButton
            runId={campaign.key}
            label="Export STIX"
            filename={`outpost-campaign-${campaign.key}.json`}
            fetcher={getCampaignStix}
          />
          <span className="font-mono text-[10px] tabular-nums uppercase tracking-wide text-text-faint">
            {fmt(campaign.span_start)} → {fmt(campaign.span_end)}
          </span>
        </span>
      </header>

      <div className="grid grid-cols-1 gap-6 p-5 lg:grid-cols-[1fr_1.4fr]">
        {/* left: member runs + IOC evidence */}
        <div className="space-y-5">
          <section>
            <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-text-muted">
              <Icon name="activity" size={12} className="text-signal" />
              Samples
            </h3>
            <ul className="space-y-1">
              {campaign.runs.map((r) => (
                <li key={r.run_id}>
                  <Link
                    to={`/runs/${r.run_id}`}
                    className="flex items-center gap-2 rounded-lg border border-transparent px-2 py-1.5 transition-colors hover:border-border-subtle hover:bg-bg-elevated"
                  >
                    <Icon name={platformIconName(r.platform)} size={12} className="shrink-0 text-text-faint" />
                    <span className="truncate font-mono text-sm text-text-primary">{r.sample_name}</span>
                    <span className="ml-auto flex items-center gap-2">
                      <span className="font-mono text-[10px] text-text-faint">{r.alert_count} alert{r.alert_count === 1 ? "" : "s"}</span>
                      <span className={`text-xs ${r.highest_severity ? SEV_DOT[r.highest_severity] : "text-risk-clean"}`}>●</span>
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          </section>

          {IOC_GROUPS.map(({ key, label, icon }) => {
            const items = campaign.iocs[key].slice(0, MAX_CHIPS);
            if (items.length === 0) return null;
            return (
              <section key={key}>
                <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-text-muted">
                  <Icon name={icon} size={12} className="text-signal" />
                  {label}
                  <span className="ml-1 font-normal normal-case text-text-faint/70">· {campaign.iocs[key].length}</span>
                </h3>
                <div className="flex flex-wrap gap-1.5">
                  {items.map((ioc) => (
                    <IocChip key={`${key}-${ioc.value}`} ioc={ioc} tone={iconTone[key]} />
                  ))}
                </div>
              </section>
            );
          })}
        </div>

        {/* right: combined timeline */}
        <section className="min-w-0">
          <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-text-muted">
            <Icon name="clock" size={12} className="text-signal" />
            Combined timeline
            <span className="ml-1 font-normal normal-case text-text-faint/70">{total} events across all samples</span>
          </h3>
          <ol className="max-h-[28rem] space-y-0.5 overflow-y-auto pr-1">
            {shown.map((ev, i) => (
              <li
                key={`${ev.run_id}-${ev.id ?? ev.timestamp}-${i}`}
                className="flex items-center gap-2.5 rounded-lg px-1.5 py-1 transition-colors hover:bg-bg-elevated"
              >
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md border border-border-subtle bg-bg-elevated/40 text-signal">
                  <Icon name={EVENT_ICON[ev.event_type] ?? "list"} size={12} />
                </span>
                <span className="w-24 shrink-0 truncate font-mono text-[10px] text-text-faint" title={`${ev.sample_name} · ${ev.run_id.slice(0, 12)}`}>
                  {ev.sample_name}
                </span>
                <span className="w-14 shrink-0 font-mono text-[11px] text-text-faint">{ev.timestamp.slice(11, 19)}</span>
                <span className={`w-32 shrink-0 font-mono text-[11px] ${TYPE_STYLE[ev.event_type]}`}>{ev.event_type.replace("_", " ")}</span>
                <span className="truncate font-mono text-xs text-text-muted">{eventDetail(ev)}</span>
              </li>
            ))}
          </ol>
          {hidden > 0 && (
            <p className="mt-2 text-[10px] text-text-faint">+ {hidden} more event(s) — open a run for the full timeline.</p>
          )}
        </section>
      </div>
    </article>
  );
}

export default function CampaignsPage() {
  // Campaigns read as real telemetry first: clusters built from synthetic
  // members (seeds / webapp detonations / the sandbox demo) are hidden unless
  // the analyst asks — archive parity with History / the Event Log.
  const [showSynthetic, setShowSynthetic] = useState(() => {
    try {
      return localStorage.getItem("outpost-campaigns-synthetic") === "1";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem("outpost-campaigns-synthetic", showSynthetic ? "1" : "0");
    } catch {
      /* storage unavailable — the toggle still applies for this visit */
    }
  }, [showSynthetic]);
  const { data: campaigns = [], isLoading, isError } = useQuery({
    queryKey: ["campaigns", showSynthetic],
    queryFn: () => getCampaigns({ include_synthetic: showSynthetic || undefined }),
  });
  // Cross-sample infra topology — the same correlation signal the Footprint
  // page surfaces, projected onto the campaign list so shared-infra clusters
  // are visible here too (including IPs that haven't formed a campaign yet).
  const { data: topology } = useQuery({
    queryKey: ["footprint", "topology"],
    queryFn: getFootprintTopology,
  });
  const strip = useMemo(
    () => (topology ? topologyClusters(topology.clusters, campaigns) : []),
    [topology, campaigns],
  );
  // Hover tooltip — each bar row reveals its member breakdown (sample names +
  // hit counts) in a fixed card, same pattern as the Overview process preview
  // but with the data already in memory, so no fetch is needed.
  const [tip, setTip] = useState<{ x: number; y: number; row: ClusterBar } | null>(null);
  const tipTimer = useRef<number | null>(null);
  const showTip = (e: ReactMouseEvent<HTMLElement>, row: ClusterBar) => {
    if (tipTimer.current !== null) window.clearTimeout(tipTimer.current);
    const r = e.currentTarget.getBoundingClientRect();
    tipTimer.current = window.setTimeout(() => {
      setTip({
        x: Math.max(8, Math.min(r.left, window.innerWidth - 304)),
        y: Math.max(8, Math.min(r.bottom + 8, window.innerHeight - 260)),
        row,
      });
    }, 120);
  };
  const hideTip = () => {
    if (tipTimer.current !== null) window.clearTimeout(tipTimer.current);
    setTip(null);
  };
  // Sort mode persists so the analyst's preferred ordering survives reloads.
  const [sort, setSort] = useState<CampaignSort>(() => {
    const saved = localStorage.getItem("outpost-campaigns-sort");
    return (CAMPAIGN_SORTS.some((s) => s.key === saved) ? saved : "reputation") as CampaignSort;
  });
  useEffect(() => {
    try {
      localStorage.setItem("outpost-campaigns-sort", sort);
    } catch {
      /* storage unavailable — ordering still applies for this visit */
    }
  }, [sort]);
  const sorted = useMemo(() => sortCampaigns(campaigns, sort), [campaigns, sort]);

  return (
    <div className="mx-auto max-w-6xl px-5 py-8 lg:px-8">
      <PageHeader
        kicker="Hunt · campaigns"
        title={
          <>
            Campaigns <span className="font-normal text-text-muted">— shared infrastructure across your runs</span>
          </>
        }
        lede="Runs that touch the same IP are grouped automatically. Known-clean IPs (shared DNS, for instance) never form a campaign; watchlisted or externally-flagged infrastructure ranks first."
      />

      {isLoading && (
        <div className="mt-8 space-y-4">
          <div className="skeleton h-24 w-full" />
          <div className="skeleton h-64 w-full" />
        </div>
      )}
      {isError && <p className="mt-8 text-sm text-risk-malicious">Couldn't load campaigns — is the OutPost backend running?</p>}
      {!isLoading && !isError && campaigns.length === 0 && (
        <div className="mt-10 rounded-2xl border border-dashed border-border-strong bg-bg-surface/40 p-14 text-center">
          <Icon name="flag" size={28} className="mx-auto text-text-faint" />
          <p className="mt-3 text-sm text-text-muted">
            No campaigns yet — two or more runs must connect to the same IP. Detonate a couple of samples and check again.
          </p>
        </div>
      )}

      {!isLoading && !isError && campaigns.length > 0 && (
        <div className="mt-6 flex flex-wrap items-center gap-x-4 gap-y-2">
          <span className="font-mono text-[10px] uppercase tracking-wide text-text-faint">Sort</span>
          <div className="flex items-center overflow-hidden rounded-lg border border-border-subtle" role="group" aria-label="Sort campaigns">
            {CAMPAIGN_SORTS.map((s) => (
              <button
                key={s.key}
                onClick={() => setSort(s.key)}
                aria-pressed={sort === s.key}
                title={s.title}
                className={`px-3 py-1.5 font-mono text-[11px] transition-colors duration-150 ${
                  sort === s.key ? "bg-accent/10 font-medium text-accent" : "text-text-muted hover:bg-bg-elevated hover:text-text-primary"
                }`}
              >
                {s.label}
              </button>
            ))}
          </div>
          <button
            onClick={() => setShowSynthetic((v) => !v)}
            aria-pressed={showSynthetic}
            title={
              showSynthetic
                ? "Hide demo/synthetic campaign members again"
                : "Include campaigns built from seeded demo runs and webapp-synthetic detonations"
            }
            className={`press rounded-lg border px-3 py-1.5 font-mono text-[11px] transition-colors duration-150 ${
              showSynthetic ? "border-accent/50 bg-accent/10 text-accent" : "border-border-subtle text-text-faint hover:text-text-primary"
            }`}
          >
            {showSynthetic ? "Show synthetic · on" : "Show synthetic"}
          </button>
        </div>
      )}

      {/* Shared-infrastructure strip — the cross-sample topology projected
          onto the campaign list. Each cluster is an IP ≥2 samples reached;
          the mark shows whether a campaign already tracks it, and every
          row deep-links to the Footprint page's topology panel. */}
      {strip.length > 0 && (
        <div className="mt-6 rounded-2xl border border-border-subtle bg-bg-surface/60 p-4">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <span className="font-mono text-[10px] uppercase tracking-wide text-text-faint">
              Shared infrastructure
            </span>
            <span className="rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[10px] text-text-faint">
              {strip.length} cluster{strip.length === 1 ? "" : "s"}
              {strip.length > 10 ? " · top 10 by size" : ""}
            </span>
            <div className="ml-auto flex items-center gap-3">
              {/* Pattern key — the fill encodes reputation for color-blind
                  viewers, not just the tint: solid = malicious, diagonal
                  hatch = suspicious, crosshatch = unknown, vertical = clean. */}
              <span
                className="hidden items-center gap-3 font-mono text-[10px] text-text-faint lg:flex"
                aria-label="Reputation key — fill pattern, not just color"
              >
                {(["malicious", "suspicious", "unknown", "clean"] as Reputation[]).map((r) => (
                  <span key={r} className="inline-flex items-center gap-1">
                    <span className="h-2 w-3 rounded-sm" style={reputationFill(r)} />
                    {r}
                  </span>
                ))}
              </span>
              <Link
                to="/footprint"
                className="press inline-flex items-center gap-1 font-mono text-[11px] text-accent transition-colors hover:underline"
              >
                footprint topology
                <Icon name="arrowRight" size={11} />
              </Link>
            </div>
          </div>
          {/* Compact bar chart — one row per cluster, bar width ∝ sample count
              (relative to the loudest), reputation-tinted, still deep-linking
              to the Footprint topology panel for each IP. */}
          <div className="space-y-1" role="list" aria-label="Shared-infrastructure clusters by size">
            {clusterBars(strip).map((b) => (
              <Link
                key={b.ip}
                to={`/footprint?sample=${encodeURIComponent(b.memberSample)}`}
                title={`${b.ip} — ${b.sample_count} sample${b.sample_count === 1 ? "" : "s"} · ${b.reputation}${b.inCampaign ? " · already a campaign" : " · not yet a campaign"}`}
                className="press relative flex items-center gap-2 overflow-hidden rounded-md px-2 py-1.5 font-mono text-[11px] transition-colors hover:bg-bg-elevated/50"
                onMouseEnter={(e) => showTip(e, b)}
                onMouseLeave={hideTip}
              >
                <span
                  aria-hidden="true"
                  className="absolute inset-y-1 left-0 rounded-sm"
                  style={{ width: `${b.pct}%`, ...reputationFill(b.reputation) }}
                />
                <Icon name="network" size={10} className="relative shrink-0 text-text-muted" />
                <span className="relative truncate text-text-primary">{b.ip}</span>
                <span className="relative shrink-0 text-text-faint">×{b.sample_count}</span>
                {b.inCampaign ? (
                  <span className="relative ml-auto shrink-0 rounded bg-risk-clean/15 px-1 py-px text-[9px] uppercase tracking-wide text-risk-clean">campaign</span>
                ) : (
                  <span className="relative ml-auto shrink-0 rounded bg-bg-elevated/60 px-1 py-px text-[9px] uppercase tracking-wide text-text-faint">new</span>
                )}
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Bar-row hover tooltip — the cluster's member breakdown (names + hit
          counts, loudest first, capped at 8 with the overflow counted). */}
      {tip &&
        (() => {
          const { rows, more } = topMembers(tip.row.members);
          return (
            <div
              role="tooltip"
              className="pointer-events-none fixed z-50 w-72 overflow-hidden rounded-xl border border-border-subtle bg-bg-surface shadow-[var(--shadow-raised)]"
              style={{ left: tip.x, top: tip.y }}
            >
              <div className="flex items-center gap-2 border-b border-border-subtle bg-bg-elevated/40 px-3 py-2">
                <Icon name="network" size={13} className="shrink-0 text-accent" />
                <span className="truncate font-mono text-xs font-semibold text-text-primary">{tip.row.ip}</span>
                <span className="ml-auto shrink-0 font-mono text-[10px] text-text-faint">×{tip.row.sample_count}</span>
              </div>
              <div className="px-3 py-2">
                {rows.length === 0 && <p className="font-mono text-[10px] text-text-faint">no members recorded</p>}
                {rows.map((m) => (
                  <div key={m.sample_name} className="flex items-baseline gap-2 py-0.5">
                    <span className="truncate font-mono text-[10px] text-text-muted" title={m.sample_name}>
                      {m.sample_name}
                    </span>
                    <span className="ml-auto shrink-0 font-mono text-[10px] tabular-nums text-text-faint">
                      {m.hits} hit{m.hits === 1 ? "" : "s"}
                    </span>
                  </div>
                ))}
                {more > 0 && (
                  <p className="mt-1 border-t border-border-subtle pt-1 font-mono text-[10px] text-text-faint">
                    +{more} more
                  </p>
                )}
              </div>
              <div className="border-t border-border-subtle bg-bg-elevated/40 px-3 py-1.5 font-mono text-[10px] text-accent">
                open in footprint topology →
              </div>
            </div>
          );
        })()}

      <div className="mt-6 space-y-6">
        {sorted.map((c) => (
          <CampaignCard key={c.key} campaign={c} />
        ))}
      </div>
    </div>
  );
}
