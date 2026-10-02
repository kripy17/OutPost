import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { Chip, PageHeader } from "../components/ui";
import NetworkContextModal from "../components/NetworkContextModal";
import {
  exportFootprint,
  getFootprint,
  getFootprintTopology,
  getSamples,
  getTargetFootprint,
  refreshEnrichmentIp,
  saveBlob,
  watchlistAdd,
} from "../lib/api";
import { intelAgeLabel } from "../lib/constants";
import type { Footprint, FootprintSeedIp } from "../types";
import { buildTopology, MAP, regTimeline, whoisTimeline } from "./footprintHelpers";

const SUGGESTED_INDICATORS = [
  { label: "198.51.100.44", type: "IP · Staging C2" },
  { label: "c2-tracker.org", type: "FQDN · Beacon Host" },
  { label: "203.0.113.204", type: "IP · Exfil Gateway" },
  { label: "api.update-telemetry.com", type: "FQDN · Fake CDN" },
  { label: "93.184.216.34", type: "IP · Anycast Edge" },
];

export interface SelectedIndicatorState {
  value: string;
  type: "ip" | "domain" | "cidr" | "asn" | "cert" | "email";
  reputation?: string;
  abuseScore?: number | null;
  asn?: string | null;
  org?: string | null;
  relations?: string[];
}

function IndicatorDrawer({
  indicator,
  onClose,
  onPivotTarget,
  onInspectDossier,
  onAddToWatchlist,
  onCopy,
}: {
  indicator: SelectedIndicatorState;
  onClose: () => void;
  onPivotTarget: (val: string) => void;
  onInspectDossier: (ip: string) => void;
  onAddToWatchlist: (val: string) => void;
  onCopy: (val: string) => void;
}) {
  const isIp = indicator.type === "ip" || /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(indicator.value);

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs animate-fade-in"
      onClick={onClose}
    >
      <div
        className="w-full max-w-md bg-bg-surface border-l border-border-subtle shadow-2xl h-full flex flex-col font-mono text-xs animate-slide-left"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="p-4 border-b border-border-subtle bg-bg-elevated/40 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="rounded bg-accent/15 border border-accent/40 px-1.5 py-0.5 text-[10px] uppercase font-bold text-accent">
              {indicator.type}
            </span>
            <span className="font-bold text-text-primary text-sm truncate max-w-[240px]" title={indicator.value}>
              {indicator.value}
            </span>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 text-text-muted hover:bg-bg-base hover:text-text-primary"
            title="Close Drawer"
          >
            <Icon name="x" size={14} />
          </button>
        </div>

        {/* Action Bar */}
        <div className="p-3 border-b border-border-subtle bg-bg-base/60 flex flex-wrap items-center gap-1.5">
          <button
            onClick={() => onPivotTarget(indicator.value)}
            className="press inline-flex items-center gap-1 rounded border border-accent/60 bg-accent/15 px-2.5 py-1 text-[11px] font-semibold text-accent hover:bg-accent/25"
            title="Set this indicator as the primary reconnaissance target"
          >
            <Icon name="zap" size={11} />
            <span>Pivot as Recon Target</span>
          </button>

          {isIp && (
            <button
              onClick={() => onInspectDossier(indicator.value)}
              className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2.5 py-1 text-[11px] text-text-muted hover:border-accent/40 hover:text-text-primary"
              title="Inspect full network intelligence dossier"
            >
              <Icon name="activity" size={11} />
              <span>Network Dossier</span>
            </button>
          )}

          <button
            onClick={() => onAddToWatchlist(indicator.value)}
            className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2.5 py-1 text-[11px] text-text-muted hover:border-accent/40 hover:text-text-primary"
            title="Add indicator to Threat Watchlist"
          >
            <Icon name="shield" size={11} />
            <span>+ Watchlist</span>
          </button>

          <Link
            to={`/events?q=${encodeURIComponent(indicator.value)}`}
            className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2.5 py-1 text-[11px] text-text-muted hover:border-accent/40 hover:text-text-primary"
            title="Search ingested EDR events for this indicator"
          >
            <Icon name="search" size={11} />
            <span>Events</span>
          </Link>

          <button
            onClick={() => onCopy(indicator.value)}
            className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2 py-1 text-[11px] text-text-muted hover:text-text-primary"
            title="Copy indicator value"
          >
            <Icon name="copy" size={11} />
            <span>Copy</span>
          </button>
        </div>

        {/* Drawer Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Metadata Grid */}
          <div className="rounded-lg border border-border-subtle bg-bg-elevated/30 p-3 space-y-2">
            <span className="text-[10px] uppercase font-bold text-text-faint tracking-wider">Indicator Profile</span>
            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div>
                <span className="text-text-faint">Reputation:</span>
                <p className="font-semibold mt-0.5">
                  <Chip
                    tone={
                      indicator.reputation === "malicious"
                        ? "malicious"
                        : indicator.reputation === "suspicious"
                          ? "suspicious"
                          : indicator.reputation === "clean"
                            ? "clean"
                            : "muted"
                    }
                    dot
                  >
                    {indicator.reputation || "unknown"}
                  </Chip>
                </p>
              </div>
              <div>
                <span className="text-text-faint">Abuse Confidence:</span>
                <p className="font-semibold text-text-primary mt-0.5">
                  {indicator.abuseScore !== undefined && indicator.abuseScore !== null ? `${indicator.abuseScore}%` : "—"}
                </p>
              </div>
              <div>
                <span className="text-text-faint">Autonomous System:</span>
                <p className="truncate text-text-muted mt-0.5" title={indicator.asn || "Unmapped"}>
                  {indicator.asn || "—"}
                </p>
              </div>
              <div>
                <span className="text-text-faint">Organization / ISP:</span>
                <p className="truncate text-text-muted mt-0.5" title={indicator.org || "Unmapped"}>
                  {indicator.org || "—"}
                </p>
              </div>
            </div>
          </div>

          {/* Relations / Linked Evidence */}
          {indicator.relations && indicator.relations.length > 0 && (
            <div className="space-y-1.5">
              <span className="text-[10px] uppercase font-bold text-text-faint tracking-wider">
                Direct Telemetry &amp; Evidence ({indicator.relations.length})
              </span>
              <div className="rounded-lg border border-border-subtle bg-bg-base/60 divide-y divide-border-subtle/40 overflow-hidden">
                {indicator.relations.map((rel, idx) => (
                  <div key={idx} className="p-2 flex items-center justify-between hover:bg-bg-elevated/30">
                    <span className="truncate text-text-primary" title={rel}>
                      {rel}
                    </span>
                    <button
                      onClick={() => onPivotTarget(rel)}
                      className="press rounded px-1.5 py-0.5 text-[10px] text-accent hover:underline shrink-0"
                    >
                      Pivot →
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Pivot Directives */}
          <div className="rounded-lg border border-border-subtle/70 bg-bg-base p-3 text-[11px] text-text-muted space-y-1.5">
            <span className="text-[10px] uppercase font-bold text-text-faint">Triage Directives</span>
            <ul className="space-y-1 text-text-faint">
              <li>• Ingested socket connections will correlate with this host across all fleet EDR sensors.</li>
              <li>• Passive expansion queries query crt.sh CT logs and RDAP registries without contacting the target.</li>
              <li>• Adding to Threat Watchlist triggers high-priority alerts on future outbound socket dials.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

function FootprintMap({
  footprint,
  onSelectIndicator,
}: {
  footprint: Footprint;
  onSelectIndicator: (indicator: SelectedIndicatorState) => void;
}) {
  const { W, H, ring1, ring2, ring3 } = MAP;
  const cx = W / 2;
  const cy = H / 2;
  const { seedPos, seedByIp, midPos, sibByIp, dnsPos } = buildTopology(footprint);

  const repFill: Record<string, string> = {
    malicious: "var(--risk-malicious)",
    suspicious: "var(--risk-suspicious)",
    clean: "var(--risk-clean)",
    unknown: "var(--text-faint)",
  };

  return (
    <div className="relative overflow-x-auto rounded-xl border border-border-subtle bg-bg-base/70 p-4">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="mx-auto h-auto w-full max-w-[680px]"
        role="img"
        aria-label="Digital footprint map — sample at center, seeds ring 1, passive infrastructure ring 2, cohosted passive DNS ring 3"
      >
        {/* Ring guides */}
        {[60, ring1, ring2, ring3].map((r) => (
          <circle key={r} cx={cx} cy={cy} r={r} fill="none" stroke="var(--border-subtle)" strokeDasharray="3 4" opacity="0.6" />
        ))}

        {/* Ring-3 connection lines */}
        {dnsPos.map((n) => {
          const owner = n.sourceKind === "seed" ? seedByIp.get(n.sourceIp ?? "") : sibByIp.get(n.sourceIp ?? "");
          if (!owner) return null;
          const tint = n.sourceKind === "seed" ? "var(--accent)" : "var(--risk-clean)";
          return <line key={`de-${n.key}`} x1={owner.x} y1={owner.y} x2={n.x} y2={n.y} stroke={tint} strokeWidth="1.2" opacity="0.7" />;
        })}

        {/* Ring-2 connection lines */}
        {midPos.map((n) => {
          const owner = seedPos[0];
          return owner ? (
            <line key={`me-${n.key}`} x1={owner.x} y1={owner.y} x2={n.x} y2={n.y} stroke="var(--border-subtle)" strokeWidth="1" strokeDasharray="2 3" opacity="0.7" />
          ) : null;
        })}

        {/* Center to seed IP lines */}
        {seedPos.map((s) => (
          <line key={`se-${s.ip}`} x1={cx} y1={cy} x2={s.x} y2={s.y} stroke="var(--border-strong)" strokeWidth="1.2" opacity="0.75" />
        ))}

        {/* Cohosted passive-DNS nodes (Ring 3) */}
        {dnsPos.map((n) => (
          <g
            key={`n-${n.key}`}
            className="cursor-pointer transition-transform duration-150 hover:scale-125"
            onClick={() =>
              onSelectIndicator({
                value: n.label,
                type: "domain",
                relations: n.sourceIp ? [`Observed resolving on host ${n.sourceIp}`] : [],
              })
            }
          >
            <circle
              cx={n.x}
              cy={n.y}
              r="7"
              fill="var(--bg-surface)"
              stroke={n.sourceKind === "seed" ? "var(--accent)" : n.sourceKind === "sib" ? "var(--risk-clean)" : "var(--text-faint)"}
              strokeWidth="1.5"
            />
            <title>{`Cohosted Domain: ${n.label} (Click for context & pivot)`}</title>
          </g>
        ))}

        {/* Ring-2 PTR resolutions and sibling IPs */}
        {midPos.map((n) => (
          <g
            key={`m-${n.key}`}
            className="cursor-pointer transition-transform duration-150 hover:scale-125"
            onClick={() =>
              onSelectIndicator({
                value: n.label,
                type: n.kind === "res" ? "domain" : "ip",
                relations: n.ip ? [`Sibling host in adjacent subnet`] : [`PTR reverse DNS resolution`],
              })
            }
          >
            <circle
              cx={n.x}
              cy={n.y}
              r="8"
              fill="var(--bg-surface)"
              stroke={n.kind === "res" ? "var(--accent)" : "var(--text-faint)"}
              strokeWidth="1.5"
            />
            <title>{`${n.kind === "res" ? "PTR Record" : "Sibling IP"}: ${n.label}`}</title>
          </g>
        ))}

        {/* Ring-1 Seed IPs */}
        {seedPos.map((s) => (
          <g
            key={`s-${s.ip}`}
            className="cursor-pointer transition-transform duration-150 hover:scale-125"
            onClick={() =>
              onSelectIndicator({
                value: s.ip,
                type: "ip",
                reputation: s.reputation,
                abuseScore: s.abuse_score,
                relations: [`Hits: ${s.hits}`, `Observed across ${s.run_count} execution run(s)`],
              })
            }
          >
            <circle cx={s.x} cy={s.y} r="14" fill={repFill[s.reputation] ?? "var(--text-faint)"} opacity="0.9" />
            <circle cx={s.x} cy={s.y} r="6" fill="var(--bg-base)" />
            <title>{`Seed IP: ${s.ip} — ${s.reputation} (${s.hits} hits) · Click to inspect`}</title>
          </g>
        ))}

        {/* Center Target Node */}
        <circle cx={cx} cy={cy} r="30" fill="var(--bg-elevated)" stroke="var(--accent)" strokeWidth="1.8" />
        <text x={cx} y={cy + 4} textAnchor="middle" fontSize="10" fontFamily="var(--font-mono)" fill="var(--text-primary)" fontWeight="bold">
          {footprint.sample.name.length > 13 ? `${footprint.sample.name.slice(0, 12)}…` : footprint.sample.name}
        </text>
      </svg>

      <div className="mt-3 flex flex-wrap items-center justify-center gap-4 font-mono text-[10px] text-text-faint border-t border-border-subtle/50 pt-2.5">
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-accent" /> Target Core</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-risk-malicious" /> Malicious Seed</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-risk-suspicious" /> Suspicious Seed</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-risk-clean" /> Clean Seed</span>
        <span className="flex items-center gap-1.5"><span className="h-3 w-3 rounded-full border border-accent bg-bg-surface" /> Passive PTR / Domain</span>
        <span className="flex items-center gap-1.5"><span className="h-3 w-3 rounded-full border border-risk-clean bg-bg-surface" /> Cohosted Sibling</span>
      </div>
    </div>
  );
}

function SeedIpTable({
  seeds,
  queryKey,
  onSelectIndicator,
}: {
  seeds: FootprintSeedIp[];
  queryKey: unknown[];
  onSelectIndicator: (indicator: SelectedIndicatorState) => void;
}) {
  const queryClient = useQueryClient();
  const [refreshing, setRefreshing] = useState<string | null>(null);

  const refresh = async (ip: string) => {
    setRefreshing(ip);
    try {
      await refreshEnrichmentIp(ip);
    } finally {
      setRefreshing(null);
      void queryClient.invalidateQueries({ queryKey });
    }
  };

  if (seeds.length === 0) {
    return (
      <p className="py-6 text-center text-xs text-text-muted">
        No network infrastructure observed for this target yet.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-surface overflow-hidden">
      <table className="w-full text-left font-mono text-xs">
        <thead className="bg-bg-elevated/70 border-b border-border-subtle text-[10px] uppercase text-text-faint">
          <tr>
            <th className="px-4 py-2.5">Observed IP Host</th>
            <th className="px-4 py-2.5">Reputation</th>
            <th className="px-4 py-2.5">Abuse Confidence</th>
            <th className="px-4 py-2.5">Cache Age</th>
            <th className="px-4 py-2.5">Socket Hits</th>
            <th className="px-4 py-2.5">Runs</th>
            <th className="px-4 py-2.5">First / Last Seen</th>
            <th className="px-4 py-2.5 text-right">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border-subtle/50">
          {seeds.map((s) => (
            <tr
              key={s.ip}
              onClick={() =>
                onSelectIndicator({
                  value: s.ip,
                  type: "ip",
                  reputation: s.reputation,
                  abuseScore: s.abuse_score,
                  relations: [`Hits: ${s.hits}`, `Across ${s.run_count} runs`],
                })
              }
              className="cursor-pointer hover:bg-bg-elevated/40 transition group"
            >
              <td className="px-4 py-2.5 font-bold text-text-primary group-hover:text-accent transition">
                {s.ip}
              </td>
              <td className="px-4 py-2.5">
                <Chip
                  tone={
                    s.reputation === "malicious"
                      ? "malicious"
                      : s.reputation === "suspicious"
                        ? "suspicious"
                        : s.reputation === "clean"
                          ? "clean"
                          : "muted"
                  }
                  dot
                >
                  {s.reputation}
                </Chip>
              </td>
              <td className="px-4 py-2.5 text-text-muted">
                {s.abuse_score !== null && s.abuse_score !== undefined ? `${s.abuse_score}%` : "—"}
              </td>
              <td className="px-4 py-2.5 text-text-faint text-[11px]">
                {s.checked_at ? intelAgeLabel(s.checked_at) : "no cache"}
              </td>
              <td className="px-4 py-2.5 tabular-nums text-text-primary">{s.hits}</td>
              <td className="px-4 py-2.5 tabular-nums text-text-faint">{s.run_count}</td>
              <td className="px-4 py-2.5 text-text-faint text-[11px]">
                {s.first_seen && s.last_seen ? `${s.first_seen.slice(0, 10)} → ${s.last_seen.slice(0, 10)}` : "—"}
              </td>
              <td className="px-4 py-2.5 text-right" onClick={(e) => e.stopPropagation()}>
                <div className="flex items-center justify-end gap-1.5">
                  <button
                    onClick={() =>
                      onSelectIndicator({
                        value: s.ip,
                        type: "ip",
                        reputation: s.reputation,
                        abuseScore: s.abuse_score,
                      })
                    }
                    className="press rounded border border-accent/50 bg-accent/10 px-2 py-0.5 text-[11px] font-semibold text-accent hover:bg-accent/20"
                  >
                    Inspect
                  </button>
                  <button
                    onClick={() => void refresh(s.ip)}
                    disabled={refreshing === s.ip}
                    className="press rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-[11px] text-text-muted hover:border-accent/40 hover:text-text-primary disabled:opacity-50"
                  >
                    {refreshing === s.ip ? "…" : "Refresh"}
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EvidenceMatrix({
  footprint,
  onSelectIndicator,
}: {
  footprint: Footprint;
  onSelectIndicator: (indicator: SelectedIndicatorState) => void;
}) {
  const [activeTab, setActiveTab] = useState<
    "resolutions" | "crt" | "subdomains" | "certs" | "siblings" | "whois" | "breaches"
  >("resolutions");

  const p = footprint.passive;

  const tabCounts = {
    resolutions: p.resolutions.length,
    crt: p.passive_dns.length,
    subdomains: (p.subdomains ?? []).length,
    certs: p.certificates.length,
    siblings: p.sibling_ips.length + p.networks.length + p.asn.length,
    whois: (p.whois ?? []).length,
    breaches: footprint.breach.rows.length,
  };

  return (
    <div className="rounded-xl border border-border-subtle bg-bg-surface overflow-hidden shadow-xs font-mono">
      {/* Evidence Tab Bar */}
      <div className="flex items-center gap-1 overflow-x-auto border-b border-border-subtle bg-bg-elevated/40 p-2 text-xs">
        <button
          onClick={() => setActiveTab("resolutions")}
          className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-medium transition ${
            activeTab === "resolutions"
              ? "bg-accent/15 font-bold text-accent shadow-xs"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <span>DNS PTR</span>
          <span className="rounded bg-bg-base px-1.5 py-0.2 text-[10px] text-text-faint">{tabCounts.resolutions}</span>
        </button>

        <button
          onClick={() => setActiveTab("crt")}
          className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-medium transition ${
            activeTab === "crt"
              ? "bg-accent/15 font-bold text-accent shadow-xs"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <span>CT Logs (crt.sh)</span>
          <span className="rounded bg-bg-base px-1.5 py-0.2 text-[10px] text-text-faint">{tabCounts.crt}</span>
        </button>

        <button
          onClick={() => setActiveTab("subdomains")}
          className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-medium transition ${
            activeTab === "subdomains"
              ? "bg-accent/15 font-bold text-accent shadow-xs"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <span>Subdomains</span>
          <span className="rounded bg-bg-base px-1.5 py-0.2 text-[10px] text-text-faint">{tabCounts.subdomains}</span>
        </button>

        <button
          onClick={() => setActiveTab("certs")}
          className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-medium transition ${
            activeTab === "certs"
              ? "bg-accent/15 font-bold text-accent shadow-xs"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <span>TLS Certificates</span>
          <span className="rounded bg-bg-base px-1.5 py-0.2 text-[10px] text-text-faint">{tabCounts.certs}</span>
        </button>

        <button
          onClick={() => setActiveTab("siblings")}
          className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-medium transition ${
            activeTab === "siblings"
              ? "bg-accent/15 font-bold text-accent shadow-xs"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <span>Siblings &amp; RDAP</span>
          <span className="rounded bg-bg-base px-1.5 py-0.2 text-[10px] text-text-faint">{tabCounts.siblings}</span>
        </button>

        <button
          onClick={() => setActiveTab("whois")}
          className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-medium transition ${
            activeTab === "whois"
              ? "bg-accent/15 font-bold text-accent shadow-xs"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <span>WHOIS Registrations</span>
          <span className="rounded bg-bg-base px-1.5 py-0.2 text-[10px] text-text-faint">{tabCounts.whois}</span>
        </button>

        <button
          onClick={() => setActiveTab("breaches")}
          className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 font-medium transition ${
            activeTab === "breaches"
              ? "bg-accent/15 font-bold text-accent shadow-xs"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <span>Breach Exposure</span>
          <span className="rounded bg-bg-base px-1.5 py-0.2 text-[10px] text-text-faint">{tabCounts.breaches}</span>
        </button>
      </div>

      {/* Tab Panels */}
      <div className="p-0">
        {activeTab === "resolutions" && (
          <table className="w-full text-left text-xs">
            <thead className="bg-bg-elevated/40 border-b border-border-subtle text-[10px] uppercase text-text-faint">
              <tr>
                <th className="px-4 py-2.5">Domain / PTR Record</th>
                <th className="px-4 py-2.5">First Observed</th>
                <th className="px-4 py-2.5">Last Observed</th>
                <th className="px-4 py-2.5">Source Engine</th>
                <th className="px-4 py-2.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/50">
              {p.resolutions.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-text-muted">
                    No reverse-DNS PTR records discovered for this infrastructure.
                  </td>
                </tr>
              ) : (
                p.resolutions.map((r, i) => (
                  <tr
                    key={i}
                    onClick={() => onSelectIndicator({ value: r.domain, type: "domain" })}
                    className="cursor-pointer hover:bg-bg-elevated/40 transition group"
                  >
                    <td className="px-4 py-2.5 font-bold text-text-primary group-hover:text-accent transition">
                      {r.domain}
                    </td>
                    <td className="px-4 py-2.5 text-text-faint">{r.first_seen.slice(0, 10)}</td>
                    <td className="px-4 py-2.5 text-text-faint">{r.last_seen.slice(0, 10)}</td>
                    <td className="px-4 py-2.5">
                      <span className="rounded bg-bg-base border border-border-subtle px-1.5 py-0.5 text-[10px] text-text-muted">
                        {r.synthetic ? "Synthetic" : "PTR Live"}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-right" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => onSelectIndicator({ value: r.domain, type: "domain" })}
                        className="press rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-[11px] text-text-muted hover:border-accent/40 hover:text-accent"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}

        {activeTab === "crt" && (
          <table className="w-full text-left text-xs">
            <thead className="bg-bg-elevated/40 border-b border-border-subtle text-[10px] uppercase text-text-faint">
              <tr>
                <th className="px-4 py-2.5">CT Log Hostname</th>
                <th className="px-4 py-2.5">Observed Source IP</th>
                <th className="px-4 py-2.5">Observation Window</th>
                <th className="px-4 py-2.5">Telemetry Origin</th>
                <th className="px-4 py-2.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/50">
              {p.passive_dns.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-text-muted">
                    No Certificate Transparency hostnames indexed for the seed infrastructure.
                  </td>
                </tr>
              ) : (
                p.passive_dns.map((d, i) => (
                  <tr
                    key={i}
                    onClick={() =>
                      onSelectIndicator({
                        value: d.domain,
                        type: "domain",
                        relations: d.source_ip ? [`Source IP: ${d.source_ip}`] : [],
                      })
                    }
                    className="cursor-pointer hover:bg-bg-elevated/40 transition group"
                  >
                    <td className="px-4 py-2.5 font-bold text-text-primary group-hover:text-accent transition">
                      {d.domain}
                    </td>
                    <td className="px-4 py-2.5 text-text-muted">{d.source_ip || "—"}</td>
                    <td className="px-4 py-2.5 text-text-faint text-[11px]">
                      {d.first_seen.slice(0, 10)} → {d.last_seen.slice(0, 10)}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="rounded bg-bg-base border border-border-subtle px-1.5 py-0.5 text-[10px] text-text-muted">
                        {d.synthetic ? "Synthetic" : "crt.sh Live"}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-right" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => onSelectIndicator({ value: d.domain, type: "domain" })}
                        className="press rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-[11px] text-text-muted hover:border-accent/40 hover:text-accent"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}

        {activeTab === "subdomains" && (
          <table className="w-full text-left text-xs">
            <thead className="bg-bg-elevated/40 border-b border-border-subtle text-[10px] uppercase text-text-faint">
              <tr>
                <th className="px-4 py-2.5">Subdomain FQDN</th>
                <th className="px-4 py-2.5">Resolving Source</th>
                <th className="px-4 py-2.5">Observation Window</th>
                <th className="px-4 py-2.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/50">
              {(p.subdomains ?? []).length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-text-muted">
                    No subdomains discovered under the apex domain.
                  </td>
                </tr>
              ) : (
                (p.subdomains ?? []).map((s, i) => (
                  <tr
                    key={i}
                    onClick={() => onSelectIndicator({ value: s.domain, type: "domain" })}
                    className="cursor-pointer hover:bg-bg-elevated/40 transition group"
                  >
                    <td className="px-4 py-2.5 font-bold text-text-primary group-hover:text-accent transition">
                      {s.domain}
                    </td>
                    <td className="px-4 py-2.5 text-text-muted">{s.source_ip || "—"}</td>
                    <td className="px-4 py-2.5 text-text-faint text-[11px]">
                      {s.first_seen.slice(0, 10)} → {s.last_seen.slice(0, 10)}
                    </td>
                    <td className="px-4 py-2.5 text-right" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => onSelectIndicator({ value: s.domain, type: "domain" })}
                        className="press rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-[11px] text-text-muted hover:border-accent/40 hover:text-accent"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}

        {activeTab === "certs" && (
          <table className="w-full text-left text-xs">
            <thead className="bg-bg-elevated/40 border-b border-border-subtle text-[10px] uppercase text-text-faint">
              <tr>
                <th className="px-4 py-2.5">Certificate Common Name (CN)</th>
                <th className="px-4 py-2.5">Issuing Authority (CA)</th>
                <th className="px-4 py-2.5">Mode</th>
                <th className="px-4 py-2.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/50">
              {p.certificates.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-text-muted">
                    No TLS certificates indexed for this infrastructure.
                  </td>
                </tr>
              ) : (
                p.certificates.map((c, i) => (
                  <tr
                    key={i}
                    onClick={() => onSelectIndicator({ value: c.cn, type: "cert", relations: [`Issuer: ${c.issuer}`] })}
                    className="cursor-pointer hover:bg-bg-elevated/40 transition group"
                  >
                    <td className="px-4 py-2.5 font-bold text-text-primary group-hover:text-accent transition">
                      {c.cn}
                    </td>
                    <td className="px-4 py-2.5 text-text-muted">{c.issuer}</td>
                    <td className="px-4 py-2.5">
                      <span className="rounded bg-bg-base border border-border-subtle px-1.5 py-0.5 text-[10px] text-text-muted">
                        {c.synthetic ? "Synthetic" : "X.509 Live"}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-right" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => onSelectIndicator({ value: c.cn, type: "cert" })}
                        className="press rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-[11px] text-text-muted hover:border-accent/40 hover:text-accent"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}

        {activeTab === "siblings" && (
          <div className="space-y-4 p-4">
            <div>
              <span className="text-[10px] uppercase font-bold text-text-faint tracking-wider">
                Sibling Hosts in Observed Subnets ({p.sibling_ips.length})
              </span>
              <div className="mt-2 grid grid-cols-1 gap-2 md:grid-cols-2">
                {p.sibling_ips.map((s, i) => (
                  <div
                    key={i}
                    onClick={() =>
                      onSelectIndicator({
                        value: s.ip,
                        type: "ip",
                        relations: [`Subnet relationship: ${s.relation}`],
                      })
                    }
                    className="cursor-pointer flex items-center justify-between rounded-lg border border-border-subtle bg-bg-base p-2.5 hover:border-accent/40 transition"
                  >
                    <div>
                      <span className="font-bold text-text-primary">{s.ip}</span>
                      <p className="text-[10px] text-text-faint">{s.relation}</p>
                    </div>
                    <button className="press rounded border border-border-subtle bg-bg-surface px-2 py-0.5 text-[10px] text-text-muted hover:text-accent">
                      Inspect
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div className="border-t border-border-subtle/50 pt-3">
              <span className="text-[10px] uppercase font-bold text-text-faint tracking-wider">
                RDAP Subnets &amp; Autonomous Systems ({p.networks.length + p.asn.length})
              </span>
              <div className="mt-2 space-y-2">
                {p.networks.map((n, i) => (
                  <div key={i} className="rounded-lg border border-border-subtle bg-bg-base p-2.5 flex items-center justify-between">
                    <div>
                      <span className="font-bold text-accent">{n.cidr}</span>
                      <span className="ml-2 text-text-muted">
                        {[n.netname, n.org, n.country].filter(Boolean).join(" · ") || n.ip}
                      </span>
                      {regTimeline(n).length > 0 && (
                        <p className="text-[10px] text-text-faint mt-0.5">{regTimeline(n).join(" · ")}</p>
                      )}
                    </div>
                    <button
                      onClick={() => onSelectIndicator({ value: n.cidr, type: "cidr", org: n.org, asn: n.netname })}
                      className="press rounded border border-border-subtle bg-bg-surface px-2 py-0.5 text-[10px] text-text-muted hover:text-accent"
                    >
                      Inspect
                    </button>
                  </div>
                ))}
                {p.asn.map((a, i) => (
                  <div key={i} className="rounded-lg border border-border-subtle bg-bg-base p-2.5 flex items-center justify-between">
                    <div>
                      <span className="font-bold text-text-primary">{a.asn || a.ip}</span>
                      <span className="ml-2 text-text-muted">
                        {[a.as_name, a.org, a.country].filter(Boolean).join(" · ")}
                      </span>
                    </div>
                    <button
                      onClick={() => onSelectIndicator({ value: a.asn || a.ip, type: "asn", org: a.org })}
                      className="press rounded border border-border-subtle bg-bg-surface px-2 py-0.5 text-[10px] text-text-muted hover:text-accent"
                    >
                      Inspect
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === "whois" && (
          <table className="w-full text-left text-xs">
            <thead className="bg-bg-elevated/40 border-b border-border-subtle text-[10px] uppercase text-text-faint">
              <tr>
                <th className="px-4 py-2.5">Domain</th>
                <th className="px-4 py-2.5">Registrar &amp; Status</th>
                <th className="px-4 py-2.5">Registration Timeline</th>
                <th className="px-4 py-2.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/50">
              {(p.whois ?? []).length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-text-muted">
                    No WHOIS records returned for discovered domain infrastructure.
                  </td>
                </tr>
              ) : (
                (p.whois ?? []).map((w, i) => (
                  <tr
                    key={i}
                    onClick={() => onSelectIndicator({ value: w.domain, type: "domain", relations: whoisTimeline(w) })}
                    className="cursor-pointer hover:bg-bg-elevated/40 transition group"
                  >
                    <td className="px-4 py-2.5 font-bold text-text-primary group-hover:text-accent transition">
                      {w.domain}
                    </td>
                    <td className="px-4 py-2.5 text-text-muted">
                      {w.registrar || "—"} {w.status?.length ? `(${w.status.slice(0, 2).join(", ")})` : ""}
                    </td>
                    <td className="px-4 py-2.5 text-text-faint text-[11px]">
                      {whoisTimeline(w).join(" · ") || "—"}
                    </td>
                    <td className="px-4 py-2.5 text-right" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => onSelectIndicator({ value: w.domain, type: "domain" })}
                        className="press rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-[11px] text-text-muted hover:border-accent/40 hover:text-accent"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}

        {activeTab === "breaches" && (
          <table className="w-full text-left text-xs">
            <thead className="bg-bg-elevated/40 border-b border-border-subtle text-[10px] uppercase text-text-faint">
              <tr>
                <th className="px-4 py-2.5">Embedded Email Identity</th>
                <th className="px-4 py-2.5">Breaches Count</th>
                <th className="px-4 py-2.5">Compromised Sources</th>
                <th className="px-4 py-2.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/50">
              {footprint.breach.rows.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-text-muted">
                    No compromised emails detected in target configuration or strings.
                  </td>
                </tr>
              ) : (
                footprint.breach.rows.map((b, i) => (
                  <tr
                    key={i}
                    onClick={() => onSelectIndicator({ value: b.email, type: "email", relations: b.breaches })}
                    className="cursor-pointer hover:bg-bg-elevated/40 transition group"
                  >
                    <td className="px-4 py-2.5 font-bold text-text-primary group-hover:text-accent transition">
                      {b.email}
                    </td>
                    <td className="px-4 py-2.5 text-risk-malicious font-bold">
                      {b.breaches.length} incident{b.breaches.length === 1 ? "" : "s"}
                    </td>
                    <td className="px-4 py-2.5 text-text-faint text-[11px]">
                      {b.breaches.slice(0, 4).join(", ")}
                    </td>
                    <td className="px-4 py-2.5 text-right" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => onSelectIndicator({ value: b.email, type: "email" })}
                        className="press rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-[11px] text-text-muted hover:border-accent/40 hover:text-accent"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export default function FootprintPage() {
  const [params] = useSearchParams();
  const linked = params.get("sample");
  const targetParam = params.get("target");
  const appliedLink = useRef(false);

  const [mode, setMode] = useState<"sample" | "indicator">("sample");
  const [viewMode, setViewMode] = useState<"graph" | "matrix">("graph");
  const [sampleId, setSampleId] = useState<string>("");
  const [indicatorInput, setIndicatorInput] = useState<string>("198.51.100.44");
  const [activeIndicator, setActiveIndicator] = useState<string>("198.51.100.44");
  const [mock, setMock] = useState(false);
  const [inspectIpModal, setInspectIpModal] = useState<string | null>(null);
  const [selectedDrawerIndicator, setSelectedDrawerIndicator] = useState<SelectedIndicatorState | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const { data: vault } = useQuery({ queryKey: ["samples", "all"], queryFn: () => getSamples({ limit: 100 }) });

  useEffect(() => {
    if (targetParam && !appliedLink.current) {
      appliedLink.current = true;
      setMode("indicator");
      setIndicatorInput(targetParam);
      setActiveIndicator(targetParam);
    } else if (linked && !appliedLink.current) {
      appliedLink.current = true;
      setMode("sample");
      setSampleId(linked);
    } else if (!linked && !targetParam && vault?.samples.length && !sampleId) {
      setSampleId(vault.samples[0].sample_id);
    }
  }, [linked, targetParam, vault, sampleId]);

  const { data: footprint, isLoading, isError } = useQuery({
    queryKey: mode === "sample" ? ["footprint", sampleId, mock] : ["footprint-target", activeIndicator, mock],
    queryFn: () =>
      mode === "sample"
        ? getFootprint(sampleId, mock)
        : getTargetFootprint(activeIndicator, mock),
    enabled: mode === "sample" ? sampleId !== "" : activeIndicator.trim() !== "",
  });

  const { data: topology } = useQuery({
    queryKey: ["footprint", "topology"],
    queryFn: getFootprintTopology,
  });

  const handleIndicatorSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!indicatorInput.trim()) return;
    setActiveIndicator(indicatorInput.trim());
  };

  const handlePivotTarget = (target: string) => {
    setSelectedDrawerIndicator(null);
    setMode("indicator");
    setIndicatorInput(target);
    setActiveIndicator(target);
    setActionNotice(`Target pivoted to ${target}`);
    setTimeout(() => setActionNotice(null), 2500);
  };

  const handleCopy = (text: string) => {
    void navigator.clipboard.writeText(text);
    setActionNotice(`Copied to clipboard: ${text}`);
    setTimeout(() => setActionNotice(null), 2500);
  };

  const handleAddToWatchlist = async (val: string) => {
    try {
      await watchlistAdd(val, "Identified via Passive Footprint Mapping");
      setActionNotice(`Added ${val} to Threat Watchlist`);
      setTimeout(() => setActionNotice(null), 3000);
    } catch {
      setActionNotice(`Failed to add ${val} to watchlist`);
      setTimeout(() => setActionNotice(null), 3000);
    }
  };

  const targetIdentifier = mode === "sample" ? sampleId : activeIndicator;

  return (
    <div className="mx-auto max-w-7xl px-6 py-8 lg:px-10 space-y-6">
      {/* Top Header */}
      <PageHeader
        kicker="Intelligence &amp; Reconnaissance"
        title="Passive Attack Surface &amp; Digital Footprint"
        lede="Passive infrastructure expansion outward from detonation seeds or target indicators across DNS, CT logs, and CIDR siblings."
        actions={
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-risk-suspicious/50 bg-risk-suspicious/10 px-2.5 py-1 font-mono text-[10px] uppercase font-bold text-risk-suspicious">
              <Icon name="zap" size={10} />
              Passive Expansion Active
            </span>
            <Link
              to="/samples"
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs text-text-muted hover:border-accent/60 hover:text-accent"
            >
              Sample Vault
              <Icon name="arrowRight" size={12} />
            </Link>
          </div>
        }
      />

      {/* Action Notification Toast */}
      {actionNotice && (
        <div className="flex items-center justify-between rounded-xl border border-signal/50 bg-signal/15 px-4 py-2 font-mono text-xs text-signal animate-fade-in">
          <span>✓ {actionNotice}</span>
          <button onClick={() => setActionNotice(null)} className="text-text-muted hover:text-text-primary">✕</button>
        </div>
      )}

      {/* Metric HUD Strip */}
      {footprint && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 font-mono">
          <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5">
            <span className="text-[10px] uppercase text-text-faint font-bold tracking-wider">Active Target</span>
            <p className="mt-1 text-sm font-bold text-text-primary truncate" title={footprint.sample.name}>
              {footprint.sample.name}
            </p>
            <span className="text-[10px] text-text-faint">{mode === "sample" ? "Binary detonation core" : "Direct indicator"}</span>
          </div>

          <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5">
            <span className="text-[10px] uppercase text-text-faint font-bold tracking-wider">Provenance Engine</span>
            <p className="mt-1 text-sm font-bold text-accent">
              {footprint.passive.source === "live" ? "Live CT/RDAP Expansion" : "Deterministic Synthetic"}
            </p>
            <span className="text-[10px] text-text-faint">
              {footprint.passive.source === "live" ? "Public certificate transparency" : "Offline airgap simulation"}
            </span>
          </div>

          <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5">
            <span className="text-[10px] uppercase text-text-faint font-bold tracking-wider">Seed Infrastructure</span>
            <p className="mt-1 text-sm font-bold text-text-primary">
              {footprint.seed_ips.length} Host{footprint.seed_ips.length === 1 ? "" : "s"}
            </p>
            <span className="text-[10px] text-text-faint">
              Across {footprint.runs.length} observed run{footprint.runs.length === 1 ? "" : "s"}
            </span>
          </div>

          <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5">
            <span className="text-[10px] uppercase text-text-faint font-bold tracking-wider">Passive Correlated Nodes</span>
            <p className="mt-1 text-sm font-bold text-risk-clean">
              {footprint.passive.resolutions.length +
                footprint.passive.passive_dns.length +
                (footprint.passive.subdomains?.length || 0) +
                footprint.passive.certificates.length +
                footprint.passive.sibling_ips.length}{" "}
              Nodes
            </p>
            <span className="text-[10px] text-text-faint">DNS PTR, CT logs, RDAP</span>
          </div>
        </div>
      )}

      {/* Recon Command Bar */}
      <div className="rounded-xl border border-border-subtle bg-bg-surface p-4 space-y-3 font-mono text-xs">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Mode Switcher */}
          <div className="flex rounded-lg border border-border-subtle bg-bg-base p-1">
            <button
              onClick={() => setMode("sample")}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 transition ${
                mode === "sample"
                  ? "bg-accent/15 font-bold text-accent"
                  : "text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="box" size={12} />
              <span>Sample Vault Binary</span>
            </button>
            <button
              onClick={() => setMode("indicator")}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 transition ${
                mode === "indicator"
                  ? "bg-accent/15 font-bold text-accent"
                  : "text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="search" size={12} />
              <span>Target Indicator (IP / FQDN)</span>
            </button>
          </div>

          {/* View Mode Switcher */}
          <div className="flex rounded-lg border border-border-subtle bg-bg-base p-1">
            <button
              onClick={() => setViewMode("graph")}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 transition ${
                viewMode === "graph"
                  ? "bg-accent/15 font-bold text-accent"
                  : "text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="activity" size={12} />
              <span>Topology Graph</span>
            </button>
            <button
              onClick={() => setViewMode("matrix")}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 transition ${
                viewMode === "matrix"
                  ? "bg-accent/15 font-bold text-accent"
                  : "text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="grid" size={12} />
              <span>Evidence Matrix</span>
            </button>
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-2 ml-auto">
            <button
              onClick={() => setMock((v) => !v)}
              aria-pressed={mock}
              className={`press inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs transition ${
                mock
                  ? "border-accent/60 bg-accent/15 text-accent font-bold"
                  : "border-border-subtle bg-bg-base text-text-muted hover:text-text-primary"
              }`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${mock ? "bg-accent" : "bg-text-faint"}`} />
              <span>{mock ? "Synthetic Preview On" : "Synthetic Simulation"}</span>
            </button>

            <button
              onClick={() => {
                void exportFootprint(targetIdentifier, "json", mock).then((blob) =>
                  saveBlob(blob, `outpost-footprint-${targetIdentifier.slice(0, 12)}.json`)
                );
              }}
              disabled={!targetIdentifier}
              className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1.5 text-text-muted hover:border-accent/40 hover:text-accent disabled:opacity-40"
              title="Export structured JSON"
            >
              <Icon name="download" size={11} />
              <span>JSON</span>
            </button>

            <button
              onClick={() => {
                void exportFootprint(targetIdentifier, "csv", mock).then((blob) =>
                  saveBlob(blob, `outpost-footprint-${targetIdentifier.slice(0, 12)}.csv`)
                );
              }}
              disabled={!targetIdentifier}
              className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1.5 text-text-muted hover:border-accent/40 hover:text-accent disabled:opacity-40"
              title="Export CSV IOC sheet"
            >
              <Icon name="download" size={11} />
              <span>CSV</span>
            </button>
          </div>
        </div>

        {/* Input Target Bar */}
        <div className="pt-2 border-t border-border-subtle/50 flex flex-wrap items-center gap-3">
          {mode === "sample" ? (
            <div className="flex items-center gap-2 flex-1 max-w-xl">
              <span className="text-text-faint text-[11px] font-semibold uppercase">Target Binary:</span>
              <select
                value={sampleId}
                onChange={(e) => setSampleId(e.target.value)}
                className="flex-1 rounded-lg border border-border-subtle bg-bg-base px-3 py-1.5 text-text-primary outline-none focus:border-accent"
                aria-label="Choose a sample"
              >
                {(vault?.samples ?? []).map((s) => (
                  <option key={s.sample_id} value={s.sample_id}>
                    {s.original_name} ({s.sample_id.slice(0, 8)})
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <form onSubmit={handleIndicatorSubmit} className="flex flex-wrap items-center gap-2 flex-1 max-w-xl">
              <div className="relative flex-1 min-w-56">
                <Icon name="search" size={13} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-faint" />
                <input
                  type="text"
                  value={indicatorInput}
                  onChange={(e) => setIndicatorInput(e.target.value)}
                  placeholder="Enter IP or FQDN (e.g. 198.51.100.44, c2-tracker.org)..."
                  className="w-full rounded-lg border border-border-subtle bg-bg-base py-1.5 pl-8 pr-3 text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
                />
              </div>
              <button
                type="submit"
                className="press rounded-lg border border-accent/60 bg-accent/15 px-3 py-1.5 font-semibold text-accent hover:bg-accent/25"
              >
                Map Infrastructure
              </button>
            </form>
          )}

          {/* Quick Target Chips */}
          {mode === "indicator" && (
            <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
              <span className="text-text-faint text-[10px] uppercase">Pivots:</span>
              {SUGGESTED_INDICATORS.map((item) => (
                <button
                  key={item.label}
                  onClick={() => {
                    setIndicatorInput(item.label);
                    setActiveIndicator(item.label);
                  }}
                  className={`press inline-flex items-center gap-1 rounded border px-2 py-0.5 transition ${
                    activeIndicator === item.label
                      ? "border-accent/60 bg-accent/15 text-accent font-semibold"
                      : "border-border-subtle bg-bg-base text-text-muted hover:border-accent/40 hover:text-text-primary"
                  }`}
                >
                  <span>{item.label}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {isLoading && <p className="py-12 text-center text-xs font-mono text-text-muted">Mapping infrastructure topology…</p>}
      {isError && (
        <p className="rounded-lg border border-risk-malicious/40 bg-bg-surface p-4 font-mono text-xs text-risk-malicious">
          Could not load footprint data — verify the OutPost backend is running.
        </p>
      )}

      {footprint && (
        <div className="space-y-6">
          {/* Zero Egress Empty State */}
          {footprint.seed_ips.length === 0 && !mock && (
            <div className="rounded-xl border border-border-subtle bg-bg-surface p-6 text-center space-y-3 font-mono">
              <div className="mx-auto flex h-10 w-10 items-center justify-center rounded-lg border border-accent/40 bg-accent/10 text-accent">
                <Icon name="globe" size={18} />
              </div>
              <h3 className="font-bold text-text-primary text-sm">No Network Egress Recorded for this Target</h3>
              <p className="text-xs text-text-muted max-w-lg mx-auto">
                No outbound socket flows observed during detonation. Enable synthetic preview to inspect deterministic infrastructure or pivot to an arbitrary target indicator.
              </p>
              <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
                <button
                  onClick={() => setMock(true)}
                  className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent/10 px-3 py-1.5 text-xs font-semibold text-accent hover:bg-accent/20"
                >
                  <Icon name="zap" size={12} />
                  Enable Synthetic Preview
                </button>
                <button
                  onClick={() => {
                    setMode("indicator");
                    setActiveIndicator("198.51.100.44");
                    setIndicatorInput("198.51.100.44");
                  }}
                  className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-base px-3 py-1.5 text-xs text-text-primary hover:border-accent/60"
                >
                  <Icon name="search" size={12} />
                  Map Target Indicator
                </button>
              </div>
            </div>
          )}

          {/* Seed IP Table */}
          {footprint.seed_ips.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between font-mono">
                <span className="text-xs font-bold text-text-primary">
                  Observed Egress Core ({footprint.seed_ips.length} Seed Host{footprint.seed_ips.length === 1 ? "" : "s"})
                </span>
                <span className="text-[10px] text-text-faint">
                  Captured across {footprint.runs.length} execution run{footprint.runs.length === 1 ? "" : "s"}
                </span>
              </div>
              <SeedIpTable
                seeds={footprint.seed_ips}
                queryKey={mode === "sample" ? ["footprint", sampleId, mock] : ["footprint-target", activeIndicator, mock]}
                onSelectIndicator={setSelectedDrawerIndicator}
              />
            </div>
          )}

          {/* Primary View: Topology Graph or Evidence Matrix */}
          {(footprint.seed_ips.length > 0 || mock) && (
            <div>
              {viewMode === "graph" ? (
                <div className="space-y-2">
                  <div className="flex items-center justify-between font-mono">
                    <span className="text-xs font-bold text-text-primary">
                      Infrastructure Topology Graph — {footprint.sample.name}
                    </span>
                    <span className="text-[10px] text-text-faint">
                      Click any node to open analyst slide-over drawer
                    </span>
                  </div>
                  <FootprintMap
                    footprint={footprint}
                    onSelectIndicator={setSelectedDrawerIndicator}
                  />
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="flex items-center justify-between font-mono">
                    <span className="text-xs font-bold text-text-primary">
                      Correlated Evidence Matrix — {footprint.sample.name}
                    </span>
                    <span className="text-[10px] text-text-faint">
                      DNS PTR, CT logs, Subdomains, TLS, RDAP, WHOIS
                    </span>
                  </div>
                  <EvidenceMatrix
                    footprint={footprint}
                    onSelectIndicator={setSelectedDrawerIndicator}
                  />
                </div>
              )}
            </div>
          )}

          {/* Cross-sample Correlation Strip */}
          {topology && (
            <div className="rounded-xl border border-border-subtle bg-bg-surface p-4 font-mono text-xs space-y-3">
              <div className="flex items-center justify-between border-b border-border-subtle/50 pb-2">
                <div>
                  <span className="text-[10px] uppercase font-bold text-text-faint tracking-wider">Campaign Correlation</span>
                  <h4 className="font-bold text-text-primary text-sm">
                    Cross-Sample Shared Infrastructure ({topology.clusters.length} Cluster{topology.clusters.length === 1 ? "" : "s"})
                  </h4>
                </div>
                <span className="text-[10px] text-text-faint">
                  {topology.total_samples} samples correlated across vault
                </span>
              </div>

              {topology.clusters.length === 0 ? (
                <p className="text-text-muted py-2">
                  No cross-sample IP overlaps discovered yet — requires multiple binaries connecting to identical external hosts.
                </p>
              ) : (
                <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2">
                  {topology.clusters.map((c) => (
                    <div
                      key={c.ip}
                      className="rounded-lg border border-border-subtle bg-bg-base/70 p-3 hover:border-accent/40 transition flex flex-col justify-between"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-text-primary">{c.ip}</span>
                          <Chip tone={c.reputation === "malicious" ? "malicious" : c.reputation === "suspicious" ? "suspicious" : "muted"} dot>
                            {c.reputation}
                          </Chip>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <button
                            onClick={() => setSelectedDrawerIndicator({ value: c.ip, type: "ip", reputation: c.reputation })}
                            className="press rounded border border-border-subtle bg-bg-surface px-2 py-0.5 text-[10px] text-text-muted hover:text-accent"
                          >
                            Inspect
                          </button>
                          <Link
                            to="/campaigns"
                            className="press rounded border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] font-semibold text-accent hover:bg-accent/20"
                          >
                            Campaign
                          </Link>
                        </div>
                      </div>

                      <div className="mt-2.5 flex flex-wrap gap-1">
                        {c.members.map((m) => (
                          <Link
                            key={`${c.ip}-${m.sample_name}`}
                            to={`/footprint?sample=${encodeURIComponent(m.sample_name)}`}
                            className="press inline-flex items-center gap-1 rounded bg-bg-elevated/70 border border-border-subtle px-1.5 py-0.5 text-[10px] text-text-muted hover:border-accent/50 hover:text-text-primary"
                            title={`${m.hits} socket hits`}
                          >
                            <span>{m.sample_name}</span>
                            <span className="text-text-faint font-semibold">· {m.hits}</span>
                          </Link>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Slide-over Indicator Inspector Drawer */}
      {selectedDrawerIndicator && (
        <IndicatorDrawer
          indicator={selectedDrawerIndicator}
          onClose={() => setSelectedDrawerIndicator(null)}
          onPivotTarget={handlePivotTarget}
          onInspectDossier={(ip) => {
            setSelectedDrawerIndicator(null);
            setInspectIpModal(ip);
          }}
          onAddToWatchlist={handleAddToWatchlist}
          onCopy={handleCopy}
        />
      )}

      {/* Modal for full RDAP / Geo / Threat feed context */}
      {inspectIpModal && (
        <NetworkContextModal ip={inspectIpModal} onClose={() => setInspectIpModal(null)} />
      )}
    </div>
  );
}
