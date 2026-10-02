import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { Chip, PageHeader, Panel } from "../components/ui";
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
import { breachNote, buildTopology, MAP, passiveNote, regTimeline, whoisTimeline } from "./footprintHelpers";

const SUGGESTED_INDICATORS = [
  { label: "198.51.100.44", type: "IP · Staging C2" },
  { label: "c2-tracker.org", type: "Domain · Beacon Host" },
  { label: "203.0.113.204", type: "IP · Exfil Gateway" },
  { label: "api.update-telemetry.com", type: "Domain · Fake CDN" },
  { label: "93.184.216.34", type: "IP · Anycast Edge" },
];

function FootprintMap({
  footprint,
  onInspectIp,
  onPivotDomain,
}: {
  footprint: Footprint;
  onInspectIp?: (ip: string) => void;
  onPivotDomain?: (domain: string) => void;
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
    <div className="overflow-x-auto">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="mx-auto h-auto w-full max-w-[640px]"
        role="img"
        aria-label="Digital footprint map — sample at the center, seed IPs on ring 1, passive infrastructure on ring 2, cohosted passive-DNS domains on ring 3 with source-tinted edges"
      >
        {/* grid rings */}
        {[60, ring1, ring2, ring3].map((r) => (
          <circle key={r} cx={cx} cy={cy} r={r} fill="none" stroke="var(--border-subtle)" strokeDasharray="2 5" />
        ))}
        {/* ring-3 edges */}
        {dnsPos.map((n) => {
          const owner = n.sourceKind === "seed" ? seedByIp.get(n.sourceIp ?? "") : sibByIp.get(n.sourceIp ?? "");
          if (!owner) return null;
          const tint = n.sourceKind === "seed" ? "var(--accent)" : "var(--risk-clean)";
          return <line key={`de-${n.key}`} x1={owner.x} y1={owner.y} x2={n.x} y2={n.y} stroke={tint} strokeWidth="1.2" opacity="0.75" />;
        })}
        {/* ring-2 edges */}
        {midPos.map((n) => {
          const owner = seedPos[0];
          return owner ? (
            <line key={`me-${n.key}`} x1={owner.x} y1={owner.y} x2={n.x} y2={n.y} stroke="var(--border-subtle)" strokeWidth="1" strokeDasharray="1 4" opacity="0.7" />
          ) : null;
        })}
        {/* seed ring edges */}
        {seedPos.map((s) => (
          <line key={`se-${s.ip}`} x1={cx} y1={cy} x2={s.x} y2={s.y} stroke="var(--border-strong)" strokeWidth="1" opacity="0.6" />
        ))}
        {/* cohosted passive-DNS nodes */}
        {dnsPos.map((n) => (
          <g
            key={`n-${n.key}`}
            className="cursor-pointer transition hover:opacity-100"
            onClick={() => onPivotDomain?.(n.label)}
          >
            <circle
              cx={n.x}
              cy={n.y}
              r="6"
              fill="var(--bg-surface)"
              stroke={n.sourceKind === "seed" ? "var(--accent)" : n.sourceKind === "sib" ? "var(--risk-clean)" : "var(--text-faint)"}
              strokeWidth="1.2"
              opacity="0.9"
            />
            <title>{`${n.label} — click to map domain infrastructure`}</title>
          </g>
        ))}
        {/* ring-2 passive nodes */}
        {midPos.map((n) => (
          <g
            key={`m-${n.key}`}
            className="cursor-pointer transition hover:opacity-100"
            onClick={() => onPivotDomain?.(n.label)}
          >
            <circle
              cx={n.x}
              cy={n.y}
              r="7"
              fill="var(--bg-surface)"
              stroke={n.kind === "res" ? "var(--accent)" : "var(--text-faint)"}
              strokeWidth="1.2"
              opacity="0.9"
            />
            <title>{`${n.label} — click to map domain infrastructure`}</title>
          </g>
        ))}
        {/* seed IPs */}
        {seedPos.map((s) => (
          <g
            key={`s-${s.ip}`}
            className="cursor-pointer transition hover:scale-110"
            onClick={() => onInspectIp?.(s.ip)}
          >
            <circle cx={s.x} cy={s.y} r="13" fill={repFill[s.reputation] ?? "var(--text-faint)"} opacity="0.85" />
            <circle cx={s.x} cy={s.y} r="6" fill="var(--bg-base)" />
            <title>{`${s.ip} — ${s.reputation} (${s.hits} connection${s.hits === 1 ? "" : "s"}) · click for context`}</title>
          </g>
        ))}
        {/* center sample / target */}
        <circle cx={cx} cy={cy} r="28" fill="var(--bg-elevated)" stroke="var(--accent)" strokeWidth="1.5" />
        <text x={cx} y={cy + 4} textAnchor="middle" fontSize="10" fontFamily="var(--font-mono)" fill="var(--text-primary)">
          {footprint.sample.name.length > 14 ? `${footprint.sample.name.slice(0, 13)}…` : footprint.sample.name}
        </text>
      </svg>
      <div className="mt-2 flex flex-wrap items-center justify-center gap-4 font-mono text-[10px] text-text-faint">
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-accent" /> target</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-risk-malicious" /> malicious IP</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-risk-suspicious" /> suspicious IP</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-risk-clean" /> clean IP</span>
        <span className="flex items-center gap-1.5"><span className="h-3.5 w-3.5 rounded-full border border-accent bg-bg-surface" /> cohosted · seed</span>
        <span className="flex items-center gap-1.5"><span className="h-3.5 w-3.5 rounded-full border border-risk-clean bg-bg-surface" /> cohosted · sibling</span>
        {footprint.passive.source === "synthetic_demo" && (
          <span className="flex items-center gap-1.5"><span className="h-3.5 w-3.5 rounded-full border border-accent bg-bg-surface" /> passive (synthetic)</span>
        )}
      </div>
    </div>
  );
}

function SeedIpTable({
  seeds,
  queryKey,
  onInspectIp,
  onAddWatchlist,
}: {
  seeds: FootprintSeedIp[];
  queryKey: unknown[];
  onInspectIp?: (ip: string) => void;
  onAddWatchlist?: (ip: string) => void;
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
      <p className="py-6 text-center text-sm text-text-muted">
        No network infrastructure observed for this target yet.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-left text-xs">
        <thead>
          <tr className="border-b border-border-subtle text-xs font-semibold uppercase tracking-wide text-text-muted">
            <th className="px-3 py-2 font-normal">IP</th>
            <th className="px-3 py-2 font-normal">Reputation</th>
            <th className="px-3 py-2 font-normal">Abuse</th>
            <th className="px-3 py-2 font-normal">Checked</th>
            <th className="px-3 py-2 font-normal">Hits</th>
            <th className="px-3 py-2 font-normal">Runs</th>
            <th className="px-3 py-2 font-normal">First / last seen</th>
            <th className="px-3 py-2 font-normal text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {seeds.map((s) => (
            <tr key={s.ip} className="border-b border-border-subtle/50 font-mono transition-colors hover:bg-bg-elevated/40">
              <td className="px-3 py-2 font-semibold text-text-primary">
                <button
                  onClick={() => onInspectIp?.(s.ip)}
                  className="hover:text-accent hover:underline text-left"
                >
                  {s.ip}
                </button>
              </td>
              <td className="px-3 py-2">
                <Chip tone={s.reputation === "malicious" ? "malicious" : s.reputation === "suspicious" ? "suspicious" : s.reputation === "clean" ? "clean" : "muted"} dot>
                  {s.reputation}
                </Chip>
              </td>
              <td className="px-3 py-2 text-text-muted">
                {s.abuse_score !== null && s.abuse_score !== undefined ? `${s.abuse_score}%` : "—"}
              </td>
              <td className="px-3 py-2 text-text-faint">
                {s.checked_at ? intelAgeLabel(s.checked_at) : "no cache"}
              </td>
              <td className="px-3 py-2 tabular-nums text-text-muted">{s.hits}</td>
              <td className="px-3 py-2 tabular-nums text-text-muted">{s.run_count}</td>
              <td className="px-3 py-2 text-text-faint">
                {s.first_seen && s.last_seen ? `${s.first_seen.slice(0, 10)} → ${s.last_seen.slice(0, 10)}` : "—"}
              </td>
              <td className="px-3 py-2 text-right">
                <div className="flex items-center justify-end gap-1.5">
                  <button
                    onClick={() => onInspectIp?.(s.ip)}
                    className="press rounded border border-border-subtle bg-bg-surface px-2 py-0.5 font-mono text-[10px] text-text-muted hover:border-accent/50 hover:text-accent"
                    title="Inspect network intelligence dossier"
                  >
                    Context
                  </button>
                  {onAddWatchlist && (
                    <button
                      onClick={() => onAddWatchlist(s.ip)}
                      className="press rounded border border-border-subtle bg-bg-surface px-2 py-0.5 font-mono text-[10px] text-text-muted hover:border-accent/50 hover:text-accent"
                      title="Add indicator to Threat Watchlist"
                    >
                      +Watch
                    </button>
                  )}
                  <Link
                    to={`/events?q=${encodeURIComponent(s.ip)}`}
                    className="press rounded border border-border-subtle bg-bg-surface px-2 py-0.5 font-mono text-[10px] text-text-muted hover:border-accent/50 hover:text-accent"
                    title="Search across all ingested events"
                  >
                    Events
                  </Link>
                  <button
                    onClick={() => void refresh(s.ip)}
                    disabled={refreshing === s.ip}
                    className="press rounded border border-border-subtle bg-bg-surface px-2 py-0.5 font-mono text-[10px] text-text-muted hover:border-accent/50 hover:text-accent disabled:opacity-50"
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

function PassiveCard({
  title,
  note,
  empty,
  nodes,
  onInspectIp,
  onPivotDomain,
  onCopy,
}: {
  title: string;
  note: string;
  empty: string;
  nodes: { label: string; sub: string; detail?: string[]; synthetic?: boolean }[];
  onInspectIp?: (ip: string) => void;
  onPivotDomain?: (domain: string) => void;
  onCopy?: (text: string) => void;
}) {
  const isIp = (val: string) => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(val);

  return (
    <Panel title={title} kicker={note}>
      {nodes.length === 0 ? (
        <p className="py-6 text-center text-xs leading-relaxed text-text-muted">{empty}</p>
      ) : (
        <ul className="space-y-1.5 max-h-[340px] overflow-y-auto pr-1">
          {nodes.map((n) => (
            <li key={`${title}-${n.label}`} className="group rounded-lg border border-border-subtle bg-bg-elevated/40 p-2.5 transition hover:border-accent/40">
              <div className="flex items-center justify-between gap-2">
                <span className="min-w-0 truncate font-mono text-xs font-semibold text-text-primary" title={n.label}>
                  {n.label}
                </span>
                <span className="flex shrink-0 items-center gap-1.5">
                  <span className="font-mono text-[10px] text-text-faint">{n.sub}</span>
                  {n.synthetic ? (
                    <span className="rounded border border-accent/50 px-1 py-0.5 font-mono text-[9px] uppercase tracking-wide text-accent">synthetic</span>
                  ) : (
                    <span className="rounded border border-risk-clean/50 px-1 py-0.5 font-mono text-[9px] uppercase tracking-wide text-risk-clean">live</span>
                  )}
                </span>
              </div>
              {n.detail && n.detail.length > 0 && (
                <p className="mt-1 truncate font-mono text-[10px] text-text-faint">{n.detail.join(" · ")}</p>
              )}
              <div className="mt-2 flex items-center justify-end gap-1.5 border-t border-border-subtle/40 pt-1.5 opacity-80 group-hover:opacity-100">
                {onCopy && (
                  <button
                    onClick={() => onCopy(n.label)}
                    className="press rounded px-1.5 py-0.5 font-mono text-[10px] text-text-muted hover:text-text-primary"
                    title="Copy indicator to clipboard"
                  >
                    Copy
                  </button>
                )}
                {isIp(n.label) && onInspectIp && (
                  <button
                    onClick={() => onInspectIp(n.label.split("/")[0])}
                    className="press rounded border border-border-subtle bg-bg-surface px-1.5 py-0.5 font-mono text-[10px] text-text-muted hover:border-accent/50 hover:text-accent"
                    title="Inspect network intelligence"
                  >
                    Context
                  </button>
                )}
                {!isIp(n.label) && onPivotDomain && (
                  <button
                    onClick={() => onPivotDomain(n.label)}
                    className="press inline-flex items-center gap-1 rounded border border-accent/50 bg-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-accent hover:bg-accent/20"
                    title="Pivot: Map infrastructure for this domain"
                  >
                    <span>Pivot Map</span>
                    <Icon name="arrowRight" size={10} />
                  </button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export default function FootprintPage() {
  const [params] = useSearchParams();
  const linked = params.get("sample");
  const targetParam = params.get("target");
  const appliedLink = useRef(false);

  const [mode, setMode] = useState<"sample" | "indicator">("sample");
  const [sampleId, setSampleId] = useState<string>("");
  const [indicatorInput, setIndicatorInput] = useState<string>("198.51.100.44");
  const [activeIndicator, setActiveIndicator] = useState<string>("198.51.100.44");
  const [mock, setMock] = useState(false);
  const [inspectIp, setInspectIp] = useState<string | null>(null);
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

  const handlePivotDomain = (domain: string) => {
    setMode("indicator");
    setIndicatorInput(domain);
    setActiveIndicator(domain);
  };

  const handleCopy = (text: string) => {
    void navigator.clipboard.writeText(text);
    setActionNotice(`Copied: ${text}`);
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
    <div className="mx-auto max-w-7xl px-6 py-10 lg:px-10">
      <PageHeader
        kicker="Intelligence &amp; Recon"
        title={
          <>
            Digital Footprint <span className="font-normal text-text-muted">— passive infrastructure mapping</span>
          </>
        }
        lede="Expand malicious infrastructure outward from binaries or network targets — passive DNS, WHOIS registration, CT certificate logs, and cohosted siblings."
        actions={
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-risk-suspicious/50 bg-risk-suspicious/10 px-2.5 py-1 font-mono text-[10px] uppercase tracking-wide text-risk-suspicious">
              <Icon name="zap" size={10} />
              Recon Suite
            </span>
            <Link
              to="/samples"
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
            >
              Sample vault
              <Icon name="arrowRight" size={12} />
            </Link>
          </div>
        }
      />

      {/* Action Notification Toast */}
      {actionNotice && (
        <div className="mb-4 flex items-center justify-between rounded-xl border border-signal/50 bg-signal/15 px-4 py-2 font-mono text-xs text-signal animate-fade-in">
          <span>✓ {actionNotice}</span>
          <button onClick={() => setActionNotice(null)} className="text-text-muted hover:text-text-primary">✕</button>
        </div>
      )}

      {/* Target Mode Selector Tabs */}
      <div className="mb-6 flex rounded-xl border border-border-subtle bg-bg-surface p-1 font-mono text-xs shadow-sm">
        <button
          onClick={() => setMode("sample")}
          className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2.5 font-medium transition ${
            mode === "sample"
              ? "bg-accent/15 font-bold text-accent shadow-xs"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="box" size={13} />
          <span>Sample Vault Binary (Detonation Seeds)</span>
        </button>
        <button
          onClick={() => setMode("indicator")}
          className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2.5 font-medium transition ${
            mode === "indicator"
              ? "bg-accent/15 font-bold text-accent shadow-xs"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="search" size={13} />
          <span>Target Indicator Investigation (IP / Domain)</span>
        </button>
      </div>

      {/* Pipeline banner */}
      <div className="mb-6 flex items-start gap-3 rounded-xl border border-accent/40 bg-accent/5 p-4">
        <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-lg border border-accent/50 bg-accent/10 text-accent">
          <Icon name="globe" size={13} />
        </span>
        <div className="min-w-0">
          <p className="font-mono text-xs font-semibold text-text-primary">
            {footprint && footprint.passive.source === "live"
              ? "Live passive expansion active — reverse DNS + crt.sh CT logs + RDAP"
              : footprint && footprint.passive.source === "synthetic_demo"
                ? "Synthetic infrastructure modeling — realistic deterministic preview active"
                : "Real seed data active; external lookups use cache / offline fallback"}
          </p>
          <p className="mt-1 text-xs leading-relaxed text-text-muted">
            The inner core is genuine: observed IPs and egress flows with cache-first reputations. The passive layer expands outward
            through PTR reverse DNS, Certificate Transparency logs (crt.sh) for subdomains and certificates, and RDAP registration
            for ASN ownership. Synthetic preview generates full deterministic topology when external APIs are unreachable or offline.
          </p>
        </div>
      </div>

      {/* Controls Bar */}
      <div className="mb-6 space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          {mode === "sample" ? (
            <label className="flex items-center gap-2">
              <span className="text-[11px] font-semibold text-text-faint">Sample:</span>
              <select
                value={sampleId}
                onChange={(e) => setSampleId(e.target.value)}
                className="min-w-64 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs text-text-primary outline-none transition-colors focus:border-accent/60"
                aria-label="Choose a sample"
              >
                {(vault?.samples ?? []).map((s) => (
                  <option key={s.sample_id} value={s.sample_id}>
                    {s.original_name}
                  </option>
                ))}
              </select>
            </label>
          ) : (
            <form onSubmit={handleIndicatorSubmit} className="flex flex-wrap items-center gap-2 flex-1 max-w-xl">
              <div className="relative flex-1 min-w-56">
                <Icon name="search" size={13} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-faint" />
                <input
                  type="text"
                  value={indicatorInput}
                  onChange={(e) => setIndicatorInput(e.target.value)}
                  placeholder="Enter IP or domain (e.g. 198.51.100.44, c2-tracker.org)..."
                  className="w-full rounded-lg border border-border-subtle bg-bg-surface py-1.5 pl-8 pr-3 font-mono text-xs text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
                />
              </div>
              <button
                type="submit"
                className="press rounded-lg border border-accent/60 bg-accent/15 px-3 py-1.5 font-mono text-xs font-semibold text-accent hover:bg-accent/25"
              >
                Map Target
              </button>
            </form>
          )}

          <button
            onClick={() => setMock((v) => !v)}
            aria-pressed={mock}
            className={`press inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 font-mono text-xs transition-colors duration-150 ${
              mock ? "border-accent/60 bg-accent/10 text-accent shadow-[var(--glow-accent)]" : "border-border-subtle text-text-muted hover:text-text-primary"
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${mock ? "bg-accent" : "bg-text-faint"}`} />
            {mock ? "Synthetic preview on" : "Show synthetic preview"}
          </button>

          <span className="mx-1 hidden h-4 w-px bg-border-subtle md:block" />
          <button
            onClick={() => {
              void exportFootprint(targetIdentifier, "json", mock).then((blob) =>
                saveBlob(blob, `outpost-footprint-${targetIdentifier.slice(0, 12)}.json`)
              );
            }}
            disabled={!targetIdentifier}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent disabled:opacity-40"
            title="Export the footprint as structured JSON"
          >
            <Icon name="download" size={12} />
            Export JSON
          </button>
          <button
            onClick={() => {
              void exportFootprint(targetIdentifier, "csv", mock).then((blob) =>
                saveBlob(blob, `outpost-footprint-${targetIdentifier.slice(0, 12)}.csv`)
              );
            }}
            disabled={!targetIdentifier}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent disabled:opacity-40"
            title="Export the footprint as a flat CSV IOC sheet"
          >
            <Icon name="download" size={12} />
            Export CSV
          </button>
        </div>

        {/* Quick Suggestion Chips for Indicator Mode */}
        {mode === "indicator" && (
          <div className="flex flex-wrap items-center gap-2 pt-1 font-mono text-[11px]">
            <span className="text-text-faint text-[10px] uppercase">Quick Targets:</span>
            {SUGGESTED_INDICATORS.map((item) => (
              <button
                key={item.label}
                onClick={() => {
                  setIndicatorInput(item.label);
                  setActiveIndicator(item.label);
                }}
                className={`press inline-flex items-center gap-1 rounded-md border px-2 py-0.5 transition ${
                  activeIndicator === item.label
                    ? "border-accent/60 bg-accent/15 text-accent font-semibold"
                    : "border-border-subtle bg-bg-surface text-text-muted hover:border-accent/40 hover:text-text-primary"
                }`}
              >
                <span>{item.label}</span>
                <span className="text-[9px] text-text-faint">({item.type})</span>
              </button>
            ))}
          </div>
        )}
      </div>

      {isLoading && <p className="py-10 text-center text-sm text-text-muted">Mapping infrastructure…</p>}
      {isError && (
        <p className="rounded-lg border border-risk-malicious/40 bg-bg-surface p-4 text-sm text-risk-malicious">
          Couldn't load the footprint — is the OutPost backend running?
        </p>
      )}

      {footprint && (
        <div className="space-y-6">
          {/* Zero Egress Empty-State Helper Card */}
          {footprint.seed_ips.length === 0 && !mock && (
            <div className="rounded-xl border border-border-subtle bg-bg-surface p-6 text-center space-y-4">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl border border-accent/40 bg-accent/10 text-accent">
                <Icon name="globe" size={24} />
              </div>
              <div>
                <h3 className="font-semibold text-text-primary text-base">No Network Egress Recorded for this Target</h3>
                <p className="mt-1 text-xs text-text-muted max-w-lg mx-auto">
                  This binary has not yet established network connections during sandbox runs, or has not been detonated yet.
                  You can detonate it to record live telemetry, toggle synthetic infrastructure preview, or pivot to an arbitrary target indicator.
                </p>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-3">
                <button
                  onClick={() => setMock(true)}
                  className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent/10 px-3.5 py-2 font-mono text-xs font-semibold text-accent hover:bg-accent/20"
                >
                  <Icon name="zap" size={13} />
                  Enable Synthetic Infrastructure Preview
                </button>
                <button
                  onClick={() => {
                    setMode("indicator");
                    setActiveIndicator("198.51.100.44");
                    setIndicatorInput("198.51.100.44");
                  }}
                  className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-base px-3.5 py-2 font-mono text-xs text-text-primary hover:border-accent/60"
                >
                  <Icon name="search" size={13} />
                  Investigate Target Indicator (IP/Domain)
                </button>
                {sampleId && (
                  <Link
                    to={`/monitor?sample=${sampleId}`}
                    className="press inline-flex items-center gap-1.5 rounded-lg border border-signal/60 bg-signal/10 px-3.5 py-2 font-mono text-xs font-semibold text-signal hover:bg-signal/20"
                  >
                    <Icon name="play" size={13} />
                    Detonate in Simulation Lab
                  </Link>
                )}
              </div>
            </div>
          )}

          {/* Seed layer — real */}
          {footprint.seed_ips.length > 0 && (
            <Panel
              kicker="Seed · real telemetry"
              title={`Observed infrastructure (${footprint.seed_ips.length})`}
              right={
                footprint.seed_ips.length > 0 ? (
                  <span className="font-mono text-[10px] text-text-faint">
                    across {footprint.runs.length} run{footprint.runs.length === 1 ? "" : "s"}
                  </span>
                ) : undefined
              }
            >
              <SeedIpTable
                seeds={footprint.seed_ips}
                queryKey={mode === "sample" ? ["footprint", sampleId, mock] : ["footprint-target", activeIndicator, mock]}
                onInspectIp={setInspectIp}
                onAddWatchlist={handleAddToWatchlist}
              />
            </Panel>
          )}

          {/* Footprint map */}
          {(footprint.seed_ips.length > 0 || mock) && (
            <Panel kicker="Topology Map" title={`Infrastructure Graph — ${footprint.sample.name}`}>
              <FootprintMap
                footprint={footprint}
                onInspectIp={setInspectIp}
                onPivotDomain={handlePivotDomain}
              />
            </Panel>
          )}

          {/* Passive layer */}
          {(footprint.seed_ips.length > 0 || mock) && (
            <div className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-3">
              <PassiveCard
                title="Resolutions"
                note={passiveNote(footprint.passive.source, "PTR")}
                empty="No reverse-DNS records for the seed IPs — nothing to resolve, or the sources are unreachable."
                nodes={footprint.passive.resolutions.map((r) => ({
                  label: r.domain,
                  sub: `${r.first_seen.slice(0, 10)} → ${r.last_seen.slice(0, 10)}`,
                  synthetic: r.synthetic,
                }))}
                onInspectIp={setInspectIp}
                onPivotDomain={handlePivotDomain}
                onCopy={handleCopy}
              />
              <PassiveCard
                title="Passive DNS history"
                note={passiveNote(footprint.passive.source, "crt.sh")}
                empty="No hostnames indexed in Certificate Transparency logs for the seed infrastructure."
                nodes={footprint.passive.passive_dns.map((d) => ({
                  label: d.domain,
                  sub: `${d.source_ip ? `${d.source_ip} · ` : ""}${d.first_seen.slice(0, 10)} → ${d.last_seen.slice(0, 10)}`,
                  synthetic: d.synthetic,
                }))}
                onInspectIp={setInspectIp}
                onPivotDomain={handlePivotDomain}
                onCopy={handleCopy}
              />
              <PassiveCard
                title="Subdomains"
                note={passiveNote(footprint.passive.source, "crt.sh")}
                empty="No subdomains discovered under the apex in Certificate Transparency logs."
                nodes={(footprint.passive.subdomains ?? []).map((d) => ({
                  label: d.domain,
                  sub: `${d.source_ip ? `${d.source_ip} · ` : ""}${d.first_seen.slice(0, 10)} → ${d.last_seen.slice(0, 10)}`,
                  synthetic: d.synthetic,
                }))}
                onInspectIp={setInspectIp}
                onPivotDomain={handlePivotDomain}
                onCopy={handleCopy}
              />
              <PassiveCard
                title="Certificates"
                note={passiveNote(footprint.passive.source, "crt.sh")}
                empty="No TLS certificates indexed for the seed infrastructure."
                nodes={footprint.passive.certificates.map((c) => ({
                  label: c.cn,
                  sub: c.issuer,
                  synthetic: c.synthetic,
                }))}
                onInspectIp={setInspectIp}
                onPivotDomain={handlePivotDomain}
                onCopy={handleCopy}
              />
              <PassiveCard
                title="Sibling infrastructure"
                note={passiveNote(footprint.passive.source, "RDAP")}
                empty="Hosts sharing a network with the seed IPs — the 'same operator' hypothesis."
                nodes={footprint.passive.sibling_ips.map((s) => ({
                  label: s.ip,
                  sub: s.relation,
                  synthetic: s.synthetic,
                }))}
                onInspectIp={setInspectIp}
                onPivotDomain={handlePivotDomain}
                onCopy={handleCopy}
              />
              <PassiveCard
                title="Registration + ASN"
                note={passiveNote(footprint.passive.source, "RDAP · ip-api")}
                empty="Registration info for the seed networks and ASN ownership."
                nodes={[
                  ...footprint.passive.networks.map((n) => ({
                    label: n.cidr,
                    sub: [n.netname, n.org, n.country].filter(Boolean).join(" · ") || n.ip,
                    detail: regTimeline(n),
                    synthetic: n.synthetic,
                  })),
                  ...footprint.passive.asn.map((a) => ({
                    label: a.asn ?? a.ip,
                    sub: [a.as_name, a.org, a.country].filter(Boolean).join(" · ") || a.ip,
                    synthetic: false,
                  })),
                ]}
                onInspectIp={setInspectIp}
                onPivotDomain={handlePivotDomain}
                onCopy={handleCopy}
              />
              <PassiveCard
                title="WHOIS"
                note={passiveNote(footprint.passive.source, "rdap.org · domain")}
                empty="No WHOIS record for the seed domains."
                nodes={(footprint.passive.whois ?? []).map((w) => ({
                  label: w.domain,
                  sub: [w.status.slice(0, 2).join(", ")].filter(Boolean).join(" · ") || "whois",
                  detail: whoisTimeline(w),
                  synthetic: w.synthetic,
                }))}
                onInspectIp={setInspectIp}
                onPivotDomain={handlePivotDomain}
                onCopy={handleCopy}
              />
              <PassiveCard
                title="Breach exposure"
                note={breachNote(footprint.breach.source)}
                empty="No breach exposure found — the sample embeds no emails (checked against XposedOrNot)."
                nodes={footprint.breach.rows.map((b) => ({
                  label: b.email,
                  sub: `${b.breaches.length} breach${b.breaches.length === 1 ? "" : "es"}`,
                  detail: b.breaches.slice(0, 6),
                  synthetic: b.synthetic,
                }))}
                onInspectIp={setInspectIp}
                onPivotDomain={handlePivotDomain}
                onCopy={handleCopy}
              />
            </div>
          )}

          {/* Cross-sample topology */}
          {topology && (
            <Panel
              kicker="Cross-sample Correlation"
              title={`Infrastructure shared across samples (${topology.clusters.length})`}
              right={
                <span className="font-mono text-[10px] text-text-faint">
                  {topology.total_samples} samples correlated
                </span>
              }
            >
              {topology.clusters.length === 0 ? (
                <p className="text-sm text-text-muted">
                  No two samples in the vault share an observed destination IP yet — correlation needs at least two binaries touching the same host.
                </p>
              ) : (
                <ul className="space-y-3">
                  {topology.clusters.map((c) => (
                    <li key={c.ip} className="rounded-lg border border-border-subtle bg-bg-elevated/30 p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`font-mono text-xs font-semibold ${
                            c.reputation === "malicious"
                              ? "text-risk-malicious"
                              : c.reputation === "suspicious"
                                ? "text-risk-suspicious"
                                : "text-text-primary"
                          }`}
                        >
                          {c.ip}
                        </span>
                        <Chip tone={c.reputation === "malicious" ? "malicious" : c.reputation === "suspicious" ? "suspicious" : "muted"} dot>
                          {c.reputation}
                        </Chip>
                        <span className="font-mono text-[10px] text-text-faint">
                          {c.sample_count} sample{c.sample_count === 1 ? "" : "s"} ·{" "}
                          {c.checked_at ? `checked ${intelAgeLabel(c.checked_at)}` : "no reputation cache"}
                        </span>
                        <div className="ml-auto flex items-center gap-2">
                          <button
                            onClick={() => setInspectIp(c.ip)}
                            className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2 py-0.5 font-mono text-[10px] text-text-muted hover:border-accent/50 hover:text-accent"
                          >
                            <Icon name="activity" size={10} />
                            Context
                          </button>
                          <Link
                            to={`/campaigns`}
                            className="press inline-flex items-center gap-1 rounded border border-accent/40 bg-accent/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-accent hover:bg-accent/20"
                            title="View adversary campaigns tracking this cluster"
                          >
                            <Icon name="flag" size={10} />
                            View Campaign
                          </Link>
                        </div>
                      </div>
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {c.members.map((m) => (
                          <Link
                            key={`${c.ip}-${m.sample_name}`}
                            to={`/footprint?sample=${encodeURIComponent(m.sample_name)}`}
                            title={`${m.hits} connection${m.hits === 1 ? "" : "s"} across ${m.run_ids.length} run${m.run_ids.length === 1 ? "" : "s"}`}
                            className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-base px-2 py-1 font-mono text-[11px] text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
                          >
                            {m.sample_name}
                            <span className="text-text-faint">· {m.hits}</span>
                          </Link>
                        ))}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          )}
        </div>
      )}

      {inspectIp && (
        <NetworkContextModal ip={inspectIp} onClose={() => setInspectIp(null)} />
      )}
    </div>
  );
}
