import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { Chip, PageHeader, Panel } from "../components/ui";
import { getFootprint, getSamples } from "../lib/api";
import type { Footprint, FootprintSeedIp } from "../types";

// Radial footprint map — sample at the center, its real seed IPs on ring 1,
// and (when synthetic preview is on) passive nodes on ring 2.
function FootprintMap({ footprint }: { footprint: Footprint }) {
  const seeds = footprint.seed_ips;
  const passiveNodes = useMemo(() => {
    const p = footprint.passive;
    return [
      ...p.resolutions.slice(0, 6).map((r) => ({ label: r.domain, tone: "res" as const })),
      ...p.sibling_ips.slice(0, 6).map((s) => ({ label: s.ip, tone: "sib" as const })),
    ];
  }, [footprint]);

  const W = 560;
  const H = 380;
  const cx = W / 2;
  const cy = H / 2;
  const ring1 = 96;
  const ring2 = 178;

  const seedPos = seeds.slice(0, 8).map((s, i) => {
    const a = (i / Math.max(seeds.length, 1)) * Math.PI * 2 - Math.PI / 2;
    return { ...s, x: cx + ring1 * Math.cos(a), y: cy + ring1 * Math.sin(a) };
  });
  const passivePos = passiveNodes.map((n, i) => {
    const a = (i / Math.max(passiveNodes.length, 1)) * Math.PI * 2 - Math.PI / 2;
    return { ...n, x: cx + ring2 * Math.cos(a), y: cy + ring2 * Math.sin(a) };
  });

  const repFill: Record<string, string> = {
    malicious: "var(--risk-malicious)",
    suspicious: "var(--risk-suspicious)",
    clean: "var(--risk-clean)",
    unknown: "var(--text-faint)",
  };

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="mx-auto h-auto w-full max-w-[640px]" role="img" aria-label="Digital footprint map — sample at the center, seed IPs on the inner ring, passive infrastructure on the outer ring">
        {/* grid rings */}
        {[48, 96, 178].map((r) => (
          <circle key={r} cx={cx} cy={cy} r={r} fill="none" stroke="var(--border-subtle)" strokeDasharray="2 5" />
        ))}
        {/* passive ring edges */}
        {passivePos.map((n) => {
          const owner = seedPos[0];
          return owner ? (
            <line key={`pe-${n.label}`} x1={owner.x} y1={owner.y} x2={n.x} y2={n.y} stroke="var(--border-subtle)" strokeWidth="1" strokeDasharray="1 4" opacity="0.7" />
          ) : null;
        })}
        {/* seed ring edges */}
        {seedPos.map((s) => (
          <line key={`se-${s.ip}`} x1={cx} y1={cy} x2={s.x} y2={s.y} stroke="var(--border-strong)" strokeWidth="1" opacity="0.6" />
        ))}
        {/* passive nodes */}
        {passivePos.map((n) => (
          <g key={`n-${n.label}`}>
            <circle cx={n.x} cy={n.y} r="7" fill="var(--bg-surface)" stroke={n.tone === "res" ? "var(--accent)" : "var(--text-faint)"} strokeWidth="1" opacity="0.9" />
            <title>{n.label}</title>
          </g>
        ))}
        {/* seed IPs */}
        {seedPos.map((s) => (
          <g key={`s-${s.ip}`}>
            <circle cx={s.x} cy={s.y} r="13" fill={repFill[s.reputation] ?? "var(--text-faint)"} opacity="0.85" />
            <circle cx={s.x} cy={s.y} r="6" fill="var(--bg-base)" />
            <title>{`${s.ip} — ${s.reputation} (${s.hits} connection${s.hits === 1 ? "" : "s"})`}</title>
          </g>
        ))}
        {/* center sample */}
        <circle cx={cx} cy={cy} r="26" fill="var(--bg-elevated)" stroke="var(--accent)" strokeWidth="1.5" />
        <text x={cx} y={cy + 4} textAnchor="middle" fontSize="11" fontFamily="var(--font-mono)" fill="var(--text-primary)">
          {footprint.sample.name.length > 12 ? `${footprint.sample.name.slice(0, 11)}…` : footprint.sample.name}
        </text>
      </svg>
      <div className="mt-2 flex flex-wrap items-center justify-center gap-4 font-mono text-[10px] text-text-faint">
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-accent" /> sample</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-risk-malicious" /> malicious IP</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-risk-suspicious" /> suspicious IP</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-risk-clean" /> clean IP</span>
        {footprint.passive.source === "synthetic_demo" && (
          <span className="flex items-center gap-1.5"><span className="h-3.5 w-3.5 rounded-full border border-accent bg-bg-surface" /> passive (synthetic)</span>
        )}
      </div>
    </div>
  );
}

function SeedIpTable({ seeds }: { seeds: FootprintSeedIp[] }) {
  if (seeds.length === 0) {
    return (
      <p className="py-6 text-center text-sm text-text-muted">
        No network infrastructure observed for this sample yet — detonate it from the Monitor page to seed the footprint.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[560px] text-left text-xs">
        <thead>
          <tr className="border-b border-border-subtle text-xs font-semibold uppercase tracking-wide text-text-muted">
            <th className="px-3 py-2 font-normal">IP</th>
            <th className="px-3 py-2 font-normal">Reputation</th>
            <th className="px-3 py-2 font-normal">Abuse</th>
            <th className="px-3 py-2 font-normal">Hits</th>
            <th className="px-3 py-2 font-normal">Runs</th>
            <th className="px-3 py-2 font-normal">First / last seen</th>
          </tr>
        </thead>
        <tbody>
          {seeds.map((s) => (
            <tr key={s.ip} className="border-b border-border-subtle/60 transition-colors duration-150 last:border-0 hover:bg-bg-elevated/40">
              <td className="px-3 py-2 font-mono text-text-primary">{s.ip}</td>
              <td className="px-3 py-2">
                <Chip tone={s.reputation === "malicious" ? "malicious" : s.reputation === "suspicious" ? "suspicious" : s.reputation === "clean" ? "clean" : "muted"} dot>
                  {s.reputation}
                </Chip>
              </td>
              <td className="px-3 py-2 font-mono tabular-nums text-text-muted">{s.abuse_score ?? "—"}</td>
              <td className="px-3 py-2 font-mono tabular-nums text-text-muted">{s.hits}</td>
              <td className="px-3 py-2 font-mono tabular-nums text-text-muted">{s.run_count}</td>
              <td className="px-3 py-2 font-mono tabular-nums text-text-faint">
                {s.first_seen.slice(0, 10)} → {s.last_seen.slice(0, 10)}
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
}: {
  title: string;
  note: string;
  empty: string;
  nodes: { label: string; sub: string; synthetic?: boolean }[];
}) {
  return (
    <Panel title={title} kicker={note}>
      {nodes.length === 0 ? (
        <p className="py-6 text-center text-xs leading-relaxed text-text-muted">{empty}</p>
      ) : (
        <ul className="space-y-1.5">
          {nodes.map((n) => (
            <li key={`${title}-${n.label}`} className="flex items-center justify-between gap-2 rounded-md border border-border-subtle bg-bg-elevated/40 px-2.5 py-1.5">
              <span className="min-w-0 truncate font-mono text-[11px] text-text-primary">{n.label}</span>
              <span className="flex shrink-0 items-center gap-1.5">
                <span className="font-mono text-[10px] text-text-faint">{n.sub}</span>
                {n.synthetic ? (
                  <span className="rounded border border-accent/50 px-1 py-0.5 font-mono text-[9px] uppercase tracking-wide text-accent">synthetic</span>
                ) : (
                  <span className="rounded border border-risk-clean/50 px-1 py-0.5 font-mono text-[9px] uppercase tracking-wide text-risk-clean">live</span>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

/** Provider label per passive card — honest about where each row came from. */
function passiveNote(source: Footprint["passive"]["source"], provider: string): string {
  if (source === "synthetic_demo") return "synthetic preview";
  if (source === "live") return `${provider} · live`;
  return "offline — not configured";
}

export default function FootprintPage() {
  const [params] = useSearchParams();
  const linked = params.get("sample");
  const appliedLink = useRef(false);
  const [sampleId, setSampleId] = useState<string>("");
  const [mock, setMock] = useState(false);

  const { data: vault } = useQuery({ queryKey: ["samples", "all"], queryFn: () => getSamples({ limit: 100 }) });

  // Deep-link support (?sample=<id>) — applied exactly once so a later vault
  // refetch can never snap the user's dropdown choice back to the linked one.
  // Otherwise default to the newest sample once the vault has loaded.
  useEffect(() => {
    if (linked && !appliedLink.current) {
      appliedLink.current = true;
      setSampleId(linked);
    } else if (!linked && vault?.samples.length && !sampleId) {
      setSampleId(vault.samples[0].sample_id);
    }
  }, [linked, vault, sampleId]);

  const { data: footprint, isLoading, isError } = useQuery({
    queryKey: ["footprint", sampleId, mock],
    queryFn: () => getFootprint(sampleId, mock),
    enabled: sampleId !== "",
  });

  return (
    <div className="mx-auto max-w-7xl px-6 py-10 lg:px-10">
      <PageHeader
        kicker="Intelligence · roadmap"
        title={
          <>
            Digital Footprint <span className="font-normal text-text-muted">— passive infrastructure mapping</span>
          </>
        }
        lede="Seed a sample's observed infrastructure and expand outward — passive DNS, certificates, and sibling hosts — to sketch the campaign behind one binary."
        actions={
          <Link
            to="/samples"
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
          >
            Sample vault
            <Icon name="arrowRight" size={12} />
          </Link>
        }
      />

      {/* Pipeline banner — live providers, honest fallback. Gated on the
          footprint being loaded so it never flashes "offline" mid-fetch. */}
      <div className="mb-6 flex items-start gap-3 rounded-xl border border-accent/40 bg-accent/5 p-4">
        <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-lg border border-accent/50 bg-accent/10 text-accent">
          <Icon name="globe" size={13} />
        </span>
        <div className="min-w-0">
          <p className="font-mono text-xs font-semibold text-text-primary">
            {footprint && footprint.passive.source === "live"
              ? "Live passive expansion — reverse DNS + crt.sh CT logs + RDAP"
              : footprint
                ? "Seed data is real; passive lookups are offline right now"
                : "Mapping the sample's observed infrastructure…"}
          </p>
          <p className="mt-1 text-xs leading-relaxed text-text-muted">
            The inner ring is genuine: every IP this sample reached, aggregated from its runs with cache-first reputations. The outer layer expands it
            through keyless public sources — PTR reverse DNS for resolutions, Certificate Transparency logs (crt.sh) for TLS certificates, and RDAP for
            registration + sibling networks. When the sources are unreachable the page degrades to an honest empty state; the preview toggle renders
            clearly-labeled synthetic data for demos.
          </p>
        </div>
      </div>

      {/* Controls */}
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2">
          <span className="text-[11px] font-semibold text-text-faint">Sample</span>
          <select
            value={sampleId}
            onChange={(e) => setSampleId(e.target.value)}
            className="min-w-56 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-primary outline-none transition-colors focus:border-accent/60"
            aria-label="Choose a sample"
          >
            {(vault?.samples ?? []).map((s) => (
              <option key={s.sample_id} value={s.sample_id}>
                {s.original_name}
              </option>
            ))}
          </select>
        </label>
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
      </div>

      {isLoading && <p className="py-10 text-center text-sm text-text-muted">Mapping infrastructure…</p>}
      {isError && (
        <p className="rounded-lg border border-risk-malicious/40 bg-bg-surface p-4 text-sm text-risk-malicious">
          Couldn't load the footprint — is the OutPost backend running?
        </p>
      )}

      {footprint && (
        <div className="space-y-6">
          {/* Seed layer — real */}
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
            <SeedIpTable seeds={footprint.seed_ips} />
          </Panel>

          {/* Footprint map */}
          <Panel kicker="Map" title="Infrastructure view">
            <FootprintMap footprint={footprint} />
          </Panel>

          {/* Passive layer — live providers (PTR → crt.sh + RDAP), with an
              honest offline empty state and the labeled synthetic preview. */}
          <div className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-4">
            <PassiveCard
              title="Resolutions"
              note={passiveNote(footprint.passive.source, "PTR")}
              empty="No reverse-DNS records for the seed IPs — nothing to resolve, or the sources are unreachable."
              nodes={footprint.passive.resolutions.map((r) => ({ label: r.domain, sub: `${r.first_seen.slice(0, 10)} → ${r.last_seen.slice(0, 10)}`, synthetic: r.synthetic }))}
            />
            <PassiveCard
              title="Certificates"
              note={passiveNote(footprint.passive.source, "crt.sh")}
              empty="No TLS certificates indexed for the seed infrastructure — crt.sh may be unreachable, or none are registered."
              nodes={footprint.passive.certificates.map((c) => ({ label: c.cn, sub: c.issuer, synthetic: c.synthetic }))}
            />
            <PassiveCard
              title="Sibling infrastructure"
              note={passiveNote(footprint.passive.source, "RDAP")}
              empty="Hosts sharing a network with the seed IPs — the 'same operator' hypothesis. Requires RDAP data."
              nodes={footprint.passive.sibling_ips.map((s) => ({ label: s.ip, sub: s.relation, synthetic: s.synthetic }))}
            />
            <PassiveCard
              title="Registration (RDAP)"
              note={passiveNote(footprint.passive.source, "RDAP")}
              empty="Registration info for the seed networks (name, CIDR, organization, country) will appear here."
              nodes={footprint.passive.networks.map((n) => ({ label: n.cidr, sub: [n.netname, n.org, n.country].filter(Boolean).join(" · ") || n.ip, synthetic: n.synthetic }))}
            />
          </div>
        </div>
      )}
    </div>
  );
}
