// Pure derivation for the footprint map — extracted from the page so the
// topology contract (seed IPs on ring 1, passive infrastructure on ring 2,
// cohosted passive-DNS domains fanning around their observed source on ring
// 3) is unit-testable without rendering SVG.

import type { Footprint } from "../types";

export const MAP = { W: 600, H: 500, ring1: 105, ring2: 175, ring3: 235 } as const;

export type MidNode = { key: string; label: string; kind: "res" | "sib"; ip?: string; angle: number; x: number; y: number };
export type DnsNode = { key: string; label: string; sourceIp?: string; sourceKind: "seed" | "sib" | "other"; x: number; y: number };

export interface TopologyShape {
  seedPos: (Footprint["seed_ips"][number] & { angle: number; x: number; y: number })[];
  seedByIp: Map<string, { x: number; y: number; angle: number }>;
  midPos: MidNode[];
  sibByIp: Map<string, MidNode>;
  dnsPos: DnsNode[];
}

const angleFor = (i: number, n: number) => (i / Math.max(n, 1)) * Math.PI * 2 - Math.PI / 2;

/** Lay out the radial footprint map as plain data — the page only renders it.
 *  Cohosted passive-DNS rows are grouped by their source IP and fanned around
 *  the seed/sibling node they were observed from, so the map reads as a
 *  topology instead of a flat ring. */
export function buildTopology(footprint: Footprint): TopologyShape {
  const { cx, cy } = { cx: MAP.W / 2, cy: MAP.H / 2 };
  const seeds = footprint.seed_ips;
  const p = footprint.passive;

  // Ring 1 — the observed seed IPs (reputation-colored).
  const seedPos = seeds.slice(0, 8).map((s, i) => {
    const a = angleFor(i, seeds.length);
    return { ...s, angle: a, x: cx + MAP.ring1 * Math.cos(a), y: cy + MAP.ring1 * Math.sin(a) };
  });
  const seedByIp = new Map(seedPos.map((s) => [s.ip, s]));

  // Ring 2 — PTR resolutions + sibling hosts (the same-block hypothesis).
  const midNodes: { key: string; label: string; kind: "res" | "sib"; ip?: string }[] = [
    ...p.resolutions.slice(0, 5).map((r) => ({ key: `res-${r.domain}`, label: r.domain, kind: "res" as const })),
    ...p.sibling_ips.slice(0, 5).map((s) => ({ key: `sib-${s.ip}`, label: s.ip, kind: "sib" as const, ip: s.ip })),
  ];
  const midPos: MidNode[] = midNodes.map((n, i) => {
    const a = angleFor(i, midNodes.length);
    return { ...n, angle: a, x: cx + MAP.ring2 * Math.cos(a), y: cy + MAP.ring2 * Math.sin(a) };
  });
  const sibByIp = new Map(midPos.filter((n) => n.kind === "sib").map((n) => [n.ip!, n]));

  // Ring 3 — cohosted passive-DNS domains, grouped by source IP so each fans
  // around its seed/sibling node (a genuine topology instead of a flat ring).
  const dnsRows = p.passive_dns.slice(0, 8);
  const bySource = new Map<string, typeof dnsRows>();
  for (const d of dnsRows) {
    const src = d.source_ip ?? "__other__";
    bySource.set(src, [...(bySource.get(src) ?? []), d]);
  }
  const dnsPos: DnsNode[] = [];
  let fallback = angleFor(0, 1) + 0.6;
  for (const [src, rows] of bySource) {
    const owner = seedByIp.get(src) ?? sibByIp.get(src);
    const base = owner?.angle ?? fallback;
    rows.forEach((d, k) => {
      const a = base + (k - (rows.length - 1) / 2) * 0.26;
      dnsPos.push({
        key: `dns-${d.domain}`,
        label: d.domain,
        sourceIp: d.source_ip,
        sourceKind: owner ? (seedByIp.has(src) ? "seed" : "sib") : "other",
        x: cx + MAP.ring3 * Math.cos(a),
        y: cy + MAP.ring3 * Math.sin(a),
      });
    });
    fallback += 0.7;
  }

  return { seedPos, seedByIp, midPos, sibByIp, dnsPos };
}

/** Provider label per passive card — honest about where each row came from. */
export function passiveNote(source: Footprint["passive"]["source"], provider: string): string {
  if (source === "synthetic_demo") return "synthetic preview";
  if (source === "live") return `${provider} · live`;
  return "offline — not configured";
}

/** The WHOIS-style registration timeline for one RDAP network row: the
 *  registrar + created/updated/expires dates, rendered as one readable
 *  line. Pieces that RDAP didn't return are omitted — never "— · — · —". */
export function regTimeline(
  n: Footprint["passive"]["networks"][number],
): string[] {
  const parts: string[] = [];
  if (n.registrar) parts.push(`registrar ${n.registrar}`);
  if (n.created) parts.push(`created ${n.created}`);
  if (n.updated) parts.push(`updated ${n.updated}`);
  if (n.expires) parts.push(`expires ${n.expires}`);
  return parts;
}
