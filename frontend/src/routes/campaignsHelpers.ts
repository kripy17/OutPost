// Campaign list ordering — persisted (`outpost-campaigns-sort`) so the deck
// resumes the analyst's preferred view. reputation = externally-flagged or
// watchlisted infrastructure first; size = most member runs first; newest =
// most recent span start first.

import type { Campaign, Reputation, TopologyCluster, TopologyClusterMember } from "../types";

export type CampaignSort = "reputation" | "size" | "newest";

export const CAMPAIGN_SORTS: { key: CampaignSort; label: string; title: string }[] = [
  { key: "reputation", label: "Reputation", title: "Watchlisted / externally-flagged infrastructure first" },
  { key: "size", label: "Size", title: "Most member runs first" },
  { key: "newest", label: "Newest", title: "Most recent activity first" },
];

/** Pure sorter — stable: equal keys keep API order. */
export function sortCampaigns(campaigns: Campaign[], sort: CampaignSort): Campaign[] {
  const repRank: Record<string, number> = { malicious: 0, suspicious: 1, unknown: 2 };
  const cmp: Record<CampaignSort, (a: Campaign, b: Campaign) => number> = {
    reputation: (a, b) => (repRank[a.reputation ?? "unknown"] ?? 2) - (repRank[b.reputation ?? "unknown"] ?? 2),
    size: (a, b) => b.runs.length - a.runs.length,
    newest: (a, b) => (b.span_start ?? "").localeCompare(a.span_start ?? ""),
  };
  return [...campaigns].sort(cmp[sort]);
}

/** Enriched topology cluster for the campaign-strip view: the cross-sample
 *  shared-infra clusters (from /footprint/topology) annotated with whether
 *  the IP is ALSO an existing campaign — so the analyst sees both the
 *  correlation signal and what's already being tracked. */
export interface TopologyStripRow extends TopologyCluster {
  /** True when a campaign already exists for this exact IP (same key). */
  inCampaign: boolean;
}

/** Map the cross-sample topology clusters onto the campaign list: each
 *  cluster becomes a strip row with an `inCampaign` flag, sorted by shared-
 *  sample count descending (the loudest campaign signal first). Pure — no
 *  fetch, no component. */
export function topologyClusters(
  clusters: TopologyCluster[],
  campaigns: Campaign[],
): TopologyStripRow[] {
  const keys = new Set(campaigns.map((c) => c.key));
  return clusters
    .map((c) => ({ ...c, inCampaign: keys.has(c.ip) }))
    .sort((a, b) => b.sample_count - a.sample_count || a.ip.localeCompare(b.ip));
}

/** One row of the strip's compact bar chart — bar width encodes the cluster's
 *  sample count relative to the loudest cluster, so relative sizes read at a
 *  glance instead of requiring a scan of the ×N counters. Pure — no fetch. */
export interface ClusterBar {
  ip: string;
  sample_count: number;
  reputation: TopologyCluster["reputation"];
  inCampaign: boolean;
  /** 0–100 bar width as a fraction of the largest cluster's sample count. */
  pct: number;
  /** Representative sample name for the footprint deep-link. */
  memberSample: string;
  /** Full member list (kept for the hover tooltip's breakdown). */
  members: TopologyClusterMember[];
}

/** Project strip rows into bar-chart rows: width scaled to the max count,
 *  capped at `limit` rows (the loudest clusters first). The max cluster gets
 *  pct 100; anything below is proportional. Pure — no fetch, no component. */
export function clusterBars(rows: TopologyStripRow[], limit = 10): ClusterBar[] {
  const max = Math.max(1, ...rows.map((r) => r.sample_count));
  return rows.slice(0, limit).map((r) => ({
    ip: r.ip,
    sample_count: r.sample_count,
    reputation: r.reputation,
    inCampaign: r.inCampaign,
    pct: Math.round((r.sample_count / max) * 100),
    memberSample: r.members[0]?.sample_name ?? "",
    members: r.members,
  }));
}

/** The hover tooltip's member breakdown: sorted by hit count descending (name
 *  tiebreak), capped at `limit` rows with the overflow counted — so a cluster
 *  with 11 samples shows the loudest 8 plus "+3 more" instead of a wall of
 *  text. Pure — no fetch, no component. */
export function topMembers(
  members: TopologyClusterMember[],
  limit = 8,
): { rows: TopologyClusterMember[]; more: number } {
  const sorted = [...members].sort(
    (a, b) => b.hits - a.hits || a.sample_name.localeCompare(b.sample_name),
  );
  return { rows: sorted.slice(0, limit), more: Math.max(0, sorted.length - limit) };
}

/** The bar fill for a reputation — pattern-encoded, not just color, so the
 *  chart stays readable for color-blind viewers: malicious is SOLID, suspicious
 *  is diagonal-hatched, clean is vertically-hatched, unknown is crosshatched.
 *  Opacity keeps the row text legible over the fill. Pure — no fetch. */
export interface ReputationFill {
  background: string;
  opacity: number;
}

export function reputationFill(reputation: Reputation): ReputationFill {
  switch (reputation) {
    case "malicious":
      return { background: "var(--risk-malicious)", opacity: 0.45 };
    case "suspicious":
      return {
        background: "repeating-linear-gradient(45deg, var(--risk-suspicious) 0 4px, transparent 4px 8px)",
        opacity: 0.6,
      };
    case "clean":
      return {
        background: "repeating-linear-gradient(90deg, var(--risk-clean) 0 2px, transparent 2px 7px)",
        opacity: 0.6,
      };
    default: // unknown
      return {
        background:
          "repeating-linear-gradient(45deg, var(--text-muted) 0 2px, transparent 2px 6px), repeating-linear-gradient(-45deg, var(--text-muted) 0 2px, transparent 2px 6px)",
        opacity: 0.6,
      };
  }
}
