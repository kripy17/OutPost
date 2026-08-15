// Campaign list ordering — persisted (`outpost-campaigns-sort`) so the deck
// resumes the analyst's preferred view. reputation = externally-flagged or
// watchlisted infrastructure first; size = most member runs first; newest =
// most recent span start first.

import type { Campaign, TopologyCluster } from "../types";

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
