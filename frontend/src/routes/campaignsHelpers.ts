// Campaign list ordering — persisted (`outpost-campaigns-sort`) so the deck
// resumes the analyst's preferred view. reputation = externally-flagged or
// watchlisted infrastructure first; size = most member runs first; newest =
// most recent span start first.

import type { Campaign } from "../types";

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
