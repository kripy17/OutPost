import { RISK_COLORS, intelAgeLabel } from "../../lib/constants";
import { toneFill, toneForReputation } from "../../lib/fillPatterns";
import { Icon } from "../Icon";
import type { Reputation } from "../../types";

// Reputation badge with source attribution: the verdict alone never says WHY,
// so the tooltip breaks down which intel feed produced it — the personal
// watchlist, AbuseIPDB's abuse score, VirusTotal's malicious-vendor count, or
// none (unknown). The optional checkedAt appends the cache age ("checked 5h
// ago") so a watcher sees staleness mid-session. Data comes straight from the
// enrichment dict on the run.
export default function ReputationBadge({
  reputation,
  watchlist = false,
  watchlistLabel = null,
  abuseScore = null,
  vtCount = null,
  checkedAt = null,
}: {
  reputation: Reputation;
  watchlist?: boolean;
  watchlistLabel?: string | null;
  abuseScore?: number | null;
  vtCount?: number | null;
  checkedAt?: string | null;
}) {
  const label = reputation || "unknown";
  const sources: string[] = [];
  if (watchlist) sources.push(`personal watchlist${watchlistLabel ? ` (${watchlistLabel})` : ""}`);
  if (abuseScore !== null && abuseScore !== undefined) sources.push(`AbuseIPDB score ${abuseScore}`);
  if (vtCount !== null && vtCount !== undefined) sources.push(`VirusTotal: ${vtCount} malicious vendor${vtCount === 1 ? "" : "s"}`);
  if (sources.length === 0) sources.push("no external intel configured — verdict unknown");
  const age = intelAgeLabel(checkedAt);
  if (age) sources.push(age);
  const tip = `Reputation: ${label}. Sources: ${sources.join(" · ")}`;

  return (
    <span className={`inline-flex items-center gap-1.5 font-mono text-xs ${RISK_COLORS[label]}`} title={tip}>
      {watchlist && (
        <span className="text-accent" title={watchlistLabel || "On your personal watchlist"}>
          <Icon name="star" size={11} />
        </span>
      )}
      {/* Pattern-encoded dot (deck-wide fill language) — the label text
          carries the verdict; the pattern adds the color-blind channel. */}
      <span className="inline-block h-2 w-2 rounded-full" style={toneFill(toneForReputation(label))} aria-hidden />
      {label}
      {sources.length > 0 && (
        <Icon name="eye" size={10} className="ml-0.5 opacity-50" aria-label="Reputation sources" />
      )}
    </span>
  );
}
