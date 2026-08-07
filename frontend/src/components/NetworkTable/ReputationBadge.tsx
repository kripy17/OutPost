import { RISK_BG, RISK_COLORS } from "../../lib/constants";
import type { Reputation } from "../../types";

export default function ReputationBadge({
  reputation,
  watchlist = false,
  watchlistLabel = null,
}: {
  reputation: Reputation;
  watchlist?: boolean;
  watchlistLabel?: string | null;
}) {
  const label = reputation || "unknown";
  return (
    <span className={`inline-flex items-center gap-1.5 font-mono text-xs ${RISK_COLORS[label]}`}>
      {watchlist && (
        <span className="text-accent-amber" title={watchlistLabel || "On your personal watchlist"}>
          ★
        </span>
      )}
      <span className={`inline-block h-2 w-2 rounded-full ${RISK_BG[label]}`} />
      {label}
    </span>
  );
}
