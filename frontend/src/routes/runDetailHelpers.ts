// Run-detail pure helper — reputation source attribution for a connection.
// Moved out of the route file so it stays unit-testable in isolation.

import type { NetworkConnection } from "../types";

/** Reputation source attribution — the feeds that produced a verdict, as a
 *  human line (watchlist / AbuseIPDB / VirusTotal / none). */
export function connectionSources(c: NetworkConnection): string[] {
  const parts: string[] = [];
  if (c.watchlist) parts.push(`personal watchlist${c.watchlist_label ? ` (${c.watchlist_label})` : ""}`);
  if (c.abuse_score !== null && c.abuse_score !== undefined) parts.push(`AbuseIPDB score ${c.abuse_score}`);
  if (c.vt_malicious_count !== null && c.vt_malicious_count !== undefined)
    parts.push(`VirusTotal: ${c.vt_malicious_count} malicious vendor${c.vt_malicious_count === 1 ? "" : "s"}`);
  if (parts.length === 0) parts.push("no external intel configured");
  return parts;
}
