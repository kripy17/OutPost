// Run-detail pure helpers — reputation source attribution for a connection
// and the recon-actor resolution from the process tree. Moved out of the
// route file so they stay unit-testable in isolation.

import type { NetworkConnection, RunDetail } from "../types";

/** A resolved recon-actor row — one enumerating process in a Discovery sweep. */
export type ReconActor = {
  pid: number;
  process_name: string | null;
  command_line: string | null;
};

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

/** Resolve the recon-actor rows for a set of PIDs by walking the run's
 *  process tree. Preserves the requested PID order (alert order) and skips
 *  PIDs that aren't in the tree (an alert may reference a PID from a batch
 *  whose process never got a node). */
export function resolvePids(roots: RunDetail["process_tree"], pids: number[]): Map<number, ReconActor> {
  const out = new Map<number, ReconActor>();
  const walk = (ns: RunDetail["process_tree"]) => {
    for (const n of ns) {
      if (n.pid !== undefined) out.set(n.pid, { pid: n.pid, process_name: n.process_name, command_line: n.command_line });
      walk(n.children);
    }
  };
  walk(roots);
  // Keep only the requested pids, preserving alert order.
  const kept = new Map<number, ReconActor>();
  for (const p of pids) if (out.has(p)) kept.set(p, out.get(p)!);
  return kept;
}
