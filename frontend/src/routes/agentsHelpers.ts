// Pure derivations for the agents fleet page — relative-time labels, the
// channel tone mapping (shared with the Overview panel and CLI chips), and
// the per-channel volume mix — extracted so the fleet readout contracts are
// unit-testable.

/** Relative time: "just now" under 5s, then s/m/h/d. `now` is injectable so
 *  tests pin the clock. */
export function relativeTime(iso: string, now: number = Date.now()): string {
  const then = new Date(iso).getTime();
  const secs = Math.max(0, Math.floor((now - then) / 1000));
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

/** Channel mix bar color — same mapping as the Overview panel and CLI chips:
 *  auditd teal, sysmon amber, any other channel (webapp, custom) muted. */
export function channelTone(channel: string): string {
  if (channel === "auditd") return "bg-risk-clean";
  if (channel === "sysmon") return "bg-accent";
  return "bg-text-faint";
}

export interface ChannelMixEntry {
  channel: string;
  count: number;
  /** Share of the host's telemetry, 0–100. */
  pct: number;
}

/** The host's telemetry mix: channels sorted by volume, each with its share
 *  of the total. Empty counts → empty list. */
export function channelMix(counts: Record<string, number>): ChannelMixEntry[] {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([channel, count]) => ({ channel, count, pct: total > 0 ? Math.round((count / total) * 100) : 0 }));
}
