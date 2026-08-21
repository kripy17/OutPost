// Overview page pure helpers — trend aggregation, findings collapse/ordering,
// alert aging, and intel-health/freshness. Moved out of the route file so the
// page stays fast-refreshable and the helpers stay unit-testable in isolation.

import type { RiskTrendBar } from "../components/Posture/Posture";
import type { GlobalAlert, IntelKeyStatus, RuleMeta, RunSummary } from "../types";

/* ── Risk trend aggregation — one bar per unique binary (peak risk), with the
   risk-0 host-monitor sessions excluded by default so the chart shows real
   findings, not the live-viewing noise. Per-session detail stays on History. */

export function aggregateTrend(runs: RunSummary[]): RiskTrendBar[] {
  const byName = new Map<string, RiskTrendBar>();
  for (const r of runs) {
    // Default out empty live-monitor sessions — they're viewing sessions,
    // not findings; a live session WITH a finding still shows.
    if (r.session_type === "live" && (r.risk_score ?? 0) === 0) continue;
    const cur = byName.get(r.sample_name) ?? { sample: r.sample_name, peak: 0, count: 0, last: "" };
    cur.peak = Math.max(cur.peak, r.risk_score ?? 0);
    cur.count += 1;
    if (!cur.last || r.started_at > cur.last) cur.last = r.started_at;
    byName.set(r.sample_name, cur);
  }
  return [...byName.values()].sort((a, b) => a.last.localeCompare(b.last));
}

interface CollapsedFinding {
  key: string;
  rule_id: string;
  sample_name: string;
  count: number;
  runs: Set<string>;
  first: GlobalAlert;
}

/** Identical findings (same rule + same sample) within a 5-minute window
 *  collapse into one row with a ×N badge — otherwise a single detonation's
 *  four alerts spam the feed four times in a row. Newest-first input. */
export function collapseFindings(alerts: GlobalAlert[]): CollapsedFinding[] {
  const WINDOW_MS = 5 * 60 * 1000;
  const groups: CollapsedFinding[] = [];
  for (const a of alerts) {
    const last = groups[groups.length - 1];
    const ts = new Date(a.triggered_at).getTime();
    const firstTs = last ? new Date(last.first.triggered_at).getTime() : 0;
    if (
      last &&
      last.rule_id === a.rule_id &&
      last.sample_name === a.sample_name &&
      Math.abs(firstTs - ts) < WINDOW_MS
    ) {
      last.count += 1;
      last.runs.add(a.run_id);
      continue;
    }
    groups.push({
      key: `${a.rule_id}|${a.sample_name}|${a.triggered_at}`,
      rule_id: a.rule_id,
      sample_name: a.sample_name,
      count: 1,
      runs: new Set([a.run_id]),
      first: a,
    });
  }
  return groups;
}

/** Risk-first ordering for the feed: malicious over suspicious, then heavier
 *  rules first, then newest. The SOC console reads "what's worst" at a glance
 *  instead of a pure time dump — time is still the final tiebreak. */
export function sortFindingsRiskFirst(groups: CollapsedFinding[], byRule: Map<string, RuleMeta>): CollapsedFinding[] {
  const sev = { malicious: 2, suspicious: 1 } as const;
  return [...groups].sort((a, b) => {
    const wa = byRule.get(a.rule_id);
    const wb = byRule.get(b.rule_id);
    const sa = sev[a.first.severity] + (wa?.weight ?? 0) / 100;
    const sb = sev[b.first.severity] + (wb?.weight ?? 0) / 100;
    if (sb !== sa) return sb - sa;
    return b.first.triggered_at.localeCompare(a.first.triggered_at);
  });
}

/** Human "open since" label for an alert, e.g. "open since 12m". */
export function openSince(a: GlobalAlert, now: number = Date.now()): string | null {
  if (a.status !== "open") return null;
  const start = new Date(a.triggered_at).getTime();
  const mins = Math.max(0, Math.floor((now - start) / 60_000));
  if (mins < 1) return "open · just now";
  if (mins < 60) return `open since ${mins}m`;
  const hrs = Math.floor(mins / 60);
  return `open since ${hrs}h`;
}

/** Age bucket for coloring the badge — 0 fresh, 1 warm (>30m), 2 hot (>2h). */
export function ageBucket(a: GlobalAlert, now: number = Date.now()): 0 | 1 | 2 {
  if (a.status !== "open") return 0;
  const mins = (now - new Date(a.triggered_at).getTime()) / 60_000;
  if (mins >= 120) return 2;
  if (mins >= 30) return 1;
  return 0;
}

/** Intel-key health — configured keys and any past the 90-day rotation age.
 *  Cheap by design: never auto-runs the live test (that would burn a provider
 *  quota unit on every page load); the deliberate Test button in Settings is
 *  the live probe. */
export function intelKeyHealth(keys: IntelKeyStatus[]): { tone: "ok" | "stale" | "none"; items: string[] } {
  const configured = keys.filter((k) => k.set);
  if (configured.length === 0) return { tone: "none", items: [] };
  const items = configured.map((k) => {
    const stale = k.source === "db" && k.age_days !== null && k.age_days > 90;
    return stale ? `${k.name} key ${k.age_days}d old — rotate` : `${k.name} key configured`;
  });
  return { tone: configured.some((k) => k.source === "db" && k.age_days !== null && k.age_days > 90) ? "stale" : "ok", items };
}

/** The Overview's run-query options — archive parity with History: soak-named
 *  collector baselines (soak-…) are hidden by default so the dashboard reads
 *  as real telemetry first; synthetic provenance stays visible (the Overview
 *  is the full-picture surface). Extracted so a contract test locks the
 *  default against future edits. */
export function overviewRunParams(): { include_soak: boolean } {
  return { include_soak: false };
}

/** Intel cache freshness — how stale the enrichment cache is fleet-wide
 *  (oldest verdict age + rows past the TTL). Feeds the one-line posture strip
 *  under the key health. */
export function intelFreshness(f: {
  total: number;
  stale_count: number;
  oldest_age_hours: number | null;
}): { tone: "ok" | "stale" | "none"; line: string | null } {
  if (!f.total) return { tone: "none", line: null };
  const age =
    f.oldest_age_hours === null ? "" : f.oldest_age_hours < 1 ? " · oldest <1h" : ` · oldest ${f.oldest_age_hours}h old`;
  if (f.stale_count > 0) return { tone: "stale", line: `${f.stale_count} of ${f.total} cached verdicts stale${age}` };
  return { tone: "ok", line: `intel cache fresh — ${f.total} verdicts${age}` };
}
