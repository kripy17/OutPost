// Risk/reputation colors — defined once, reused everywhere (docs/04 styling notes).
// Tails match the design tokens in docs/07-UI-DESIGN-SYSTEM.md.

import type { Reputation, Severity } from "../types";

export const RISK_COLORS: Record<Reputation, string> = {
  clean: "text-risk-clean",
  suspicious: "text-risk-suspicious",
  malicious: "text-risk-malicious",
  unknown: "text-text-muted",
};

export const RISK_BG: Record<Reputation, string> = {
  clean: "bg-risk-clean",
  suspicious: "bg-risk-suspicious",
  malicious: "bg-risk-malicious",
  unknown: "bg-text-muted",
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  suspicious: "text-risk-suspicious",
  malicious: "text-risk-malicious",
};

export const SEVERITY_BG: Record<Severity, string> = {
  suspicious: "bg-risk-suspicious",
  malicious: "bg-risk-malicious",
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  suspicious: "Suspicious",
  malicious: "Malicious",
};

// Kill-chain stages (rule_id → stage) — mirrors detection._KILL_CHAIN_STAGE
// so the run-detail stepper and the backend correlation stay in lockstep.
export const KILL_CHAIN_STAGE: Record<string, string> = {
  masquerading: "Defense Evasion",
  "suspicious-parent-child": "Execution",
  "lolbin-abuse": "Execution",
  "first-seen-process": "Execution",
  beaconing: "Command and Control",
  "unusual-port": "Command and Control",
  "registry-persistence": "Persistence",
  "autostart-persistence": "Persistence",
  "ssh-authorized-keys": "Persistence",
  "scheduled-task": "Persistence",
  "suid-set": "Privilege Escalation",
  "credential-dump": "Credential Access",
  "suspicious-extension": "Defense Evasion",
  "shell-history-wipe": "Defense Evasion",
  "enumeration-burst": "Discovery",
  "data-staging": "Exfiltration",
  "rename-burst": "Impact",
  "attack-chain": "Full Chain",
};

export const KILL_CHAIN_ORDER = [
  "Execution",
  "Defense Evasion",
  "Command and Control",
  "Persistence",
  "Privilege Escalation",
  "Credential Access",
  "Discovery",
  "Exfiltration",
  "Impact",
  "Full Chain",
];

// Trend windows for the History charts — span + bucket size per window.
// Hourly buckets on 24h (the dashboard's original resolution); daily buckets
// on 7d and All so the trend line stays legible over longer spans.
export type TrendWindow = "24h" | "7d" | "all";

/** MM-DD — axis label for daily-bucketed windows (7d / all). */
export function fmtDayShort(ts: number): string {
  return new Date(ts).toISOString().slice(5, 10);
}

export const TREND_WINDOWS: { key: TrendWindow; label: string; spanMs: number; bucketMs: number }[] = [
  { key: "24h", label: "24h", spanMs: 24 * 3_600_000, bucketMs: 3_600_000 },
  { key: "7d", label: "7d", spanMs: 7 * 86_400_000, bucketMs: 86_400_000 },
  { key: "all", label: "All", spanMs: Infinity, bucketMs: 86_400_000 },
];

// Enumeration-burst alert details read "…: label, label, label" — the
// trailing list is the distinct recon *kinds* (the CLI's chips and the
// webapp's ReconActorsPanel badges both parse this same shape). Shared here
// so the run-detail panel and the live Monitor stay in lockstep.
export function enumKindsFromDetails(details: string): string[] {
  const idx = details.indexOf(": ");
  if (idx === -1) return [];
  return details
    .slice(idx + 2)
    .split(", ")
    .map((s) => s.trim())
    .filter(Boolean);
}

// Risk bands (roadmap 1.3) — score → color + label, reused by the detail
// gauge and the history-card badge. Bands: 0 none, 1-29 low, 30-59 elevated,
// 60+ critical.
export function riskBand(score: number | undefined): { label: string; color: string; bg: string } {
  // Defensive: a stale backend/client may not yet send risk_score (undefined
  // would otherwise fall through every comparison into "critical").
  const s = score ?? 0;
  if (s <= 0) return { label: "none", color: "text-risk-clean", bg: "bg-risk-clean" };
  if (s < 30) return { label: "low", color: "text-risk-clean", bg: "bg-risk-clean" };
  if (s < 60) return { label: "elevated", color: "text-risk-suspicious", bg: "bg-risk-suspicious" };
  return { label: "critical", color: "text-risk-malicious", bg: "bg-risk-malicious" };
}
