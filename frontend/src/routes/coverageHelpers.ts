// Pure derivation for the ATT&CK Coverage matrix — extracted from the page
// so the gap-detection contract (every one of the 14 Enterprise tactics has
// at least one rule, enforced by verify.sh) is unit-testable.

import type { RuleMeta } from "../types";

// The full MITRE ATT&CK (v15) Enterprise tactic order — all 14 canonical
// tactics. `covered` tactics are derived from the rules; the list itself is
// static so the matrix always shows the complete picture, including gaps.
export const TACTICS = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
] as const;

// Tactic → one-line what-it-means, shown under the header of a gap column so
// a missing tactic reads as "here's what we can't see yet", not just a hole.
export const TACTIC_BLURB: Record<string, string> = {
  Reconnaissance: "Learning about targets first — active scanning, port sweeps, host discovery.",
  "Resource Development": "Building the attack kit — compiling tools, acquiring payloads before the intrusion.",
  "Initial Access": "How an attacker gets in — phishing lures, exploit kits, exposed services.",
  Execution: "Running code — script hosts, LOLBins, inline interpreters.",
  Persistence: "Staying loaded across reboot — Run keys, cron, autostart, tasks.",
  "Privilege Escalation": "Gaining higher rights — SUID, token tricks, service abuse.",
  "Defense Evasion": "Hiding — masquerading, wiping logs, anti-forensics.",
  "Credential Access": "Stealing secrets — LSASS dumps, hives, key material.",
  Discovery: "Learning the environment — enumeration of users, shares, domains.",
  "Lateral Movement": "Moving host-to-host — remote execution, RDP, SMB tricks.",
  Collection: "Gathering data to steal — staging, clipboard, archives.",
  "Command and Control": "Talking to the operator — beacons, unusual ports.",
  Exfiltration: "Getting data out — archive-and-upload, DNS tunneling.",
  Impact: "Damage — ransomware bursts, destruction, encryption.",
};

/** Chip tone from the rule's *actual* fired severity (backend RULE_META), not
 *  a weight proxy — lolbin-abuse (weight 14) is malicious, suid-set (weight
 *  18) is suspicious, and only severity tells them apart. */
export function severityTone(severity: string): string {
  return severity === "malicious"
    ? "border-risk-malicious/30 text-risk-malicious"
    : "border-risk-suspicious/30 text-risk-suspicious";
}

export interface CoverageShape {
  /** tactic → its rules, insertion-ordered. */
  byTactic: Map<string, RuleMeta[]>;
  /** Canonical tactics with at least one rule (canonical order). */
  covered: string[];
  /** Canonical tactics with no rule — the visible blind spots. */
  gaps: string[];
  /** Rules whose tactic isn't in the canonical list — never dropped, they
   *  render in a catch-all column instead of vanishing silently. */
  unknownTactics: string[];
  techniqueCount: number;
}

/** Bucket rules by tactic and derive the coverage/gap split. Pure — the page
 *  renders exactly this shape; CI's coverage gate reads the same 14 tactics. */
export function buildCoverage(rules: RuleMeta[]): CoverageShape {
  const byTactic = new Map<string, RuleMeta[]>();
  for (const rule of rules) {
    const t = rule.tactic;
    if (!byTactic.has(t)) byTactic.set(t, []);
    byTactic.get(t)!.push(rule);
  }
  const canonical = TACTICS as readonly string[];
  const covered = canonical.filter((t) => byTactic.has(t));
  const gaps = canonical.filter((t) => !byTactic.has(t));
  // Rules whose tactic isn't in the canonical list (future stage, renamed
  // tactic, backend typo) must never vanish — the matrix renders them in a
  // catch-all column instead of silently dropping them (the "N rules" stat
  // counts them, so an invisible rule would contradict the header).
  const unknownTactics = [...byTactic.keys()].filter((t) => !canonical.includes(t));
  const techniqueCount = new Set(rules.map((r) => r.technique)).size;
  return { byTactic, covered, gaps, unknownTactics, techniqueCount };
}
