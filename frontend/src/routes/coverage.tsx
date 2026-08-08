// Coverage — MITRE ATT&CK tactic-coverage matrix (the "what can OutPost see?"
// page). Renders every Enterprise tactic as a column: tactics with mapped
// rules show their technique chips (technique code · rule name · weight);
// tactics with no rule are shown as dimmed gap columns so the blind spots are
// as visible as the coverage. Data is the same GET /rules/meta the detail
// page's ATT&CK chips read — one source of truth, no drift.

import { useQuery } from "@tanstack/react-query";
import ExportButton from "../components/ExportButton/ExportButton";
import { getNavigatorLayer, getRuleMeta } from "../lib/api";
import { PageHeader, Panel } from "../components/ui";
import type { RuleMeta } from "../types";

// The full MITRE ATT&CK (v15) Enterprise tactic order — all 14 canonical
// tactics. `covered` tactics are derived at render time; the list itself is
// static so the matrix always shows the complete picture, including the gaps.
// The verify.sh coverage gate enforces that every one of these has at least
// one rule, so the page and CI tell the same story.
const TACTICS = [
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
const TACTIC_BLURB: Record<string, string> = {
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

// Chip tone from the rule's *actual* fired severity (backend RULE_META), not
// a weight proxy — lolbin-abuse (weight 14) is malicious, suid-set (weight 18)
// is suspicious, and only severity tells them apart.
function severityTone(severity: string): string {
  return severity === "malicious"
    ? "border-risk-malicious/30 text-risk-malicious"
    : "border-risk-suspicious/30 text-risk-suspicious";
}

// The coverage matrix as an official MITRE Navigator layer — downloads the
// same JSON the Navigator's "Upload a layer" dialog accepts.
function NavigatorExportButton() {
  return (
    <span title="Downloads a MITRE ATT&CK Navigator v4.3 layer — open it via attack-navigator → Upload a layer">
      <ExportButton label="Export Navigator layer" filename="outpost-navigator-layer.json" fetcher={getNavigatorLayer} />
    </span>
  );
}

function TacticColumn({
  tactic,
  rules,
  unknown = false,
}: {
  tactic: string;
  rules: RuleMeta[];
  unknown?: boolean;
}) {
  const isGap = rules.length === 0;
  const totalWeight = rules.reduce((n, r) => n + r.weight, 0);
  return (
    <Panel
      kicker={unknown ? `${tactic} · not in canonical list` : tactic}
      title={
        isGap ? (
          <span className="text-text-muted">
            No rule yet <span className="text-risk-suspicious">· gap</span>
          </span>
        ) : (
          <span>
            {rules.length} rule{rules.length === 1 ? "" : "s"}
            <span className="ml-2 font-mono text-[10px] font-normal text-text-faint">Σ weight {totalWeight}</span>
          </span>
        )
      }
      className={isGap ? "opacity-70" : ""}
    >
      {isGap ? (
        <div className="flex min-h-[108px] flex-col gap-3">
          <p className="text-xs leading-relaxed text-text-muted">
            {TACTIC_BLURB[tactic] ?? "A tactic OutPost does not yet observe."}
          </p>
          <p className="mt-auto flex items-center gap-1.5 font-mono text-[10px] text-risk-suspicious">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-risk-suspicious/70" />
            uncovered — candidate for the next rule
          </p>
        </div>
      ) : (
        <ul className="space-y-2">
          {rules
            .slice()
            .sort((a, b) => b.weight - a.weight)
            .map((rule) => (
              <li key={rule.rule_id} className="group">
                <div className={`flex items-baseline gap-2 rounded-lg border bg-bg-elevated/40 px-2.5 py-2 transition-colors duration-150 ${severityTone(rule.severity)} group-hover:bg-bg-elevated/70`}>
                  <code className="shrink-0 font-mono text-[11px] font-semibold">{rule.technique}</code>
                  <span className="min-w-0 flex-1 truncate text-xs text-text-primary" title={rule.rule_name}>
                    {rule.rule_name}
                  </span>
                  <span className="shrink-0 font-mono text-[10px] text-text-faint">+{rule.weight}</span>
                </div>
              </li>
            ))}
        </ul>
      )}
    </Panel>
  );
}

export default function CoveragePage() {
  const { data = [], isLoading, isError } = useQuery({
    queryKey: ["rules-meta"],
    queryFn: getRuleMeta,
    staleTime: 30_000,
  });

  // Bucket rules by tactic, preserving the canonical order.
  const byTactic = new Map<string, RuleMeta[]>();
  for (const rule of data) {
    const t = rule.tactic;
    if (!byTactic.has(t)) byTactic.set(t, []);
    byTactic.get(t)!.push(rule);
  }
  const covered = TACTICS.filter((t) => byTactic.has(t));
  const gaps = TACTICS.filter((t) => !byTactic.has(t));
  // Rules whose tactic isn't in the canonical list (future stage, renamed
  // tactic, backend typo) must never vanish — the matrix renders them in a
  // catch-all column instead of silently dropping them (the "N rules" stat
  // counts them, so an invisible rule would contradict the header).
  const unknownTactics = [...byTactic.keys()].filter((t) => !(TACTICS as readonly string[]).includes(t));
  const techniques = new Set(data.map((r) => r.technique)).size;

  return (
    <div className="mx-auto max-w-7xl px-6 py-10">
      <PageHeader
        kicker="Intelligence · ATT&CK"
        title={
          <>
            Detection coverage <span className="font-normal text-text-muted">— the MITRE matrix we see</span>
          </>
        }
        lede="Every tactic OutPost can (and cannot) detect, mapped to the rules that cover it. Gap columns are the roadmap — each one is a candidate rule family."
      />

      {isLoading && <p className="mt-6 text-sm text-text-muted">Mapping rules to tactics…</p>}
      {isError && (
        <p className="mt-6 rounded border border-risk-malicious/40 px-3 py-2 text-sm text-risk-malicious">
          Couldn't reach the backend for rule metadata.
        </p>
      )}

      {!isLoading && !isError && (
        <>
          {/* Summary strip — coverage at a glance, gaps called out. */}
          <div className="mt-6 flex flex-wrap items-center gap-x-6 gap-y-2 font-mono text-[11px] text-text-faint">
            <span>
              <span className="font-semibold text-text-primary">{covered.length}</span> / {TACTICS.length} tactics covered
            </span>
            <span>
              <span className="font-semibold text-text-primary">{data.length}</span> rules
            </span>
            <span>
              <span className="font-semibold text-text-primary">{techniques}</span> techniques
            </span>
            {gaps.length > 0 && (
              <span className="rounded-full border border-risk-suspicious/30 px-2 py-0.5 text-risk-suspicious">
                {gaps.length} gap{gaps.length === 1 ? "" : "s"}: {gaps.join(" · ")}
              </span>
            )}
            <span className="ml-auto">
              <NavigatorExportButton />
            </span>
          </div>

          {/* The matrix — one column per tactic, canonical order. */}
          <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
            {TACTICS.map((tactic) => (
              <TacticColumn key={tactic} tactic={tactic} rules={byTactic.get(tactic) ?? []} />
            ))}
            {unknownTactics.map((tactic) => (
              <TacticColumn
                key={tactic}
                tactic={tactic}
                rules={byTactic.get(tactic) ?? []}
                unknown
              />
            ))}
          </div>

          {/* Legend for the technique chips. */}
          <p className="mt-4 font-mono text-[10px] text-text-faint">
            chips show ATT&CK technique · rule · risk weight · red chip = malicious-severity rule, amber = suspicious.
            Gap columns stay visible on purpose — the uncovered tactics are the roadmap.
          </p>
        </>
      )}
    </div>
  );
}
