// Coverage — MITRE ATT&CK tactic-coverage matrix (the "what can OutPost see?"
// page). Renders every Enterprise tactic as a column: tactics with mapped
// rules show their technique chips (technique code · rule name · weight);
// tactics with no rule are shown as dimmed gap columns so the blind spots are
// as visible as the coverage. Data is the same GET /rules/meta the detail
// page's ATT&CK chips read — one source of truth, no drift.

import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import ExportButton from "../components/ExportButton/ExportButton";
import { Icon } from "../components/Icon";
import { getNavigatorLayer, getRuleMeta } from "../lib/api";
import { PageHeader, Panel } from "../components/ui";
import { buildCoverage, severityTone, TACTICS, TACTIC_BLURB } from "./coverageHelpers";
import type { RuleMeta } from "../types";

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
                <Link
                  to="/rules"
                  className={`flex items-baseline gap-2 rounded-lg border bg-bg-elevated/40 px-2.5 py-2 transition-colors duration-150 ${severityTone(rule.severity)} group-hover:border-accent/50 group-hover:bg-bg-elevated/70`}
                  title={rule.technique_name ? `${rule.technique} · ${rule.technique_name}` : `View detection rule details for ${rule.rule_name}`}
                >
                  <code className="shrink-0 font-mono text-[11px] font-semibold">{rule.technique}</code>
                  {rule.technique_name && (
                    <span className="hidden min-w-0 flex-1 truncate text-[10px] text-text-faint lg:inline" title={rule.technique_name}>
                      {rule.technique_name}
                    </span>
                  )}
                  <span className="min-w-0 flex-1 truncate text-xs text-text-primary group-hover:text-accent" title={rule.rule_name}>
                    {rule.rule_name}
                  </span>
                  <span className="shrink-0 font-mono text-[10px] text-text-faint">+{rule.weight}</span>
                </Link>
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
  // "Gaps only" focus mode — dims covered tactics entirely so the blind spots
  // read at a glance. Persisted (`outpost-coverage-gaps`) across visits.
  const [gapsOnly, setGapsOnly] = useState(() => localStorage.getItem("outpost-coverage-gaps") === "1");
  useEffect(() => {
    try {
      localStorage.setItem("outpost-coverage-gaps", gapsOnly ? "1" : "0");
    } catch {
      /* storage unavailable — toggle still applies for this visit */
    }
  }, [gapsOnly]);

  // Bucket rules by tactic, preserving the canonical order — pure derivation
  // (coverageHelpers) so the gap-detection contract is unit-testable.
  const { byTactic, covered, gaps, unknownTactics, techniqueCount: techniques } = buildCoverage(data);

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
            <button
              onClick={() => setGapsOnly((v) => !v)}
              aria-pressed={gapsOnly}
              className={`press inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 transition-colors duration-150 ${
                gapsOnly ? "border-accent/50 bg-accent/10 text-accent" : "border-border-subtle text-text-muted hover:text-text-primary"
              }`}
              title={gapsOnly ? "Show every tactic, covered or not" : "Hide covered tactics — focus on the blind spots"}
            >
              {gapsOnly && <Icon name="eye" size={10} />}
              gaps only
            </button>
            <span className="ml-auto">
              <NavigatorExportButton />
            </span>
          </div>

          {/* The matrix — one column per tactic, canonical order. In "gaps only"
              mode, covered tactics collapse away and only the blind spots
              (canonical gaps + any unknown-tactic catch-all) remain. */}
          {gapsOnly && gaps.length === 0 ? (
            <div className="mt-6 rounded-2xl border border-dashed border-border-strong bg-bg-surface/40 p-10 text-center">
              <Icon name="shield" size={24} className="mx-auto text-risk-clean" />
              <p className="mt-3 text-sm text-text-muted">
                No gaps — every one of the {TACTICS.length} tactics has at least one rule. Nothing to hunt.
              </p>
            </div>
          ) : (
            <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
              {(gapsOnly ? gaps : TACTICS).map((tactic) => (
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
          )}

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
