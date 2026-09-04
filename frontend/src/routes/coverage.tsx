// Coverage — MITRE ATT&CK tactic-coverage matrix (the "what can OutPost see?"
// page). Renders every Enterprise tactic as a column: tactics with mapped
// rules show their technique chips (technique code · rule name · weight);
// tactics with no rule are shown as dimmed gap columns so the blind spots are
// as visible as the coverage. Data is the same GET /rules/meta the detail
// page's ATT&CK chips read — one source of truth, no drift.
// Also supports Adversary Simulation Matrix mode: unit test techniques mapped
// across tactics with automated cleanup and telemetry contracts.

import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import ExportButton from "../components/ExportButton/ExportButton";
import { Icon } from "../components/Icon";
import { getNavigatorLayer, getRuleMeta, listTechniqueTests, runTechniqueTest } from "../lib/api";
import { PageHeader, Panel } from "../components/ui";
import { buildCoverage, severityTone, TACTICS, TACTIC_BLURB } from "./coverageHelpers";
import type { RuleMeta, TechniqueRunResult, TechniqueTestItem } from "../types";

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
  searchQuery = "",
  unknown = false,
}: {
  tactic: string;
  rules: RuleMeta[];
  searchQuery?: string;
  unknown?: boolean;
}) {
  const isGap = rules.length === 0;
  const totalWeight = rules.reduce((n, r) => n + r.weight, 0);
  const q = searchQuery.toLowerCase().trim();

  const filteredRules = q
    ? rules.filter(
        (r) =>
          r.rule_name.toLowerCase().includes(q) ||
          r.technique.toLowerCase().includes(q) ||
          r.rule_id.toLowerCase().includes(q),
      )
    : rules;

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
        <div className="flex min-h-[108px] flex-col justify-between gap-3">
          <p className="text-xs leading-relaxed text-text-muted">
            {TACTIC_BLURB[tactic] ?? "A tactic OutPost does not yet observe."}
          </p>
          <div className="space-y-2">
            <p className="flex items-center gap-1.5 font-mono text-[10px] text-risk-suspicious">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-risk-suspicious/70" />
              uncovered — candidate for the next rule
            </p>
            <Link
              to={`/rules?create=1&tactic=${encodeURIComponent(tactic)}`}
              className="press inline-flex items-center gap-1 rounded-md border border-accent/40 bg-accent/10 px-2.5 py-1 font-mono text-[10px] font-semibold text-accent hover:bg-accent/20"
            >
              <Icon name="plus" size={10} />
              Author Rule for {tactic}
            </Link>
          </div>
        </div>
      ) : filteredRules.length === 0 && q ? (
        <p className="py-4 text-center font-mono text-[11px] text-text-faint">No rules match query</p>
      ) : (
        <ul className="space-y-2">
          {filteredRules
            .slice()
            .sort((a, b) => b.weight - a.weight)
            .map((rule) => (
              <li key={rule.rule_id} className="group">
                <Link
                  to={`/rules?rule_id=${encodeURIComponent(rule.rule_id)}`}
                  className={`flex items-baseline gap-2 rounded-lg border bg-bg-elevated/40 px-2.5 py-2 transition-colors duration-150 ${severityTone(rule.severity)} group-hover:border-accent/50 group-hover:bg-bg-elevated/70`}
                  title={`Open ${rule.rule_name} (${rule.rule_id}) in Detection Rule Workbench`}
                >
                  <code className="shrink-0 font-mono text-[11px] font-semibold">{rule.technique}</code>
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

function SimulationTacticColumn({
  tactic,
  techniques,
  searchQuery = "",
  runningTestId = null,
  onRunTest,
}: {
  tactic: string;
  techniques: TechniqueTestItem[];
  searchQuery?: string;
  runningTestId?: string | null;
  onRunTest: (testId: string) => void;
}) {
  const isGap = techniques.length === 0;
  const q = searchQuery.toLowerCase().trim();

  const filtered = q
    ? techniques.filter(
        (t) =>
          t.name.toLowerCase().includes(q) ||
          t.technique_id.toLowerCase().includes(q) ||
          t.id.toLowerCase().includes(q) ||
          t.description.toLowerCase().includes(q),
      )
    : techniques;

  return (
    <Panel
      kicker={tactic}
      title={
        isGap ? (
          <span className="text-text-muted">
            Untested <span className="text-text-faint">· 0 canaries</span>
          </span>
        ) : (
          <span>
            {techniques.length} canary{techniques.length === 1 ? "" : " tests"}
          </span>
        )
      }
      className={isGap ? "opacity-70" : ""}
    >
      {isGap ? (
        <div className="flex min-h-[108px] flex-col justify-between gap-3">
          <p className="text-xs leading-relaxed text-text-muted">
            {TACTIC_BLURB[tactic] ?? "No adversary unit tests registered for this tactic."}
          </p>
          <span className="font-mono text-[10px] text-text-faint">Simulation catalog coverage gap</span>
        </div>
      ) : filtered.length === 0 && q ? (
        <p className="py-4 text-center font-mono text-[11px] text-text-faint">No canaries match query</p>
      ) : (
        <ul className="space-y-2">
          {filtered.map((t) => (
            <li key={t.id} className="rounded-lg border border-border-subtle bg-bg-elevated/40 p-2.5 transition hover:border-accent/40">
              <div className="flex items-baseline justify-between gap-2">
                <span className="font-mono text-xs font-bold text-accent">{t.technique_id}</span>
                <div className="flex items-center gap-1">
                  {(t.supported_platforms || []).map((p) => (
                    <span key={p} className="rounded bg-bg-base px-1 py-0.2 font-mono text-[9px] uppercase text-text-faint">
                      {p === "darwin" ? "macOS" : p}
                    </span>
                  ))}
                </div>
              </div>

              <div className="mt-1 text-xs font-semibold text-text-primary leading-snug">{t.name}</div>
              <p className="mt-1 text-[11px] text-text-muted line-clamp-2 leading-relaxed">{t.description}</p>

              <div className="mt-2 flex items-center justify-between border-t border-border-subtle/50 pt-2">
                <span className="font-mono text-[9px] text-emerald-400">✓ Cleanup contract</span>
                <button
                  type="button"
                  disabled={runningTestId === t.id}
                  onClick={() => onRunTest(t.id)}
                  className="press inline-flex items-center gap-1 rounded bg-accent/15 px-2 py-0.5 font-mono text-[10px] font-semibold text-accent hover:bg-accent/25 disabled:opacity-50"
                >
                  {runningTestId === t.id ? (
                    <Icon name="refresh" size={10} className="animate-spin" />
                  ) : (
                    <Icon name="terminal" size={10} />
                  )}
                  <span>{runningTestId === t.id ? "Running..." : "Run Canary"}</span>
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export default function CoveragePage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [coverageMode, setCoverageMode] = useState<"rules" | "simulations">("rules");
  const [simPlatform, setSimPlatform] = useState<string>("all");
  const [runningTestId, setRunningTestId] = useState<string | null>(null);
  const [activeTestResult, setActiveTestResult] = useState<TechniqueRunResult | null>(null);

  const { data = [], isLoading, isError } = useQuery({
    queryKey: ["rules-meta"],
    queryFn: getRuleMeta,
    staleTime: 30_000,
  });

  const { data: simTechniques = [] } = useQuery<TechniqueTestItem[]>({
    queryKey: ["sim-techniques", simPlatform],
    queryFn: () => listTechniqueTests(undefined, simPlatform === "all" ? undefined : simPlatform),
    staleTime: 30_000,
  });

  // "Gaps only" focus mode
  const [gapsOnly, setGapsOnly] = useState(() => localStorage.getItem("outpost-coverage-gaps") === "1");
  useEffect(() => {
    try {
      localStorage.setItem("outpost-coverage-gaps", gapsOnly ? "1" : "0");
    } catch {
      /* storage unavailable */
    }
  }, [gapsOnly]);

  const { byTactic, covered, gaps, unknownTactics, techniqueCount: techniques } = buildCoverage(data);

  // Group simulation techniques by tactic
  const simByTactic = new Map<string, TechniqueTestItem[]>();
  for (const t of TACTICS) {
    simByTactic.set(t, []);
  }
  for (const st of simTechniques) {
    const list = simByTactic.get(st.tactic) || [];
    list.push(st);
    simByTactic.set(st.tactic, list);
  }

  const handleRunTest = async (testId: string) => {
    setRunningTestId(testId);
    setActiveTestResult(null);
    try {
      const res = await runTechniqueTest(testId);
      setActiveTestResult(res);
    } catch (e: any) {
      console.error(e);
    } finally {
      setRunningTestId(null);
    }
  };

  return (
    <div className="mx-auto max-w-7xl px-6 py-10">
      <PageHeader
        kicker="Intelligence · ATT&CK Matrix"
        title={
          <>
            MITRE Enterprise Coverage <span className="font-normal text-text-muted">— detection &amp; simulation</span>
          </>
        }
        lede="Analyze detection rules and adversary technique simulations mapped across MITRE ATT&CK tactics. Uncovered columns represent opportunities for rule creation and attack canary testing."
        actions={
          <div className="flex items-center gap-2">
            <div className="inline-flex rounded-lg border border-border-subtle bg-bg-surface p-0.5 text-xs font-semibold">
              <button
                type="button"
                onClick={() => setCoverageMode("rules")}
                className={`rounded-md px-3 py-1 transition ${
                  coverageMode === "rules" ? "bg-accent text-bg-base font-bold shadow-sm" : "text-text-muted hover:text-text"
                }`}
              >
                Detection Rules
              </button>
              <button
                type="button"
                onClick={() => setCoverageMode("simulations")}
                className={`rounded-md px-3 py-1 transition ${
                  coverageMode === "simulations" ? "bg-accent text-bg-base font-bold shadow-sm" : "text-text-muted hover:text-text"
                }`}
              >
                Adversary Canaries
              </button>
            </div>
          </div>
        }
      />

      {/* Live Technique Canary Execution Result Modal / Drawer */}
      {activeTestResult && (
        <div className="mt-6 rounded-2xl border border-accent/40 bg-bg-elevated/80 p-4 space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-border-subtle pb-2">
            <div className="flex items-center gap-2">
              <span className={`h-2.5 w-2.5 rounded-full ${activeTestResult.status === "success" ? "bg-emerald-400" : "bg-rose-400"}`} />
              <span className="font-bold text-text-normal">
                {activeTestResult.technique_id} · {activeTestResult.name}
              </span>
              <span className="text-[10px] text-text-faint">({activeTestResult.status} in {activeTestResult.elapsed_ms}ms)</span>
            </div>
            <button
              type="button"
              onClick={() => setActiveTestResult(null)}
              className="text-text-faint hover:text-text-normal"
            >
              <Icon name="x" size={14} />
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px]">
            <div>
              <span className="text-text-faint block">Exit Code:</span>
              <strong className={activeTestResult.exit_code === 0 ? "text-emerald-400" : "text-rose-400"}>
                {activeTestResult.exit_code}
              </strong>
            </div>
            <div>
              <span className="text-text-faint block">Cleanup Contract:</span>
              <strong className="text-emerald-400">{activeTestResult.cleanup_status}</strong>
            </div>
            <div>
              <span className="text-text-faint block">Telemetry Contract:</span>
              <strong className={activeTestResult.telemetry_verified ? "text-emerald-400" : "text-amber-400"}>
                {activeTestResult.telemetry_verified ? "Verified (100%)" : `${activeTestResult.telemetry_coverage_pct ?? 50}%`}
              </strong>
            </div>
            <div>
              <span className="text-text-faint block">Events / Alerts:</span>
              <strong className="text-accent">
                {activeTestResult.events_count} events · {activeTestResult.alerts_count} alert(s)
              </strong>
            </div>
          </div>

          {activeTestResult.stdout && (
            <div className="rounded bg-[#0a0c10] p-2 text-[10px] text-emerald-400 max-h-24 overflow-y-auto">
              <pre className="whitespace-pre-wrap">{activeTestResult.stdout}</pre>
            </div>
          )}
        </div>
      )}

      {isLoading && <p className="mt-6 text-sm text-text-muted">Mapping rules to tactics…</p>}
      {isError && (
        <p className="mt-6 rounded border border-risk-malicious/40 px-3 py-2 text-sm text-risk-malicious">
          Couldn't reach the backend for rule metadata.
        </p>
      )}

      {!isLoading && !isError && (
        <>
          {/* Controls Strip */}
          <div className="mt-6 flex flex-wrap items-center justify-between gap-4 font-mono text-[11px] text-text-faint">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
              {coverageMode === "rules" ? (
                <>
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
                      {gaps.length} gap{gaps.length === 1 ? "" : "s"}
                    </span>
                  )}
                  <button
                    onClick={() => setGapsOnly((v) => !v)}
                    aria-pressed={gapsOnly}
                    className={`press inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 transition-colors duration-150 ${
                      gapsOnly ? "border-accent/50 bg-accent/10 text-accent" : "border-border-subtle text-text-muted hover:text-text-primary"
                    }`}
                  >
                    {gapsOnly && <Icon name="eye" size={10} />}
                    gaps only
                  </button>
                </>
              ) : (
                <>
                  <span>
                    <span className="font-semibold text-text-primary">{simTechniques.length}</span> adversary canaries
                  </span>
                  <div className="flex items-center gap-1">
                    {["all", "linux", "darwin", "windows"].map((p) => (
                      <button
                        key={p}
                        type="button"
                        onClick={() => setSimPlatform(p)}
                        className={`rounded px-2 py-0.5 text-[10px] uppercase font-semibold ${
                          simPlatform === p ? "bg-accent text-bg-base" : "bg-bg-surface text-text-muted hover:text-text"
                        }`}
                      >
                        {p === "darwin" ? "macOS" : p}
                      </button>
                    ))}
                  </div>
                </>
              )}
            </div>

            <div className="flex items-center gap-3">
              <div className="relative">
                <Icon name="search" size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-faint" />
                <input
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder={coverageMode === "rules" ? "Filter techniques & rules…" : "Filter adversary canaries…"}
                  className="w-52 rounded-lg border border-border-subtle bg-bg-surface py-1 pl-8 pr-3 font-mono text-xs text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
                />
              </div>
              {coverageMode === "rules" && <NavigatorExportButton />}
            </div>
          </div>

          {/* Matrix Grid */}
          {coverageMode === "rules" ? (
            gapsOnly && gaps.length === 0 ? (
              <div className="mt-6 rounded-2xl border border-dashed border-border-strong bg-bg-surface/40 p-10 text-center">
                <Icon name="shield" size={24} className="mx-auto text-risk-clean" />
                <p className="mt-3 text-sm text-text-muted">
                  No gaps — every one of the {TACTICS.length} tactics has at least one rule. Nothing to hunt.
                </p>
              </div>
            ) : (
              <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
                {(gapsOnly ? gaps : TACTICS).map((tactic) => (
                  <TacticColumn
                    key={tactic}
                    tactic={tactic}
                    rules={byTactic.get(tactic) ?? []}
                    searchQuery={searchQuery}
                  />
                ))}
                {unknownTactics.map((tactic) => (
                  <TacticColumn
                    key={tactic}
                    tactic={tactic}
                    rules={byTactic.get(tactic) ?? []}
                    searchQuery={searchQuery}
                    unknown
                  />
                ))}
              </div>
            )
          ) : (
            <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
              {TACTICS.map((tactic) => (
                <SimulationTacticColumn
                  key={tactic}
                  tactic={tactic}
                  techniques={simByTactic.get(tactic) ?? []}
                  searchQuery={searchQuery}
                  runningTestId={runningTestId}
                  onRunTest={handleRunTest}
                />
              ))}
            </div>
          )}

          <p className="mt-4 font-mono text-[10px] text-text-faint">
            {coverageMode === "rules"
              ? "Chips show ATT&CK technique · rule · risk weight · red chip = malicious-severity rule, amber = suspicious. Gap columns stay visible on purpose."
              : "Canary tests execute safe, non-destructive synthetic behavioral telemetry with automated cleanup and sensor contract assertions."}
          </p>
        </>
      )}
    </div>
  );
}
