import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Icon } from "../Icon";
import { importSigmaRule, transpileSigmaRule } from "../../lib/api";

const DEFAULT_SIGMA_TEMPLATE = `title: Detect Suspicious Process Injection
id: rule-custom-injection-01
status: test
description: Detects process injection primitives into system services
author: OutPost Detection Engineering
date: 2026/10/10
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - 'ptrace'
      - 'process_vm_writev'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1055
`;

interface RuleEditorWorkbenchProps {
  initialYaml?: string;
  onOpenBacktest?: (rule: { name: string; customYaml?: string }) => void;
  onOpenTest?: (rule: { name: string; customYaml?: string }) => void;
}

export function RuleEditorWorkbench({
  initialYaml,
  onOpenBacktest,
  onOpenTest,
}: RuleEditorWorkbenchProps) {
  const queryClient = useQueryClient();
  const [authorMode, setAuthorMode] = useState<"builder" | "yaml">("builder");
  const [yaml, setYaml] = useState(initialYaml || DEFAULT_SIGMA_TEMPLATE);

  // Visual Rule Builder state
  const [builderTitle, setBuilderTitle] = useState("Detect Suspicious Process Injection");
  const [builderDesc, setBuilderDesc] = useState("Detects process injection primitives into system services");
  const [builderLevel, setBuilderLevel] = useState("high");
  const [builderPlatform, setBuilderPlatform] = useState("linux");
  const [builderCategory, setBuilderCategory] = useState("process_creation");
  const [builderTactic, setBuilderTactic] = useState("defense_evasion");
  const [builderTechnique, setBuilderTechnique] = useState("T1055");
  const [builderCriteria, setBuilderCriteria] = useState<Array<{ field: string; modifier: string; value: string }>>([
    { field: "CommandLine", modifier: "contains", value: "ptrace, process_vm_writev" },
  ]);
  const [builderExclusions, setBuilderExclusions] = useState<Array<{ field: string; modifier: string; value: string }>>([
    { field: "User", modifier: "contains", value: "gdb_service" },
  ]);

  // Transpilation state
  const [transpiledResult, setTranspiledResult] = useState<any | null>(null);
  const [transpileError, setTranspileError] = useState<string | null>(null);
  const [transpiling, setTranspiling] = useState(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // Generate YAML from builder state
  const generateYamlFromBuilder = () => {
    const lines = [
      `title: ${builderTitle.trim()}`,
      `id: custom-${Date.now().toString(36)}`,
      `status: experimental`,
      `description: ${builderDesc.trim()}`,
      `author: OutPost Detection Engineering`,
      `date: ${new Date().toISOString().slice(0, 10).replace(/-/g, "/")}`,
      `logsource:`,
      `  category: ${builderCategory}`,
      `  product: ${builderPlatform}`,
      `detection:`,
      `  selection:`,
    ];

    builderCriteria.forEach((crit) => {
      const vals = crit.value.split(",").map((v) => v.trim()).filter(Boolean);
      lines.push(`    ${crit.field}|${crit.modifier}:`);
      vals.forEach((v) => lines.push(`      - '${v}'`));
    });

    if (builderExclusions.length > 0 && builderExclusions.some((e) => e.value.trim())) {
      lines.push(`  filter:`);
      builderExclusions.forEach((ex) => {
        if (!ex.value.trim()) return;
        const vals = ex.value.split(",").map((v) => v.trim()).filter(Boolean);
        lines.push(`    ${ex.field}|${ex.modifier}:`);
        vals.forEach((v) => lines.push(`      - '${v}'`));
      });
      lines.push(`  condition: selection and not filter`);
    } else {
      lines.push(`  condition: selection`);
    }

    lines.push(`level: ${builderLevel}`);
    lines.push(`tags:`);
    if (builderTactic) lines.push(`  - attack.${builderTactic.toLowerCase()}`);
    if (builderTechnique) lines.push(`  - attack.${builderTechnique.toLowerCase()}`);

    return lines.join("\n");
  };

  const handleTranspile = async (yamlToTranspile: string) => {
    setTranspiling(true);
    setTranspileError(null);
    try {
      const res = await transpileSigmaRule(yamlToTranspile);
      setTranspiledResult(res);
    } catch (err) {
      setTranspileError(err instanceof Error ? err.message : "Sigma transpilation failed");
      setTranspiledResult(null);
    } finally {
      setTranspiling(false);
    }
  };

  const importMutation = useMutation({
    mutationFn: (ruleYaml: string) => importSigmaRule(ruleYaml, true),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["sigma-custom"] });
      setActionNotice("Rule successfully deployed to OutPost active detection engine!");
      setTimeout(() => setActionNotice(null), 3000);
    },
    onError: (err) => {
      setTranspileError(err instanceof Error ? err.message : "Deployment failed");
    },
  });

  // When switching from builder to YAML, sync the generated YAML
  const handleSwitchToYaml = () => {
    const generated = generateYamlFromBuilder();
    setYaml(generated);
    setAuthorMode("yaml");
    void handleTranspile(generated);
  };

  useEffect(() => {
    if (initialYaml) {
      setYaml(initialYaml);
      void handleTranspile(initialYaml);
    }
  }, [initialYaml]);

  return (
    <div className="space-y-6 font-sans">
      {/* Studio Header Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle pb-4">
        <div>
          <h2 className="text-base font-bold text-text-primary">Sigma AST Authoring &amp; Transpilation Studio</h2>
          <p className="text-xs text-text-muted font-mono mt-0.5">
            Engineered detection rule compiler targeting OutPost real-time query engine
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <div className="flex rounded-lg border border-border-subtle bg-bg-base p-0.5">
            <button
              onClick={() => setAuthorMode("builder")}
              className={`rounded px-2.5 py-1 text-xs font-semibold transition ${
                authorMode === "builder" ? "bg-accent text-white" : "text-text-muted hover:text-text-primary"
              }`}
            >
              Visual Builder
            </button>
            <button
              onClick={handleSwitchToYaml}
              className={`rounded px-2.5 py-1 text-xs font-semibold transition ${
                authorMode === "yaml" ? "bg-accent text-white" : "text-text-muted hover:text-text-primary"
              }`}
            >
              Raw YAML
            </button>
          </div>

          <button
            onClick={() => {
              const currentYaml = authorMode === "builder" ? generateYamlFromBuilder() : yaml;
              onOpenTest?.({ name: builderTitle, customYaml: currentYaml });
            }}
            className="press rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-semibold text-text-primary hover:border-accent hover:text-accent transition shadow-xs"
          >
            Dry-Run Test
          </button>

          <button
            onClick={() => {
              const currentYaml = authorMode === "builder" ? generateYamlFromBuilder() : yaml;
              onOpenBacktest?.({ name: builderTitle, customYaml: currentYaml });
            }}
            className="press rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-semibold text-text-primary hover:border-accent hover:text-accent transition shadow-xs"
          >
            Historical Backtest
          </button>

          <button
            onClick={() => {
              const currentYaml = authorMode === "builder" ? generateYamlFromBuilder() : yaml;
              importMutation.mutate(currentYaml);
            }}
            disabled={importMutation.isPending}
            className="press rounded-lg border border-accent bg-accent px-4 py-1.5 font-bold text-white transition hover:bg-accent/90 disabled:opacity-50 shadow-xs"
          >
            {importMutation.isPending ? "Deploying…" : "Deploy to Engine"}
          </button>
        </div>
      </div>

      {actionNotice && (
        <div className="flex items-center gap-2 rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs font-mono text-emerald-400">
          <Icon name="check" size={14} />
          <span>{actionNotice}</span>
        </div>
      )}

      {/* Editor & Transpiler Split View */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
        {/* Left Column: Authoring Canvas */}
        <div className="space-y-4">
          {authorMode === "builder" ? (
            <div className="rounded-2xl border border-border-subtle bg-bg-surface p-5 space-y-4 font-mono text-xs shadow-xs">
              <span className="text-[10px] font-bold uppercase tracking-wider text-accent block">
                Rule Metadata &amp; Taxonomy
              </span>

              <div className="space-y-3">
                <div>
                  <label className="text-[10px] uppercase text-text-faint block mb-1">Rule Title</label>
                  <input
                    value={builderTitle}
                    onChange={(e) => setBuilderTitle(e.target.value)}
                    className="w-full rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1.5 text-xs text-text-primary outline-none focus:border-accent font-sans font-bold"
                  />
                </div>

                <div>
                  <label className="text-[10px] uppercase text-text-faint block mb-1">Description</label>
                  <input
                    value={builderDesc}
                    onChange={(e) => setBuilderDesc(e.target.value)}
                    className="w-full rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1.5 text-xs text-text-primary outline-none focus:border-accent font-sans"
                  />
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                  <div>
                    <label className="text-[10px] uppercase text-text-faint block mb-1">Severity</label>
                    <select
                      value={builderLevel}
                      onChange={(e) => setBuilderLevel(e.target.value)}
                      className="w-full rounded-lg border border-border-subtle bg-bg-base px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                    >
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] uppercase text-text-faint block mb-1">Platform</label>
                    <select
                      value={builderPlatform}
                      onChange={(e) => setBuilderPlatform(e.target.value)}
                      className="w-full rounded-lg border border-border-subtle bg-bg-base px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                    >
                      <option value="linux">Linux</option>
                      <option value="windows">Windows</option>
                      <option value="macos">macOS</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] uppercase text-text-faint block mb-1">Category</label>
                    <select
                      value={builderCategory}
                      onChange={(e) => setBuilderCategory(e.target.value)}
                      className="w-full rounded-lg border border-border-subtle bg-bg-base px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                    >
                      <option value="process_creation">Process Create</option>
                      <option value="network_connection">Network Socket</option>
                      <option value="file_event">File Write</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] uppercase text-text-faint block mb-1">MITRE Tactic</label>
                    <input
                      value={builderTactic}
                      onChange={(e) => setBuilderTactic(e.target.value)}
                      className="w-full rounded-lg border border-border-subtle bg-bg-base px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                      placeholder="defense_evasion"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] uppercase text-text-faint block mb-1">Technique ID</label>
                    <input
                      value={builderTechnique}
                      onChange={(e) => setBuilderTechnique(e.target.value)}
                      className="w-full rounded-lg border border-border-subtle bg-bg-base px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                      placeholder="e.g. T1059"
                    />
                  </div>
                </div>
              </div>

              {/* Criteria Matcher */}
              <div className="border-t border-border-subtle/60 pt-3 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">
                    Detection Criteria (Match Selection)
                  </span>
                  <button
                    onClick={() => setBuilderCriteria([...builderCriteria, { field: "CommandLine", modifier: "contains", value: "" }])}
                    className="text-accent underline text-[10px]"
                  >
                    + Add Field
                  </button>
                </div>
                {builderCriteria.map((crit, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <input
                      value={crit.field}
                      onChange={(e) => {
                        const copy = [...builderCriteria];
                        copy[idx].field = e.target.value;
                        setBuilderCriteria(copy);
                      }}
                      className="w-28 rounded-lg border border-border-subtle bg-bg-base px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                      placeholder="Field"
                    />
                    <select
                      value={crit.modifier}
                      onChange={(e) => {
                        const copy = [...builderCriteria];
                        copy[idx].modifier = e.target.value;
                        setBuilderCriteria(copy);
                      }}
                      className="w-24 rounded-lg border border-border-subtle bg-bg-base px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                    >
                      <option value="contains">contains</option>
                      <option value="endswith">endswith</option>
                      <option value="startswith">startswith</option>
                      <option value="re">regex</option>
                    </select>
                    <input
                      value={crit.value}
                      onChange={(e) => {
                        const copy = [...builderCriteria];
                        copy[idx].value = e.target.value;
                        setBuilderCriteria(copy);
                      }}
                      className="flex-1 rounded-lg border border-border-subtle bg-bg-base px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                      placeholder="Comma-separated tokens…"
                    />
                    {builderCriteria.length > 1 && (
                      <button
                        onClick={() => setBuilderCriteria(builderCriteria.filter((_, i) => i !== idx))}
                        className="press text-text-faint hover:text-rose-400 p-1"
                      >
                        <Icon name="x" size={12} />
                      </button>
                    )}
                  </div>
                ))}
              </div>

              {/* Allowlist Exclusions */}
              <div className="border-t border-border-subtle/60 pt-3 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">
                    Exclusions &amp; Filter (Allowlisting)
                  </span>
                  <button
                    onClick={() => setBuilderExclusions([...builderExclusions, { field: "User", modifier: "contains", value: "" }])}
                    className="text-accent underline text-[10px]"
                  >
                    + Add Filter
                  </button>
                </div>
                {builderExclusions.map((ex, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <input
                      value={ex.field}
                      onChange={(e) => {
                        const copy = [...builderExclusions];
                        copy[idx].field = e.target.value;
                        setBuilderExclusions(copy);
                      }}
                      className="w-28 rounded-lg border border-border-subtle bg-bg-base px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                      placeholder="Field"
                    />
                    <select
                      value={ex.modifier}
                      onChange={(e) => {
                        const copy = [...builderExclusions];
                        copy[idx].modifier = e.target.value;
                        setBuilderExclusions(copy);
                      }}
                      className="w-24 rounded-lg border border-border-subtle bg-bg-base px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                    >
                      <option value="contains">contains</option>
                      <option value="endswith">endswith</option>
                      <option value="startswith">startswith</option>
                    </select>
                    <input
                      value={ex.value}
                      onChange={(e) => {
                        const copy = [...builderExclusions];
                        copy[idx].value = e.target.value;
                        setBuilderExclusions(copy);
                      }}
                      className="flex-1 rounded-lg border border-border-subtle bg-bg-base px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                      placeholder="Benign tokens to exclude…"
                    />
                    <button
                      onClick={() => setBuilderExclusions(builderExclusions.filter((_, i) => i !== idx))}
                      className="press text-text-faint hover:text-rose-400 p-1"
                    >
                      <Icon name="x" size={12} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              <div className="flex items-center justify-between font-mono text-[10px] text-text-faint">
                <span>Sigma Rule Specification (YAML)</span>
                <button
                  onClick={() => handleTranspile(yaml)}
                  className="press text-accent underline hover:text-accent/80"
                >
                  Re-Transpile Query
                </button>
              </div>
              <textarea
                value={yaml}
                onChange={(e) => {
                  setYaml(e.target.value);
                  void handleTranspile(e.target.value);
                }}
                rows={22}
                className="w-full rounded-2xl border border-border-subtle bg-bg-inset p-4 font-mono text-xs text-emerald-400 outline-none focus:border-accent shadow-xs leading-relaxed"
                placeholder="Enter Sigma YAML..."
              />
            </div>
          )}
        </div>

        {/* Right Column: Live Transpiler & AST Verification */}
        <div className="space-y-4">
          <div className="rounded-2xl border border-border-subtle bg-bg-surface p-5 space-y-4 font-mono text-xs shadow-xs">
            <div className="flex items-center justify-between border-b border-border-subtle pb-3">
              <span className="text-[10px] font-bold uppercase tracking-wider text-accent">
                OutPost Engine Transpilation Preview
              </span>
              <span className="flex items-center gap-1.5 text-[10px] text-text-faint">
                <span className={`h-1.5 w-1.5 rounded-full ${transpiledResult ? "bg-emerald-400" : "bg-amber-400"}`} />
                <span>{transpiledResult ? "Valid AST" : "Pending Transpilation"}</span>
              </span>
            </div>

            {transpiling ? (
              <p className="py-6 text-center text-text-muted">Transpiling Sigma AST into OutPost engine bytecode…</p>
            ) : transpileError ? (
              <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-rose-400">
                <p className="font-bold">AST Compilation Error:</p>
                <p className="mt-1">{transpileError}</p>
              </div>
            ) : transpiledResult ? (
              <div className="space-y-3">
                <div>
                  <span className="text-[10px] uppercase text-text-faint block mb-1">Target Engine Filter:</span>
                  <pre className="rounded-xl border border-border-subtle bg-bg-inset p-3 text-sky-400 overflow-x-auto text-[11px] leading-relaxed">
                    {transpiledResult.outpost_filter || transpiledResult.query || JSON.stringify(transpiledResult, null, 2)}
                  </pre>
                </div>

                <div className="grid grid-cols-2 gap-2 text-[10px]">
                  <div className="rounded-lg border border-border-subtle bg-bg-base p-2">
                    <span className="text-text-faint block">Event Log Category</span>
                    <span className="font-bold text-text-primary uppercase">{transpiledResult.category || "process_creation"}</span>
                  </div>
                  <div className="rounded-lg border border-border-subtle bg-bg-base p-2">
                    <span className="text-text-faint block">Condition Expression</span>
                    <span className="font-bold text-text-primary">{transpiledResult.condition || "selection"}</span>
                  </div>
                </div>
              </div>
            ) : (
              <p className="py-6 text-center text-text-muted">
                Edit rule parameters or raw YAML to view instant compilation.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
