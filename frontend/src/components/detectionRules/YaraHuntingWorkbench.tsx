import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../Icon";
import { Panel } from "../ui";
import {
  deleteCustomYaraRule,
  getCustomYaraRules,
  getSamples,
  saveCustomYaraRule,
  testYaraRule,
} from "../../lib/api";
import { clearYaraDraft, readYaraDraft, writeYaraDraft, type YaraDraft } from "../../routes/rulesDrafts";
import type { CustomYaraRule, YaraTestResponse } from "../../types";

const YARA_TEMPLATE = `rule my_signature {
  meta:
    description = "Suspicious packer or malware indicator"
    author = "OutPost Analyst"
  strings:
    $s1 = "cmd.exe" ascii wide
    $s2 = { 4D 5A 90 00 }
  condition:
    all of them
}`;

export function YaraHuntingWorkbench() {
  const queryClient = useQueryClient();
  const savedRules = useQuery({ queryKey: ["custom-yara-rules"], queryFn: getCustomYaraRules });
  const samples = useQuery({ queryKey: ["samples"], queryFn: () => getSamples({ limit: 100 }) });

  // Draft restore from localStorage
  const initialDraft = readYaraDraft();
  const [ruleText, setRuleText] = useState(initialDraft?.ruleText ?? YARA_TEMPLATE);
  const [family, setFamily] = useState(initialDraft?.family ?? "");
  const [description, setDescription] = useState(initialDraft?.description ?? "");
  const [scope, setScope] = useState<"all" | "picked">(initialDraft?.scope ?? "all");
  const [picked, setPicked] = useState<string[]>(initialDraft?.picked ?? []);
  const [editingName, setEditingName] = useState<string | null>(null);

  // Persistence to localStorage
  useEffect(() => {
    const d: YaraDraft = { ruleText, family, description, scope, picked };
    writeYaraDraft(d);
  }, [ruleText, family, description, scope, picked]);

  const testMutation = useMutation({
    mutationFn: () =>
      testYaraRule(ruleText, scope === "picked" ? picked : undefined),
  });

  const saveMutation = useMutation({
    mutationFn: (_name?: string) =>
      saveCustomYaraRule(
        ruleText,
        family.trim() || undefined,
        description.trim() || undefined,
      ),
    onSuccess: () => {
      clearYaraDraft();
      setEditingName(null);
      void queryClient.invalidateQueries({ queryKey: ["custom-yara-rules"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (name: string) => deleteCustomYaraRule(name),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["custom-yara-rules"] });
    },
  });

  const testResult: YaraTestResponse | undefined = testMutation.data;

  const handleLoadRule = (r: CustomYaraRule) => {
    setRuleText(r.source);
    setFamily(r.family ?? "");
    setDescription(r.description ?? "");
    setEditingName(r.name);
  };

  const handleNewRule = () => {
    setRuleText(YARA_TEMPLATE);
    setFamily("");
    setDescription("");
    setEditingName(null);
    clearYaraDraft();
  };

  return (
    <div className="space-y-6 font-sans">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border-subtle pb-4">
        <div>
          <h2 className="text-base font-bold text-text-primary">YARA Threat Hunting &amp; Binary Lab</h2>
          <p className="text-xs text-text-muted font-mono mt-0.5">
            Author byte-level heuristic signatures and test them against vault binary samples
          </p>
        </div>
        <button
          onClick={handleNewRule}
          className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs font-semibold text-text-primary hover:border-accent hover:text-accent transition shadow-xs"
        >
          <Icon name="plus" size={12} />
          <span>New YARA Signature</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Saved Library Rail */}
        <div className="space-y-3 font-mono text-xs">
          <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint block">
            Custom YARA Library ({savedRules.data?.rules.length ?? 0})
          </span>
          {savedRules.isLoading ? (
            <p className="text-text-muted py-4">Loading custom YARA signatures…</p>
          ) : (savedRules.data?.rules.length ?? 0) === 0 ? (
            <div className="rounded-xl border border-border-subtle bg-bg-surface p-6 text-center text-text-muted">
              <p className="font-semibold text-text-primary">No Custom YARA Signatures</p>
              <p className="text-text-faint mt-1">Author and save your first binary signature on the right.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {savedRules.data!.rules.map((r) => (
                <div
                  key={r.name}
                  className={`group rounded-xl border p-3 transition cursor-pointer ${
                    editingName === r.name
                      ? "border-accent bg-accent/10 shadow-xs"
                      : "border-border-subtle bg-bg-surface hover:border-accent/40"
                  }`}
                  onClick={() => handleLoadRule(r)}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-text-primary">{r.name}</span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        if (window.confirm(`Delete custom YARA signature '${r.name}'?`)) {
                          deleteMutation.mutate(r.name);
                        }
                      }}
                      className="press rounded p-1 text-text-faint hover:text-rose-400 transition"
                      title="Delete signature"
                    >
                      <Icon name="x" size={12} />
                    </button>
                  </div>
                  {r.family && (
                    <span className="mt-1 inline-block rounded bg-bg-elevated px-1.5 py-0.2 text-[9px] text-accent uppercase font-bold">
                      {r.family}
                    </span>
                  )}
                  {r.description && (
                    <p className="mt-1 text-[10px] text-text-muted truncate font-sans">{r.description}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Editor & Scope Configuration */}
        <div className="lg:col-span-2 space-y-4 font-mono text-xs">
          <div className="rounded-2xl border border-border-subtle bg-bg-surface p-5 space-y-4 shadow-xs">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold uppercase tracking-wider text-accent">
                {editingName ? `Editing '${editingName}'` : "New YARA Signature Editor"}
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => testMutation.mutate()}
                  disabled={testMutation.isPending}
                  className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 text-xs font-semibold text-text-primary hover:border-accent hover:text-accent transition shadow-xs"
                >
                  <Icon name={testMutation.isPending ? "refresh" : "play"} size={12} className={testMutation.isPending ? "animate-spin" : ""} />
                  <span>{testMutation.isPending ? "Scanning Samples…" : "Test Against Vault"}</span>
                </button>
                <button
                  onClick={() => {
                    const match = ruleText.match(/rule\s+([a-zA-Z0-9_]+)/);
                    const ruleName = match ? match[1] : `rule_${Date.now()}`;
                    saveMutation.mutate(ruleName);
                  }}
                  disabled={saveMutation.isPending}
                  className="press inline-flex items-center gap-1.5 rounded-lg border border-accent bg-accent px-4 py-1.5 text-xs font-bold text-white transition hover:bg-accent/90 disabled:opacity-50 shadow-xs"
                >
                  <span>{saveMutation.isPending ? "Saving…" : "Save Signature"}</span>
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] uppercase text-text-faint block mb-1">Malware Family / Group</label>
                <input
                  value={family}
                  onChange={(e) => setFamily(e.target.value)}
                  className="w-full rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1.5 text-xs text-text-primary outline-none focus:border-accent"
                  placeholder="e.g. RedLine, CobaltStrike"
                />
              </div>
              <div>
                <label className="text-[10px] uppercase text-text-faint block mb-1">Description / Intent</label>
                <input
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1.5 text-xs text-text-primary outline-none focus:border-accent font-sans"
                  placeholder="e.g. Detects packed dropper stage 1"
                />
              </div>
            </div>

            <div>
              <label className="text-[10px] uppercase text-text-faint block mb-1">YARA Rule Specification</label>
              <textarea
                value={ruleText}
                onChange={(e) => setRuleText(e.target.value)}
                rows={16}
                className="w-full rounded-xl border border-border-subtle bg-bg-inset p-4 text-emerald-400 font-mono text-xs outline-none focus:border-accent leading-relaxed select-all"
              />
            </div>

            {/* Test Sample Scope Selector */}
            <div className="border-t border-border-subtle/60 pt-3 space-y-2">
              <span className="text-[10px] uppercase font-bold text-text-faint block">
                Evaluation Sample Scope
              </span>
              <div className="flex items-center gap-4">
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="radio"
                    name="scope"
                    checked={scope === "all"}
                    onChange={() => setScope("all")}
                    className="accent-accent"
                  />
                  <span>All Vault Samples ({samples.data?.samples.length ?? 0})</span>
                </label>
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="radio"
                    name="scope"
                    checked={scope === "picked"}
                    onChange={() => setScope("picked")}
                    className="accent-accent"
                  />
                  <span>Selected Subset ({picked.length})</span>
                </label>
              </div>

              {scope === "picked" && samples.data && (
                <div className="max-h-36 overflow-y-auto space-y-1 rounded-xl border border-border-subtle bg-bg-base p-2">
                  {samples.data.samples.map((s) => (
                    <label key={s.sample_id} className="flex items-center gap-2 p-1 hover:bg-bg-elevated/40 rounded cursor-pointer">
                      <input
                        type="checkbox"
                        checked={picked.includes(s.sample_id)}
                        onChange={(e) => {
                          if (e.target.checked) setPicked([...picked, s.sample_id]);
                          else setPicked(picked.filter((id) => id !== s.sample_id));
                        }}
                        className="accent-accent"
                      />
                      <span className="font-bold text-text-primary">{s.original_name}</span>
                      <span className="text-[10px] text-text-faint truncate max-w-[200px]">{s.sha256}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Test Evaluation Feedback */}
          {testResult && (
            <Panel
              kicker="Sample Match Telemetry"
              title={testResult.compiled ? `Rule Evaluated Cleanly — ${testResult.matched ?? 0} Matches` : "Syntax Evaluation Error"}
            >
              {!testResult.compiled ? (
                <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-rose-400">
                  <p className="font-bold">YARA Compiler Error:</p>
                  <p className="mt-1 font-mono text-xs">{testResult.error || "Failed to compile YARA rule syntax."}</p>
                </div>
              ) : (testResult.matched ?? 0) === 0 ? (
                <p className="text-text-muted py-2 font-mono text-xs">
                  Evaluated {testResult.total ?? 0} vault samples with zero signature matches.
                </p>
              ) : (
                <div className="space-y-3 font-mono">
                  <span className="text-[10px] uppercase text-text-faint font-semibold block">
                    Matching Vault Artifacts:
                  </span>
                  <div className="space-y-2">
                    {(testResult.samples || [])
                      .filter((s) => s.matched)
                      .map((m) => (
                        <div
                          key={m.sample_id}
                          className="rounded-xl border border-border-subtle bg-bg-base/80 p-3 space-y-1.5"
                        >
                          <div className="flex items-center justify-between">
                            <Link
                              to={`/samples/${m.sample_id}`}
                              className="font-bold text-accent hover:underline"
                            >
                              {m.original_name || m.sample_id}
                            </Link>
                            <span className="text-[10px] text-text-faint tabular-nums">
                              {m.detected_platform} · {(m.size / 1024).toFixed(1)} KB
                            </span>
                          </div>
                          {m.hits && m.hits.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              {m.hits.map((hit, i) => (
                                <span
                                  key={i}
                                  className="rounded bg-bg-surface px-1.5 py-0.5 text-[9px] text-emerald-400 border border-border-subtle font-mono"
                                >
                                  {hit}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
