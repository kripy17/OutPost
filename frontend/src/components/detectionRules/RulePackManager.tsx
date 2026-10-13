import { useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Icon } from "../Icon";
import {
  exportRulePack,
  getSigmaBundleExport,
  importRulePack,
  importSigmaRule,
  resetRules,
  saveBlob,
} from "../../lib/api";
import type { RulePack } from "../../types";

export function RulePackPanel() {
  const queryClient = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const sigmaFileRef = useRef<HTMLInputElement>(null);
  const [packMsg, setPackMsg] = useState<string | null>(null);
  const [packErr, setPackErr] = useState<string | null>(null);

  const doExport = async () => {
    setPackErr(null);
    try {
      const pack = await exportRulePack();
      const stamp = new Date().toISOString().slice(0, 10);
      saveBlob(
        new Blob([JSON.stringify(pack, null, 2)], { type: "application/json" }),
        `outpost-rules-${stamp}.json`,
      );
      setPackMsg(
        `Exported ${pack.tuning.length} tuning knob(s), ${pack.suppressions.length} suppression(s), enum tables, FP threshold — keep the file in git for diffable rule revisions.`,
      );
    } catch {
      setPackErr("Export failed — is the backend running?");
    }
  };

  const doExportSigma = async () => {
    setPackErr(null);
    try {
      const blob = await getSigmaBundleExport();
      saveBlob(blob, "outpost-sigma-rules.yml");
      setPackMsg(
        "Exported full multi-document Sigma YAML ruleset bundle — ready for Splunk, Elastic, Sentinel, and pySigma pipelines.",
      );
    } catch {
      setPackErr("Sigma export failed — is the backend running?");
    }
  };

  const doImport = async (file: File) => {
    setPackMsg(null);
    try {
      const pack = JSON.parse(await file.text()) as RulePack;
      const s = await importRulePack(pack);
      setPackMsg(
        `Imported ${file.name} — ${s.tuning_applied} knob(s) synced, ${s.suppressions_added} suppression(s) added` +
          (s.suppressions_skipped ? `, ${s.suppressions_skipped} skipped (already present)` : "") +
          `, enum patterns ${s.enum_patterns_applied ? "applied" : "unchanged"}, FP threshold ${s.fp_threshold_applied ? "set" : "unchanged"}.`,
      );
      void queryClient.invalidateQueries({ queryKey: ["tuning"] });
      void queryClient.invalidateQueries({ queryKey: ["rule-fp"] });
      void queryClient.invalidateQueries({ queryKey: ["enum-patterns"] });
    } catch (e) {
      setPackErr(e instanceof Error ? e.message.slice(0, 240) : "Import failed — not a valid rule pack?");
    }
  };

  const doImportSigma = async (file: File) => {
    setPackMsg(null);
    setPackErr(null);
    try {
      const yamlContent = await file.text();
      const res = await importSigmaRule(yamlContent, true);
      const count = (res as any).count ?? 1;
      setPackMsg(`Imported ${file.name} — ${count} SigmaHQ rule(s) activated into live detection store.`);
      void queryClient.invalidateQueries({ queryKey: ["custom-sigma-rules"] });
    } catch (e) {
      setPackErr(e instanceof Error ? e.message.slice(0, 240) : "Failed to import Sigma YAML rule.");
    }
  };

  return (
    <div className="space-y-4 font-sans">
      <div className="border-b border-border-subtle pb-3">
        <p className="kicker">Operations · Rule Packs &amp; Portability</p>
        <h3 className="mt-0.5 text-base font-semibold text-text-primary">Versioned Rule Sets &amp; Bundles</h3>
      </div>
      <div className="rounded-xl border border-border-subtle bg-bg-surface p-5">
        <p className="text-xs leading-relaxed text-text-muted">
          Export the complete operational rule surface — tuning overrides, suppressions, per-OS enumeration tables, FP
          threshold — as one JSON document, or export raw Sigma YAML bundles for external SIEM integration. Keep
          exports in git: diff what changed between rule revisions, and roll back anytime by re-importing an earlier
          export.
        </p>
        <div className="mt-5 flex flex-wrap items-center gap-3 font-mono text-xs">
          <button
            onClick={() => void doExport()}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/50 bg-accent/10 px-3.5 py-2 font-semibold text-accent transition-all duration-150 hover:bg-accent/20"
          >
            <Icon name="download" size={13} />
            Export pack (JSON)
          </button>
          <button
            onClick={() => void doExportSigma()}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/50 bg-cyan-500/10 px-3.5 py-2 font-semibold text-cyan-400 transition-all duration-150 hover:bg-cyan-500/20"
            title="Download multi-document Sigma YAML bundle for Splunk / Elastic / Sentinel"
          >
            <Icon name="terminal" size={13} />
            Export Sigma Bundle (.yml)
          </button>
          <button
            onClick={() => fileRef.current?.click()}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-base px-3.5 py-2 text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
          >
            <Icon name="download" size={13} className="rotate-180" />
            Import pack (JSON)
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".json,application/json"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void doImport(f);
              e.target.value = "";
            }}
          />
          <button
            onClick={() => sigmaFileRef.current?.click()}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-base px-3.5 py-2 text-text-muted transition-colors duration-150 hover:border-cyan-400 hover:text-cyan-400"
            title="Import single or multi-document SigmaHQ YAML rulepack (.yml / .yaml)"
          >
            <Icon name="download" size={13} className="rotate-180 text-cyan-400" />
            Import Sigma (.yml)
          </button>
          <input
            ref={sigmaFileRef}
            type="file"
            accept=".yml,.yaml,text/yaml"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void doImportSigma(f);
              e.target.value = "";
            }}
          />
        </div>
        {packMsg && <p className="mt-3 font-mono text-[11px] leading-relaxed text-risk-clean">{packMsg}</p>}
        {packErr && <p className="mt-3 font-mono text-[11px] leading-relaxed text-risk-malicious">{packErr}</p>}
      </div>
    </div>
  );
}

export function FactoryResetPanel() {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const doReset = async () => {
    const ok = window.confirm(
      "Factory-reset the rule surface? This clears EVERY tuning override, suppression, and " +
        "pattern-table edit — enumeration, anti-forensics, and the FP threshold — back to stock. " +
        "Run triage state (alert statuses, allowlists) is untouched. This cannot be undone (export a rule pack first).",
    );
    if (!ok) return;
    setBusy(true);
    setErr(null);
    try {
      const r = await resetRules();
      setMsg(
        `Reset to stock — ${r.tuning_cleared} tuning override(s), ${r.suppressions_cleared} suppression(s), ` +
          `${r.settings_cleared} pattern/threshold key(s) cleared.`,
      );
      for (const key of [["tuning"], ["rule-fp"], ["enum-patterns"], ["log-patterns"], ["suppressions"]]) {
        void queryClient.invalidateQueries({ queryKey: key });
      }
    } catch {
      setErr("Reset failed — is the backend running?");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4 font-sans">
      <div className="border-b border-border-subtle pb-2">
        <p className="kicker">Operations · Danger Zone</p>
        <h3 className="mt-0.5 text-base font-semibold text-text-primary">Factory Reset Rules</h3>
      </div>
      <div className="flex flex-wrap items-center gap-4 rounded-xl border border-risk-malicious/30 bg-bg-surface p-5">
        <p className="min-w-0 flex-1 text-xs leading-relaxed text-text-muted">
          Clear every tuning override, suppression, and pattern-table edit (enumeration + anti-forensics + FP threshold)
          back to the engine&apos;s stock behavior — a single consolidated transaction, audited. Export a rule pack
          first if you might want the current surface back.
        </p>
        <button
          onClick={() => void doReset()}
          disabled={busy}
          className="press shrink-0 rounded-lg border border-risk-malicious/60 bg-risk-malicious/10 px-4 py-2 font-mono text-xs font-semibold text-risk-malicious transition-colors duration-150 hover:bg-risk-malicious/20 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? "Resetting…" : "Factory reset"}
        </button>
        {msg && <p className="w-full font-mono text-[11px] leading-relaxed text-risk-clean">{msg}</p>}
        {err && <p className="w-full font-mono text-[11px] leading-relaxed text-risk-malicious">{err}</p>}
      </div>
    </div>
  );
}

export function RulePackManager() {
  return (
    <div className="space-y-6">
      <RulePackPanel />
      <FactoryResetPanel />
    </div>
  );
}
