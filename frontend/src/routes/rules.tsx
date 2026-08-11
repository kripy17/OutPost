import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
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
} from "../lib/api";
import { clearEnumDrafts, clearYaraDraft, readEnumDrafts, readYaraDraft, writeEnumDrafts, writeYaraDraft } from "./rulesDrafts";
import type { CustomYaraRule, EnumPatternRow, FpDayPoint, LogPatternKind, RuleFpEntry, RulePack, TuningKnob, YaraTestResponse } from "../types";

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

function readLogDrafts(): Record<LogPatternKind, Record<string, EnumPatternRow[]>> | null {
  try {
    const raw = localStorage.getItem("outpost-log-drafts");
    if (!raw) return null;
    const d: unknown = JSON.parse(raw);
    if (!d || typeof d !== "object" || Array.isArray(d)) return null;
    const out: Record<string, Record<string, EnumPatternRow[]>> = {};
    for (const [kind, platforms] of Object.entries(d as Record<string, unknown>)) {
      if (!platforms || typeof platforms !== "object" || Array.isArray(platforms)) continue;
      const per: Record<string, EnumPatternRow[]> = {};
      for (const [platform, rows] of Object.entries(platforms as Record<string, unknown>)) {
        if (!Array.isArray(rows)) continue;
        const clean = rows.filter(
          (r): r is EnumPatternRow =>
            !!r && typeof r === "object" && typeof (r as EnumPatternRow).pattern === "string" && typeof (r as EnumPatternRow).label === "string",
        );
        if (clean.length) per[platform] = clean;
      }
      if (Object.keys(per).length) out[kind] = per;
    }
    return Object.keys(out).length ? (out as Record<LogPatternKind, Record<string, EnumPatternRow[]>>) : null;
  } catch {
    return null;
  }
}

function writeLogDrafts(drafts: Record<LogPatternKind, Record<string, EnumPatternRow[]>>) {
  try {
    if (Object.keys(drafts).length) localStorage.setItem("outpost-log-drafts", JSON.stringify(drafts));
    else localStorage.removeItem("outpost-log-drafts");
  } catch {
    /* storage unavailable */
  }
}

function clearLogDrafts() {
  try {
    localStorage.removeItem("outpost-log-drafts");
  } catch {
    /* ignore */
  }
}

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
            Export pack
          </button>
          <button
            onClick={() => fileRef.current?.click()}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
          >
            <Icon name="download" size={12} className="rotate-180" />
            Import pack
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
          threshold) back to the engine&apos;s stock behavior — one atomic call, audited. Export a rule pack first if
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


export default function RulesPage() {
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useQuery({ queryKey: ["tuning"], queryFn: getTuning });
  const { data: fp } = useQuery({ queryKey: ["rule-fp"], queryFn: getRuleFp });
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [fpDraft, setFpDraft] = useState<string>("");

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
    <div className="mx-auto max-w-4xl px-6 py-10">
      <PageHeader
        kicker="Operations · rules"
        title={
          <>
            Detection rules <span className="font-normal text-text-muted">— tune thresholds &amp; author signatures</span>
          </>
        }
        lede="Three knobs: live threshold tuning, per-OS enumeration pattern tables, and the signature lab — write, test, and save YARA-style rules against the sample vault."
      />

      {isLoading && <p className="mt-6 text-sm text-text-muted">Loading tunables…</p>}
      {isError && <p className="mt-6 text-sm text-risk-malicious">Couldn't load tunables — is the backend running?</p>}

      <RulePackPanel />

      <FactoryResetPanel />

      <YaraLab />

      <EnumPatternsEditor />

      <LogPatternsEditor />

      {/* FP feedback surface — noise threshold + per-rule counters */}
      {fp && (
        <div className="mt-8">
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

      {data && (
        <div className="mt-6 space-y-3">
          {data.knobs.map((knob: TuningKnob) => {
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
                    className="w-24 rounded border border-border-subtle bg-bg-base px-2 py-1.5 font-mono text-sm text-text-primary focus:border-accent/60 focus:outline-none"
                    aria-label={`${knob.param} value`}
                  />
                  <button
                    onClick={() => save.mutate({ param: knob.param, value: drafts[knob.param] ?? "" })}
                    disabled={save.isPending}
                    className="press rounded border border-accent/60 px-3 py-1.5 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/10 disabled:opacity-50"
                  >
                    Apply
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
    </div>
  );
}
