import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Icon } from "../components/Icon";
import { PageHeader, Panel } from "../components/ui";
import { getEnumPatterns, getTuning, resetTuning, setEnumPatterns, setTuning } from "../lib/api";
import type { EnumPatternRow, TuningKnob } from "../types";

const PLATFORM_LABELS: Record<string, string> = {
  windows: "Windows",
  linux: "Linux",
  macos: "macOS",
};

function EnumPatternsEditor() {
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useQuery({ queryKey: ["enum-patterns"], queryFn: getEnumPatterns });
  const [drafts, setDrafts] = useState<Record<string, EnumPatternRow[]>>({});
  const [dirty, setDirty] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (data) {
      setDrafts({});
      setDirty(false);
    }
  }, [data]);

  const save = useMutation({
    mutationFn: (platforms: Record<string, EnumPatternRow[]>) => setEnumPatterns(platforms),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["enum-patterns"] });
      setDirty(false);
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
    setDirty(true);
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
                        setDrafts(next);
                        setDirty(Object.keys(next).length > 0);
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

const KNOB_LABELS: Record<string, string> = {
  BEACON_MIN_CONNECTIONS: "Min connections to flag beaconing",
  BEACON_WINDOW_MINUTES: "Beaconing look-back window (min)",
  BEACON_VARIANCE_THRESHOLD: "Beacon interval variance (s)",
  RENAME_BURST_THRESHOLD: "File writes to flag ransomware burst",
  RENAME_BURST_WINDOW_SECONDS: "Burst window (s)",
  ENUM_BURST_THRESHOLD: "Distinct discovery commands to flag enumeration",
  ENUM_WINDOW_SECONDS: "Enumeration look-back window (s)",
  STAGING_WINDOW_SECONDS: "Archive-then-upload window (s)",
};

export default function RulesPage() {
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useQuery({ queryKey: ["tuning"], queryFn: getTuning });
  const [drafts, setDrafts] = useState<Record<string, string>>({});

  const save = useMutation({
    mutationFn: ({ param, value }: { param: string; value: string }) => setTuning(param, value),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["tuning"] }),
  });
  const reset = useMutation({
    mutationFn: (param: string) => resetTuning(param),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["tuning"] }),
  });

  return (
    <div className="mx-auto max-w-4xl px-6 py-10">
      <PageHeader
        kicker="Operations · tuning"
        title={
          <>
            Detection rules <span className="font-normal text-text-muted">— tune thresholds live</span>
          </>
        }
        lede="Edit the knobs behind beaconing and ransomware-burst detection. Changes apply to the next ingested batch — no backend restart."
      />

      {isLoading && <p className="mt-6 text-sm text-text-muted">Loading tunables…</p>}
      {isError && <p className="mt-6 text-sm text-risk-malicious">Couldn't load tunables — is the backend running?</p>}

      <EnumPatternsEditor />

      {data && (
        <div className="mt-8 space-y-3">
          {data.knobs.map((knob: TuningKnob) => (
            <Panel key={knob.param} title={KNOB_LABELS[knob.param] ?? knob.param}>
              <div className="flex flex-wrap items-center gap-3">
                <code className="rounded border border-border-subtle bg-bg-elevated/50 px-2 py-1 font-mono text-[11px] text-accent">
                  {knob.param}
                </code>
                <span className="font-mono text-[10px] text-text-faint">
                  default {knob.default} · type {knob.type} · rule {knob.rule_id}
                </span>
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
            </Panel>
          ))}
        </div>
      )}
    </div>
  );
}
