import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Icon } from "../Icon";
import { Panel } from "../ui";
import {
  resetFpThreshold,
  resetTuning,
  setFpThreshold,
  setTuning,
} from "../../lib/api";
import type { FpDayPoint, RuleFpEntry, RuleFpResponse, TuningKnob, TuningResponse } from "../../types";

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
  beacon_interval_tolerance_seconds: "Beaconing interval tolerance",
  beacon_min_intervals: "Minimum beacon intervals before alert",
  enum_burst_window_seconds: "Enumeration burst time window",
  enum_burst_min_unique_commands: "Minimum distinct enumeration commands",
  log_tamper_process_kill_grace_seconds: "Logging tamper grace period",
  rapid_fire_threshold_events_per_second: "Rapid-fire event velocity threshold",
  c2_domain_entropy_min_bits: "C2 domain Shannon entropy cutoff",
};

interface RuleTuningDrawerProps {
  tuningData?: TuningResponse;
  fpData?: RuleFpResponse;
  isLoading: boolean;
  isError: boolean;
}

export function FpSparkline({ history }: { history: FpDayPoint[] }) {
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

export function RuleTuningDrawer({
  tuningData,
  fpData,
  isLoading,
  isError,
}: RuleTuningDrawerProps) {
  const queryClient = useQueryClient();
  const [knobFilter, setKnobFilter] = useState("");
  const [showOverriddenOnly, setShowOverriddenOnly] = useState(false);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [fpDraft, setFpDraft] = useState<string>("");

  useEffect(() => {
    if (fpData) setFpDraft((d) => (d === "" ? String(fpData.threshold) : d));
  }, [fpData]);

  const save = useMutation({
    mutationFn: ({ param, value }: { param: string; value: string }) => setTuning(param, value),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["tuning"] });
    },
  });

  const reset = useMutation({
    mutationFn: (param: string) => resetTuning(param),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["tuning"] });
    },
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

  const applySuggestion = (s: RuleFpEntry["suggestion"]) => {
    if (!s) return;
    save.mutate({ param: s.param, value: String(s.suggested) }, {
      onSuccess: () => {
        void queryClient.invalidateQueries({ queryKey: ["rule-fp"] });
        void queryClient.invalidateQueries({ queryKey: ["tuning"] });
      },
    });
  };

  const fpFor = (ruleId: string): RuleFpEntry | undefined => fpData?.rules.find((r) => r.rule_id === ruleId);
  const noisyCount = fpData?.rules.filter((r) => r.over_threshold).length ?? 0;

  if (isLoading) {
    return <p className="py-8 text-center font-mono text-xs text-text-muted">Loading detection tuning configurations…</p>;
  }

  if (isError) {
    return <p className="py-8 text-center font-mono text-xs text-rose-400">Failed to load detection tuning parameters.</p>;
  }

  const knobs = tuningData?.knobs ?? [];

  return (
    <div className="space-y-6 font-sans">
      {/* FP Feedback & Noise Threshold Controls */}
      {fpData && (
        <Panel
          kicker="Heuristic Noise Suppression"
          title="Automated False-Positive Feedback Threshold"
        >
          <div className="space-y-3 font-mono text-xs">
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-text-muted">Threshold FPs before raise recommendation:</span>
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min={1}
                  value={fpDraft !== "" ? fpDraft : String(fpData.threshold)}
                  onChange={(e) => setFpDraft(e.target.value)}
                  className="w-20 rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 text-sm font-bold text-text-primary focus:border-accent outline-none"
                  aria-label="FP suggestion threshold"
                />
                <button
                  onClick={() => {
                    const n = Math.max(1, Math.floor(Number(fpDraft) || fpData.threshold));
                    saveFpThreshold.mutate(n);
                  }}
                  disabled={saveFpThreshold.isPending}
                  className="press rounded-lg border border-accent/60 bg-accent/15 px-3 py-1 font-bold text-accent transition hover:bg-accent/25 disabled:opacity-50"
                >
                  Set Threshold
                </button>
                {fpData.threshold !== fpData.default_threshold && (
                  <button
                    onClick={() => resetFp.mutate()}
                    className="press rounded-lg border border-border-subtle bg-bg-surface px-3 py-1 text-text-muted hover:text-text-primary transition"
                  >
                    Reset Default
                  </button>
                )}
              </div>
            </div>
            <p className="text-[11px] text-text-faint leading-relaxed font-sans">
              Rules generating recurring analyst false positives receive a deterministic recommendation to raise their trigger barrier. Currently{" "}
              {noisyCount === 0 ? (
                <strong className="text-emerald-400">zero rules exceed the noise threshold.</strong>
              ) : (
                <strong className="text-amber-400">{noisyCount} rule{noisyCount === 1 ? " exceeds" : "s exceed"} the noise threshold.</strong>
              )}
            </p>
          </div>
        </Panel>
      )}

      {/* Search and Filters */}
      <div className="flex flex-wrap items-center justify-between gap-3 font-mono text-xs">
        <div className="relative min-w-64 flex-1">
          <Icon name="search" size={12} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-faint" />
          <input
            type="text"
            value={knobFilter}
            onChange={(e) => setKnobFilter(e.target.value)}
            placeholder="Search knobs by name, parameter code, or rule ID…"
            className="w-full rounded-xl border border-border-subtle bg-bg-surface py-2 pl-9 pr-3 text-xs text-text-primary placeholder:text-text-faint focus:border-accent outline-none"
          />
        </div>
        <button
          type="button"
          onClick={() => setShowOverriddenOnly(!showOverriddenOnly)}
          className={`press inline-flex items-center gap-1.5 rounded-xl border px-3 py-2 transition ${
            showOverriddenOnly
              ? "border-accent bg-accent/15 font-bold text-accent"
              : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="filter" size={12} />
          <span>{showOverriddenOnly ? "Tuned Overrides Only" : "All Knobs"}</span>
        </button>
      </div>

      {/* Tunable Knobs List */}
      <div className="space-y-3 font-mono text-xs">
        {knobs
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
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center gap-3">
                    <code className="rounded border border-border-subtle bg-bg-elevated/50 px-2 py-0.5 font-mono text-[11px] text-accent font-bold">
                      {knob.param}
                    </code>
                    <span className="text-[10px] text-text-faint">
                      default: {knob.default} · type: {knob.type} · rule: {knob.rule_id}
                    </span>
                    {fpRow && fpRow.count > 0 && (
                      <span
                        className={`rounded-full border px-2 py-0.5 text-[10px] tabular-nums ${
                          fpRow.over_threshold
                            ? "border-amber-500/40 bg-amber-500/10 text-amber-400"
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
                      className={`ml-auto rounded-full border px-2 py-0.5 text-[9px] uppercase tracking-wider font-bold ${
                        knob.tuned
                          ? "border-accent/50 bg-accent/15 text-accent"
                          : "border-border-subtle bg-bg-base text-text-faint"
                      }`}
                    >
                      {knob.tuned ? "tuned" : "default"}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <input
                      type="text"
                      inputMode="numeric"
                      value={drafts[knob.param] ?? String(knob.current)}
                      onChange={(e) => setDrafts((d) => ({ ...d, [knob.param]: e.target.value }))}
                      className="w-36 rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1.5 text-sm font-bold text-text-primary focus:border-accent outline-none tabular-nums"
                      aria-label={knob.param}
                    />
                    <button
                      onClick={() => save.mutate({ param: knob.param, value: drafts[knob.param] ?? String(knob.current) })}
                      disabled={save.isPending}
                      className="press rounded-lg border border-accent bg-accent px-3.5 py-1.5 font-bold text-white transition hover:bg-accent/90 disabled:opacity-50"
                    >
                      Save
                    </button>
                    {knob.tuned && (
                      <button
                        onClick={() => reset.mutate(knob.param)}
                        className="press rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 text-text-muted hover:text-text-primary transition"
                      >
                        Reset
                      </button>
                    )}
                  </div>

                  {fpRow?.over_threshold && fpRow.suggestion && (
                    <div className="flex flex-wrap items-center gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 p-2.5 text-xs">
                      <Icon name="alert" size={13} className="text-amber-400 shrink-0" />
                      <span className="text-text-primary font-sans">{fpRow.suggestion.detail}</span>
                      <button
                        onClick={() => applySuggestion(fpRow.suggestion)}
                        disabled={save.isPending}
                        className="press ml-auto rounded-lg border border-amber-500/50 bg-amber-500/20 px-2.5 py-1 text-[11px] font-bold text-amber-400 hover:bg-amber-500/30 transition disabled:opacity-50"
                      >
                        Apply Suggested ({fpRow.suggestion.suggested})
                      </button>
                    </div>
                  )}
                </div>
              </Panel>
            );
          })}
      </div>
    </div>
  );
}
