import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { PageHeader, Panel } from "../components/ui";
import { getTuning, resetTuning, setTuning } from "../lib/api";
import type { TuningKnob } from "../types";

const KNOB_LABELS: Record<string, string> = {
  BEACON_MIN_CONNECTIONS: "Min connections to flag beaconing",
  BEACON_WINDOW_MINUTES: "Beaconing look-back window (min)",
  BEACON_VARIANCE_THRESHOLD: "Beacon interval variance (s)",
  RENAME_BURST_THRESHOLD: "File writes to flag ransomware burst",
  RENAME_BURST_WINDOW_SECONDS: "Burst window (s)",
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

      {data && (
        <div className="mt-6 space-y-3">
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
