import { useCallback, useEffect, useState } from "react";
import { Icon } from "../Icon";
import { backtestCustomRule, backtestRule } from "../../lib/api";
import type { RuleBacktestResult } from "../../types";

interface RuleBacktestModalProps {
  ruleId?: string;
  ruleName: string;
  customYaml?: string;
  onClose: () => void;
}

export function RuleBacktestModal({
  ruleId,
  ruleName,
  customYaml,
  onClose,
}: RuleBacktestModalProps) {
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

  const runBacktest = useCallback(async () => {
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
  }, [customYaml, ruleId, maxEvents]);

  useEffect(() => {
    void runBacktest();
  }, [runBacktest]);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={`Historical Rule Backtest — ${ruleName}`}
      className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs transition-opacity font-sans"
      onClick={onClose}
    >
      <div
        className="flex h-full w-full max-w-2xl flex-col border-l border-border-subtle bg-bg-surface shadow-2xl animate-slide-in overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border-subtle px-6 py-4 bg-bg-base/70">
          <div>
            <span className="font-mono text-[10px] uppercase tracking-wide text-text-faint">
              Detection Validation &amp; Historical Backtesting
            </span>
            <h3 className="font-mono text-sm font-bold text-text-primary">
              Historical Rule Backtest — <span className="text-accent">{ruleName}</span>
            </h3>
          </div>
          <button
            onClick={onClose}
            className="press rounded-lg p-1 text-text-muted hover:bg-bg-base hover:text-text-primary transition"
            aria-label="Close modal"
          >
            <Icon name="x" size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-4 font-mono text-xs">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-text-faint">Scanned Window:</span>
              <select
                value={maxEvents}
                onChange={(e) => setMaxEvents(Number(e.target.value))}
                disabled={running}
                className="rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 text-text-primary outline-none focus:border-accent"
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
              className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent/15 px-3 py-1.5 font-bold text-accent hover:bg-accent/25 disabled:opacity-50 transition shadow-xs"
            >
              <Icon name={running ? "refresh" : "play"} size={12} className={running ? "animate-spin" : ""} />
              <span>{running ? "Scanning History…" : "Re-run Backtest"}</span>
            </button>
          </div>

          {error && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-rose-400">
              {error}
            </div>
          )}

          {result && (
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-3">
                <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 space-y-1">
                  <span className="text-[10px] text-text-faint uppercase font-semibold">Events Evaluated</span>
                  <p className="text-base font-bold text-text-primary tabular-nums">{(result.events_scanned ?? 0).toLocaleString()}</p>
                </div>
                <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 space-y-1">
                  <span className="text-[10px] text-text-faint uppercase font-semibold">Rule Trigger Hits</span>
                  <p className="text-base font-bold text-accent tabular-nums">
                    {result.matches_count} ({result.match_rate_pct}%)
                  </p>
                </div>
                <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 space-y-1">
                  <span className="text-[10px] text-text-faint uppercase font-semibold">Est. False Positive Risk</span>
                  <p
                    className={`text-base font-bold uppercase ${
                      result.estimated_fp_risk === "low"
                        ? "text-emerald-400"
                        : result.estimated_fp_risk === "medium"
                          ? "text-amber-400"
                          : "text-rose-400"
                    }`}
                  >
                    {result.estimated_fp_risk}
                  </p>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold text-text-faint">
                    Matched Historical Events ({(result.sample_matches || []).length})
                  </span>
                </div>
                {(result.sample_matches || []).length === 0 ? (
                  <div className="rounded-xl border border-border-subtle bg-bg-base/40 p-6 text-center text-text-muted">
                    <p className="font-semibold text-text-primary">Zero Historical Trigger Matches</p>
                    <p className="text-text-faint mt-1">
                      No events in the selected historical window matched this rule's conditions.
                    </p>
                  </div>
                ) : (
                  <div className="max-h-72 overflow-y-auto space-y-2 pr-1">
                    {(result.sample_matches || []).map((m: any, idx: number) => (
                      <div
                        key={idx}
                        className="rounded-xl border border-border-subtle bg-bg-base/80 p-3 text-[11px] space-y-1"
                      >
                        <div className="flex items-center justify-between text-text-muted">
                          <span className="font-bold text-accent">{m.process_name || m.event_type}</span>
                          <span className="text-[10px] text-text-faint tabular-nums">
                            {m.timestamp?.slice(0, 19).replace("T", " ")} UTC
                          </span>
                        </div>
                        <p className="truncate text-text-primary select-all" title={m.command_line || m.match_reason}>
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
