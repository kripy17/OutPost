import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Icon } from "../components/Icon";
import { platformIconName } from "../components/iconMeta";
import { PageHeader } from "../components/ui";
import { getPlaybooks, runLiveSimulation } from "../lib/api";
import { ProcessCausalityTree } from "../components/ProcessCausalityTree";
import type { AttackPlaybook } from "../types";

export default function MonitorPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [detonatingPlaybookId, setDetonatingPlaybookId] = useState<string | null>(null);
  const [simViewMode, setSimViewMode] = useState<"terminal" | "tree" | "alerts" | "delta">("terminal");
  const [activeResult, setActiveResult] = useState<{
    run_id: string;
    scenario_id: string;
    name: string;
    platform: string;
    terminal_output: string;
    terminal_lines: string[];
    stages: Array<{
      stage: number;
      name: string;
      cmd: string;
      exit_code: number;
      status: string;
    }>;
    events_count: number;
    alerts_count: number;
    alerts: any[];
    risk_score: number;
    process_tree: any[];
    detonation_delta?: any;
  } | null>(null);

  const [searchQuery, setSearchQuery] = useState("");
  const { data: playbooks, isLoading } = useQuery<AttackPlaybook[]>({
    queryKey: ["playbooks"],
    queryFn: getPlaybooks,
  });

  const filteredPlaybooks = (playbooks || []).filter((pb) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      pb.name.toLowerCase().includes(q) ||
      pb.description.toLowerCase().includes(q) ||
      (pb.techniques || []).some((t) => t.toLowerCase().includes(q))
    );
  });

  const handleRunLiveSimulation = async (playbookId: string) => {
    setDetonatingPlaybookId(playbookId);
    const pb = (playbooks || []).find((p) => p.id === playbookId);
    
    // Set immediate active feedback
    setActiveResult({
      run_id: "executing...",
      scenario_id: playbookId,
      name: pb?.name || playbookId,
      platform: "linux",
      terminal_output: `[OutPost Simulation Lab] Initializing sandbox environment...\n[OutPost Simulation Lab] Launching playbook: ${pb?.name || playbookId}\n[OutPost Simulation Lab] Spawning subprocesses and monitoring kernel telemetry...`,
      terminal_lines: [],
      stages: (pb?.techniques || []).map((t, idx) => ({
        stage: idx + 1,
        name: t,
        cmd: "executing stage command in sandbox...",
        exit_code: 0,
        status: "running",
      })),
      events_count: 0,
      alerts_count: 0,
      alerts: [],
      risk_score: 0,
      process_tree: [],
    });

    try {
      const res = await runLiveSimulation(playbookId);
      setActiveResult(res);
      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
      void queryClient.invalidateQueries({ queryKey: ["statusbar"] });
      void queryClient.invalidateQueries({ queryKey: ["forensics"] });
    } catch (err: unknown) {
      console.error("Live simulation failed:", err);
    } finally {
      setDetonatingPlaybookId(null);
    }
  };

  return (
    <div className="mx-auto max-w-6xl px-6 py-8 space-y-8">
      <PageHeader
        kicker="Lab · Adversary Simulation"
        title="Live Simulation Lab"
        lede="Deterministic multi-stage adversary attack scenarios executed live in an isolated sandbox to test detection rules, kernel telemetry feeds, and real-time kill-chain reconstruction."
      />

      {/* Quarantined Synthetic Telemetry Notice */}
      <div className="rounded-2xl border border-accent/40 bg-gradient-to-r from-accent/10 via-bg-surface/90 to-bg-surface/90 p-4 font-mono text-xs">
        <div className="flex items-center gap-2 font-semibold text-accent">
          <Icon name="shield" size={15} />
          <span>Live Subprocess Sandbox · Real-Time Detection Verification</span>
        </div>
        <p className="mt-1.5 text-[11px] leading-relaxed text-text-muted">
          All simulation scenarios execute real sandboxed subprocesses in isolated temporary environments. Telemetry is streamed into the OutPost behavioral detection engine, firing real alerts and populating the Event Manager in real time.
        </p>
      </div>

      {/* Live Execution Cockpit (When active or completed) */}
      {activeResult && (
        <div className="panel overflow-hidden border-accent/60 p-6 space-y-6 shadow-[0_12px_32px_-8px_rgba(217,164,65,0.2)]">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border-subtle pb-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-accent/50 bg-accent/20 text-accent shadow-[var(--glow-accent)]">
                <Icon name="terminal" size={20} />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-accent">Live Execution Trace</span>
                  <span className="rounded-full border border-border-subtle bg-bg-surface px-2 py-0.5 font-mono text-[10px] text-text-faint">
                    Run {activeResult.run_id}
                  </span>
                  <span className="rounded-full bg-accent/20 px-2 py-0.5 font-mono text-[10px] font-bold text-accent">
                    Risk Score: {activeResult.risk_score}
                  </span>
                </div>
                <h3 className="font-sans text-base font-bold text-text-primary">
                  {activeResult.name}
                </h3>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => navigate(`/events?source=simulation`)}
                className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs text-text-muted hover:border-accent/50 hover:text-accent"
              >
                <Icon name="list" size={12} />
                View in Event Manager
              </button>

              <Link
                to={`/runs/${activeResult.run_id}`}
                className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent/15 px-3.5 py-1.5 font-mono text-xs font-semibold text-accent hover:bg-accent/25"
              >
                <Icon name="external" size={12} />
                Open Full Run Dossier
              </Link>
            </div>
          </div>

          {/* Stage Progress Stepper */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {(activeResult.stages || []).map((stg) => (
              <div
                key={stg.stage}
                className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 font-mono text-xs space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold uppercase text-text-faint">Stage {stg.stage}</span>
                  <span className="inline-flex items-center gap-1 rounded bg-accent/15 px-1.5 py-0.5 text-[9px] font-bold text-accent">
                    <Icon name="check" size={10} />
                    {stg.status}
                  </span>
                </div>
                <p className="font-semibold text-text-primary truncate">{stg.name}</p>
                <p className="text-[10px] text-text-muted truncate">$ {stg.cmd}</p>
              </div>
            ))}
          </div>

          {/* Cockpit Sub-View Tabs */}
          <div className="flex items-center gap-2 border-b border-border-subtle pb-2 font-mono text-xs">
            <button
              onClick={() => setSimViewMode("terminal")}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
                simViewMode === "terminal"
                  ? "bg-accent/15 font-bold text-accent"
                  : "text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="terminal" size={12} />
              <span>Live Terminal Stream</span>
            </button>
            <button
              onClick={() => setSimViewMode("tree")}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
                simViewMode === "tree"
                  ? "bg-accent/15 font-bold text-accent"
                  : "text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="process" size={12} />
              <span>Process Causality Tree ({(activeResult.process_tree || []).length})</span>
            </button>
            <button
              onClick={() => setSimViewMode("alerts")}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
                simViewMode === "alerts"
                  ? "bg-accent/15 font-bold text-accent"
                  : "text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="alert" size={12} />
              <span>Triggered Detections ({(activeResult.alerts || []).length})</span>
            </button>
            <button
              onClick={() => setSimViewMode("delta")}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
                simViewMode === "delta"
                  ? "bg-accent/15 font-bold text-accent"
                  : "text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="grid" size={12} />
              <span>Detonation Baseline Delta</span>
            </button>
          </div>

          {/* SubView 1: Terminal Console Output */}
          {simViewMode === "terminal" && (
            <div className="space-y-2">
              <div className="flex items-center justify-between font-mono text-[11px] text-text-faint">
                <span className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-accent animate-pulse" />
                  Live Subprocess Terminal Output (stdout/stderr)
                </span>
                <span>{activeResult.events_count ?? 0} events captured · {activeResult.alerts_count ?? 0} alerts</span>
              </div>
              <pre className="max-h-80 overflow-y-auto rounded-xl border border-border-subtle bg-[#0a0c10] p-4 font-mono text-xs leading-relaxed text-[#c9d1d9] shadow-inner selection:bg-accent selection:text-black">
                {activeResult.terminal_output || "Awaiting execution trace..."}
              </pre>
            </div>
          )}

          {/* SubView 2: Process Causality Tree */}
          {simViewMode === "tree" && (
            <div className="space-y-2">
              <div className="flex items-center justify-between font-mono text-[11px] text-text-faint">
                <span>Subprocess Parent-Child Lineage spawned during scenario execution</span>
                <span>{activeResult.process_tree?.length ?? 0} root nodes</span>
              </div>
              <div className="rounded-xl border border-border-subtle bg-bg-base/80 p-4">
                <ProcessCausalityTree nodes={activeResult.process_tree || []} />
              </div>
            </div>
          )}

          {/* SubView 3: Live Alerts Radar */}
          {simViewMode === "alerts" && (
            <div className="space-y-3 font-mono text-xs">
              <h4 className="font-semibold text-text-primary flex items-center gap-2">
                <Icon name="alert" size={14} className="text-risk-malicious" />
                Triggered Detections ({(activeResult.alerts || []).length})
              </h4>
              {(activeResult.alerts || []).length === 0 ? (
                <p className="text-xs text-text-muted">No alerts triggered for this execution yet.</p>
              ) : (
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  {(activeResult.alerts || []).map((al: any, i: number) => (
                    <div
                      key={i}
                      className="flex items-start justify-between rounded-xl border border-risk-malicious/30 bg-risk-malicious/10 p-3.5"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-text-primary">{al.rule_name}</span>
                          <span className="text-[10px] text-text-faint">({al.rule_id})</span>
                        </div>
                        <p className="mt-1 text-[11px] text-text-muted">{al.details}</p>
                      </div>
                      <span className="rounded border border-risk-malicious/50 bg-risk-malicious/20 px-2 py-0.5 text-[9px] font-bold uppercase text-risk-malicious">
                        {al.severity}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* SubView 4: Detonation Baseline Delta */}
          {simViewMode === "delta" && (
            <div className="space-y-4 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-text-primary">Pre/Post Detonation System Delta</span>
                <span className="text-[10px] text-text-faint">Host state differential captured before vs after execution</span>
              </div>

              {activeResult.detonation_delta ? (
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  <div className="rounded-xl border border-border-subtle bg-bg-base/40 p-4 space-y-2.5">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-signal">+ Spawned / Resident Processes ({activeResult.detonation_delta.new_processes?.length ?? 0})</span>
                    </div>
                    {(activeResult.detonation_delta.new_processes || []).length > 0 ? (
                      <div className="space-y-1.5 max-h-56 overflow-y-auto">
                        {activeResult.detonation_delta.new_processes.map((np: any, idx: number) => (
                          <div key={idx} className="flex items-center justify-between rounded-lg border border-signal/30 bg-signal/5 p-2 text-[11px]">
                            <span className="font-bold text-text-primary">{np.name}</span>
                            <span className="text-[10px] text-text-faint">PID {np.pid} · {np.user}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-[11px] text-text-faint">No resident processes remained running after execution.</p>
                    )}
                  </div>

                  <div className="rounded-xl border border-border-subtle bg-bg-base/40 p-4 space-y-2.5">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-accent">+ Newly Opened Sockets ({activeResult.detonation_delta.new_sockets?.length ?? 0})</span>
                    </div>
                    {(activeResult.detonation_delta.new_sockets || []).length > 0 ? (
                      <div className="space-y-1.5 max-h-56 overflow-y-auto">
                        {activeResult.detonation_delta.new_sockets.map((ns: any, idx: number) => (
                          <div key={idx} className="flex items-center justify-between rounded-lg border border-accent/30 bg-accent/5 p-2 text-[11px]">
                            <span className="font-mono text-text-primary">{ns.local_ip}:{ns.local_port}</span>
                            <span className="text-[10px] uppercase font-bold text-accent">{ns.protocol} ({ns.status})</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-[11px] text-text-faint">No open listening or remote network sockets lingered.</p>
                    )}
                  </div>
                </div>
              ) : (
                <div className="rounded-xl border border-border-subtle bg-bg-elevated/20 p-6 text-center text-text-faint">
                  Baseline snapshot captured; zero anomalous system state drift detected after completion.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Attack Scenario Playbooks Catalog */}
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h3 className="font-sans text-sm font-bold text-text-primary">
              Available Attack Playbooks ({filteredPlaybooks?.length ?? 0})
            </h3>
            <p className="text-xs text-text-muted">
              Select a scenario to trigger deterministic execution and trace detection rules in real time.
            </p>
          </div>
          <div className="relative">
            <Icon name="search" size={14} className="absolute left-2.5 top-2.5 text-text-faint" />
            <input
              type="text"
              placeholder="Search playbooks..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-9 w-64 rounded-lg border border-border-subtle bg-bg-surface pl-9 pr-3 text-xs outline-none focus:border-accent/50"
            />
          </div>
        </div>

        {isLoading ? (
          <div className="py-12 text-center font-mono text-xs text-text-faint">
            Loading adversary attack playbooks...
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {(filteredPlaybooks || []).map((pb) => {
              const isDetonating = detonatingPlaybookId === pb.id;
              const isCritical = pb.severity === "critical";
              return (
                <div
                  key={pb.id}
                  className="panel group relative flex flex-col justify-between p-5 transition-all duration-200 hover:border-accent/60 hover:shadow-[0_8px_24px_-6px_rgba(217,164,65,0.15)]"
                >
                  <div>
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <span className="rounded border border-border-subtle bg-bg-elevated/60 p-1 font-mono text-[10px] uppercase text-text-muted">
                          <Icon name={platformIconName(pb.platform)} size={12} />
                        </span>
                        <h4 className="font-sans text-xs font-semibold text-text-primary group-hover:text-accent">
                          {pb.name}
                        </h4>
                      </div>
                      <span
                        className={`inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[9px] uppercase tracking-wide ${
                          isCritical
                            ? "border border-risk-malicious/40 bg-risk-malicious/15 text-risk-malicious"
                            : "border border-risk-suspicious/40 bg-risk-suspicious/15 text-risk-suspicious"
                        }`}
                      >
                        <span className="h-1.5 w-1.5 rounded-full bg-current" />
                        {pb.severity}
                      </span>
                    </div>

                    <p className="mt-2.5 text-xs leading-relaxed text-text-muted">
                      {pb.description}
                    </p>

                    <div className="mt-3 flex flex-wrap items-center gap-1.5">
                      {(pb.techniques || []).map((t) => (
                        <span
                          key={t}
                          className="rounded border border-border-subtle bg-bg-inset px-1.5 py-0.5 font-mono text-[9px] text-text-faint"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="mt-5 flex items-center justify-between border-t border-border-subtle pt-3.5">
                    <span className="font-mono text-[10px] text-text-faint">
                      {pb.tactics?.join(" → ") || "Multi-stage execution"}
                    </span>
                    <button
                      onClick={() => handleRunLiveSimulation(pb.id)}
                      disabled={detonatingPlaybookId !== null}
                      className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent/15 px-3.5 py-1.5 font-mono text-[11px] font-semibold text-accent transition-all duration-150 hover:bg-accent/25 hover:shadow-[var(--glow-accent)] disabled:opacity-50"
                    >
                      <Icon
                        name={isDetonating ? "refresh" : "play"}
                        size={11}
                        className={isDetonating ? "animate-spin" : ""}
                      />
                      {isDetonating ? "Executing Live..." : "Run Live Simulation"}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
