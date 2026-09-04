import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Icon } from "../components/Icon";
import { platformIconName } from "../components/iconMeta";
import { PageHeader } from "../components/ui";
import {
  executeSimulationStage,
  getPlaybooks,
  getSandboxArtifactUrl,
  listTechniqueTests,
  runLiveSimulation,
  runTechniqueTest,
} from "../lib/api";
import { ProcessCausalityTree } from "../components/ProcessCausalityTree";
import type {
  DroppedArtifactItem,
  PlaybookScenario,
  SimulationStageResult,
  TechniqueRunResult,
  TechniqueTestItem,
} from "../types";

export default function MonitorPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // Active execution state
  const [detonatingPlaybookId, setDetonatingPlaybookId] = useState<string | null>(null);
  const [executionError, setExecutionError] = useState<string | null>(null);
  const [platformFilter, setPlatformFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");

  // Step-by-Step Interactive Mode State
  const [stepScenario, setStepScenario] = useState<PlaybookScenario | null>(null);
  const [currentStageIndex, setCurrentStageIndex] = useState<number>(1);
  const [stepRunId, setStepRunId] = useState<string | null>(null);
  const [stepSandboxDir, setStepSandboxDir] = useState<string | null>(null);
  const [stageHistory, setStageHistory] = useState<SimulationStageResult[]>([]);
  const [isExecutingStage, setIsExecutingStage] = useState<boolean>(false);
  const [stepDroppedArtifacts, setStepDroppedArtifacts] = useState<DroppedArtifactItem[]>([]);

  // View mode tab for the cockpit
  const [simViewMode, setSimViewMode] = useState<"terminal" | "tree" | "alerts" | "artifacts" | "delta">("terminal");

  // Top-level View Mode: "campaigns" vs "techniques"
  const [activeTab, setActiveTab] = useState<"campaigns" | "techniques">("campaigns");

  // Technique tests state
  const [techniqueTactic, setTechniqueTactic] = useState<string>("all");
  const [techniqueSearch, setTechniqueSearch] = useState<string>("");
  const [runningTechniqueId, setRunningTechniqueId] = useState<string | null>(null);
  const [techniqueResult, setTechniqueResult] = useState<TechniqueRunResult | null>(null);
  const [expandedTechniqueId, setExpandedTechniqueId] = useState<string | null>(null);

  // Automated run result
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
    dropped_artifacts?: DroppedArtifactItem[];
  } | null>(null);

  const { data: playbooks, isLoading } = useQuery<PlaybookScenario[]>({
    queryKey: ["playbooks"],
    queryFn: getPlaybooks,
  });

  const { data: techniques = [] } = useQuery<TechniqueTestItem[]>({
    queryKey: ["techniques", techniqueTactic, techniqueSearch],
    queryFn: () => listTechniqueTests(techniqueTactic === "all" ? undefined : techniqueTactic, undefined, techniqueSearch.trim() || undefined),
  });

  const handleRunTechnique = async (testId: string) => {
    setRunningTechniqueId(testId);
    setExecutionError(null);
    try {
      const res = await runTechniqueTest(testId);
      setTechniqueResult(res);
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["events"] });
    } catch (e: any) {
      setExecutionError(e.message || "Failed to execute technique test");
    } finally {
      setRunningTechniqueId(null);
    }
  };

  const filteredPlaybooks = (playbooks || []).filter((pb) => {
    if (platformFilter !== "all" && pb.platform !== platformFilter) return false;
    if (severityFilter !== "all" && pb.severity !== severityFilter) return false;
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      pb.name.toLowerCase().includes(q) ||
      pb.description.toLowerCase().includes(q) ||
      (pb.techniques || []).some((t) => t.toLowerCase().includes(q))
    );
  });

  // Automated Run
  const handleRunFullLiveSimulation = async (scenarioId: string) => {
    setDetonatingPlaybookId(scenarioId);
    setExecutionError(null);
    try {
      const res = await runLiveSimulation(scenarioId);
      setActiveResult(res);
      setStepScenario(null);
      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
      void queryClient.invalidateQueries({ queryKey: ["statusbar"] });
      void queryClient.invalidateQueries({ queryKey: ["forensics"] });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Execution failed. Check backend sandbox status.";
      setExecutionError(msg);
      console.error("Live simulation failed:", err);
    } finally {
      setDetonatingPlaybookId(null);
    }
  };

  // Launch Interactive Step-by-Step Mode
  const handleStartStepMode = (scenario: PlaybookScenario) => {
    setStepScenario(scenario);
    setCurrentStageIndex(1);
    setStepRunId(null);
    setStepSandboxDir(null);
    setStageHistory([]);
    setStepDroppedArtifacts([]);
    setActiveResult(null);
    setExecutionError(null);
    setSimViewMode("terminal");
  };

  // Run next single stage in step mode
  const handleExecuteNextStage = async () => {
    if (!stepScenario || isExecutingStage) return;
    setIsExecutingStage(true);
    setExecutionError(null);
    try {
      const res = await executeSimulationStage(
        stepScenario.id,
        currentStageIndex,
        stepRunId || undefined,
        stepSandboxDir || undefined,
      );

      setStageHistory((prev) => [...prev, res]);
      setStepRunId(res.run_id);
      if (res.sandbox_dir) {
        setStepSandboxDir(res.sandbox_dir);
      }
      if (res.dropped_artifacts && res.dropped_artifacts.length > 0) {
        setStepDroppedArtifacts((prev) => [...prev, ...(res.dropped_artifacts || [])]);
      }

      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["runs"] });

      if (res.alerts_count > 0) {
        setSimViewMode("alerts");
      }

      if (!res.is_final_stage) {
        setCurrentStageIndex((prev) => prev + 1);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Stage execution failed.";
      setExecutionError(msg);
    } finally {
      setIsExecutingStage(false);
    }
  };

  // Run all remaining stages automatically
  const handleRunAllRemainingStages = async () => {
    if (!stepScenario || isExecutingStage) return;
    const totalStages = stepScenario.stages?.length || stepScenario.stages_count;
    let nextStage = currentStageIndex;
    let activeRunId = stepRunId;
    let activeWs = stepSandboxDir;

    setIsExecutingStage(true);
    setExecutionError(null);

    try {
      while (nextStage <= totalStages) {
        const res = await executeSimulationStage(
          stepScenario.id,
          nextStage,
          activeRunId || undefined,
          activeWs || undefined,
        );
        setStageHistory((prev) => [...prev, res]);
        activeRunId = res.run_id;
        setStepRunId(res.run_id);
        if (res.sandbox_dir) {
          activeWs = res.sandbox_dir;
          setStepSandboxDir(res.sandbox_dir);
        }
        if (res.dropped_artifacts && res.dropped_artifacts.length > 0) {
          setStepDroppedArtifacts((prev) => [...prev, ...(res.dropped_artifacts || [])]);
        }
        if (res.alerts_count > 0) {
          setSimViewMode("alerts");
        }
        if (res.is_final_stage) break;
        nextStage++;
        setCurrentStageIndex(nextStage);
      }
      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
    } catch (err: unknown) {
      setExecutionError(err instanceof Error ? err.message : "Auto-advance failed.");
    } finally {
      setIsExecutingStage(false);
    }
  };

  // Cumulative terminal logs for step mode
  const cumulativeStepLogs = stageHistory
    .map(
      (st) =>
        `>>> [Stage ${st.stage_number}/${st.total_stages}] ${st.stage_name}\n$ ${st.command}\n[Exit: ${st.exit_code} | Duration: ${st.elapsed_ms}ms]\n${st.stdout || "(no stdout)"}\n${st.stderr ? `[STDERR]:\n${st.stderr}\n` : ""}`,
    )
    .join("\n" + "=".repeat(60) + "\n\n");

  // Cumulative alerts for step mode
  const cumulativeStepAlerts = stageHistory.flatMap((s) => s.alerts || []);

  const totalStepStages = stepScenario?.stages?.length || stepScenario?.stages_count || 0;
  const isStepFinished = stageHistory.length > 0 && stageHistory[stageHistory.length - 1]?.is_final_stage;

  return (
    <div className="mx-auto max-w-6xl px-6 py-8 space-y-8">
      <PageHeader
        kicker="Lab · Adversary Simulation"
        title="Live Adversary Simulation Cockpit"
        lede="Deterministic, multi-stage adversary campaigns executed live in an isolated Linux sandbox. Run fully automated campaigns or advance step-by-step to inspect host posture, telemetry feeds, and detection hits at each attack milestone."
      />

      {/* Real Subprocess Sandbox Notice */}
      <div className="rounded-2xl border border-accent/40 bg-gradient-to-r from-accent/10 via-bg-surface/90 to-bg-surface/90 p-4 font-mono text-xs shadow-sm">
        <div className="flex items-center gap-2 font-semibold text-accent">
          <Icon name="shield" size={15} />
          <span>Real Subprocess Sandbox · Deep Kernel Telemetry · Real-Time Rule Hits</span>
        </div>
        <p className="mt-1.5 text-[11px] leading-relaxed text-text-muted">
          All adversary campaigns execute real sandboxed subprocesses in ephemeral temporary workspaces. Telemetry is ingested directly by OutPost's behavioral detection engine, producing authentic events, process lineages, Shannon entropy metrics, and SigmaHQ detection alerts in real time.
        </p>
      </div>

      {/* Top-Level Mode Selector */}
      <div className="flex items-center gap-2 border-b border-border-subtle pb-3 font-mono text-sm">
        <button
          onClick={() => setActiveTab("campaigns")}
          className={`flex items-center gap-2 rounded-xl px-4 py-2 transition ${
            activeTab === "campaigns"
              ? "bg-accent/20 font-bold text-accent border border-accent/40 shadow-sm"
              : "text-text-muted hover:text-text-primary hover:bg-white/5"
          }`}
        >
          <Icon name="play" size={14} />
          <span>Multi-Stage Campaigns ({filteredPlaybooks?.length ?? 0})</span>
        </button>
        <button
          onClick={() => setActiveTab("techniques")}
          className={`flex items-center gap-2 rounded-xl px-4 py-2 transition ${
            activeTab === "techniques"
              ? "bg-accent/20 font-bold text-accent border border-accent/40 shadow-sm"
              : "text-text-muted hover:text-text-primary hover:bg-white/5"
          }`}
        >
          <Icon name="target" size={14} />
          <span>Technique Unit Tests ({techniques.length})</span>
        </button>
      </div>

      {activeTab === "campaigns" && (
        <>

      {executionError && (
        <div className="rounded-2xl border border-risk-malicious/50 bg-risk-malicious/10 p-4 font-mono text-xs text-risk-malicious flex items-start gap-3">
          <Icon name="alert" size={16} className="shrink-0 mt-0.5" />
          <div>
            <span className="font-bold">Execution Error</span>
            <p className="mt-1 text-[11px] text-text-muted">{executionError}</p>
          </div>
        </div>
      )}

      {/* Active Automated Detonation Loading Bar */}
      {detonatingPlaybookId !== null && (
        <div className="rounded-2xl border border-accent/50 bg-accent/10 p-5 font-mono text-xs space-y-3">
          <div className="flex items-center justify-between text-accent">
            <span className="flex items-center gap-2 font-bold">
              <Icon name="refresh" size={14} className="animate-spin" />
              Executing live subprocesses in sandbox cage...
            </span>
            <span className="text-[11px] opacity-80">Scenario: {detonatingPlaybookId}</span>
          </div>
          <div className="h-1.5 w-full bg-border-subtle rounded-full overflow-hidden">
            <div className="h-full bg-accent animate-pulse w-3/4 transition-all duration-300" />
          </div>
          <p className="text-[11px] text-text-muted">
            Monitoring syscalls, inspecting process causality lineage, capturing dropped files, and evaluating real-time SigmaHQ rules...
          </p>
        </div>
      )}

      {/* ── INTERACTIVE STEP-BY-STEP COCKPIT ─────────────────────────────────── */}
      {stepScenario && (
        <div className="panel overflow-hidden border-accent/70 p-6 space-y-6 shadow-[0_12px_32px_-8px_rgba(217,164,65,0.25)]">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border-subtle pb-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-accent/60 bg-accent/20 text-accent shadow-[var(--glow-accent)]">
                <Icon name="terminal" size={20} />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-accent">Interactive Campaign Stepper</span>
                  {stepRunId && (
                    <span className="rounded-full border border-border-subtle bg-bg-surface px-2 py-0.5 font-mono text-[10px] text-text-faint">
                      Run {stepRunId}
                    </span>
                  )}
                  <span className="rounded-full bg-accent/20 px-2 py-0.5 font-mono text-[10px] font-bold text-accent">
                    Stage {stageHistory.length} of {totalStepStages}
                  </span>
                </div>
                <h3 className="font-sans text-base font-bold text-text-primary">
                  {stepScenario.name}
                </h3>
              </div>
            </div>

            {/* Stepper Controls */}
            <div className="flex flex-wrap items-center gap-2">
              {!isStepFinished ? (
                <>
                  <button
                    onClick={() => void handleExecuteNextStage()}
                    disabled={isExecutingStage}
                    className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/70 bg-accent/20 px-4 py-2 font-mono text-xs font-bold text-accent transition hover:bg-accent/30 hover:shadow-[var(--glow-accent)] disabled:opacity-50"
                  >
                    <Icon name={isExecutingStage ? "refresh" : "play"} size={12} className={isExecutingStage ? "animate-spin" : ""} />
                    <span>{isExecutingStage ? "Executing Stage..." : `Execute Stage ${currentStageIndex}`}</span>
                  </button>

                  <button
                    onClick={() => void handleRunAllRemainingStages()}
                    disabled={isExecutingStage}
                    className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 font-mono text-xs text-text-muted hover:border-accent/60 hover:text-accent disabled:opacity-50"
                  >
                    <Icon name="zap" size={12} />
                    <span>Run Remaining</span>
                  </button>
                </>
              ) : (
                <div className="inline-flex items-center gap-1.5 rounded-lg bg-risk-clean/20 border border-risk-clean/50 px-3 py-1.5 font-mono text-xs font-bold text-risk-clean">
                  <Icon name="check" size={12} />
                  <span>Campaign Completed</span>
                </div>
              )}

              {stepRunId && (
                <Link
                  to={`/runs/${stepRunId}`}
                  className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 font-mono text-xs text-text-muted hover:border-accent/60 hover:text-accent"
                >
                  <Icon name="external" size={12} />
                  <span>Open Run Dossier</span>
                </Link>
              )}

              <button
                onClick={() => setStepScenario(null)}
                className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-2 font-mono text-xs text-text-muted hover:text-text-primary"
                title="Exit step-by-step runner"
              >
                <Icon name="x" size={12} />
                <span>Close</span>
              </button>
            </div>
          </div>

          {/* Interactive Visual Stage Stepper */}
          <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
            {(stepScenario.stages || []).map((stage, idx) => {
              const stageNum = idx + 1;
              const resultForStage = stageHistory.find((s) => s.stage_number === stageNum);
              const isCurrent = stageNum === currentStageIndex && !isStepFinished;
              const isPast = stageNum < currentStageIndex || isStepFinished;
              const hasAlerts = (resultForStage?.alerts_count || 0) > 0;

              return (
                <div
                  key={stageNum}
                  className={`rounded-xl border p-3 font-mono text-xs transition-all ${
                    isCurrent
                      ? "border-accent bg-accent/15 shadow-[0_0_12px_rgba(217,164,65,0.25)] ring-1 ring-accent"
                      : isPast
                        ? hasAlerts
                          ? "border-risk-malicious/40 bg-risk-malicious/10"
                          : "border-risk-clean/40 bg-risk-clean/5"
                        : "border-border-subtle bg-bg-base/50 opacity-60"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold uppercase text-text-faint">Stage {stageNum}</span>
                    <span
                      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] font-bold uppercase ${
                        isCurrent
                          ? "bg-accent/30 text-accent animate-pulse"
                          : isPast
                            ? hasAlerts
                              ? "bg-risk-malicious/20 text-risk-malicious"
                              : "bg-risk-clean/20 text-risk-clean"
                            : "bg-bg-inset text-text-faint"
                      }`}
                    >
                      <Icon
                        name={
                          isCurrent
                            ? isExecutingStage
                              ? "refresh"
                              : "activity"
                            : isPast
                              ? hasAlerts
                                ? "alert"
                                : "check"
                              : "box"
                        }
                        size={10}
                        className={isCurrent && isExecutingStage ? "animate-spin" : ""}
                      />
                      {isCurrent
                        ? isExecutingStage
                          ? "Executing"
                          : "Ready"
                        : isPast
                          ? hasAlerts
                            ? `${resultForStage?.alerts_count} Alert${(resultForStage?.alerts_count || 0) > 1 ? "s" : ""}`
                            : "Passed"
                          : "Queued"}
                    </span>
                  </div>
                  <p className="mt-1 font-semibold text-text-primary truncate">{stage.name}</p>
                  <p className="mt-0.5 text-[10px] text-text-muted font-mono truncate">$ {stage.cmd}</p>
                </div>
              );
            })}
          </div>

          {/* Stepper Cockpit Sub-View Tabs */}
          <div className="flex items-center gap-2 border-b border-border-subtle pb-2 font-mono text-xs">
            <button
              onClick={() => setSimViewMode("terminal")}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
                simViewMode === "terminal" ? "bg-accent/15 font-bold text-accent" : "text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="terminal" size={12} />
              <span>Live Terminal Log</span>
            </button>
            <button
              onClick={() => setSimViewMode("alerts")}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
                simViewMode === "alerts" ? "bg-accent/15 font-bold text-accent" : "text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="alert" size={12} />
              <span>Triggered Detections ({cumulativeStepAlerts.length})</span>
            </button>
            <button
              onClick={() => setSimViewMode("artifacts")}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
                simViewMode === "artifacts" ? "bg-accent/15 font-bold text-accent" : "text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="file" size={12} />
              <span>Dropped Forensic Artifacts ({stepDroppedArtifacts.length})</span>
            </button>
          </div>

          {/* Stepper SubView 1: Terminal Log */}
          {simViewMode === "terminal" && (
            <div className="space-y-2">
              <div className="flex items-center justify-between font-mono text-[11px] text-text-faint">
                <span className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-accent animate-pulse" />
                  Live Sandbox Execution Console (stdout/stderr)
                </span>
                <span>{stageHistory.length} stage(s) executed</span>
              </div>
              <pre className="max-h-80 overflow-y-auto rounded-xl border border-border-subtle bg-[#0a0c10] p-4 font-mono text-xs leading-relaxed text-[#c9d1d9] shadow-inner selection:bg-accent selection:text-black">
                {cumulativeStepLogs || "Awaiting stage execution. Click 'Execute Stage 1' to start the campaign..."}
              </pre>
            </div>
          )}

          {/* Stepper SubView 2: Alerts */}
          {simViewMode === "alerts" && (
            <div className="space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-text-primary flex items-center gap-2">
                  <Icon name="alert" size={14} className="text-risk-malicious" />
                  Real Detection Rules Triggered ({cumulativeStepAlerts.length})
                </span>
                {stepRunId && cumulativeStepAlerts.length > 0 && (
                  <Link
                    to={`/investigations?create=1&run_id=${stepRunId}&title=${encodeURIComponent(stepScenario.name + " Attack Dossier")}`}
                    className="press inline-flex items-center gap-1.5 rounded-lg border border-risk-malicious/50 bg-risk-malicious/15 px-3 py-1 text-[11px] font-semibold text-risk-malicious hover:bg-risk-malicious/25"
                  >
                    <Icon name="shield" size={11} />
                    Escalate to Case Dossier
                  </Link>
                )}
              </div>
              {cumulativeStepAlerts.length === 0 ? (
                <p className="text-xs text-text-muted py-4 text-center border border-border-subtle rounded-xl bg-bg-base/30">
                  No detection rules triggered yet. Advance through the stages to observe behavioral rule firing.
                </p>
              ) : (
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  {cumulativeStepAlerts.map((al: any, i: number) => (
                    <div
                      key={i}
                      className="flex items-start justify-between rounded-xl border border-risk-malicious/40 bg-risk-malicious/10 p-3.5"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-text-primary">{al.rule_name}</span>
                          <span className="text-[10px] text-text-faint font-mono">({al.rule_id})</span>
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

          {/* Stepper SubView 3: Dropped Artifacts */}
          {simViewMode === "artifacts" && (
            <div className="space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-text-primary">Captured Artifacts & Canary Documents</span>
                <span className="text-[10px] text-text-faint">Extracted from sandbox cage before teardown</span>
              </div>

              {stepDroppedArtifacts.length === 0 ? (
                <div className="rounded-xl border border-border-subtle bg-bg-base/30 p-6 text-center text-text-muted">
                  {isStepFinished
                    ? "Zero persistent disk artifacts remained in the sandbox workspace."
                    : "No dropped artifacts extracted yet. Complete the campaign to persist and analyze dropped files."}
                </div>
              ) : (
                <div className="space-y-3">
                  {stepDroppedArtifacts.map((art, idx) => (
                    <div
                      key={idx}
                      className="rounded-xl border border-border-subtle bg-bg-base/60 p-4 space-y-2.5 hover:border-accent/50 transition"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <Icon name="file" size={14} className="text-accent" />
                          <span className="font-bold text-text-primary">{art.name}</span>
                          <span className="rounded bg-bg-elevated px-2 py-0.5 text-[10px] text-text-faint">
                            {art.size_bytes} bytes
                          </span>
                          {art.is_high_entropy && (
                            <span className="rounded bg-risk-malicious/20 border border-risk-malicious/40 px-2 py-0.5 text-[9px] font-bold text-risk-malicious uppercase">
                              High Entropy ({art.entropy}/8.0)
                            </span>
                          )}
                        </div>

                        {stepRunId && (
                          <a
                            href={getSandboxArtifactUrl(stepRunId, art.filename)}
                            download
                            className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/50 bg-accent/15 px-3 py-1 text-[11px] font-bold text-accent hover:bg-accent/25"
                          >
                            <Icon name="download" size={11} />
                            <span>Download Artifact</span>
                          </a>
                        )}
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] text-text-muted bg-bg-surface p-2.5 rounded-lg border border-border-subtle">
                        <div>
                          <span className="text-text-faint uppercase text-[9px] block">SHA-256</span>
                          <span className="break-all font-mono">{art.sha256}</span>
                        </div>
                        <div>
                          <span className="text-text-faint uppercase text-[9px] block">Entropy</span>
                          <span className="font-mono">{art.entropy} / 8.0</span>
                        </div>
                      </div>

                      {art.preview && art.preview.length > 0 && (
                        <div>
                          <span className="text-text-faint text-[10px] block mb-1">Extracted Strings Preview:</span>
                          <div className="bg-[#0a0c10] p-2 rounded text-[10px] font-mono text-emerald-400 max-h-24 overflow-y-auto space-y-0.5">
                            {art.preview.map((line, lidx) => (
                              <div key={lidx} className="truncate">{line}</div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── AUTOMATED RUN EXECUTION COCKPIT ─────────────────────────────────── */}
      {activeResult && !stepScenario && (
        <div className="panel overflow-hidden border-accent/60 p-6 space-y-6 shadow-[0_12px_32px_-8px_rgba(217,164,65,0.2)]">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border-subtle pb-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-accent/50 bg-accent/20 text-accent shadow-[var(--glow-accent)]">
                <Icon name="terminal" size={20} />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-accent">Full Campaign Trace</span>
                  <span className="rounded-full border border-border-subtle bg-bg-surface px-2 py-0.5 font-mono text-[10px] text-text-faint">
                    Run {activeResult.run_id}
                  </span>
                  <span className="rounded-full bg-accent/20 px-2 py-0.5 font-mono text-[10px] font-bold text-accent">
                    Risk Score: {activeResult.risk_score}/100
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
                View in Events
              </button>

              {(activeResult.alerts || []).length > 0 && (
                <Link
                  to={`/investigations?create=1&run_id=${activeResult.run_id}&title=${encodeURIComponent(activeResult.name + " Detonation")}`}
                  className="press inline-flex items-center gap-1.5 rounded-lg border border-risk-malicious/50 bg-risk-malicious/15 px-3 py-1.5 font-mono text-xs font-semibold text-risk-malicious hover:bg-risk-malicious/25"
                >
                  <Icon name="shield" size={12} />
                  Escalate to Case Dossier
                </Link>
              )}

              <Link
                to={`/runs/${activeResult.run_id}`}
                className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent/15 px-3.5 py-1.5 font-mono text-xs font-semibold text-accent hover:bg-accent/25"
              >
                <Icon name="external" size={12} />
                Open Full Run Dossier
              </Link>

              <button
                onClick={() => setActiveResult(null)}
                className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1.5 font-mono text-xs text-text-muted hover:text-text-primary"
              >
                <Icon name="x" size={12} />
              </button>
            </div>
          </div>

          {/* Stage Progress Stepper */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {(activeResult.stages || []).map((stg) => {
              const isPassed = stg.status === "success" || stg.exit_code === 0;
              const isFailed = stg.status === "failed" || (stg.exit_code !== 0 && stg.exit_code !== -1);
              return (
                <div
                  key={stg.stage}
                  className={`rounded-xl border p-3 font-mono text-xs space-y-1.5 ${
                    isPassed
                      ? "border-risk-clean/30 bg-risk-clean/5"
                      : isFailed
                        ? "border-risk-malicious/30 bg-risk-malicious/5"
                        : "border-border-subtle bg-bg-base/60"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold uppercase text-text-faint">Stage {stg.stage}</span>
                    <span
                      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] font-bold uppercase ${
                        isPassed
                          ? "bg-risk-clean/20 text-risk-clean"
                          : isFailed
                            ? "bg-risk-malicious/20 text-risk-malicious"
                            : "bg-accent/20 text-accent"
                      }`}
                    >
                      <Icon name={isPassed ? "check" : isFailed ? "x" : "activity"} size={10} />
                      {stg.status} (exit {stg.exit_code})
                    </span>
                  </div>
                  <p className="font-semibold text-text-primary truncate">{stg.name}</p>
                  <p className="text-[10px] text-text-muted truncate font-mono">$ {stg.cmd}</p>
                </div>
              );
            })}
          </div>

          {/* Cockpit Sub-View Tabs */}
          <div className="flex items-center gap-2 border-b border-border-subtle pb-2 font-mono text-xs">
            <button
              onClick={() => setSimViewMode("terminal")}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
                simViewMode === "terminal" ? "bg-accent/15 font-bold text-accent" : "text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="terminal" size={12} />
              <span>Live Terminal Stream</span>
            </button>
            <button
              onClick={() => setSimViewMode("tree")}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
                simViewMode === "tree" ? "bg-accent/15 font-bold text-accent" : "text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="process" size={12} />
              <span>Process Causality Tree ({(activeResult.process_tree || []).length})</span>
            </button>
            <button
              onClick={() => setSimViewMode("alerts")}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
                simViewMode === "alerts" ? "bg-accent/15 font-bold text-accent" : "text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="alert" size={12} />
              <span>Triggered Detections ({(activeResult.alerts || []).length})</span>
            </button>
            <button
              onClick={() => setSimViewMode("artifacts")}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
                simViewMode === "artifacts" ? "bg-accent/15 font-bold text-accent" : "text-text-muted hover:text-text-primary"
              }`}
            >
              <Icon name="file" size={12} />
              <span>Dropped Forensic Artifacts ({(activeResult.dropped_artifacts || []).length})</span>
            </button>
            <button
              onClick={() => setSimViewMode("delta")}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 transition ${
                simViewMode === "delta" ? "bg-accent/15 font-bold text-accent" : "text-text-muted hover:text-text-primary"
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

          {/* SubView 3: Alerts */}
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
                          <span className="text-[10px] text-text-faint font-mono">({al.rule_id})</span>
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

          {/* SubView 4: Dropped Forensic Artifacts */}
          {simViewMode === "artifacts" && (
            <div className="space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-text-primary">Captured Artifacts & Canary Documents</span>
                <span className="text-[10px] text-text-faint">Persistent files recovered from sandbox cage</span>
              </div>

              {(!activeResult.dropped_artifacts || activeResult.dropped_artifacts.length === 0) ? (
                <div className="rounded-xl border border-border-subtle bg-bg-base/30 p-6 text-center text-text-muted">
                  No dropped artifacts extracted from this campaign execution.
                </div>
              ) : (
                <div className="space-y-3">
                  {activeResult.dropped_artifacts.map((art, idx) => (
                    <div
                      key={idx}
                      className="rounded-xl border border-border-subtle bg-bg-base/60 p-4 space-y-2.5 hover:border-accent/50 transition"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <Icon name="file" size={14} className="text-accent" />
                          <span className="font-bold text-text-primary">{art.name}</span>
                          <span className="rounded bg-bg-elevated px-2 py-0.5 text-[10px] text-text-faint">
                            {art.size_bytes} bytes
                          </span>
                          {art.is_high_entropy && (
                            <span className="rounded bg-risk-malicious/20 border border-risk-malicious/40 px-2 py-0.5 text-[9px] font-bold text-risk-malicious uppercase">
                              High Entropy ({art.entropy}/8.0)
                            </span>
                          )}
                        </div>

                        <a
                          href={getSandboxArtifactUrl(activeResult.run_id, art.filename)}
                          download
                          className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/50 bg-accent/15 px-3 py-1 text-[11px] font-bold text-accent hover:bg-accent/25"
                        >
                          <Icon name="download" size={11} />
                          <span>Download Artifact</span>
                        </a>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] text-text-muted bg-bg-surface p-2.5 rounded-lg border border-border-subtle">
                        <div>
                          <span className="text-text-faint uppercase text-[9px] block">SHA-256</span>
                          <span className="break-all font-mono">{art.sha256}</span>
                        </div>
                        <div>
                          <span className="text-text-faint uppercase text-[9px] block">Entropy</span>
                          <span className="font-mono">{art.entropy} / 8.0</span>
                        </div>
                      </div>

                      {art.preview && art.preview.length > 0 && (
                        <div>
                          <span className="text-text-faint text-[10px] block mb-1">Extracted Strings Preview:</span>
                          <div className="bg-[#0a0c10] p-2 rounded text-[10px] font-mono text-emerald-400 max-h-24 overflow-y-auto space-y-0.5">
                            {art.preview.map((line, lidx) => (
                              <div key={lidx} className="truncate">{line}</div>
                            ))}
                          </div>
                        </div>
                      )}

                      {art.yara_hits && art.yara_hits.length > 0 && (
                        <div className="rounded-lg border border-purple-500/30 bg-purple-500/5 p-2.5 space-y-1.5">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-purple-400 block">
                            Matched YARA Signatures ({art.yara_hits.length})
                          </span>
                          <div className="flex flex-wrap gap-1.5">
                            {art.yara_hits.map((hit, hidx) => (
                              <span
                                key={hidx}
                                className="rounded border border-purple-500/40 bg-purple-950/40 px-2 py-0.5 text-[10px] font-mono text-purple-200"
                              >
                                {hit.name} ({hit.family})
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* SubView 5: Detonation Baseline Delta */}
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

      {/* ── ATTACK SCENARIO PLAYBOOKS CATALOG ───────────────────────────────── */}
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h3 className="font-sans text-sm font-bold text-text-primary">
              Available Attack Campaigns & Playbooks ({filteredPlaybooks?.length ?? 0})
            </h3>
            <p className="text-xs text-text-muted">
              Choose an adversary campaign below to run as a full automated barrage or step through interactively.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            {/* Platform filter */}
            <div className="flex items-center rounded-lg border border-border-subtle bg-bg-surface p-0.5 font-mono text-[11px]">
              {(["all", "linux", "windows", "macos"] as const).map((p) => (
                <button
                  key={p}
                  onClick={() => setPlatformFilter(p)}
                  className={`rounded-md px-2.5 py-1 capitalize transition ${
                    platformFilter === p
                      ? "bg-accent/20 font-bold text-accent shadow-sm"
                      : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  {p}
                </button>
              ))}
            </div>

            {/* Severity filter */}
            <div className="flex items-center rounded-lg border border-border-subtle bg-bg-surface p-0.5 font-mono text-[11px]">
              {(["all", "critical", "high", "suspicious"] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => setSeverityFilter(s)}
                  className={`rounded-md px-2.5 py-1 capitalize transition ${
                    severityFilter === s
                      ? "bg-accent/20 font-bold text-accent shadow-sm"
                      : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>

            <div className="relative">
              <Icon name="search" size={14} className="absolute left-2.5 top-2.5 text-text-faint" />
              <input
                type="text"
                placeholder="Search campaigns..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-8 w-52 rounded-lg border border-border-subtle bg-bg-surface pl-8 pr-3 text-xs outline-none focus:border-accent/50 font-mono"
              />
            </div>
          </div>
        </div>

        {isLoading ? (
          <div className="py-12 text-center font-mono text-xs text-text-faint">
            Loading adversary attack campaigns...
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {(filteredPlaybooks || []).map((pb) => {
              const isDetonating = detonatingPlaybookId === pb.id;
              const isCritical = pb.severity === "critical";
              const isHigh = pb.severity === "high";
              const isSelectedStep = stepScenario?.id === pb.id;

              return (
                <div
                  key={pb.id}
                  className={`panel group relative flex flex-col justify-between p-5 transition-all duration-200 hover:border-accent/60 hover:shadow-[0_8px_24px_-6px_rgba(217,164,65,0.15)] ${
                    isSelectedStep ? "border-accent ring-1 ring-accent bg-accent/5" : ""
                  }`}
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
                            : isHigh
                              ? "border border-amber-500/40 bg-amber-500/15 text-amber-400"
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
                      <span className="rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-[9px] font-semibold text-accent">
                        {pb.stages_count || pb.stages?.length || 1} Stages
                      </span>
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

                  <div className="mt-5 flex flex-wrap items-center justify-between gap-2 border-t border-border-subtle pt-3.5">
                    <button
                      onClick={() => handleStartStepMode(pb)}
                      className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-[11px] text-text-muted transition hover:border-accent/60 hover:text-accent"
                    >
                      <Icon name="sliders" size={11} />
                      <span>Step-by-Step Mode</span>
                    </button>

                    <button
                      onClick={() => void handleRunFullLiveSimulation(pb.id)}
                      disabled={detonatingPlaybookId !== null || isExecutingStage}
                      className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent/15 px-3.5 py-1.5 font-mono text-[11px] font-semibold text-accent transition-all duration-150 hover:bg-accent/25 hover:shadow-[var(--glow-accent)] disabled:opacity-50"
                    >
                      <Icon
                        name={isDetonating ? "refresh" : "play"}
                        size={11}
                        className={isDetonating ? "animate-spin" : ""}
                      />
                      <span>{isDetonating ? "Executing Full Run..." : "Run All Stages"}</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
      </>
      )}

      {/* ── ADVERSARY TECHNIQUE UNIT TESTS ───────────────────────────────── */}
      {activeTab === "techniques" && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h3 className="font-sans text-sm font-bold text-text-primary">
                Adversary Technique Unit Tests ({techniques.length})
              </h3>
              <p className="text-xs text-text-muted">
                Fine-grained, modular tests mapped to MITRE ATT&CK techniques with prerequisites verification, real telemetry generation, and automated cleanup contracts.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative">
                <Icon name="search" size={14} className="absolute left-2.5 top-2.5 text-text-faint" />
                <input
                  type="text"
                  placeholder="Search techniques (e.g. cron, bash, suid)..."
                  value={techniqueSearch}
                  onChange={(e) => setTechniqueSearch(e.target.value)}
                  className="h-8 w-64 rounded-lg border border-border-subtle bg-bg-surface pl-8 pr-3 text-xs outline-none focus:border-accent/50 font-mono"
                />
              </div>
            </div>
          </div>

          {/* Tactic Filter Pills */}
          <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
            {["all", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Exfiltration"].map((t) => (
              <button
                key={t}
                onClick={() => setTechniqueTactic(t)}
                className={`rounded-lg px-3 py-1.5 transition ${
                  techniqueTactic === t
                    ? "bg-accent/20 font-bold text-accent border border-accent/40"
                    : "bg-bg-surface border border-border-subtle text-text-muted hover:text-text-primary"
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          {/* Active Technique Result Card */}
          {techniqueResult && (
            <div className="rounded-2xl border border-accent/50 bg-bg-surface p-5 font-mono text-xs space-y-4 shadow-xl">
              <div className="flex items-center justify-between border-b border-border-subtle pb-3">
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      techniqueResult.status === "success"
                        ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                        : "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                    }`}
                  >
                    {techniqueResult.status} (exit {techniqueResult.exit_code})
                  </span>
                  <span className="font-bold text-text-primary">
                    {techniqueResult.technique_id} · {techniqueResult.name}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-text-muted text-[11px]">
                  <span>{techniqueResult.elapsed_ms}ms</span>
                  <span>·</span>
                  <button onClick={() => setTechniqueResult(null)} className="hover:text-accent font-bold">
                    Close ×
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-5 gap-3 text-[11px]">
                <div className="bg-panel-muted/60 p-2.5 rounded-lg border border-border-subtle/50">
                  <span className="text-text-muted block text-[10px] uppercase">Prerequisites</span>
                  <span className={techniqueResult.prereqs_met ? "text-emerald-400 font-bold" : "text-rose-400 font-bold"}>
                    {techniqueResult.prereqs_met ? "Verified OK" : "Failed / Missing"}
                  </span>
                </div>
                <div className="bg-panel-muted/60 p-2.5 rounded-lg border border-border-subtle/50">
                  <span className="text-text-muted block text-[10px] uppercase">Cleanup Contract</span>
                  <span className="text-emerald-400 font-bold capitalize">
                    {techniqueResult.cleanup_status}
                  </span>
                </div>
                <div className="bg-panel-muted/60 p-2.5 rounded-lg border border-border-subtle/50">
                  <span className="text-text-muted block text-[10px] uppercase">Telemetry Contract</span>
                  <span className={techniqueResult.telemetry_verified ? "text-emerald-400 font-bold" : "text-amber-400 font-bold"}>
                    {techniqueResult.telemetry_verified ? "Contract Verified" : "Partial Coverage"} ({techniqueResult.telemetry_coverage_pct ?? 100}%)
                  </span>
                </div>
                <div className="bg-panel-muted/60 p-2.5 rounded-lg border border-border-subtle/50">
                  <span className="text-text-muted block text-[10px] uppercase">Telemetry Ingested</span>
                  <span className="text-accent font-bold">
                    {techniqueResult.events_count} events
                  </span>
                </div>
                <div className="bg-panel-muted/60 p-2.5 rounded-lg border border-border-subtle/50">
                  <span className="text-text-muted block text-[10px] uppercase">Triggered Alerts</span>
                  <span className={techniqueResult.alerts_count > 0 ? "text-rose-400 font-bold" : "text-text-muted font-bold"}>
                    {techniqueResult.alerts_count} alert(s) fired
                  </span>
                </div>
              </div>

              {techniqueResult.matched_telemetry && techniqueResult.matched_telemetry.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
                  <span className="text-text-faint">Verified Sensor Events:</span>
                  {techniqueResult.matched_telemetry.map((t, idx) => (
                    <span key={idx} className="rounded bg-emerald-950/40 border border-emerald-500/40 px-1.5 py-0.5 text-emerald-300 font-bold">
                      ✓ {t}
                    </span>
                  ))}
                  {(techniqueResult.missing_telemetry || []).map((t, idx) => (
                    <span key={idx} className="rounded bg-amber-950/40 border border-amber-500/40 px-1.5 py-0.5 text-amber-300">
                      ✗ {t}
                    </span>
                  ))}
                </div>
              )}

              {/* Terminal output */}
              <div className="space-y-1">
                <span className="text-[10px] text-text-faint uppercase font-bold">
                  Execution Output (stdout / stderr)
                </span>
                <pre className="max-h-52 overflow-y-auto rounded-lg border border-border-subtle bg-[#0a0c10] p-3 text-[11px] text-[#c9d1d9] leading-relaxed font-mono">
                  {techniqueResult.stdout || "(no stdout)"}
                  {techniqueResult.stderr ? `\n[STDERR]:\n${techniqueResult.stderr}` : ""}
                </pre>
              </div>
            </div>
          )}

          {/* Technique Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {techniques.map((tech) => {
              const isRunning = runningTechniqueId === tech.id;
              const isExpanded = expandedTechniqueId === tech.id;

              return (
                <div
                  key={tech.id}
                  className="rounded-xl border border-border-subtle bg-bg-surface p-5 space-y-3 transition hover:border-accent/40 shadow-sm"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="rounded border border-accent/40 bg-accent/15 px-2 py-0.5 font-mono text-[10px] font-bold text-accent">
                          {tech.technique_id}
                        </span>
                        <span className="rounded border border-border-subtle bg-bg-inset px-2 py-0.5 font-mono text-[10px] text-text-muted">
                          {tech.tactic}
                        </span>
                      </div>
                      <h4 className="font-semibold text-text-primary text-xs leading-snug">{tech.name}</h4>
                    </div>

                    <button
                      onClick={() => handleRunTechnique(tech.id)}
                      disabled={runningTechniqueId !== null}
                      className={`btn btn-sm shrink-0 font-mono text-xs ${
                        isRunning ? "btn-primary animate-pulse" : "btn-primary"
                      }`}
                    >
                      <Icon
                        name={isRunning ? "refresh" : "play"}
                        size={11}
                        className={isRunning ? "animate-spin mr-1" : "mr-1"}
                      />
                      {isRunning ? "Running…" : "Run Technique"}
                    </button>
                  </div>

                  <p className="text-xs text-text-muted leading-relaxed">{tech.description}</p>

                  <div className="border-t border-border-subtle/50 pt-2 flex items-center justify-between text-[11px] font-mono text-text-faint">
                    <span>Platforms: {tech.supported_platforms.join(", ")}</span>
                    <button
                      onClick={() => setExpandedTechniqueId(isExpanded ? null : tech.id)}
                      className="hover:text-accent underline cursor-pointer"
                    >
                      {isExpanded ? "Hide Code ▲" : "View Code ▼"}
                    </button>
                  </div>

                  {isExpanded && (
                    <div className="mt-2 space-y-2 rounded-lg border border-border-subtle bg-[#0a0c10] p-3 text-[10px] font-mono">
                      <div>
                        <span className="text-accent uppercase font-bold block mb-0.5">Attack Command:</span>
                        <pre className="text-[#c9d1d9] whitespace-pre-wrap break-all">{tech.attack_command}</pre>
                      </div>
                      {tech.cleanup_command && (
                        <div>
                          <span className="text-text-muted uppercase font-bold block mb-0.5">Cleanup Script:</span>
                          <pre className="text-text-muted whitespace-pre-wrap break-all">{tech.cleanup_command}</pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
