import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Icon } from "../components/Icon";
import { platformIconName } from "../components/iconMeta";
import { PageHeader } from "../components/ui";
import { ProcessCausalityTree } from "../components/ProcessCausalityTree";
import {
  detonateDynamic,
  executeSimulationStage,
  getPlaybooks,
  getSamples,
  getSandboxArtifactUrl,
  getSandboxDrivers,
  listTechniqueTests,
  runLiveSimulation,
  runTechniqueTest,
} from "../lib/api";
import type {
  DroppedArtifactItem,
  PlaybookScenario,
  SampleRow,
  SamplesResponse,
  SimulationStageResult,
  TechniqueRunResult,
  TechniqueTestItem,
} from "../types";

interface LiveExecutionResult {
  run_id: string;
  target_id: string;
  name: string;
  platform: string;
  source_type: "canary" | "vault" | "stage";
  terminal_output: string;
  terminal_lines: string[];
  exit_code: number;
  elapsed_ms?: number;
  events_count: number;
  alerts_count: number;
  alerts: any[];
  risk_score: number;
  process_tree: any[];
  dropped_artifacts: DroppedArtifactItem[];
  created_files: Array<{ name: string; path?: string; size_bytes?: number }>;
  network_connections?: Array<{ ip: string; port: number; protocol: string; status?: string }>;
  stages?: Array<{
    stage: number;
    name: string;
    cmd: string;
    exit_code: number;
    status: string;
  }>;
}

export default function MonitorPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const terminalEndRef = useRef<HTMLDivElement | null>(null);

  // Top Gallery Navigation Tab
  const [galleryTab, setGalleryTab] = useState<"canaries" | "vault" | "techniques">("canaries");

  // Filters & Search
  const [platformFilter, setPlatformFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [isolationDriver, setIsolationDriver] = useState<string>("auto");

  // Execution states
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [activeTargetId, setActiveTargetId] = useState<string | null>(null);
  const [executionError, setExecutionError] = useState<string | null>(null);
  const [copiedTerminal, setCopiedTerminal] = useState<boolean>(false);

  // Active execution result (Full Run or Vault Sample)
  const [activeResult, setActiveResult] = useState<LiveExecutionResult | null>(null);

  // Interactive Step-by-Step Mode State
  const [isStepModeActive, setIsStepModeActive] = useState<boolean>(false);
  const [stepScenario, setStepScenario] = useState<PlaybookScenario | null>(null);
  const [currentStageIndex, setCurrentStageIndex] = useState<number>(1);
  const [stepRunId, setStepRunId] = useState<string | null>(null);
  const [stepSandboxDir, setStepSandboxDir] = useState<string | null>(null);
  const [stageHistory, setStageHistory] = useState<SimulationStageResult[]>([]);
  const [stepDroppedArtifacts, setStepDroppedArtifacts] = useState<DroppedArtifactItem[]>([]);
  const [stepCreatedFiles, setStepCreatedFiles] = useState<Array<{ name: string; path?: string; size_bytes?: number }>>([]);

  // Right Deck Sub-Tab Inspector
  const [inspectorTab, setInspectorTab] = useState<"files" | "processes" | "network" | "detections">("files");

  // Technique Unit Tests State
  const [techniqueTactic, setTechniqueTactic] = useState<string>("all");
  const [runningTechniqueId, setRunningTechniqueId] = useState<string | null>(null);
  const [techniqueResult, setTechniqueResult] = useState<TechniqueRunResult | null>(null);
  const [expandedTechniqueId, setExpandedTechniqueId] = useState<string | null>(null);

  // Queries
  const { data: playbooks = [], isLoading: isLoadingPlaybooks } = useQuery<PlaybookScenario[]>({
    queryKey: ["playbooks"],
    queryFn: getPlaybooks,
  });

  const { data: vaultData } = useQuery<SamplesResponse>({
    queryKey: ["samples", { limit: 50 }],
    queryFn: () => getSamples({ limit: 50 }),
  });

  const { data: drivers = [] } = useQuery({
    queryKey: ["sandbox-drivers"],
    queryFn: getSandboxDrivers,
  });

  const { data: techniques = [] } = useQuery<TechniqueTestItem[]>({
    queryKey: ["techniques", techniqueTactic, searchQuery],
    queryFn: () => listTechniqueTests(techniqueTactic === "all" ? undefined : techniqueTactic, undefined, searchQuery.trim() || undefined),
  });

  // Auto-scroll terminal when new lines appear
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [activeResult?.terminal_output, stageHistory.length]);

  // Filtered Playbooks
  const filteredPlaybooks = playbooks.filter((pb) => {
    if (platformFilter !== "all" && pb.platform !== platformFilter) return false;
    if (severityFilter !== "all" && pb.severity !== severityFilter) return false;
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      pb.name.toLowerCase().includes(q) ||
      pb.description.toLowerCase().includes(q) ||
      (pb.techniques || []).some((t) => t.toLowerCase().includes(q))
    );
  });

  // Filtered Vault Samples
  const vaultSamples: SampleRow[] = (vaultData?.samples || []).filter((s) => {
    if (platformFilter !== "all" && s.detected_platform !== platformFilter) return false;
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      s.original_name.toLowerCase().includes(q) ||
      (s.family || "").toLowerCase().includes(q) ||
      s.sha256.toLowerCase().includes(q)
    );
  });

  // Copy terminal text
  const handleCopyTerminal = () => {
    const text = isStepModeActive ? cumulativeStepLogs : activeResult?.terminal_output || "";
    if (!text) return;
    void navigator.clipboard.writeText(text);
    setCopiedTerminal(true);
    setTimeout(() => setCopiedTerminal(false), 2000);
  };

  // Reset Cockpit to Standby
  const handleResetCockpit = () => {
    setActiveResult(null);
    setIsStepModeActive(false);
    setStepScenario(null);
    setCurrentStageIndex(1);
    setStepRunId(null);
    setStepSandboxDir(null);
    setStageHistory([]);
    setStepDroppedArtifacts([]);
    setStepCreatedFiles([]);
    setExecutionError(null);
    setActiveTargetId(null);
  };

  // Run Full Automated Live Canary Simulation
  const handleRunFullPlaybook = async (scenario: PlaybookScenario) => {
    setIsExecuting(true);
    setActiveTargetId(scenario.id);
    setExecutionError(null);
    setIsStepModeActive(false);
    setStepScenario(null);

    try {
      const res = await runLiveSimulation(scenario.id);
      
      // Parse network connections from stdout/stderr
      const text = res.terminal_output || "";
      const ipMatches = Array.from(new Set(text.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g) || [])).filter(
        (ip) => !ip.startsWith("127.") && !ip.startsWith("0.") && !ip.startsWith("255.")
      );
      const networkConns = ipMatches.map((ip) => ({
        ip,
        port: text.includes(":4444") ? 4444 : 443,
        protocol: "TCP",
        status: "ESTABLISHED",
      }));

      // Unify created files from created_files and dropped_artifacts
      const createdList: Array<{ name: string; path?: string; size_bytes?: number }> = [
        ...(res.created_files || []),
      ];
      (res.dropped_artifacts || []).forEach((da: DroppedArtifactItem) => {
        if (!createdList.some((c) => c.name === da.name)) {
          createdList.push({ name: da.name, size_bytes: da.size_bytes });
        }
      });

      setActiveResult({
        run_id: res.run_id,
        target_id: scenario.id,
        name: scenario.name,
        platform: res.platform || scenario.platform,
        source_type: "canary",
        terminal_output: res.terminal_output,
        terminal_lines: res.terminal_lines || (res.terminal_output ? res.terminal_output.split("\n") : []),
        exit_code: 0,
        events_count: res.events_count ?? 0,
        alerts_count: res.alerts_count ?? (res.alerts?.length || 0),
        alerts: res.alerts || [],
        risk_score: res.risk_score ?? 0,
        process_tree: res.process_tree || [],
        dropped_artifacts: res.dropped_artifacts || [],
        created_files: createdList,
        network_connections: networkConns,
        stages: res.stages || [],
      });

      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Execution failed. Check sandbox backend status.";
      setExecutionError(msg);
      console.error("Live simulation failed:", err);
    } finally {
      setIsExecuting(false);
      setActiveTargetId(null);
    }
  };

  // Run Vault Executable Sample Dynamically
  const handleDetonateVaultSample = async (sample: SampleRow) => {
    setIsExecuting(true);
    setActiveTargetId(sample.sample_id);
    setExecutionError(null);
    setIsStepModeActive(false);
    setStepScenario(null);

    try {
      const res = await detonateDynamic({
        sample_id: sample.sample_id,
        isolation_driver: isolationDriver,
      });

      // Parse network connections
      const text = (res.stdout || "") + "\n" + (res.stderr || "");
      const ipMatches = Array.from(new Set(text.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g) || [])).filter(
        (ip) => !ip.startsWith("127.") && !ip.startsWith("0.") && !ip.startsWith("255.")
      );
      const networkConns = ipMatches.map((ip) => ({
        ip,
        port: text.includes(":4444") ? 4444 : 80,
        protocol: "TCP",
        status: "OUTBOUND",
      }));

      // Unify created files
      const createdList: Array<{ name: string; path?: string; size_bytes?: number }> = [];
      (res.dropped_artifacts || []).forEach((da: DroppedArtifactItem) => {
        createdList.push({ name: da.name, size_bytes: da.size_bytes });
      });

      setActiveResult({
        run_id: res.run_id,
        target_id: sample.sample_id,
        name: sample.original_name,
        platform: res.platform || sample.detected_platform,
        source_type: "vault",
        terminal_output: res.terminal_output || res.stdout || res.stderr || `Execution completed with exit code ${res.exit_code}`,
        terminal_lines: res.terminal_lines || (res.terminal_output ? res.terminal_output.split("\n") : []),
        exit_code: res.exit_code ?? 0,
        events_count: res.events_count ?? (res.timeline?.length || 0),
        alerts_count: res.alerts_count ?? (res.alerts?.length || 0),
        alerts: res.alerts || [],
        risk_score: res.risk_score ?? 0,
        process_tree: res.process_tree || [],
        dropped_artifacts: res.dropped_artifacts || [],
        created_files: createdList,
        network_connections: networkConns,
      });

      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Vault sample detonation failed.";
      setExecutionError(msg);
      console.error("Vault detonation failed:", err);
    } finally {
      setIsExecuting(false);
      setActiveTargetId(null);
    }
  };

  // Launch Step-by-Step Interactive Mode
  const handleStartStepMode = (scenario: PlaybookScenario) => {
    setIsStepModeActive(true);
    setStepScenario(scenario);
    setCurrentStageIndex(1);
    setStepRunId(null);
    setStepSandboxDir(null);
    setStageHistory([]);
    setStepDroppedArtifacts([]);
    setStepCreatedFiles([]);
    setActiveResult(null);
    setExecutionError(null);
    setActiveTargetId(scenario.id);
  };

  // Execute Next Single Stage in Stepper
  const handleExecuteNextStage = async () => {
    if (!stepScenario || isExecuting) return;
    setIsExecuting(true);
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
        setStepDroppedArtifacts((prev) => {
          const combined = [...prev];
          (res.dropped_artifacts || []).forEach((da) => {
            if (!combined.some((c) => c.name === da.name)) combined.push(da);
          });
          return combined;
        });
      }
      if (res.created_files && res.created_files.length > 0) {
        setStepCreatedFiles((prev) => {
          const combined = [...prev];
          (res.created_files || []).forEach((cf) => {
            if (!combined.some((c) => c.name === cf.name)) combined.push(cf);
          });
          return combined;
        });
      }

      void queryClient.invalidateQueries({ queryKey: ["events"] });
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: ["runs"] });

      if (!res.is_final_stage) {
        setCurrentStageIndex((prev) => prev + 1);
      }
    } catch (err: unknown) {
      setExecutionError(err instanceof Error ? err.message : "Stage execution failed.");
    } finally {
      setIsExecuting(false);
    }
  };

  // Run all remaining stages in stepper
  const handleRunAllRemainingStages = async () => {
    if (!stepScenario || isExecuting) return;
    const totalStages = stepScenario.stages?.length || stepScenario.stages_count;
    let nextStage = currentStageIndex;
    let activeRunId = stepRunId;
    let activeWs = stepSandboxDir;

    setIsExecuting(true);
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
          setStepDroppedArtifacts((prev) => {
            const combined = [...prev];
            (res.dropped_artifacts || []).forEach((da) => {
              if (!combined.some((c) => c.name === da.name)) combined.push(da);
            });
            return combined;
          });
        }
        if (res.created_files && res.created_files.length > 0) {
          setStepCreatedFiles((prev) => {
            const combined = [...prev];
            (res.created_files || []).forEach((cf) => {
              if (!combined.some((c) => c.name === cf.name)) combined.push(cf);
            });
            return combined;
          });
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
      setIsExecuting(false);
    }
  };

  // Run Individual MITRE ATT&CK Technique Test
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

  // Cumulative logs for step mode
  const cumulativeStepLogs = stageHistory
    .map(
      (st) =>
        `>>> [Stage ${st.stage_number}/${st.total_stages}] ${st.stage_name}\n$ ${st.command}\n[Exit: ${st.exit_code} | Duration: ${st.elapsed_ms}ms]\n${st.stdout || "(no stdout)"}${st.stderr ? `\n[STDERR]:\n${st.stderr}` : ""}`,
    )
    .join("\n" + "=".repeat(60) + "\n\n");

  const cumulativeStepAlerts = stageHistory.flatMap((s) => s.alerts || []);
  const totalStepStages = stepScenario?.stages?.length || stepScenario?.stages_count || 0;
  const isStepFinished = stageHistory.length > 0 && stageHistory[stageHistory.length - 1]?.is_final_stage;

  // Derive active live cockpit metrics
  const displayRunId = isStepModeActive ? stepRunId : activeResult?.run_id;
  const displayName = isStepModeActive ? stepScenario?.name : activeResult?.name;
  const displayFiles: Array<{ name: string; path?: string; size_bytes?: number }> = isStepModeActive
    ? (() => {
        const map = new Map<string, { name: string; path?: string; size_bytes?: number }>();
        stepCreatedFiles.forEach((f) => map.set(f.name, f));
        stepDroppedArtifacts.forEach((d) => {
          if (!map.has(d.name)) map.set(d.name, { name: d.name, size_bytes: d.size_bytes });
        });
        return Array.from(map.values());
      })()
    : activeResult?.created_files || [];
  const displayArtifacts = isStepModeActive ? stepDroppedArtifacts : activeResult?.dropped_artifacts || [];
  const displayAlerts = isStepModeActive ? cumulativeStepAlerts : activeResult?.alerts || [];
  const displayProcesses = isStepModeActive
    ? stageHistory.map((s, idx) => ({
        pid: 1000 + idx,
        process_name: s.command.split(" ")[0] || "sh",
        command_line: s.command,
        status: s.status,
      }))
    : activeResult?.process_tree || [];
  const displayNetwork = activeResult?.network_connections || [];

  const hasActiveSession = Boolean(activeResult || isStepModeActive);

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 space-y-8">
      {/* ── Page Header & Architecture Status Strip ───────────────────────── */}
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <PageHeader
          kicker="Simulation Lab · Dynamic Behavior & Canary Cockpit"
          title="Adversary Simulation & Dynamic Behavioral Sandbox"
          lede="Detonate safe non-destructive behavioral canaries and vault samples in an isolated sandbox. Watch live command execution in the terminal alongside dynamic tracking of processes spawned, files created, network sockets, and detection rule hits."
        />
        <div className="flex shrink-0 items-center gap-2 font-mono text-xs">
          <div className="flex items-center gap-2 rounded-xl border border-accent/40 bg-accent/10 px-3.5 py-2 text-accent shadow-sm">
            <span className="h-2 w-2 rounded-full bg-accent animate-pulse" />
            <span className="font-bold">Sandbox Driver:</span>
            <select
              value={isolationDriver}
              onChange={(e) => setIsolationDriver(e.target.value)}
              className="bg-transparent font-bold text-accent outline-none cursor-pointer border-b border-accent/40 text-xs"
              title="Select sandbox isolation driver"
            >
              <option value="auto" className="bg-bg-surface text-text-primary">Auto (Kernel Namespaces / Micro-Sandbox)</option>
              {drivers.map((d) => (
                <option key={d.id} value={d.id} className="bg-bg-surface text-text-primary">
                  {d.name} {d.available ? "✓" : "(unavailable)"}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Execution Error Banner */}
      {executionError && (
        <div className="rounded-2xl border border-risk-malicious/50 bg-risk-malicious/10 p-4 font-mono text-xs text-risk-malicious flex items-start gap-3 shadow-sm">
          <Icon name="alert" size={16} className="shrink-0 mt-0.5" />
          <div className="flex-1">
            <span className="font-bold">Sandbox Execution Error</span>
            <p className="mt-1 text-[11px] text-text-muted">{executionError}</p>
          </div>
          <button onClick={() => setExecutionError(null)} className="text-text-muted hover:text-text-primary font-bold">
            ×
          </button>
        </div>
      )}

      {/* ── DUAL-DECK SIDE-BY-SIDE LIVE COCKPIT ─────────────────────────────── */}
      <section className="panel overflow-hidden border-border-subtle p-0 shadow-2xl bg-bg-surface/80 backdrop-blur-sm">
        {/* Cockpit Header Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle bg-bg-surface px-5 py-3.5">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span className="h-3 w-3 rounded-full bg-rose-500/80 inline-block" />
              <span className="h-3 w-3 rounded-full bg-amber-500/80 inline-block" />
              <span className="h-3 w-3 rounded-full bg-emerald-500/80 inline-block" />
            </div>
            <span className="font-mono text-xs font-bold text-text-primary flex items-center gap-2">
              <Icon name="terminal" size={14} className="text-accent" />
              {displayName ? (
                <span>outpost-sandbox: <span className="text-accent">{displayName}</span></span>
              ) : (
                <span className="text-text-muted">outpost-sandbox: standby-chamber</span>
              )}
            </span>
          </div>

          <div className="flex items-center gap-2 font-mono text-xs">
            {isExecuting ? (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-accent/20 border border-accent/50 px-3 py-0.5 text-[11px] font-bold text-accent animate-pulse">
                <Icon name="refresh" size={11} className="animate-spin" />
                DETONATING IN SANDBOX
              </span>
            ) : hasActiveSession ? (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/20 border border-emerald-500/40 px-3 py-0.5 text-[11px] font-bold text-emerald-400">
                <Icon name="check" size={11} />
                SESSION ACTIVE · RECORDED
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-bg-inset border border-border-subtle px-3 py-0.5 text-[11px] text-text-faint">
                ● STANDBY · AWAITING TARGET
              </span>
            )}

            {hasActiveSession && (
              <>
                <button
                  onClick={handleCopyTerminal}
                  className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-[11px] text-text-muted hover:border-accent/50 hover:text-accent"
                  title="Copy terminal output to clipboard"
                >
                  <Icon name={copiedTerminal ? "check" : "copy"} size={11} />
                  <span>{copiedTerminal ? "Copied" : "Copy Log"}</span>
                </button>

                <button
                  onClick={handleResetCockpit}
                  className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-[11px] text-text-muted hover:text-rose-400 hover:border-rose-400/50"
                  title="Reset cockpit and clear output"
                >
                  <Icon name="refresh" size={11} />
                  <span>Reset Lab</span>
                </button>
              </>
            )}
          </div>
        </div>

        {/* Dual Deck Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 min-h-[460px] divide-y lg:divide-y-0 lg:divide-x divide-border-subtle">
          {/* ── LEFT DECK: Interactive Sandbox Terminal Window (7 Columns) ── */}
          <div className="lg:col-span-7 flex flex-col justify-between bg-[#080b11] p-4 font-mono text-xs">
            <div className="space-y-3 flex-1 flex flex-col">
              {/* Stepper Controls Strip (If in Step-by-Step Mode) */}
              {isStepModeActive && stepScenario && (
                <div className="rounded-xl border border-accent/40 bg-accent/10 p-3 space-y-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-[11px] font-bold text-accent uppercase flex items-center gap-1.5">
                      <Icon name="sliders" size={13} />
                      Interactive Stepper: Stage {stageHistory.length} of {totalStepStages}
                    </span>
                    <div className="flex items-center gap-2">
                      {!isStepFinished ? (
                        <>
                          <button
                            onClick={() => void handleExecuteNextStage()}
                            disabled={isExecuting}
                            className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/70 bg-accent/25 px-3 py-1 text-xs font-bold text-accent transition hover:bg-accent/40 disabled:opacity-50"
                          >
                            <Icon name={isExecuting ? "refresh" : "play"} size={11} className={isExecuting ? "animate-spin" : ""} />
                            <span>{isExecuting ? "Executing…" : `Execute Stage ${currentStageIndex}`}</span>
                          </button>
                          <button
                            onClick={() => void handleRunAllRemainingStages()}
                            disabled={isExecuting}
                            className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-[11px] text-text-muted hover:text-accent disabled:opacity-50"
                          >
                            <Icon name="zap" size={11} />
                            <span>Run All</span>
                          </button>
                        </>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-lg bg-emerald-500/20 border border-emerald-500/50 px-2.5 py-1 text-[11px] font-bold text-emerald-400">
                          <Icon name="check" size={11} />
                          Completed
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Stage Progress Pills */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5 text-[10px]">
                    {(stepScenario.stages || []).map((stg, sidx) => {
                      const stgNum = sidx + 1;
                      const hasExecuted = stgNum < currentStageIndex || isStepFinished;
                      const isCurrent = stgNum === currentStageIndex && !isStepFinished;
                      return (
                        <div
                          key={sidx}
                          className={`rounded border p-1.5 truncate ${
                            isCurrent
                              ? "border-accent bg-accent/20 text-accent font-bold ring-1 ring-accent"
                              : hasExecuted
                                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                                : "border-border-subtle bg-bg-base/40 text-text-faint"
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span>Stage {stgNum}</span>
                            <span>{isCurrent ? "Ready" : hasExecuted ? "✓" : "—"}</span>
                          </div>
                          <div className="truncate opacity-80">{stg.name}</div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Terminal Screen Console */}
              <div className="flex-1 rounded-xl border border-border-subtle/60 bg-[#06080d] p-4 overflow-y-auto max-h-[380px] shadow-inner selection:bg-accent selection:text-black">
                {hasActiveSession ? (
                  <div className="space-y-1 text-[11px] leading-relaxed font-mono">
                    <div className="text-emerald-400 font-bold mb-2 flex items-center gap-1.5">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                      <span>[OutPost Sandbox Cage Active · Process PID Isolated]</span>
                    </div>

                    {isStepModeActive ? (
                      stageHistory.length === 0 ? (
                        <div className="text-text-muted py-6 text-center">
                          Ready. Click <span className="text-accent font-bold">"Execute Stage 1"</span> above to dispatch the first attack stage into the isolated workspace.
                        </div>
                      ) : (
                        stageHistory.map((sh, sidx) => (
                          <div key={sidx} className="space-y-1 pb-3 border-b border-white/5 last:border-b-0">
                            <div className="text-accent font-bold">
                              &gt;&gt;&gt; [Stage {sh.stage_number}/{sh.total_stages}] {sh.stage_name}
                            </div>
                            <div className="text-cyan-300">$ {sh.command}</div>
                            <div className="text-text-faint text-[10px]">
                              [Exit: {sh.exit_code} | Duration: {sh.elapsed_ms}ms]
                            </div>
                            {sh.stdout && (
                              <pre className="text-text-muted whitespace-pre-wrap pl-2 font-mono">{sh.stdout}</pre>
                            )}
                            {sh.stderr && (
                              <pre className="text-rose-400 whitespace-pre-wrap pl-2 font-mono">[STDERR]: {sh.stderr}</pre>
                            )}
                          </div>
                        ))
                      )
                    ) : (
                      (activeResult?.terminal_lines || []).map((line, lidx) => {
                        const isCmd = line.startsWith("$") || line.includes("Executing") || line.startsWith(">>>");
                        const isErr = line.toLowerCase().includes("error") || line.toLowerCase().includes("stderr") || line.includes("[!]");
                        const isInfo = line.startsWith("[*]") || line.startsWith("[OutPost");
                        return (
                          <div
                            key={lidx}
                            className={`whitespace-pre-wrap break-all ${
                              isCmd
                                ? "text-accent font-bold"
                                : isErr
                                  ? "text-rose-400"
                                  : isInfo
                                    ? "text-emerald-400"
                                    : "text-[#c9d1d9]"
                            }`}
                          >
                            {line}
                          </div>
                        );
                      })
                    )}
                    <div ref={terminalEndRef} />
                  </div>
                ) : (
                  /* Pristine Standby State */
                  <div className="flex flex-col items-center justify-center h-full min-h-[300px] text-center space-y-3 font-mono py-12">
                    <div className="h-12 w-12 rounded-2xl border border-accent/40 bg-accent/10 flex items-center justify-center text-accent shadow-[var(--glow-accent)]">
                      <Icon name="terminal" size={24} />
                    </div>
                    <div className="space-y-1">
                      <p className="text-text-primary font-bold text-sm">Sandbox Terminal Standby</p>
                      <p className="text-text-muted text-xs max-w-sm">
                        Select a behavioral canary or vault sample from the gallery below to initiate isolated execution and watch the console output in real time.
                      </p>
                    </div>
                    <div className="rounded-lg bg-bg-surface border border-border-subtle px-3 py-1.5 text-[11px] text-accent">
                      outpost-sandbox:~$ <span className="animate-pulse">_</span>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Terminal Footer Status Bar */}
            <div className="mt-3 pt-2.5 border-t border-border-subtle/50 flex items-center justify-between text-[11px] text-text-faint">
              <span className="flex items-center gap-1.5">
                <span className={`h-2 w-2 rounded-full ${hasActiveSession ? "bg-emerald-400 animate-pulse" : "bg-text-faint"}`} />
                <span>Isolated Target Directory: Ephemeral Sandbox</span>
              </span>
              <span>Shell: /bin/bash (restricted cgroup)</span>
            </div>
          </div>

          {/* ── RIGHT DECK: Live Behavioral Flight Recorder (5 Columns) ───── */}
          <div className="lg:col-span-5 flex flex-col justify-between bg-bg-surface p-4 font-mono text-xs space-y-4">
            <div className="space-y-4">
              {/* Top 4 Real-Time Behavioral KPI Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-2 gap-2 text-center">
                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-2.5 space-y-0.5">
                  <div className="flex items-center justify-center gap-1 text-accent text-[11px]">
                    <Icon name="file" size={13} />
                    <span className="font-bold">Files Created</span>
                  </div>
                  <div className="text-lg font-bold text-text-primary">
                    {displayFiles.length}
                  </div>
                  <span className="text-[9px] text-text-faint uppercase block">on disk</span>
                </div>

                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-2.5 space-y-0.5">
                  <div className="flex items-center justify-center gap-1 text-cyan-400 text-[11px]">
                    <Icon name="process" size={13} />
                    <span className="font-bold">Processes</span>
                  </div>
                  <div className="text-lg font-bold text-text-primary">
                    {displayProcesses.length}
                  </div>
                  <span className="text-[9px] text-text-faint uppercase block">spawned</span>
                </div>

                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-2.5 space-y-0.5">
                  <div className="flex items-center justify-center gap-1 text-emerald-400 text-[11px]">
                    <Icon name="network" size={13} />
                    <span className="font-bold">Network Sockets</span>
                  </div>
                  <div className="text-lg font-bold text-text-primary">
                    {displayNetwork.length}
                  </div>
                  <span className="text-[9px] text-text-faint uppercase block">outbound</span>
                </div>

                <div className="rounded-xl border border-border-subtle bg-bg-base/70 p-2.5 space-y-0.5">
                  <div className="flex items-center justify-center gap-1 text-rose-400 text-[11px]">
                    <Icon name="alert" size={13} />
                    <span className="font-bold">Rule Hits</span>
                  </div>
                  <div className={`text-lg font-bold ${displayAlerts.length > 0 ? "text-rose-400" : "text-text-primary"}`}>
                    {displayAlerts.length}
                  </div>
                  <span className="text-[9px] text-text-faint uppercase block">detections</span>
                </div>
              </div>

              {/* Inspector Sub-Tab Switcher */}
              <div className="flex items-center gap-1 border-b border-border-subtle pb-2 text-[11px]">
                <button
                  onClick={() => setInspectorTab("files")}
                  className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1 transition ${
                    inspectorTab === "files" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <Icon name="file" size={12} />
                  <span>Files Created ({displayFiles.length})</span>
                </button>
                <button
                  onClick={() => setInspectorTab("processes")}
                  className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1 transition ${
                    inspectorTab === "processes" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <Icon name="process" size={12} />
                  <span>Processes ({displayProcesses.length})</span>
                </button>
                <button
                  onClick={() => setInspectorTab("network")}
                  className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1 transition ${
                    inspectorTab === "network" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <Icon name="network" size={12} />
                  <span>Network ({displayNetwork.length})</span>
                </button>
                <button
                  onClick={() => setInspectorTab("detections")}
                  className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1 transition ${
                    inspectorTab === "detections" ? "bg-accent/20 font-bold text-accent" : "text-text-muted hover:text-text-primary"
                  }`}
                >
                  <Icon name="alert" size={12} />
                  <span>Detections ({displayAlerts.length})</span>
                </button>
              </div>

              {/* Inspector Tab 1: Files Created & Dropped Artifacts */}
              {inspectorTab === "files" && (
                <div className="space-y-2.5 max-h-[290px] overflow-y-auto pr-1">
                  {displayFiles.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
                      <Icon name="file" size={20} className="mx-auto text-text-faint mb-2" />
                      <p className="font-semibold text-text-primary">No Files Created Yet</p>
                      <p className="text-[11px] text-text-muted mt-1">
                        When the sample creates files, writes canary documents, or generates payloads, they will populate here live.
                      </p>
                    </div>
                  ) : (
                    displayFiles.map((f, fidx) => {
                      const art = displayArtifacts.find((a) => a.name === f.name);
                      return (
                        <div
                          key={fidx}
                          className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 space-y-2 hover:border-accent/40 transition"
                        >
                          <div className="flex items-start justify-between gap-2">
                            <div className="space-y-0.5 truncate">
                              <div className="flex items-center gap-1.5 text-accent font-bold text-xs truncate">
                                <Icon name="file" size={13} className="shrink-0" />
                                <span className="truncate">{f.name}</span>
                              </div>
                              <div className="text-[10px] text-text-faint font-mono">
                                Size: {f.size_bytes !== undefined ? `${f.size_bytes} B` : "Dynamic"}
                                {art?.entropy ? ` · Entropy: ${art.entropy}/8.0` : ""}
                              </div>
                            </div>

                            {art && displayRunId && (
                              <a
                                href={getSandboxArtifactUrl(displayRunId, art.filename)}
                                download
                                className="press inline-flex items-center gap-1 rounded border border-accent/50 bg-accent/15 px-2 py-0.5 text-[10px] font-bold text-accent hover:bg-accent/25 shrink-0"
                              >
                                <Icon name="download" size={10} />
                                <span>Download</span>
                              </a>
                            )}
                          </div>

                          {art?.preview && art.preview.length > 0 && (
                            <div className="bg-[#06080d] p-2 rounded text-[10px] font-mono text-emerald-400 max-h-16 overflow-y-auto space-y-0.5">
                              {art.preview.map((line, plidx) => (
                                <div key={plidx} className="truncate">{line}</div>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              )}

              {/* Inspector Tab 2: Processes Spawned */}
              {inspectorTab === "processes" && (
                <div className="space-y-2 max-h-[290px] overflow-y-auto pr-1">
                  {displayProcesses.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
                      <Icon name="process" size={20} className="mx-auto text-text-faint mb-2" />
                      <p className="font-semibold text-text-primary">No Subprocesses Spawned</p>
                      <p className="text-[11px] text-text-muted mt-1">
                        Active processes executed in the sandbox cgroup will appear here with PID, PPID, and arguments.
                      </p>
                    </div>
                  ) : activeResult?.process_tree && activeResult.process_tree.length > 0 ? (
                    <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3">
                      <ProcessCausalityTree nodes={activeResult.process_tree} />
                    </div>
                  ) : (
                    displayProcesses.map((pr: any, pidx: number) => (
                      <div key={pidx} className="rounded-xl border border-border-subtle bg-bg-base/60 p-2.5 space-y-1">
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="font-bold text-text-primary">{pr.process_name}</span>
                          <span className="text-[10px] text-text-faint">PID {pr.pid}</span>
                        </div>
                        <p className="text-[10px] text-text-muted font-mono truncate">$ {pr.command_line}</p>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Inspector Tab 3: Network Activity */}
              {inspectorTab === "network" && (
                <div className="space-y-2 max-h-[290px] overflow-y-auto pr-1">
                  {displayNetwork.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
                      <Icon name="network" size={20} className="mx-auto text-text-faint mb-2" />
                      <p className="font-semibold text-text-primary">No Network Sockets</p>
                      <p className="text-[11px] text-text-muted mt-1">
                        Outbound socket connections and C2 beacons detected during execution will be recorded here.
                      </p>
                    </div>
                  ) : (
                    displayNetwork.map((net, nidx) => (
                      <div key={nidx} className="rounded-xl border border-accent/40 bg-accent/10 p-3 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-accent">{net.ip}:{net.port}</span>
                          <span className="rounded bg-accent/20 px-1.5 py-0.5 text-[9px] font-bold uppercase text-accent">
                            {net.protocol}
                          </span>
                        </div>
                        <p className="text-[10px] text-text-muted">Status: {net.status || "ESTABLISHED"}</p>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Inspector Tab 4: Triggered Detection Rules */}
              {inspectorTab === "detections" && (
                <div className="space-y-2 max-h-[290px] overflow-y-auto pr-1">
                  {displayAlerts.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-border-subtle p-6 text-center text-text-muted">
                      <Icon name="shield" size={20} className="mx-auto text-text-faint mb-2" />
                      <p className="font-semibold text-text-primary">Zero Detections Fired</p>
                      <p className="text-[11px] text-text-muted mt-1">
                        Telemetry generated by the execution will be evaluated live by OutPost's detection engine.
                      </p>
                    </div>
                  ) : (
                    displayAlerts.map((al: any, aidx: number) => (
                      <div
                        key={aidx}
                        className="rounded-xl border border-risk-malicious/40 bg-risk-malicious/10 p-3 space-y-1.5"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <span className="font-bold text-text-primary text-xs">{al.rule_name}</span>
                          <span className="rounded border border-risk-malicious/40 bg-risk-malicious/20 px-1.5 py-0.5 text-[9px] font-bold uppercase text-risk-malicious">
                            {al.severity}
                          </span>
                        </div>
                        <p className="text-[11px] text-text-muted leading-relaxed">{al.details}</p>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>

            {/* Cockpit Permanent Record Banner & Pivot Strip */}
            {displayRunId && (
              <div className="rounded-xl border border-border-subtle bg-bg-base p-3 space-y-2">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-text-muted flex items-center gap-1.5 font-bold">
                    <Icon name="activity" size={12} className="text-accent" />
                    Recorded Run Dossier: <span className="text-accent">{displayRunId}</span>
                  </span>
                  <span className="text-text-faint text-[10px]">Permanent Audit Trail</span>
                </div>
                <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-border-subtle/50 text-[11px]">
                  <Link
                    to={`/runs/${displayRunId}`}
                    className="press inline-flex items-center gap-1 rounded-lg border border-accent/50 bg-accent/15 px-2.5 py-1 font-semibold text-accent hover:bg-accent/25"
                  >
                    <Icon name="external" size={11} />
                    <span>Run Dossier</span>
                  </Link>

                  <button
                    onClick={() => navigate(`/events?run_id=${displayRunId}`)}
                    className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-text-muted hover:border-accent/40 hover:text-accent"
                  >
                    <Icon name="list" size={11} />
                    <span>Events Log</span>
                  </button>

                  {displayAlerts.length > 0 && (
                    <Link
                      to={`/investigations?create=1&run_id=${displayRunId}&title=${encodeURIComponent((displayName || "Detonation") + " Attack Dossier")}`}
                      className="press inline-flex items-center gap-1 rounded-lg border border-risk-malicious/50 bg-risk-malicious/15 px-2.5 py-1 font-semibold text-risk-malicious hover:bg-risk-malicious/25"
                    >
                      <Icon name="shield" size={11} />
                      <span>Escalate Case</span>
                    </Link>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* ── DETONATION TARGET GALLERY (SAMPLE SELECTOR) ────────────────────── */}
      <section className="space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border-subtle pb-3">
          {/* Gallery Mode Tabs */}
          <div className="flex items-center gap-2 font-mono text-xs">
            <button
              onClick={() => setGalleryTab("canaries")}
              className={`flex items-center gap-2 rounded-xl px-4 py-2 transition ${
                galleryTab === "canaries"
                  ? "bg-accent/20 font-bold text-accent border border-accent/40 shadow-sm"
                  : "text-text-muted hover:text-text-primary hover:bg-white/5"
              }`}
            >
              <Icon name="play" size={13} />
              <span>Adversary Canaries & Campaigns ({filteredPlaybooks.length})</span>
            </button>

            <button
              onClick={() => setGalleryTab("vault")}
              className={`flex items-center gap-2 rounded-xl px-4 py-2 transition ${
                galleryTab === "vault"
                  ? "bg-accent/20 font-bold text-accent border border-accent/40 shadow-sm"
                  : "text-text-muted hover:text-text-primary hover:bg-white/5"
              }`}
            >
              <Icon name="box" size={13} />
              <span>Vault Executable Samples ({vaultSamples.length})</span>
            </button>

            <button
              onClick={() => setGalleryTab("techniques")}
              className={`flex items-center gap-2 rounded-xl px-4 py-2 transition ${
                galleryTab === "techniques"
                  ? "bg-accent/20 font-bold text-accent border border-accent/40 shadow-sm"
                  : "text-text-muted hover:text-text-primary hover:bg-white/5"
              }`}
            >
              <Icon name="target" size={13} />
              <span>MITRE Technique Unit Tests ({techniques.length})</span>
            </button>
          </div>

          {/* Filtering & Search Toolbar */}
          <div className="flex flex-wrap items-center gap-2.5 font-mono text-xs">
            {galleryTab !== "techniques" && (
              <>
                <div className="flex items-center rounded-lg border border-border-subtle bg-bg-surface p-0.5 text-[11px]">
                  {(["all", "linux", "windows", "macos"] as const).map((p) => (
                    <button
                      key={p}
                      onClick={() => setPlatformFilter(p)}
                      className={`rounded-md px-2 py-0.5 capitalize transition ${
                        platformFilter === p
                          ? "bg-accent/20 font-bold text-accent shadow-sm"
                          : "text-text-muted hover:text-text-primary"
                      }`}
                    >
                      {p}
                    </button>
                  ))}
                </div>

                {galleryTab === "canaries" && (
                  <div className="flex items-center rounded-lg border border-border-subtle bg-bg-surface p-0.5 text-[11px]">
                    {(["all", "critical", "high", "suspicious"] as const).map((s) => (
                      <button
                        key={s}
                        onClick={() => setSeverityFilter(s)}
                        className={`rounded-md px-2 py-0.5 capitalize transition ${
                          severityFilter === s
                            ? "bg-accent/20 font-bold text-accent shadow-sm"
                            : "text-text-muted hover:text-text-primary"
                        }`}
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                )}
              </>
            )}

            <div className="relative">
              <Icon name="search" size={13} className="absolute left-2.5 top-2.5 text-text-faint" />
              <input
                type="text"
                placeholder="Filter samples by name..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-7 w-48 rounded-lg border border-border-subtle bg-bg-surface pl-8 pr-2.5 text-xs outline-none focus:border-accent/50 font-mono"
              />
            </div>
          </div>
        </div>

        {/* ── GALLERY TAB 1: CURATED ADVERSARY CANARIES ──────────────────────── */}
        {galleryTab === "canaries" && (
          <div>
            {isLoadingPlaybooks ? (
              <div className="py-12 text-center font-mono text-xs text-text-faint">
                Loading adversary simulation canaries…
              </div>
            ) : filteredPlaybooks.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-border-subtle p-8 text-center text-text-muted font-mono text-xs">
                No adversary canaries match your filters.
              </div>
            ) : (
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
                {filteredPlaybooks.map((pb) => {
                  const isDetonating = isExecuting && activeTargetId === pb.id;
                  const isCurrentActive = (activeResult?.target_id === pb.id) || (stepScenario?.id === pb.id);
                  const isCritical = pb.severity === "critical";
                  const isHigh = pb.severity === "high";

                  return (
                    <div
                      key={pb.id}
                      className={`panel group flex flex-col justify-between p-4 transition-all duration-200 hover:border-accent/60 ${
                        isCurrentActive ? "border-accent ring-1 ring-accent bg-accent/5 shadow-md" : ""
                      }`}
                    >
                      <div className="space-y-2.5">
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="rounded border border-border-subtle bg-bg-elevated/60 p-1 font-mono text-[10px] text-text-muted">
                              <Icon name={platformIconName(pb.platform)} size={13} />
                            </span>
                            <h4 className="font-sans text-xs font-bold text-text-primary group-hover:text-accent leading-snug">
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

                        <p className="text-xs leading-relaxed text-text-muted line-clamp-2">
                          {pb.description}
                        </p>

                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-[9px] font-semibold text-accent">
                            {pb.stages_count || pb.stages?.length || 1} Stages
                          </span>
                          {(pb.techniques || []).slice(0, 3).map((t) => (
                            <span
                              key={t}
                              className="rounded border border-border-subtle bg-bg-inset px-1.5 py-0.5 font-mono text-[9px] text-text-faint"
                            >
                              {t}
                            </span>
                          ))}
                          {(pb.techniques || []).length > 3 && (
                            <span className="text-[9px] text-text-faint font-mono">
                              +{pb.techniques.length - 3} more
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="mt-4 flex items-center justify-between gap-2 border-t border-border-subtle pt-3 font-mono text-xs">
                        <button
                          onClick={() => handleStartStepMode(pb)}
                          disabled={isExecuting}
                          className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-[11px] text-text-muted hover:border-accent/50 hover:text-accent disabled:opacity-50"
                        >
                          <Icon name="sliders" size={11} />
                          <span>Step Mode</span>
                        </button>

                        <button
                          onClick={() => void handleRunFullPlaybook(pb)}
                          disabled={isExecuting}
                          className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent/15 px-3 py-1 text-[11px] font-bold text-accent transition hover:bg-accent/25 hover:shadow-[var(--glow-accent)] disabled:opacity-50"
                        >
                          <Icon
                            name={isDetonating ? "refresh" : "play"}
                            size={11}
                            className={isDetonating ? "animate-spin" : ""}
                          />
                          <span>{isDetonating ? "Detonating…" : "Detonate Sample"}</span>
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ── GALLERY TAB 2: VAULT EXECUTABLE SAMPLES ───────────────────────── */}
        {galleryTab === "vault" && (
          <div className="space-y-4">
            <div className="flex items-center justify-between text-xs text-text-muted font-mono">
              <span>Executable samples, scripts, and binaries stored in OutPost's vault.</span>
              <Link to="/samples" className="text-accent hover:underline flex items-center gap-1">
                <Icon name="plus" size={12} />
                <span>Upload Sample to Vault</span>
              </Link>
            </div>

            {vaultSamples.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-border-subtle p-8 text-center text-text-muted font-mono text-xs space-y-2">
                <Icon name="box" size={24} className="mx-auto text-text-faint" />
                <p className="font-bold text-text-primary">No Matching Vault Samples Found</p>
                <p className="text-[11px]">Upload custom binaries or scripts to the vault to detonate them here.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
                {vaultSamples.map((s) => {
                  const isDetonating = isExecuting && activeTargetId === s.sample_id;
                  const isCurrentActive = activeResult?.target_id === s.sample_id;

                  return (
                    <div
                      key={s.sample_id}
                      className={`panel group flex flex-col justify-between p-4 transition-all duration-200 hover:border-accent/60 ${
                        isCurrentActive ? "border-accent ring-1 ring-accent bg-accent/5 shadow-md" : ""
                      }`}
                    >
                      <div className="space-y-2.5">
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-2 truncate">
                            <span className="rounded border border-border-subtle bg-bg-elevated/60 p-1 font-mono text-[10px] text-text-muted">
                              <Icon name={platformIconName(s.detected_platform)} size={13} />
                            </span>
                            <h4 className="font-sans text-xs font-bold text-text-primary group-hover:text-accent leading-snug truncate">
                              {s.original_name}
                            </h4>
                          </div>
                          <span className="rounded bg-bg-elevated px-2 py-0.5 font-mono text-[9px] text-text-faint shrink-0">
                            {s.size} B
                          </span>
                        </div>

                        <p className="text-[11px] text-text-muted font-mono truncate">
                          Family: {s.family || "executable"} · SHA256: {s.sha256.slice(0, 12)}…
                        </p>

                        <div className="flex flex-wrap items-center gap-1.5 font-mono text-[9px]">
                          <span className="rounded border border-border-subtle bg-bg-surface px-1.5 py-0.5 text-text-faint">
                            Runs: {s.runs_count ?? 0}
                          </span>
                          <span className="rounded border border-border-subtle bg-bg-surface px-1.5 py-0.5 text-text-faint capitalize">
                            {s.detected_platform}
                          </span>
                        </div>
                      </div>

                      <div className="mt-4 flex items-center justify-between gap-2 border-t border-border-subtle pt-3 font-mono text-xs">
                        <Link
                          to={`/samples/${s.sample_id}`}
                          className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-[11px] text-text-muted hover:border-accent/50 hover:text-accent"
                        >
                          <Icon name="file" size={11} />
                          <span>Inspect</span>
                        </Link>

                        <button
                          onClick={() => void handleDetonateVaultSample(s)}
                          disabled={isExecuting}
                          className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent/15 px-3 py-1 text-[11px] font-bold text-accent transition hover:bg-accent/25 hover:shadow-[var(--glow-accent)] disabled:opacity-50"
                        >
                          <Icon
                            name={isDetonating ? "refresh" : "play"}
                            size={11}
                            className={isDetonating ? "animate-spin" : ""}
                          />
                          <span>{isDetonating ? "Detonating…" : "Detonate Sample"}</span>
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ── GALLERY TAB 3: MITRE ATT&CK TECHNIQUE UNIT TESTS ──────────────── */}
        {galleryTab === "techniques" && (
          <div className="space-y-5">
            {/* Tactic Filters */}
            <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
              {["all", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Exfiltration"].map((t) => (
                <button
                  key={t}
                  onClick={() => setTechniqueTactic(t)}
                  className={`rounded-lg px-2.5 py-1 transition ${
                    techniqueTactic === t
                      ? "bg-accent/20 font-bold text-accent border border-accent/40"
                      : "bg-bg-surface border border-border-subtle text-text-muted hover:text-text-primary"
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>

            {/* Technique Result Banner */}
            {techniqueResult && (
              <div className="rounded-2xl border border-accent/50 bg-bg-surface p-4 font-mono text-xs space-y-3 shadow-xl">
                <div className="flex items-center justify-between border-b border-border-subtle pb-2.5">
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
                  <button onClick={() => setTechniqueResult(null)} className="hover:text-accent font-bold">
                    Close ×
                  </button>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px]">
                  <div className="bg-bg-base/60 p-2 rounded border border-border-subtle/50">
                    <span className="text-text-muted block text-[10px] uppercase">Prerequisites</span>
                    <span className={techniqueResult.prereqs_met ? "text-emerald-400 font-bold" : "text-rose-400 font-bold"}>
                      {techniqueResult.prereqs_met ? "Verified OK" : "Missing"}
                    </span>
                  </div>
                  <div className="bg-bg-base/60 p-2 rounded border border-border-subtle/50">
                    <span className="text-text-muted block text-[10px] uppercase">Cleanup</span>
                    <span className="text-emerald-400 font-bold capitalize">
                      {techniqueResult.cleanup_status}
                    </span>
                  </div>
                  <div className="bg-bg-base/60 p-2 rounded border border-border-subtle/50">
                    <span className="text-text-muted block text-[10px] uppercase">Telemetry Ingested</span>
                    <span className="text-accent font-bold">
                      {techniqueResult.events_count} events
                    </span>
                  </div>
                  <div className="bg-bg-base/60 p-2 rounded border border-border-subtle/50">
                    <span className="text-text-muted block text-[10px] uppercase">Detections</span>
                    <span className={techniqueResult.alerts_count > 0 ? "text-rose-400 font-bold" : "text-text-muted"}>
                      {techniqueResult.alerts_count} alert(s)
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Technique Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {techniques.map((tech) => {
                const isRunning = runningTechniqueId === tech.id;
                const isExpanded = expandedTechniqueId === tech.id;

                return (
                  <div
                    key={tech.id}
                    className="panel p-4 space-y-3 transition hover:border-accent/40 shadow-sm"
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
                        onClick={() => void handleRunTechnique(tech.id)}
                        disabled={runningTechniqueId !== null}
                        className="press inline-flex items-center gap-1 rounded-lg border border-accent/60 bg-accent/15 px-2.5 py-1 text-xs font-bold text-accent transition hover:bg-accent/25 disabled:opacity-50 shrink-0 font-mono"
                      >
                        <Icon
                          name={isRunning ? "refresh" : "play"}
                          size={11}
                          className={isRunning ? "animate-spin" : ""}
                        />
                        <span>{isRunning ? "Running…" : "Run Test"}</span>
                      </button>
                    </div>

                    <p className="text-xs text-text-muted leading-relaxed line-clamp-2">{tech.description}</p>

                    <div className="border-t border-border-subtle/50 pt-2 flex items-center justify-between text-[11px] font-mono text-text-faint">
                      <span>Platforms: {tech.supported_platforms.join(", ")}</span>
                      <button
                        onClick={() => setExpandedTechniqueId(isExpanded ? null : tech.id)}
                        className="hover:text-accent cursor-pointer"
                      >
                        {isExpanded ? "Hide Code ▲" : "View Code ▼"}
                      </button>
                    </div>

                    {isExpanded && (
                      <div className="space-y-2 rounded-lg border border-border-subtle bg-[#06080d] p-3 text-[10px] font-mono">
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
      </section>
    </div>
  );
}
