import { useEffect, useState } from "react";
import { captureBaselineSnapshot, getSnapshotDifferential } from "../lib/api";

interface DifferentialSnapshotViewProps {
  onSelectProcess?: (pid: number) => void;
}

export function DifferentialSnapshotView({ onSelectProcess }: DifferentialSnapshotViewProps) {
  const [loading, setLoading] = useState(false);
  const [capturingBaseline, setCapturingBaseline] = useState(false);
  const [diffData, setDiffData] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<"added_procs" | "removed_procs" | "listeners" | "outbound" | "temp_drops">("added_procs");
  const [error, setError] = useState<string | null>(null);

  const fetchDiff = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getSnapshotDifferential();
      setDiffData(data);
    } catch (err: any) {
      setError(err?.message || "Failed to compute snapshot differential.");
    } finally {
      setLoading(false);
    }
  };

  const handleCaptureBaseline = async () => {
    try {
      setCapturingBaseline(true);
      setError(null);
      await captureBaselineSnapshot();
      await fetchDiff();
    } catch (err: any) {
      setError(err?.message || "Failed to capture baseline snapshot.");
    } finally {
      setCapturingBaseline(false);
    }
  };

  useEffect(() => {
    fetchDiff();
  }, []);

  const summary = diffData?.summary || {
    added_processes_count: 0,
    removed_processes_count: 0,
    new_listeners_count: 0,
    closed_listeners_count: 0,
    new_outbound_count: 0,
    closed_outbound_count: 0,
    temp_drops_count: 0,
  };

  const metricsDelta = diffData?.metrics_delta || {
    cpu_delta: 0,
    memory_mb_delta: 0,
    process_count_delta: 0,
    socket_count_delta: 0,
  };

  return (
    <div className="space-y-4">
      {/* Control Header & Baseline Status */}
      <div className="bg-panel-bg border border-panel-border rounded-lg p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-base font-semibold text-text-primary">Differential Host Baseline Delta</span>
            <span className="px-2 py-0.5 rounded text-xs font-medium bg-accent/15 text-accent border border-accent/30">
              Omarchy X-Ray Delta Engine
            </span>
          </div>
          <p className="text-xs text-text-muted mt-1">
            Baseline recorded:{" "}
            <span className="text-text-primary font-mono">
              {diffData?.baseline_timestamp ? new Date(diffData.baseline_timestamp).toLocaleTimeString() : "Pending"}
            </span>{" "}
            · Comparing against live host state.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCaptureBaseline}
            disabled={capturingBaseline}
            className="px-3 py-1.5 rounded text-xs font-medium bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30 transition cursor-pointer disabled:opacity-50"
          >
            {capturingBaseline ? "Capturing..." : "📸 Capture New Baseline"}
          </button>
          <button
            onClick={fetchDiff}
            disabled={loading}
            className="px-3 py-1.5 rounded text-xs font-medium bg-panel-border/60 text-text-primary border border-panel-border hover:bg-panel-border transition cursor-pointer"
          >
            {loading ? "Diffing..." : "🔄 Refresh Delta"}
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 p-3 rounded text-xs">
          {error}
        </div>
      )}

      {/* Metrics Delta Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-panel-bg/80 border border-panel-border rounded p-3 text-center">
          <div className="text-xs text-text-muted">Process Delta</div>
          <div className={`text-lg font-bold font-mono ${metricsDelta.process_count_delta > 0 ? "text-emerald-400" : metricsDelta.process_count_delta < 0 ? "text-red-400" : "text-text-primary"}`}>
            {metricsDelta.process_count_delta > 0 ? `+${metricsDelta.process_count_delta}` : metricsDelta.process_count_delta}
          </div>
        </div>
        <div className="bg-panel-bg/80 border border-panel-border rounded p-3 text-center">
          <div className="text-xs text-text-muted">Sockets Delta</div>
          <div className={`text-lg font-bold font-mono ${metricsDelta.socket_count_delta > 0 ? "text-amber-400" : metricsDelta.socket_count_delta < 0 ? "text-blue-400" : "text-text-primary"}`}>
            {metricsDelta.socket_count_delta > 0 ? `+${metricsDelta.socket_count_delta}` : metricsDelta.socket_count_delta}
          </div>
        </div>
        <div className="bg-panel-bg/80 border border-panel-border rounded p-3 text-center">
          <div className="text-xs text-text-muted">CPU Delta</div>
          <div className={`text-lg font-bold font-mono ${metricsDelta.cpu_delta > 0 ? "text-amber-400" : "text-text-primary"}`}>
            {metricsDelta.cpu_delta > 0 ? `+${metricsDelta.cpu_delta}%` : `${metricsDelta.cpu_delta}%`}
          </div>
        </div>
        <div className="bg-panel-bg/80 border border-panel-border rounded p-3 text-center">
          <div className="text-xs text-text-muted">Memory Delta</div>
          <div className={`text-lg font-bold font-mono ${metricsDelta.memory_mb_delta > 0 ? "text-amber-400" : "text-text-primary"}`}>
            {metricsDelta.memory_mb_delta > 0 ? `+${metricsDelta.memory_mb_delta} MB` : `${metricsDelta.memory_mb_delta} MB`}
          </div>
        </div>
      </div>

      {/* Subview Tabs */}
      <div className="flex border-b border-panel-border gap-2">
        <button
          onClick={() => setActiveTab("added_procs")}
          className={`px-3 py-2 text-xs font-medium border-b-2 transition cursor-pointer flex items-center gap-1.5 ${
            activeTab === "added_procs"
              ? "border-emerald-500 text-emerald-400 bg-emerald-500/10"
              : "border-transparent text-text-muted hover:text-text-primary"
          }`}
        >
          <span>Spawned Processes</span>
          <span className="px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 font-mono text-[10px]">
            +{summary.added_processes_count}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("removed_procs")}
          className={`px-3 py-2 text-xs font-medium border-b-2 transition cursor-pointer flex items-center gap-1.5 ${
            activeTab === "removed_procs"
              ? "border-red-500 text-red-400 bg-red-500/10"
              : "border-transparent text-text-muted hover:text-text-primary"
          }`}
        >
          <span>Exited Processes</span>
          <span className="px-1.5 py-0.2 rounded bg-red-500/20 text-red-300 font-mono text-[10px]">
            -{summary.removed_processes_count}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("listeners")}
          className={`px-3 py-2 text-xs font-medium border-b-2 transition cursor-pointer flex items-center gap-1.5 ${
            activeTab === "listeners"
              ? "border-amber-500 text-amber-400 bg-amber-500/10"
              : "border-transparent text-text-muted hover:text-text-primary"
          }`}
        >
          <span>New Listeners</span>
          <span className="px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 font-mono text-[10px]">
            +{summary.new_listeners_count}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("outbound")}
          className={`px-3 py-2 text-xs font-medium border-b-2 transition cursor-pointer flex items-center gap-1.5 ${
            activeTab === "outbound"
              ? "border-purple-500 text-purple-400 bg-purple-500/10"
              : "border-transparent text-text-muted hover:text-text-primary"
          }`}
        >
          <span>New Outbound C2</span>
          <span className="px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 font-mono text-[10px]">
            +{summary.new_outbound_count}
          </span>
        </button>

        {summary.temp_drops_count > 0 && (
          <button
            onClick={() => setActiveTab("temp_drops")}
            className={`px-3 py-2 text-xs font-medium border-b-2 transition cursor-pointer flex items-center gap-1.5 ${
              activeTab === "temp_drops"
                ? "border-red-500 text-red-400 bg-red-500/15 animate-pulse"
                : "border-transparent text-red-400 hover:text-red-300"
            }`}
          >
            <span>⚠️ Temp Drops</span>
            <span className="px-1.5 py-0.2 rounded bg-red-500/30 text-red-200 font-mono text-[10px]">
              {summary.temp_drops_count}
            </span>
          </button>
        )}
      </div>

      {/* Tab Panels */}
      <div className="bg-panel-bg border border-panel-border rounded-lg p-4 min-h-[220px]">
        {activeTab === "added_procs" && (
          <div className="space-y-2">
            {(diffData?.added_processes || []).length === 0 ? (
              <div className="text-center py-8 text-xs text-text-muted">
                No new processes spawned since baseline.
              </div>
            ) : (
              (diffData?.added_processes || []).map((proc: any) => (
                <div
                  key={proc.pid}
                  className="flex items-center justify-between p-2.5 rounded bg-panel-border/20 hover:bg-panel-border/40 transition border border-emerald-500/20"
                >
                  <div className="flex items-center gap-3">
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-500/20 text-emerald-300">
                      +{proc.pid}
                    </span>
                    <div>
                      <div className="text-xs font-semibold text-text-primary flex items-center gap-2">
                        {proc.name}
                        {proc.package_status === "unmanaged_suspicious" && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] bg-red-500/20 text-red-300 border border-red-500/40">
                            Unmanaged /tmp
                          </span>
                        )}
                        {proc.package_status === "managed_package" && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] bg-blue-500/20 text-blue-300">
                            {proc.package_label || "Package"}
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] font-mono text-text-muted truncate max-w-xl">
                        {proc.cmdline || proc.exe || "No cmdline"}
                      </div>
                    </div>
                  </div>

                  {onSelectProcess && (
                    <button
                      onClick={() => onSelectProcess(proc.pid)}
                      className="px-2.5 py-1 rounded text-xs font-medium bg-accent/15 text-accent hover:bg-accent/25 transition cursor-pointer"
                    >
                      Inspect X-Ray
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === "removed_procs" && (
          <div className="space-y-2">
            {(diffData?.removed_processes || []).length === 0 ? (
              <div className="text-center py-8 text-xs text-text-muted">
                No processes terminated since baseline.
              </div>
            ) : (
              (diffData?.removed_processes || []).map((proc: any) => (
                <div
                  key={proc.pid}
                  className="flex items-center justify-between p-2.5 rounded bg-panel-border/20 border border-red-500/20"
                >
                  <div className="flex items-center gap-3">
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-red-500/20 text-red-300">
                      -{proc.pid}
                    </span>
                    <div>
                      <div className="text-xs font-semibold text-text-primary">{proc.name}</div>
                      <div className="text-[11px] font-mono text-text-muted truncate max-w-xl">
                        {proc.cmdline || proc.exe || "Terminated"}
                      </div>
                    </div>
                  </div>
                  <span className="text-xs text-text-muted font-mono">Exited</span>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === "listeners" && (
          <div className="space-y-2">
            {(diffData?.new_listeners || []).length === 0 ? (
              <div className="text-center py-8 text-xs text-text-muted">
                No new listening sockets opened since baseline.
              </div>
            ) : (
              (diffData?.new_listeners || []).map((sock: any, idx: number) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-2.5 rounded bg-panel-border/20 border border-amber-500/20"
                >
                  <div className="flex items-center gap-3">
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-500/20 text-amber-300 uppercase">
                      +{sock.protocol}
                    </span>
                    <div>
                      <div className="text-xs font-semibold text-text-primary font-mono">
                        {sock.local_ip}:{sock.local_port}
                      </div>
                      <div className="text-[11px] text-text-muted">
                        PID {sock.pid || "?"} ({sock.process_name || "Unknown"})
                      </div>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded text-xs font-medium bg-amber-500/20 text-amber-300">
                    LISTEN
                  </span>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === "outbound" && (
          <div className="space-y-2">
            {(diffData?.new_outbound || []).length === 0 ? (
              <div className="text-center py-8 text-xs text-text-muted">
                No new outbound connections established since baseline.
              </div>
            ) : (
              (diffData?.new_outbound || []).map((sock: any, idx: number) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-2.5 rounded bg-panel-border/20 border border-purple-500/20"
                >
                  <div className="flex items-center gap-3">
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-purple-500/20 text-purple-300 uppercase">
                      +{sock.protocol}
                    </span>
                    <div>
                      <div className="text-xs font-semibold text-text-primary font-mono">
                        {sock.local_ip}:{sock.local_port} → {sock.remote_ip}:{sock.remote_port}
                      </div>
                      <div className="text-[11px] text-text-muted">
                        PID {sock.pid || "?"} ({sock.process_name || "Unknown"}) · {sock.status || "ESTABLISHED"}
                      </div>
                    </div>
                  </div>
                  {sock.is_suspicious_port && (
                    <span className="px-2 py-0.5 rounded text-xs font-medium bg-red-500/20 text-red-300 border border-red-500/40">
                      Suspicious Port
                    </span>
                  )}
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === "temp_drops" && (
          <div className="space-y-2">
            {(diffData?.temp_drops || []).map((proc: any) => (
              <div
                key={proc.pid}
                className="flex items-center justify-between p-2.5 rounded bg-red-500/10 border border-red-500/30"
              >
                <div className="flex items-center gap-3">
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-red-500/20 text-red-300">
                    PID {proc.pid}
                  </span>
                  <div>
                    <div className="text-xs font-semibold text-red-300">{proc.name}</div>
                    <div className="text-[11px] font-mono text-red-200 truncate max-w-xl">
                      {proc.exe}
                    </div>
                  </div>
                </div>
                {onSelectProcess && (
                  <button
                    onClick={() => onSelectProcess(proc.pid)}
                    className="px-2.5 py-1 rounded text-xs font-medium bg-red-500/20 text-red-200 hover:bg-red-500/30 transition cursor-pointer"
                  >
                    Examine Drop
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
