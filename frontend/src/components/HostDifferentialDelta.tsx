import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Icon } from "./Icon";
import { Panel } from "./ui";
import { captureBaselineSnapshot, getSnapshotDifferential } from "../lib/api";

interface HostDifferentialDeltaProps {
  hostId: string;
  onInspectPid?: (pid: number) => void;
  onInspectIp?: (ip: string) => void;
}

export function HostDifferentialDelta({
  hostId,
  onInspectPid,
  onInspectIp,
}: HostDifferentialDeltaProps) {
  const queryClient = useQueryClient();
  const [activeCategory, setActiveCategory] = useState<"all" | "processes" | "listeners" | "outbound" | "temp">("all");

  const {
    data: diff,
    isLoading,
    isFetching,
    refetch,
  } = useQuery({
    queryKey: ["host-diff", hostId],
    queryFn: () => getSnapshotDifferential(hostId),
    refetchInterval: 15_000,
  });

  const captureMutation = useMutation({
    mutationFn: () => captureBaselineSnapshot(hostId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["host-diff", hostId] });
    },
  });

  const summary = diff?.summary ?? {
    added_processes_count: 0,
    removed_processes_count: 0,
    new_listeners_count: 0,
    closed_listeners_count: 0,
    new_outbound_count: 0,
    closed_outbound_count: 0,
    temp_drops_count: 0,
  };

  const hasChanges =
    summary.added_processes_count > 0 ||
    summary.removed_processes_count > 0 ||
    summary.new_listeners_count > 0 ||
    summary.new_outbound_count > 0 ||
    summary.temp_drops_count > 0;

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Top Controller & Status Strip */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-border-subtle bg-bg-surface p-4 shadow-sm">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="flex h-6 w-6 items-center justify-center rounded-lg bg-accent/15 text-accent">
              <Icon name="compare" size={13} />
            </span>
            <span className="font-bold text-text-primary text-sm">
              Differential Host Baseline Delta
            </span>
            <span className="rounded bg-bg-elevated px-2 py-0.5 text-[10px] text-text-muted">
              Velociraptor Artifact Standard
            </span>
          </div>
          <p className="text-[11px] text-text-muted">
            Inspect real-time execution drift against established host baseline (+/- new processes, open listening ports, and /tmp payloads).
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={() => refetch()}
            disabled={isFetching}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-base/80 px-3 py-1.5 text-xs text-text-muted hover:border-accent hover:text-accent disabled:opacity-50"
          >
            <Icon name="refresh" size={12} className={isFetching ? "animate-spin" : ""} />
            <span>{isFetching ? "Evaluating..." : "↻ Refresh Delta"}</span>
          </button>

          <button
            type="button"
            onClick={() => captureMutation.mutate()}
            disabled={captureMutation.isPending}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/15 px-3 py-1.5 text-xs font-semibold text-accent hover:bg-accent/25 shadow-xs disabled:opacity-50"
          >
            <Icon name="zap" size={12} className={captureMutation.isPending ? "animate-spin" : ""} />
            <span>{captureMutation.isPending ? "Capturing..." : "📸 Take New Baseline"}</span>
          </button>
        </div>
      </div>

      {/* Snapshot Timestamps & Metrics Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3 space-y-1">
          <span className="text-[10px] text-text-faint uppercase font-bold">Baseline Captured</span>
          <p className="text-text-primary text-xs truncate">
            {diff?.baseline_timestamp ? new Date(diff.baseline_timestamp).toLocaleTimeString() : "Initial System Boot"}
          </p>
        </div>
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3 space-y-1">
          <span className="text-[10px] text-text-faint uppercase font-bold">Current Evaluation</span>
          <p className="text-accent text-xs truncate">
            {diff?.current_timestamp ? new Date(diff.current_timestamp).toLocaleTimeString() : "Live Active"}
          </p>
        </div>
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3 space-y-1">
          <span className="text-[10px] text-text-faint uppercase font-bold">CPU Drift</span>
          <p className={`text-xs font-bold ${
            (diff?.metrics_delta?.cpu_delta ?? 0) > 10 ? "text-amber-400" : "text-text-primary"
          }`}>
            {(diff?.metrics_delta?.cpu_delta ?? 0) >= 0 ? `+${diff?.metrics_delta?.cpu_delta ?? 0}%` : `${diff?.metrics_delta?.cpu_delta ?? 0}%`}
          </p>
        </div>
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3 space-y-1">
          <span className="text-[10px] text-text-faint uppercase font-bold">Memory Drift</span>
          <p className={`text-xs font-bold ${
            (diff?.metrics_delta?.memory_mb_delta ?? 0) > 100 ? "text-amber-400" : "text-text-primary"
          }`}>
            {(diff?.metrics_delta?.memory_mb_delta ?? 0) >= 0 ? `+${diff?.metrics_delta?.memory_mb_delta ?? 0} MB` : `${diff?.metrics_delta?.memory_mb_delta ?? 0} MB`}
          </p>
        </div>
      </div>

      {/* Delta KPI Chips */}
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => setActiveCategory("all")}
          className={`press rounded-lg px-3 py-1.5 border transition ${
            activeCategory === "all"
              ? "border-accent bg-accent/15 text-accent font-bold"
              : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
          }`}
        >
          All Activity ({summary.added_processes_count + summary.new_listeners_count + summary.new_outbound_count + summary.temp_drops_count})
        </button>

        <button
          type="button"
          onClick={() => setActiveCategory("processes")}
          className={`press rounded-lg px-3 py-1.5 border transition flex items-center gap-1.5 ${
            activeCategory === "processes"
              ? "border-accent bg-accent/15 text-accent font-bold"
              : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
          }`}
        >
          <span className="text-emerald-400">+{summary.added_processes_count}</span>
          <span>New Processes</span>
          {summary.removed_processes_count > 0 && (
            <span className="text-text-faint text-[10px]">(-{summary.removed_processes_count} exited)</span>
          )}
        </button>

        <button
          type="button"
          onClick={() => setActiveCategory("listeners")}
          className={`press rounded-lg px-3 py-1.5 border transition flex items-center gap-1.5 ${
            activeCategory === "listeners"
              ? "border-accent bg-accent/15 text-accent font-bold"
              : summary.new_listeners_count > 0
                ? "border-rose-500/40 bg-rose-500/10 text-rose-300"
                : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
          }`}
        >
          <span className={summary.new_listeners_count > 0 ? "text-rose-400 font-bold" : "text-text-muted"}>
            +{summary.new_listeners_count}
          </span>
          <span>New Listening Ports</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveCategory("outbound")}
          className={`press rounded-lg px-3 py-1.5 border transition flex items-center gap-1.5 ${
            activeCategory === "outbound"
              ? "border-accent bg-accent/15 text-accent font-bold"
              : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
          }`}
        >
          <span className="text-cyan-400">+{summary.new_outbound_count}</span>
          <span>New Outbound Connections</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveCategory("temp")}
          className={`press rounded-lg px-3 py-1.5 border transition flex items-center gap-1.5 ${
            activeCategory === "temp"
              ? "border-accent bg-accent/15 text-accent font-bold"
              : summary.temp_drops_count > 0
                ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
                : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
          }`}
        >
          <span className={summary.temp_drops_count > 0 ? "text-amber-400 font-bold" : "text-text-muted"}>
            +{summary.temp_drops_count}
          </span>
          <span>/tmp &amp; User Dropped Executables</span>
        </button>
      </div>

      {isLoading ? (
        <div className="py-12 text-center text-text-muted">
          <Icon name="refresh" size={16} className="animate-spin mx-auto mb-2" />
          <p>Calculating host differential baseline delta...</p>
        </div>
      ) : !hasChanges ? (
        <Panel>
          <div className="py-12 text-center space-y-2">
            <div className="h-10 w-10 mx-auto rounded-full bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <Icon name="check" size={18} />
            </div>
            <h4 className="font-bold text-text-primary text-sm">Clean Differential Baseline</h4>
            <p className="text-text-muted text-xs max-w-md mx-auto">
              No unauthorized processes, rogue listening sockets, or suspicious staging artifacts have deviated from the baseline snapshot on this endpoint.
            </p>
          </div>
        </Panel>
      ) : (
        <div className="space-y-6">
          {/* New Processes Table */}
          {(activeCategory === "all" || activeCategory === "processes") && diff && diff.added_processes.length > 0 && (
            <Panel
              kicker="Process Drift (+)"
              title={`${diff.added_processes.length} Newly Created Process${diff.added_processes.length > 1 ? "es" : ""}`}
            >
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr className="border-b border-border-subtle text-[10px] text-text-faint uppercase">
                      <th className="pb-2 font-normal">PID</th>
                      <th className="pb-2 font-normal">Process Name</th>
                      <th className="pb-2 font-normal">Command Line</th>
                      <th className="pb-2 font-normal">User</th>
                      <th className="pb-2 text-right font-normal">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-subtle/40">
                    {diff.added_processes.map((proc: any) => (
                      <tr key={proc.pid} className="hover:bg-bg-elevated/30 transition-colors">
                        <td className="py-2.5 font-bold text-accent">{proc.pid}</td>
                        <td className="py-2.5 font-bold text-text-primary">{proc.name}</td>
                        <td className="py-2.5 max-w-md truncate text-text-muted" title={proc.cmdline || proc.exe}>
                          {proc.cmdline || proc.exe || "—"}
                        </td>
                        <td className="py-2.5 text-text-faint">{proc.username || proc.user || "—"}</td>
                        <td className="py-2.5 text-right">
                          {onInspectPid && (
                            <button
                              type="button"
                              onClick={() => onInspectPid(proc.pid)}
                              className="press rounded border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] text-accent hover:bg-accent/20"
                            >
                              Investigate
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          )}

          {/* New Listening Sockets Table */}
          {(activeCategory === "all" || activeCategory === "listeners") && diff && diff.new_listeners.length > 0 && (
            <Panel
              kicker="Network Attack Surface (+)"
              title={`${diff.new_listeners.length} Newly Opened Listening Socket${diff.new_listeners.length > 1 ? "s" : ""}`}
            >
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr className="border-b border-border-subtle text-[10px] text-text-faint uppercase">
                      <th className="pb-2 font-normal">Binding Address</th>
                      <th className="pb-2 font-normal">Port</th>
                      <th className="pb-2 font-normal">Protocol</th>
                      <th className="pb-2 font-normal">Binding Process</th>
                      <th className="pb-2 font-normal">Risk Verdict</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-subtle/40">
                    {diff.new_listeners.map((s: any, idx: number) => {
                      const isWildcard = s.local_ip === "0.0.0.0" || s.local_ip === "::";
                      return (
                        <tr key={idx} className="hover:bg-bg-elevated/30 transition-colors">
                          <td className="py-2.5 font-bold text-text-primary">{s.local_ip}</td>
                          <td className="py-2.5 font-bold text-accent">{s.local_port}</td>
                          <td className="py-2.5 uppercase text-text-muted">{s.protocol}</td>
                          <td className="py-2.5 text-text-muted">
                            {s.process_name ? `${s.process_name} (PID ${s.pid})` : `PID ${s.pid}`}
                          </td>
                          <td className="py-2.5">
                            {isWildcard ? (
                              <span className="rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 px-1.5 py-0.5 text-[9px] uppercase font-bold">
                                Public 0.0.0.0 Exposure ⚠️
                              </span>
                            ) : (
                              <span className="rounded bg-emerald-500/15 text-emerald-400 px-1.5 py-0.5 text-[9px] uppercase font-bold">
                                Localhost Loopback
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </Panel>
          )}

          {/* New Outbound Connections */}
          {(activeCategory === "all" || activeCategory === "outbound") && diff && diff.new_outbound.length > 0 && (
            <Panel
              kicker="Egress Traffic (+)"
              title={`${diff.new_outbound.length} New Outbound Connection${diff.new_outbound.length > 1 ? "s" : ""}`}
            >
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr className="border-b border-border-subtle text-[10px] text-text-faint uppercase">
                      <th className="pb-2 font-normal">Remote Destination</th>
                      <th className="pb-2 font-normal">Protocol</th>
                      <th className="pb-2 font-normal">Process</th>
                      <th className="pb-2 text-right font-normal">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border-subtle/40">
                    {diff.new_outbound.map((s: any, idx: number) => (
                      <tr key={idx} className="hover:bg-bg-elevated/30 transition-colors">
                        <td className="py-2.5 font-bold text-accent">
                          {s.remote_ip}:{s.remote_port}
                        </td>
                        <td className="py-2.5 uppercase text-text-muted">{s.protocol}</td>
                        <td className="py-2.5 text-text-muted">
                          {s.process_name ? `${s.process_name} (PID ${s.pid})` : `PID ${s.pid}`}
                        </td>
                        <td className="py-2.5 text-right">
                          {onInspectIp && s.remote_ip && (
                            <button
                              type="button"
                              onClick={() => onInspectIp(s.remote_ip)}
                              className="press rounded border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] text-accent hover:bg-accent/20"
                            >
                              Pivot IP
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          )}

          {/* Temp Dropped Binaries */}
          {(activeCategory === "all" || activeCategory === "temp") && diff && diff.temp_drops.length > 0 && (
            <Panel
              kicker="Filesystem Forensics (+)"
              title={`${diff.temp_drops.length} Suspicious /tmp or User Staged Payload${diff.temp_drops.length > 1 ? "s" : ""}`}
            >
              <div className="space-y-2">
                {diff.temp_drops.map((p: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg border border-amber-500/40 bg-amber-500/10 flex items-center justify-between gap-3 text-amber-300"
                  >
                    <div className="space-y-0.5 truncate min-w-0">
                      <div className="font-bold text-white truncate">{p.exe || p.name}</div>
                      <div className="text-[10px] text-text-muted truncate">
                        PID {p.pid} · Cmd: {p.cmdline || "—"}
                      </div>
                    </div>
                    <span className="rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 px-2 py-0.5 text-[9px] uppercase font-bold shrink-0">
                      Unmanaged Staged Binary
                    </span>
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </div>
      )}
    </div>
  );
}
