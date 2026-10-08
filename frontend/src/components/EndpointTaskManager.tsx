import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Icon } from "./Icon";
import {
  getHostXRaySnapshot,
  controlProcessXRay,
  scanLiveMemoryYara,
  getForensicCapsule,
} from "../lib/api";
import ProcessContextModal from "./ProcessContextModal";

interface ProcessItem {
  pid: number;
  ppid: number;
  name: string;
  cmdline: string;
  exe: string;
  user: string;
  status: string;
  cpu_percent: number;
  memory_rss_mb?: number;
  memory_mb?: number;
  memory_rss_bytes?: number;
  username?: string;
  threads?: number;
  started_at?: string;
  provenance?: {
    status?: string;
    label?: string;
    managed?: boolean;
    package?: string;
  };
  is_suspicious?: boolean;
  threat_score?: number;
}

export const EndpointTaskManager: React.FC<{ hostId?: string }> = ({ hostId = "local" }) => {
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState<"all" | "suspicious" | "sockets" | "root" | "resource">("all");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selectedPidForModal, setSelectedPidForModal] = useState<number | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [yaraResult, setYaraResult] = useState<{
    matches_found: number;
    matches: Array<{ pid: number; name: string; rule: string }>;
  } | null>(null);

  // Fetch live system snapshot
  const { data: snapshot, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["live-task-manager-snapshot", hostId],
    queryFn: () => getHostXRaySnapshot(),
    refetchInterval: autoRefresh ? 5000 : false,
  });

  const processes: ProcessItem[] = useMemo(() => {
    return (snapshot?.processes || []) as ProcessItem[];
  }, [snapshot]);

  const sockets = useMemo(() => {
    return snapshot?.sockets || [];
  }, [snapshot]);

  const metrics = snapshot?.metrics || {
    cpu_percent: 0,
    memory_total_mb: 0,
    memory_used_mb: 0,
  };

  const memPercent =
    metrics.memory_total_mb > 0
      ? Math.round((metrics.memory_used_mb / metrics.memory_total_mb) * 100)
      : 0;

  // Map sockets by PID
  const socketsByPid = useMemo(() => {
    const map = new Map<number, any[]>();
    sockets.forEach((s: any) => {
      if (s.pid) {
        const list = map.get(s.pid) || [];
        list.push(s);
        map.set(s.pid, list);
      }
    });
    return map;
  }, [sockets]);

  // Process control mutations
  const processControl = useMutation({
    mutationFn: async ({ pid, action }: { pid: number; action: "terminate" | "kill" | "freeze" | "resume" }) => {
      return controlProcessXRay(pid, action);
    },
    onSuccess: (res, vars) => {
      setActionNotice(`Executed ${vars.action.toUpperCase()} on PID ${vars.pid}: ${res.message || "success"}`);
      void queryClient.invalidateQueries({ queryKey: ["live-task-manager-snapshot", hostId] });
      setTimeout(() => setActionNotice(null), 3500);
    },
    onError: (err: any) => {
      setActionNotice(`Action failed: ${err?.message || "Permission denied or process already exited"}`);
      setTimeout(() => setActionNotice(null), 4000);
    },
  });

  // YARA live memory scan
  const yaraScanMutation = useMutation({
    mutationFn: async () => {
      return scanLiveMemoryYara(60);
    },
    onSuccess: (res) => {
      setYaraResult(res);
      setActionNotice(`YARA memory scan complete: ${res.matches_found} threat signatures identified across ${res.total_processes_scanned || 0} active processes.`);
      setTimeout(() => setActionNotice(null), 5000);
    },
  });

  // Export forensic capsule
  const handleExportCapsule = async (pid: number) => {
    try {
      const capsule = await getForensicCapsule(pid);
      const blob = new Blob([JSON.stringify(capsule, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `process_${pid}_forensics.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      setActionNotice(`Export failed: ${e?.message || "Unknown error"}`);
    }
  };

  // Flag suspicious processes based on known patterns or YARA
  const flaggedPids = useMemo(() => {
    const set = new Set<number>();
    (yaraResult?.matches || []).forEach((m) => set.add(m.pid));
    processes.forEach((p) => {
      const rawCmd = Array.isArray(p.cmdline) ? p.cmdline.join(" ") : String(p.cmdline || "");
      const cmd = rawCmd.toLowerCase();
      if (
        cmd.includes("nc -e") ||
        cmd.includes("/bin/sh -i") ||
        cmd.includes("vssadmin delete") ||
        cmd.includes("mimikatz") ||
        cmd.includes("base64 -d |") ||
        cmd.includes("beacon") ||
        cmd.includes("c2") ||
        (p.provenance && p.provenance.status === "unmanaged_suspicious")
      ) {
        set.add(p.pid);
      }
    });
    return set;
  }, [processes, yaraResult]);

  // Filtered processes
  const filteredProcesses = useMemo(() => {
    return processes.filter((p) => {
      // Query filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const rawCmd = Array.isArray(p.cmdline) ? p.cmdline.join(" ") : String(p.cmdline || "");
        const matchName = (p.name || "").toLowerCase().includes(q);
        const matchCmd = rawCmd.toLowerCase().includes(q);
        const matchUser = (p.user || p.username || "").toLowerCase().includes(q);
        const matchPid = String(p.pid).includes(q);
        if (!matchName && !matchCmd && !matchUser && !matchPid) return false;
      }

      // Type filter
      if (filterType === "suspicious") {
        return flaggedPids.has(p.pid);
      }
      if (filterType === "sockets") {
        return (socketsByPid.get(p.pid) || []).length > 0;
      }
      if (filterType === "root") {
        return p.user === "root" || p.user === "SYSTEM";
      }
      if (filterType === "resource") {
        const rss = typeof p.memory_mb === "number" ? p.memory_mb : typeof p.memory_rss_bytes === "number" ? Math.round(p.memory_rss_bytes / (1024 * 1024)) : (p.memory_rss_mb || 0);
        return p.cpu_percent > 5.0 || rss > 150;
      }

      return true;
    });
  }, [processes, searchQuery, filterType, flaggedPids, socketsByPid]);

  // Sort: Flagged threats first, then CPU% descending
  const sortedProcesses = useMemo(() => {
    return [...filteredProcesses].sort((a, b) => {
      const aFlag = flaggedPids.has(a.pid) ? 1 : 0;
      const bFlag = flaggedPids.has(b.pid) ? 1 : 0;
      if (aFlag !== bFlag) return bFlag - aFlag;
      return (b.cpu_percent || 0) - (a.cpu_percent || 0);
    });
  }, [filteredProcesses, flaggedPids]);

  return (
    <div className="space-y-5 font-mono text-xs">
      {/* Top Action Notice */}
      {actionNotice && (
        <div className="flex items-center justify-between rounded-xl border border-signal/60 bg-signal/15 px-4 py-2.5 text-signal animate-fade-in shadow-xs">
          <span>✓ {actionNotice}</span>
          <button onClick={() => setActionNotice(null)} className="font-bold hover:opacity-75">✕</button>
        </div>
      )}

      {/* Real-time System Metrics HUD */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-1 shadow-xs">
          <span className="text-[10px] text-text-faint uppercase font-bold block">Live Processes</span>
          <div className="flex items-baseline gap-2">
            <span className="text-xl font-bold text-text-primary">{processes.length}</span>
            <span className="text-[10px] text-text-muted">active</span>
          </div>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-1 shadow-xs">
          <span className="text-[10px] text-text-faint uppercase font-bold block">Network Sockets</span>
          <div className="flex items-baseline gap-2">
            <span className="text-xl font-bold text-accent">{sockets.length}</span>
            <span className="text-[10px] text-text-muted">listening / est</span>
          </div>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-1 shadow-xs">
          <span className="text-[10px] text-text-faint uppercase font-bold block">CPU Load</span>
          <div className="flex items-baseline gap-2">
            <span className="text-xl font-bold text-text-primary">{metrics.cpu_percent}%</span>
            <div className="h-1.5 w-16 overflow-hidden rounded-full bg-bg-elevated ml-auto">
              <div
                className="h-full rounded-full bg-accent transition-all duration-300"
                style={{ width: `${Math.min(100, metrics.cpu_percent)}%` }}
              />
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-1 shadow-xs">
          <span className="text-[10px] text-text-faint uppercase font-bold block">Memory Usage</span>
          <div className="flex items-baseline gap-2">
            <span className="text-xl font-bold text-text-primary">{memPercent}%</span>
            <div className="h-1.5 w-16 overflow-hidden rounded-full bg-bg-elevated ml-auto">
              <div
                className="h-full rounded-full bg-emerald-500 transition-all duration-300"
                style={{ width: `${Math.min(100, memPercent)}%` }}
              />
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5 space-y-1 shadow-xs">
          <span className="text-[10px] text-text-faint uppercase font-bold block">Threat Anomalies</span>
          <div className="flex items-baseline gap-2">
            <span className={`text-xl font-bold ${flaggedPids.size > 0 ? "text-rose-400" : "text-emerald-400"}`}>
              {flaggedPids.size}
            </span>
            <span className="text-[10px] text-text-muted">{flaggedPids.size > 0 ? "flagged PIDs" : "clean"}</span>
          </div>
        </div>
      </div>

      {/* Control Ribbon */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border-subtle bg-bg-surface p-3 shadow-xs">
        {/* Search */}
        <div className="relative min-w-64 flex-1">
          <Icon name="search" size={12} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-faint" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search active processes by Name, PID, User, or Command Line..."
            className="w-full rounded-lg border border-border-subtle bg-bg-base py-1.5 pl-9 pr-3 text-xs text-text-primary placeholder:text-text-faint focus:border-accent outline-none"
          />
        </div>

        {/* Global Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => yaraScanMutation.mutate()}
            disabled={yaraScanMutation.isPending}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-rose-500/50 bg-rose-500/15 px-3 py-1.5 text-xs font-bold text-rose-400 hover:bg-rose-500/25 disabled:opacity-50"
            title="Scan virtual memory spaces of active processes with YARA engine"
          >
            <Icon name="zap" size={12} className={yaraScanMutation.isPending ? "animate-spin" : ""} />
            <span>{yaraScanMutation.isPending ? "Scanning Memory…" : "Scan Memory (YARA)"}</span>
          </button>

          <button
            type="button"
            onClick={() => refetch()}
            disabled={isFetching}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-base px-3 py-1.5 text-xs font-semibold text-text-muted hover:text-text-primary"
            title="Refresh process list immediately"
          >
            <Icon name="refresh" size={12} className={isFetching ? "animate-spin text-accent" : ""} />
            <span>Refresh</span>
          </button>

          <label className="flex items-center gap-1.5 text-[11px] text-text-muted cursor-pointer pl-1">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="accent-[var(--accent)]"
            />
            <span>Auto-poll (5s)</span>
          </label>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-subtle pb-2">
        <div className="flex flex-wrap items-center gap-1">
          {[
            { id: "all", label: `All Processes (${processes.length})` },
            { id: "suspicious", label: `Threats & Anomalies (${flaggedPids.size})` },
            { id: "sockets", label: `With Network Sockets (${Array.from(socketsByPid.keys()).length})` },
            { id: "root", label: `Privileged / Root` },
            { id: "resource", label: `High Resource (CPU/RAM)` },
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setFilterType(tab.id as any)}
              className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition ${
                filterType === tab.id
                  ? "bg-accent/20 border border-accent/60 text-accent shadow-xs"
                  : "text-text-muted hover:text-text-primary hover:bg-bg-elevated"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <span className="text-[11px] text-text-faint">
          Displaying {sortedProcesses.length} of {processes.length} processes
        </span>
      </div>

      {/* Main Process Table */}
      <div className="rounded-xl border border-border-subtle bg-bg-surface overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-border-subtle bg-bg-base/70 text-[10px] uppercase font-bold text-text-faint tracking-wider">
              <tr>
                <th className="px-3.5 py-2.5">Process / Image</th>
                <th className="px-3.5 py-2.5">PID</th>
                <th className="px-3.5 py-2.5">PPID</th>
                <th className="px-3.5 py-2.5">User</th>
                <th className="px-3.5 py-2.5">CPU %</th>
                <th className="px-3.5 py-2.5">RAM RSS</th>
                <th className="px-3.5 py-2.5">Sockets</th>
                <th className="px-3.5 py-2.5">Integrity &amp; Threat</th>
                <th className="px-3.5 py-2.5 text-right">Containment Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/40">
              {isLoading ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-text-muted">
                    Acquiring live endpoint process table...
                  </td>
                </tr>
              ) : sortedProcesses.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-text-muted">
                    No active processes match the filter.
                  </td>
                </tr>
              ) : (
                sortedProcesses.map((p) => {
                  const isFlagged = flaggedPids.has(p.pid);
                  const pSockets = socketsByPid.get(p.pid) || [];
                  const isBusy = processControl.isPending && processControl.variables?.pid === p.pid;

                  return (
                    <tr
                      key={p.pid}
                      className={`hover:bg-bg-elevated/40 transition-colors ${
                        isFlagged ? "bg-rose-500/5 hover:bg-rose-500/10" : ""
                      }`}
                    >
                      {/* Name & Cmdline */}
                      <td className="px-3.5 py-2 max-w-[280px]">
                        <div className="flex items-center gap-2">
                          <span className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-md border ${
                            isFlagged
                              ? "border-rose-500/50 bg-rose-500/15 text-rose-400"
                              : "border-border-subtle bg-bg-base text-text-muted"
                          }`}>
                            <Icon name="terminal" size={11} />
                          </span>
                          <div className="min-w-0 flex-1">
                            <span className="font-bold text-text-primary truncate block" title={p.name}>
                              {p.name}
                            </span>
                            <span className="text-[10px] text-text-faint truncate block" title={Array.isArray(p.cmdline) ? p.cmdline.join(" ") : String(p.cmdline || "")}>
                              {Array.isArray(p.cmdline) ? p.cmdline.join(" ") : String(p.cmdline || "")}
                            </span>
                          </div>
                        </div>
                      </td>

                      {/* PID */}
                      <td className="px-3.5 py-2 font-bold text-accent tabular-nums">
                        {p.pid}
                      </td>

                      {/* PPID */}
                      <td className="px-3.5 py-2 text-text-muted tabular-nums">
                        {p.ppid}
                      </td>

                      {/* User */}
                      <td className="px-3.5 py-2">
                        <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${
                          (p.user || p.username) === "root" || (p.user || p.username) === "SYSTEM"
                            ? "bg-amber-500/10 text-amber-400 border border-amber-500/30"
                            : "bg-bg-base text-text-muted border border-border-subtle"
                        }`}>
                          {p.user || p.username || "system"}
                        </span>
                      </td>

                      {/* CPU % */}
                      <td className="px-3.5 py-2 tabular-nums font-semibold text-text-primary">
                        {p.cpu_percent.toFixed(1)}%
                      </td>

                      {/* Memory RSS */}
                      <td className="px-3.5 py-2 tabular-nums text-text-muted">
                        {typeof p.memory_mb === "number" ? p.memory_mb : typeof p.memory_rss_bytes === "number" ? Math.round(p.memory_rss_bytes / (1024 * 1024)) : (p.memory_rss_mb || 0)} MB
                      </td>

                      {/* Sockets */}
                      <td className="px-3.5 py-2">
                        {pSockets.length > 0 ? (
                          <span
                            className="inline-flex items-center gap-1 rounded bg-accent/10 px-1.5 py-0.5 text-[10px] font-bold text-accent border border-accent/30 cursor-pointer"
                            title={pSockets.map((s) => `${s.local_port || "any"} -> ${s.foreign_ip || "*"}:${s.foreign_port || "*"}`).join("\n")}
                          >
                            <Icon name="activity" size={10} />
                            <span>{pSockets.length} ports</span>
                          </span>
                        ) : (
                          <span className="text-text-faint text-[10px]">—</span>
                        )}
                      </td>

                      {/* Integrity & Threat Status */}
                      <td className="px-3.5 py-2">
                        {isFlagged ? (
                          <span className="inline-flex items-center gap-1 rounded bg-rose-500/15 border border-rose-500/40 px-2 py-0.5 text-[10px] font-bold text-rose-400 uppercase tracking-wide">
                            <Icon name="alert" size={10} />
                            <span>THREAT DETECTED</span>
                          </span>
                        ) : p.provenance?.status === "managed_package" ? (
                          <span className="rounded bg-emerald-500/10 border border-emerald-500/30 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-400">
                            Verified Package
                          </span>
                        ) : (
                          <span className="rounded bg-bg-base border border-border-subtle px-1.5 py-0.5 text-[10px] text-text-faint">
                            User Process
                          </span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="px-3.5 py-2 text-right">
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() => setSelectedPidForModal(p.pid)}
                            className="press rounded border border-border-subtle bg-bg-base px-2 py-1 text-[10px] font-semibold text-text-muted hover:border-accent hover:text-accent"
                            title="Open deep process X-Ray inspector"
                          >
                            X-Ray
                          </button>

                          <button
                            type="button"
                            onClick={() => processControl.mutate({ pid: p.pid, action: "terminate" })}
                            disabled={isBusy}
                            className="press rounded border border-amber-500/50 bg-amber-500/10 px-2 py-1 text-[10px] font-bold text-amber-400 hover:bg-amber-500/20 disabled:opacity-50"
                            title="Graceful SIGTERM process termination"
                          >
                            {isBusy ? "…" : "Terminate"}
                          </button>

                          <button
                            type="button"
                            onClick={() => processControl.mutate({ pid: p.pid, action: "kill" })}
                            disabled={isBusy}
                            className="press rounded border border-rose-500/50 bg-rose-500/10 px-2 py-1 text-[10px] font-bold text-rose-400 hover:bg-rose-500/20 disabled:opacity-50"
                            title="Immediate SIGKILL force kill"
                          >
                            Kill
                          </button>

                          <button
                            type="button"
                            onClick={() => handleExportCapsule(p.pid)}
                            className="press rounded border border-border-subtle bg-bg-base px-1.5 py-1 text-[10px] text-text-faint hover:text-text-primary"
                            title="Export forensic capsule (.json)"
                          >
                            <Icon name="download" size={11} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Deep Process Context Modal */}
      {selectedPidForModal !== null && (
        <ProcessContextModal
          pid={selectedPidForModal}
          onClose={() => setSelectedPidForModal(null)}
        />
      )}
    </div>
  );
};

export default EndpointTaskManager;
