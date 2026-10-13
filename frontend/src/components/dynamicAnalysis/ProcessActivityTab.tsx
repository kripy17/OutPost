import { useMemo, useState } from "react";
import { Icon } from "../Icon";
import { Panel } from "../ui";
import type { AnalysisObservation } from "../../types";

interface ProcessActivityTabProps {
  observations: AnalysisObservation[];
  runId: string;
}

interface ProcessInfo {
  pid: number;
  ppid: number | null;
  name: string;
  commandLine: string;
  timestamp: string;
  hostId: string;
  bootId?: string;
  startTime?: string;
  children: ProcessInfo[];
  fileWrites: string[];
  networkCalls: string[];
  rawEventsCount: number;
}

export function ProcessActivityTab({ observations, runId: _runId }: ProcessActivityTabProps) {
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [searchFilter, setSearchFilter] = useState("");

  const handleCopyCmd = (cmd: string, e: React.MouseEvent) => {
    e.stopPropagation();
    void navigator.clipboard.writeText(cmd);
    setCopiedCmd(cmd);
    setTimeout(() => setCopiedCmd(null), 1800);
  };

  // Build process map from observations
  const { processesMap, rootProcesses } = useMemo(() => {
    const pMap = new Map<number, ProcessInfo>();

    // Step 1: Identify processes from process_create events and any other events with pid
    observations.forEach((obs) => {
      const pid = obs.pid;
      if (!pid) return;

      if (!pMap.has(pid)) {
        pMap.set(pid, {
          pid,
          ppid: obs.ppid ?? null,
          name: obs.process_name || `PID_${pid}`,
          commandLine: obs.command_line || (obs.exe_path ? `${obs.exe_path}` : obs.process_name || `[pid ${pid}]`),
          timestamp: obs.timestamp || "",
          hostId: obs.host_id || "local",
          bootId: obs.boot_id || undefined,
          startTime: obs.process_start_time || undefined,
          children: [],
          fileWrites: [],
          networkCalls: [],
          rawEventsCount: 0,
        });
      }

      const pInfo = pMap.get(pid)!;
      pInfo.rawEventsCount++;

      // Update command line / name if better data is found
      if (obs.command_line && pInfo.commandLine.startsWith("[pid")) {
        pInfo.commandLine = obs.command_line;
      }
      if (obs.process_name && pInfo.name.startsWith("PID_")) {
        pInfo.name = obs.process_name;
      }

      // Collect related activity
      if (obs.file_path && !pInfo.fileWrites.includes(obs.file_path)) {
        pInfo.fileWrites.push(obs.file_path);
      }
      if (obs.dest_ip) {
        const dest = `${obs.dest_ip}${obs.dest_port ? `:${obs.dest_port}` : ""}`;
        if (!pInfo.networkCalls.includes(dest)) {
          pInfo.networkCalls.push(dest);
        }
      }
    });

    // Step 2: Build tree hierarchy
    const roots: ProcessInfo[] = [];
    pMap.forEach((proc) => {
      if (proc.ppid && pMap.has(proc.ppid) && proc.ppid !== proc.pid) {
        pMap.get(proc.ppid)!.children.push(proc);
      } else {
        roots.push(proc);
      }
    });

    return { processesMap: pMap, rootProcesses: roots };
  }, [observations]);

  const selectedProcess = selectedPid !== null ? processesMap.get(selectedPid) : null;

  const renderProcessNode = (proc: ProcessInfo, depth = 0) => {
    const isSelected = selectedPid === proc.pid;
    const matchesSearch = searchFilter.trim()
      ? proc.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
        proc.commandLine.toLowerCase().includes(searchFilter.toLowerCase()) ||
        String(proc.pid).includes(searchFilter)
      : true;

    return (
      <div key={proc.pid} className="space-y-1">
        <div
          onClick={() => setSelectedPid(proc.pid)}
          className={`group flex items-start gap-2.5 rounded-xl border p-2.5 font-mono text-xs cursor-pointer transition ${
            isSelected
              ? "border-accent bg-accent/10 shadow-xs"
              : matchesSearch
                ? "border-border-subtle bg-bg-surface hover:border-accent/40 hover:bg-bg-elevated/40"
                : "border-border-subtle/30 opacity-40 bg-bg-surface"
          }`}
          style={{ marginLeft: `${depth * 20}px` }}
        >
          {/* Tree connector branch icon */}
          <div className="flex items-center gap-1.5 shrink-0 mt-0.5">
            {depth > 0 ? (
              <span className="text-text-faint select-none font-bold">└─</span>
            ) : (
              <span className="flex h-5 w-5 items-center justify-center rounded bg-accent/20 text-accent font-bold text-[10px]">
                ●
              </span>
            )}
            <span className="font-bold text-accent tabular-nums min-w-[48px]">
              PID {proc.pid}
            </span>
          </div>

          <div className="min-w-0 flex-1 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-bold text-text-primary text-[11px]">{proc.name}</span>
              {proc.ppid !== null && (
                <span className="rounded bg-bg-elevated px-1.5 py-0.2 text-[9px] text-text-faint">
                  PPID {proc.ppid}
                </span>
              )}
              {proc.fileWrites.length > 0 && (
                <span className="rounded border border-border-subtle bg-bg-base px-1.5 py-0.2 text-[9px] text-amber-400">
                  {proc.fileWrites.length} files
                </span>
              )}
              {proc.networkCalls.length > 0 && (
                <span className="rounded border border-border-subtle bg-bg-base px-1.5 py-0.2 text-[9px] text-sky-400">
                  {proc.networkCalls.length} sockets
                </span>
              )}
              {proc.timestamp && (
                <span className="ml-auto text-[10px] text-text-faint tabular-nums">
                  {proc.timestamp.slice(11, 19)} UTC
                </span>
              )}
            </div>

            {/* Command Line with copy button */}
            <div className="flex items-center gap-1.5 group-hover:text-text-primary text-text-secondary text-[10px]">
              <code className="truncate max-w-[500px] select-all bg-bg-base/60 px-1 py-0.5 rounded border border-border-subtle/50">
                {proc.commandLine}
              </code>
              <button
                onClick={(e) => handleCopyCmd(proc.commandLine, e)}
                className="press rounded p-0.5 text-text-faint hover:text-text-primary transition shrink-0"
                title="Copy command line"
              >
                <Icon
                  name={copiedCmd === proc.commandLine ? "check" : "copy"}
                  size={10}
                  className={copiedCmd === proc.commandLine ? "text-emerald-400" : ""}
                />
              </button>
            </div>
          </div>
        </div>

        {/* Recursive Children */}
        {proc.children.map((child) => renderProcessNode(child, depth + 1))}
      </div>
    );
  };

  return (
    <div className="space-y-6 font-sans">
      <Panel
        kicker="Process Execution Hierarchy"
        title="Compound Process Tree &amp; Execution Lineage"
        right={
          <div className="flex items-center gap-2 font-mono text-xs">
            <input
              type="text"
              placeholder="Search PID, name, cmdline…"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              className="w-48 rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 text-[11px] text-text-primary placeholder:text-text-faint outline-none focus:border-accent"
            />
            {selectedPid !== null && (
              <button
                onClick={() => setSelectedPid(null)}
                className="press rounded-lg border border-border-subtle bg-bg-surface px-2 py-1 text-[10px] text-text-muted hover:text-text-primary transition"
              >
                Clear Filter
              </button>
            )}
          </div>
        }
      >
        {processesMap.size === 0 ? (
          <div className="p-8 text-center font-mono text-xs text-text-muted">
            <Icon name="terminal" size={24} className="mx-auto mb-2 text-text-faint" />
            <p className="font-bold text-text-primary">No Process Spawns Recorded</p>
            <p className="text-text-faint mt-1">
              Zero process lifecycle events were observed during this analysis run.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="space-y-2">
              {rootProcesses.map((root) => renderProcessNode(root))}
            </div>
          </div>
        )}
      </Panel>

      {/* Selected Process Detail Drilldown Drawer */}
      {selectedProcess && (
        <Panel
          kicker="Process Forensic Dossier"
          title={`Forensics for PID ${selectedProcess.pid} — ${selectedProcess.name}`}
          right={
            <button
              onClick={() => setSelectedPid(null)}
              className="press rounded-lg p-1 text-text-muted hover:text-text-primary transition"
            >
              <Icon name="x" size={14} />
            </button>
          }
        >
          <div className="space-y-4 font-mono text-xs">
            {/* Compound Process Identity Card */}
            <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3 space-y-2">
              <span className="text-[10px] uppercase font-bold text-accent tracking-wider">
                Compound Process Identity (Kernel Determinism)
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                <div>
                  <span className="text-text-faint text-[10px] block">Host Identifier</span>
                  <span className="font-bold text-text-primary">{selectedProcess.hostId}</span>
                </div>
                <div>
                  <span className="text-text-faint text-[10px] block">Boot UUID</span>
                  <span className="font-bold text-text-primary truncate">{selectedProcess.bootId || "local_boot"}</span>
                </div>
                <div>
                  <span className="text-text-faint text-[10px] block">Process PID</span>
                  <span className="font-bold text-text-primary tabular-nums">{selectedProcess.pid}</span>
                </div>
                <div>
                  <span className="text-text-faint text-[10px] block">Start Timestamp</span>
                  <span className="font-bold text-text-primary tabular-nums">
                    {selectedProcess.startTime || selectedProcess.timestamp || "—"}
                  </span>
                </div>
              </div>
            </div>

            {/* Command Line Details */}
            <div className="space-y-1">
              <span className="text-[10px] uppercase text-text-faint font-semibold">Full Command Line</span>
              <pre className="rounded-xl border border-border-subtle bg-bg-inset p-3 text-emerald-400 overflow-x-auto select-all text-[11px]">
                {selectedProcess.commandLine}
              </pre>
            </div>

            {/* Files & Sockets Touched */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="space-y-1.5 rounded-xl border border-border-subtle bg-bg-surface p-3">
                <span className="text-[10px] uppercase text-text-faint font-semibold block">
                  Files Modified / Written ({selectedProcess.fileWrites.length})
                </span>
                {selectedProcess.fileWrites.length === 0 ? (
                  <p className="text-text-faint text-[10px]">No file writes attributed to this PID</p>
                ) : (
                  <ul className="space-y-1 max-h-36 overflow-y-auto">
                    {selectedProcess.fileWrites.map((f, i) => (
                      <li key={i} className="truncate text-text-secondary select-all text-[11px] font-mono">
                        • {f}
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div className="space-y-1.5 rounded-xl border border-border-subtle bg-bg-surface p-3">
                <span className="text-[10px] uppercase text-text-faint font-semibold block">
                  Outbound Sockets &amp; Beacons ({selectedProcess.networkCalls.length})
                </span>
                {selectedProcess.networkCalls.length === 0 ? (
                  <p className="text-text-faint text-[10px]">No network connections attributed to this PID</p>
                ) : (
                  <ul className="space-y-1 max-h-36 overflow-y-auto">
                    {selectedProcess.networkCalls.map((net, i) => (
                      <li key={i} className="truncate text-accent select-all text-[11px] font-mono">
                        • {net}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}
