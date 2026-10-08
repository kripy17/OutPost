import React, { useState, useMemo, useRef } from "react";
import { Icon } from "./Icon";

export interface ProcessTopologyNode {
  id: string;
  pid: number;
  name: string;
  cmdline: string;
  user: string;
  cpu_percent: number;
  memory_rss_mb: number;
  is_flagged: boolean;
  socket_count: number;
  x: number;
  y: number;
}

export interface SocketTopologyNode {
  id: string;
  pid: number;
  local_addr: string;
  foreign_addr: string | null;
  status: string;
  direction: string;
  is_external: boolean;
  x: number;
  y: number;
}

interface ProcessNetworkTopologyMapProps {
  processes: any[];
  sockets: any[];
  flaggedPids: Set<number>;
  onSelectPid?: (pid: number) => void;
  onKillPid?: (pid: number) => void;
  onYaraScanPid?: (pid: number) => void;
  height?: number;
}

export default function ProcessNetworkTopologyMap({
  processes = [],
  sockets = [],
  flaggedPids = new Set(),
  onSelectPid,
  onKillPid,
  onYaraScanPid,
  height = 540,
}: ProcessNetworkTopologyMapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [startPan, setStartPan] = useState({ x: 0, y: 0 });
  const [filterQuery, setFilterQuery] = useState("");
  const [anomaliesOnly, setAnomaliesOnly] = useState(false);

  // Compute Layout of Processes and Sockets
  const { procNodes, socketNodes, edges } = useMemo(() => {
    // Filter processes to top active / relevant ones so canvas remains responsive and legible
    let displayProcs = processes;
    if (anomaliesOnly) {
      displayProcs = processes.filter((p) => flaggedPids.has(p.pid));
    }
    if (filterQuery.trim()) {
      const q = filterQuery.toLowerCase().trim();
      displayProcs = displayProcs.filter(
        (p) =>
          (p.name || "").toLowerCase().includes(q) ||
          String(p.pid).includes(q) ||
          (p.user || p.username || "").toLowerCase().includes(q),
      );
    }

    // Limit to 45 procs maximum for visual clarity
    const limitedProcs = displayProcs.slice(0, 45);
    const procMap = new Map<number, ProcessTopologyNode>();
    const socketMap = new Map<string, SocketTopologyNode>();
    const edgeList: Array<{ id: string; sourceX: number; sourceY: number; targetX: number; targetY: number; isSuspicious: boolean }> = [];

    // Map sockets by PID
    const socketsByPid = new Map<number, any[]>();
    sockets.forEach((s) => {
      if (s.pid) {
        const list = socketsByPid.get(s.pid) || [];
        list.push(s);
        socketsByPid.set(s.pid, list);
      }
    });

    const totalProcs = limitedProcs.length;
    const cols = Math.max(3, Math.ceil(Math.sqrt(totalProcs * 1.5)));
    const colSpacing = 220;
    const rowSpacing = 90;

    limitedProcs.forEach((p, idx) => {
      const row = Math.floor(idx / cols);
      const col = idx % cols;
      const x = 80 + col * colSpacing;
      const y = 80 + row * rowSpacing;
      const isFlagged = flaggedPids.has(p.pid);
      const pSockets = socketsByPid.get(p.pid) || [];

      const rawCmd = Array.isArray(p.cmdline) ? p.cmdline.join(" ") : String(p.cmdline || "");
      const rss = typeof p.memory_mb === "number" ? p.memory_mb : typeof p.memory_rss_bytes === "number" ? Math.round(p.memory_rss_bytes / (1024 * 1024)) : (p.memory_rss_mb || 0);

      const pNode: ProcessTopologyNode = {
        id: `proc_${p.pid}`,
        pid: p.pid,
        name: p.name || "unknown",
        cmdline: rawCmd,
        user: p.user || p.username || "system",
        cpu_percent: p.cpu_percent || 0,
        memory_rss_mb: rss,
        is_flagged: isFlagged,
        socket_count: pSockets.length,
        x,
        y,
      };
      procMap.set(p.pid, pNode);

      // Add socket satellite nodes for processes with open sockets
      pSockets.slice(0, 3).forEach((s, sIdx) => {
        const sockId = `sock_${p.pid}_${sIdx}`;
        const foreign = s.foreign_ip || s.raddr || null;
        const local = s.local_port ? `:${s.local_port}` : s.laddr || ":?";
        const isExternal = Boolean(foreign && !foreign.startsWith("127.") && !foreign.startsWith("0.0.0.0"));

        const angle = (sIdx / Math.max(pSockets.length, 1)) * Math.PI - Math.PI / 2;
        const sockX = x + Math.cos(angle) * 75 + (col % 2 === 0 ? 30 : -30);
        const sockY = y + Math.sin(angle) * 55;

        const sNode: SocketTopologyNode = {
          id: sockId,
          pid: p.pid,
          local_addr: local,
          foreign_addr: foreign,
          status: s.status || "ESTABLISHED",
          direction: s.direction || (foreign ? "OUTBOUND" : "LISTEN"),
          is_external: isExternal,
          x: sockX,
          y: sockY,
        };
        socketMap.set(sockId, sNode);

        edgeList.push({
          id: `edge_${p.pid}_${sockId}`,
          sourceX: x,
          sourceY: y,
          targetX: sockX,
          targetY: sockY,
          isSuspicious: isFlagged || isExternal,
        });
      });
    });

    return {
      procNodes: Array.from(procMap.values()),
      socketNodes: Array.from(socketMap.values()),
      edges: edgeList,
    };
  }, [processes, sockets, flaggedPids, anomaliesOnly, filterQuery]);

  // Pan & Zoom handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest(".proc-card")) return;
    setIsPanning(true);
    setStartPan({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isPanning) return;
    setPan({ x: e.clientX - startPan.x, y: e.clientY - startPan.y });
  };

  const handleMouseUp = () => setIsPanning(false);

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.08 : 0.92;
    setZoom((z) => Math.min(2.2, Math.max(0.4, z * factor)));
  };

  const selectedProc = useMemo(() => {
    if (!selectedPid) return null;
    return processes.find((p) => p.pid === selectedPid);
  }, [selectedPid, processes]);

  return (
    <div
      ref={containerRef}
      className="relative w-full rounded-2xl border border-zinc-800 bg-[#090d16] overflow-hidden select-none font-sans"
      style={{ height }}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onWheel={handleWheel}
    >
      {/* Background Grid Pattern */}
      <div
        className="absolute inset-0 pointer-events-none opacity-20"
        style={{
          backgroundImage: "radial-gradient(circle at 1px 1px, #6366f1 1px, transparent 0)",
          backgroundSize: "24px 24px",
          transform: `translate(${pan.x % 24}px, ${pan.y % 24}px)`,
        }}
      />

      {/* Top Controls Bar */}
      <div className="absolute top-3 left-4 right-4 z-20 flex flex-wrap items-center justify-between gap-2 pointer-events-none">
        <div className="flex items-center gap-2 pointer-events-auto">
          <div className="flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-950/85 backdrop-blur-md px-3 py-1.5 shadow-sm text-xs">
            <span className="flex h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="font-semibold text-zinc-100">Live Process &amp; Socket Topology</span>
            <span className="text-zinc-500 text-[11px]">({procNodes.length} Processes · {socketNodes.length} Sockets)</span>
          </div>

          <div className="relative">
            <input
              type="text"
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              placeholder="Search PID / Name in Topology..."
              className="w-48 rounded-lg border border-zinc-800 bg-zinc-950/90 py-1 pl-7 pr-2.5 text-xs text-zinc-200 placeholder:text-zinc-600 focus:border-blue-500 outline-none"
            />
            <span className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-zinc-500">
              <Icon name="search" size={11} />
            </span>
          </div>
        </div>

        {/* Right Action Buttons */}
        <div className="flex items-center gap-1.5 pointer-events-auto">
          <button
            onClick={() => setAnomaliesOnly(!anomaliesOnly)}
            className={`rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
              anomaliesOnly
                ? "border-rose-500/60 bg-rose-500/20 text-rose-300"
                : "border-zinc-800 bg-zinc-950/85 text-zinc-400 hover:text-zinc-200"
            }`}
          >
            {anomaliesOnly ? "Anomalies Only (Active)" : "All Processes"}
          </button>

          <div className="flex items-center rounded-lg border border-zinc-800 bg-zinc-950/85 p-0.5 text-xs text-zinc-400">
            <button
              onClick={() => setZoom((z) => Math.min(2.2, z * 1.15))}
              className="p-1 hover:text-zinc-200 hover:bg-zinc-800 rounded"
              title="Zoom In"
            >
              <Icon name="plus" size={12} />
            </button>
            <span className="px-1.5 font-mono text-[10px] text-zinc-400">
              {Math.round(zoom * 100)}%
            </span>
            <button
              onClick={() => setZoom((z) => Math.max(0.4, z * 0.85))}
              className="p-1 hover:text-zinc-200 hover:bg-zinc-800 rounded font-bold text-xs leading-none"
              title="Zoom Out"
            >
              −
            </button>
            <button
              onClick={() => {
                setZoom(1);
                setPan({ x: 0, y: 0 });
                setSelectedPid(null);
              }}
              className="p-1 hover:text-zinc-200 hover:bg-zinc-800 rounded ml-0.5"
              title="Reset View"
            >
              <Icon name="refresh" size={12} />
            </button>
          </div>
        </div>
      </div>

      {/* SVG Canvas */}
      <svg
        className="w-full h-full cursor-grab active:cursor-grabbing"
        style={{
          transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
          transformOrigin: "0 0",
        }}
      >
        {/* Socket Edges */}
        {edges.map((e) => (
          <line
            key={e.id}
            x1={e.sourceX}
            y1={e.sourceY}
            x2={e.targetX}
            y2={e.targetY}
            stroke={e.isSuspicious ? "#f43f5e" : "#3b82f6"}
            strokeWidth={e.isSuspicious ? 1.8 : 1}
            strokeDasharray={e.isSuspicious ? undefined : "3 2"}
            strokeOpacity={e.isSuspicious ? 0.8 : 0.4}
          />
        ))}

        {/* Socket Nodes */}
        {socketNodes.map((s) => (
          <g key={s.id} transform={`translate(${s.x}, ${s.y})`} className="pointer-events-none">
            <circle
              r="7"
              fill={s.is_external ? "#1e131d" : "#0d1b2a"}
              stroke={s.is_external ? "#f43f5e" : "#38bdf8"}
              strokeWidth="1.2"
            />
            <text
              y="14"
              textAnchor="middle"
              fill="#94a3b8"
              fontSize="8"
              fontFamily="monospace"
              className="select-none"
            >
              {s.foreign_addr ? s.foreign_addr.slice(0, 14) : s.local_addr}
            </text>
          </g>
        ))}

        {/* Process Nodes */}
        {procNodes.map((p) => {
          const isSelected = selectedPid === p.pid;
          const isAnom = p.is_flagged;

          return (
            <g
              key={p.id}
              className="proc-card cursor-pointer group"
              transform={`translate(${p.x}, ${p.y})`}
              onClick={(e) => {
                e.stopPropagation();
                setSelectedPid(p.pid);
                onSelectPid?.(p.pid);
              }}
            >
              {/* Outer Threat Halo */}
              {isAnom && (
                <rect
                  x="-88"
                  y="-26"
                  width="176"
                  height="52"
                  rx="12"
                  fill="none"
                  stroke="#ef4444"
                  strokeWidth="2"
                  strokeOpacity="0.4"
                  className="animate-pulse"
                />
              )}

              {/* Main Process Box */}
              <rect
                x="-82"
                y="-22"
                width="164"
                height="44"
                rx="8"
                fill={isAnom ? "#1c0d12" : isSelected ? "#141c2e" : "#0d121d"}
                stroke={isSelected ? "#60a5fa" : isAnom ? "#ef4444" : "#1e293b"}
                strokeWidth={isSelected ? "2" : "1.2"}
                filter="drop-shadow(0 2px 4px rgba(0,0,0,0.5))"
                className="transition-all duration-150 group-hover:scale-105"
              />

              {/* PID Badge */}
              <rect
                x="-76"
                y="-15"
                width="36"
                height="16"
                rx="4"
                fill={isAnom ? "#450a0a" : "#1e293b"}
              />
              <text
                x="-58"
                y="-3"
                textAnchor="middle"
                fill={isAnom ? "#fca5a5" : "#94a3b8"}
                fontSize="9"
                fontFamily="monospace"
                fontWeight="bold"
                className="select-none pointer-events-none"
              >
                {p.pid}
              </text>

              {/* Process Name */}
              <text
                x="-34"
                y="-4"
                fill="#f1f5f9"
                fontSize="11"
                fontWeight="600"
                className="select-none pointer-events-none"
              >
                {p.name.length > 14 ? p.name.slice(0, 13) + "…" : p.name}
              </text>

              {/* CPU & Memory Footprint */}
              <text
                x="-76"
                y="13"
                fill="#64748b"
                fontSize="8.5"
                fontFamily="monospace"
                className="select-none pointer-events-none"
              >
                {p.user} · {p.cpu_percent.toFixed(1)}% · {p.memory_rss_mb}MB
              </text>

              {/* Open Sockets Indicator */}
              {p.socket_count > 0 && (
                <circle cx="70" cy="-12" r="3.5" fill="#38bdf8" />
              )}
            </g>
          );
        })}
      </svg>

      {/* Selected Process Inspector Slide-over */}
      {selectedProc && (
        <div className="absolute right-4 bottom-4 top-16 z-30 w-84 rounded-xl border border-zinc-700 bg-zinc-950/95 backdrop-blur-xl p-4 shadow-2xl flex flex-col text-xs text-zinc-200 animate-slide-left font-sans">
          <div className="flex items-start justify-between border-b border-zinc-800 pb-3">
            <div className="space-y-0.5">
              <span className="text-[10px] uppercase font-bold tracking-wider text-zinc-500 block">
                PROCESS INSPECTOR · PID {selectedProc.pid}
              </span>
              <h4 className="font-bold text-sm text-white">{selectedProc.name}</h4>
              <span className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${
                flaggedPids.has(selectedProc.pid)
                  ? "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                  : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
              }`}>
                {flaggedPids.has(selectedProc.pid) ? "ANOMALY DETECTED" : "NORMAL INTEGRITY"}
              </span>
            </div>
            <button
              onClick={() => setSelectedPid(null)}
              className="text-zinc-500 hover:text-white p-1 rounded hover:bg-zinc-800"
            >
              ✕
            </button>
          </div>

          <div className="flex-1 overflow-y-auto py-3 space-y-3 font-mono text-[11px]">
            <div>
              <span className="text-[10px] text-zinc-500 block font-sans">COMMAND LINE</span>
              <pre className="mt-1 rounded bg-zinc-900 p-2 text-[10px] text-zinc-300 whitespace-pre-wrap break-all border border-zinc-800">
                {Array.isArray(selectedProc.cmdline) ? selectedProc.cmdline.join(" ") : String(selectedProc.cmdline || selectedProc.name)}
              </pre>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div className="rounded border border-zinc-800 bg-zinc-900/60 p-2">
                <span className="text-[9px] text-zinc-500 block font-sans">USER CONTEXT</span>
                <span className="text-zinc-200 font-bold">{selectedProc.user || selectedProc.username || "system"}</span>
              </div>
              <div className="rounded border border-zinc-800 bg-zinc-900/60 p-2">
                <span className="text-[9px] text-zinc-500 block font-sans">PARENT PID</span>
                <span className="text-zinc-200 font-bold">{selectedProc.ppid || 1}</span>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div className="rounded border border-zinc-800 bg-zinc-900/60 p-2">
                <span className="text-[9px] text-zinc-500 block font-sans">CPU LOAD</span>
                <span className="text-blue-400 font-bold">{Number(selectedProc.cpu_percent || 0).toFixed(1)}%</span>
              </div>
              <div className="rounded border border-zinc-800 bg-zinc-900/60 p-2">
                <span className="text-[9px] text-zinc-500 block font-sans">RAM RSS</span>
                <span className="text-emerald-400 font-bold">
                  {typeof selectedProc.memory_mb === "number" ? selectedProc.memory_mb : typeof selectedProc.memory_rss_bytes === "number" ? Math.round(selectedProc.memory_rss_bytes / (1024 * 1024)) : (selectedProc.memory_rss_mb || 0)} MB
                </span>
              </div>
            </div>
          </div>

          {/* Quick Signal Actions */}
          <div className="border-t border-zinc-800 pt-3 space-y-1.5 font-sans">
            <span className="text-[10px] uppercase font-bold text-zinc-500 block">CONTAINMENT DISPATCH</span>
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={() => onKillPid?.(selectedProc.pid)}
                className="inline-flex items-center justify-center gap-1 rounded-lg border border-rose-500/40 bg-rose-500/15 py-1.5 text-xs font-semibold text-rose-300 hover:bg-rose-500/25 transition"
              >
                <Icon name="zap" size={11} />
                <span>SIGKILL</span>
              </button>
              <button
                onClick={() => onYaraScanPid?.(selectedProc.pid)}
                className="inline-flex items-center justify-center gap-1 rounded-lg border border-amber-500/40 bg-amber-500/15 py-1.5 text-xs font-semibold text-amber-300 hover:bg-amber-500/25 transition"
              >
                <Icon name="search" size={11} />
                <span>YARA Scan</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
