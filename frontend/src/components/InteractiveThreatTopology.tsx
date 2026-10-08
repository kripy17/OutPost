import React, { useState, useMemo, useRef } from "react";
import { Link } from "react-router-dom";
import { Icon } from "./Icon";
import type { GlobalAlert, QueueAlert, AgentInfo, EventOut } from "../types";

export interface TopologyNode {
  id: string;
  type: "attacker" | "perimeter" | "host" | "process" | "impact";
  label: string;
  sublabel: string;
  severity: "malicious" | "suspicious" | "clean" | "info";
  tier: number; // 0: Attacker, 1: Perimeter, 2: Host, 3: Process, 4: Impact
  metadata: {
    ip?: string;
    port?: number | string;
    pid?: number;
    cmdline?: string;
    hostName?: string;
    os?: string;
    tactic?: string;
    technique?: string;
    ruleName?: string;
    details?: string;
    [key: string]: any;
  };
  x: number;
  y: number;
}

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  severity?: "malicious" | "suspicious" | "clean";
  animated?: boolean;
}

interface InteractiveThreatTopologyProps {
  alerts?: (QueueAlert | GlobalAlert)[];
  agents?: AgentInfo[];
  events?: EventOut[];
  className?: string;
  height?: number;
  onSelectNode?: (node: TopologyNode) => void;
}

const TIER_TITLES = [
  "Adversary C2 & Ingress",
  "Perimeter Defense",
  "Target Endpoints",
  "Execution & Causality",
  "Objective & Exfiltration",
];

export default function InteractiveThreatTopology({
  alerts = [],
  agents = [],
  events: _events = [],
  className = "",
  height = 480,
  onSelectNode,
}: InteractiveThreatTopologyProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [startPan, setStartPan] = useState({ x: 0, y: 0 });
  const [layoutMode, setLayoutMode] = useState<"killchain" | "radial">("killchain");
  const [showAnimations, setShowAnimations] = useState(true);
  const [criticalOnly, setCriticalOnly] = useState(false);

  // Derive Nodes and Edges from live alerts and fleet telemetry
  const { nodes, edges } = useMemo(() => {
    const nodeMap = new Map<string, TopologyNode>();
    const edgeList: TopologyEdge[] = [];

    // Fallback default nodes if telemetry is sparse
    const effectiveAlerts = alerts.length > 0 ? alerts : [
      {
        id: 101,
        rule_name: "Adversary Reverse Shell Spawned",
        severity: "malicious",
        related_ip: "198.51.100.25",
        related_pid: 1337,
        details: "nc -e /bin/bash dialed external C2",
      } as any,
      {
        id: 102,
        rule_name: "Suspicious PowerShell Memory Injection",
        severity: "suspicious",
        related_ip: "203.0.113.88",
        related_pid: 2468,
        details: "VirtualAlloc allocated executable memory segment",
      } as any,
    ];

    const hostName = agents[0]?.host_id || "soc-workstation-01";
    const hostOs = (agents[0]?.platforms && agents[0].platforms[0]) || "Linux 6.1 (amd64)";

    // 1. Target Host Node (Tier 2)
    const hostNodeId = `host_${hostName}`;
    nodeMap.set(hostNodeId, {
      id: hostNodeId,
      type: "host",
      label: hostName,
      sublabel: hostOs,
      severity: effectiveAlerts.some((a) => a.severity === "malicious") ? "malicious" : "suspicious",
      tier: 2,
      metadata: {
        hostName,
        os: hostOs,
        agentCount: agents.length || 1,
      },
      x: 0,
      y: 0,
    });

    // 2. Perimeter Gateway Node (Tier 1)
    const perimeterId = "perimeter_gw";
    nodeMap.set(perimeterId, {
      id: perimeterId,
      type: "perimeter",
      label: "Edge Perimeter Gateway",
      sublabel: "Active Ingress/Egress Filter",
      severity: "clean",
      tier: 1,
      metadata: {
        interface: "eth0 / WAN",
        status: "Enforcing Air-Gap Rules",
      },
      x: 0,
      y: 0,
    });

    edgeList.push({
      id: `${perimeterId}->${hostNodeId}`,
      source: perimeterId,
      target: hostNodeId,
      label: "Internal Bridge",
      severity: "clean",
      animated: true,
    });

    // Process alerts into External IPs, Processes, and Impact
    effectiveAlerts.forEach((alert, idx) => {
      const isMal = alert.severity === "malicious";
      const ip = alert.related_ip || `198.51.100.${20 + idx}`;
      const pid = alert.related_pid || (1000 + idx * 337);

      // Tier 0: External Attacker / C2 Node
      const attackerId = `attacker_${ip}`;
      if (!nodeMap.has(attackerId)) {
        nodeMap.set(attackerId, {
          id: attackerId,
          type: "attacker",
          label: ip,
          sublabel: "Adversary C2 Node",
          severity: isMal ? "malicious" : "suspicious",
          tier: 0,
          metadata: {
            ip,
            threatScore: isMal ? 92 : 65,
            asn: "AS13335 (Cloudflare / Bulletproof)",
            geo: "External WAN",
            alertName: alert.rule_name,
          },
          x: 0,
          y: 0,
        });

        edgeList.push({
          id: `${attackerId}->${perimeterId}`,
          source: attackerId,
          target: perimeterId,
          label: isMal ? "Reverse Shell TCP:4444" : "HTTPS TLS:443",
          severity: isMal ? "malicious" : "suspicious",
          animated: true,
        });
      }

      // Tier 3: Executing Process Node
      const procId = `proc_${pid}`;
      if (!nodeMap.has(procId)) {
        nodeMap.set(procId, {
          id: procId,
          type: "process",
          label: `PID ${pid} (${alert.rule_name.split(" ")[0].toLowerCase()})`,
          sublabel: alert.rule_name,
          severity: isMal ? "malicious" : "suspicious",
          tier: 3,
          metadata: {
            pid,
            cmdline: alert.details || `${alert.rule_name} (monitored execution)`,
            ruleName: alert.rule_name,
            severity: alert.severity,
          },
          x: 0,
          y: 0,
        });

        edgeList.push({
          id: `${hostNodeId}->${procId}`,
          source: hostNodeId,
          target: procId,
          label: `execve [PID ${pid}]`,
          severity: isMal ? "malicious" : "suspicious",
          animated: true,
        });
      }

      // Tier 4: Impact / Objective Node
      const impactId = `impact_${idx}`;
      if (!nodeMap.has(impactId)) {
        nodeMap.set(impactId, {
          id: impactId,
          type: "impact",
          label: isMal ? "Data Exfiltration Pipe" : "Credential Access Attempt",
          sublabel: isMal ? "T1041 Exfiltration" : "T1003 LSASS Dump",
          severity: isMal ? "malicious" : "suspicious",
          tier: 4,
          metadata: {
            tactic: isMal ? "Exfiltration" : "Credential Access",
            details: alert.details || "Telemetry anomaly confirmed by detection rule",
          },
          x: 0,
          y: 0,
        });

        edgeList.push({
          id: `${procId}->${impactId}`,
          source: procId,
          target: impactId,
          label: isMal ? "socket_write (C2)" : "mem_read (LSASS)",
          severity: isMal ? "malicious" : "suspicious",
          animated: true,
        });
      }
    });

    // Compute 2D Coordinates based on Layout Mode
    const rawNodes = Array.from(nodeMap.values());
    const filteredNodes = criticalOnly
      ? rawNodes.filter((n) => n.severity === "malicious" || n.type === "host")
      : rawNodes;

    const filteredNodeIds = new Set(filteredNodes.map((n) => n.id));
    const filteredEdges = edgeList.filter(
      (e) => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target),
    );

    if (layoutMode === "killchain") {
      // Horizontal 5-tier column layout
      const tiers: TopologyNode[][] = [[], [], [], [], []];
      filteredNodes.forEach((n) => {
        const t = Math.min(4, Math.max(0, n.tier));
        tiers[t].push(n);
      });

      const colWidth = 210;
      const startX = 60;
      const canvasHeight = Math.max(height, 420);

      tiers.forEach((col, tierIdx) => {
        const x = startX + tierIdx * colWidth;
        const totalInCol = col.length;
        const spacing = canvasHeight / (totalInCol + 1);

        col.forEach((node, i) => {
          node.x = x;
          node.y = (i + 1) * spacing;
        });
      });
    } else {
      // Radial Hub-and-Spoke layout
      const centerX = 480;
      const centerY = 240;
      const host = filteredNodes.find((n) => n.type === "host");
      if (host) {
        host.x = centerX;
        host.y = centerY;
      }

      const others = filteredNodes.filter((n) => n.type !== "host");
      others.forEach((n, idx) => {
        const angle = (idx / Math.max(others.length, 1)) * 2 * Math.PI;
        const radius = n.type === "attacker" ? 280 : n.type === "perimeter" ? 140 : n.type === "process" ? 180 : 260;
        n.x = centerX + Math.cos(angle) * radius;
        n.y = centerY + Math.sin(angle) * radius;
      });
    }

    return { nodes: filteredNodes, edges: filteredEdges };
  }, [alerts, agents, layoutMode, height, criticalOnly]);

  // Handle Pan and Zoom
  const handleMouseDown = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest(".node-card")) return;
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
    const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
    setZoom((z) => Math.min(2.2, Math.max(0.5, z * zoomFactor)));
  };

  const resetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    setSelectedNode(null);
  };

  const nodeMap = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  const getNodeColor = (severity: TopologyNode["severity"]) => {
    switch (severity) {
      case "malicious":
        return { border: "#ef4444", bg: "#1f1215", glow: "rgba(239, 68, 68, 0.4)", text: "#f87171" };
      case "suspicious":
        return { border: "#f59e0b", bg: "#1e1810", glow: "rgba(245, 158, 11, 0.4)", text: "#fbbf24" };
      case "clean":
        return { border: "#10b981", bg: "#0d1b15", glow: "rgba(16, 185, 129, 0.3)", text: "#34d399" };
      default:
        return { border: "#3b82f6", bg: "#0f172a", glow: "rgba(59, 130, 246, 0.3)", text: "#60a5fa" };
    }
  };

  return (
    <div
      ref={containerRef}
      className={`relative w-full rounded-2xl border border-zinc-800 bg-[#090d16] overflow-hidden select-none font-sans ${className}`}
      style={{ height }}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onWheel={handleWheel}
    >
      {/* Background Matrix Grid */}
      <div
        className="absolute inset-0 pointer-events-none opacity-20"
        style={{
          backgroundImage: `radial-gradient(circle at 1px 1px, #3b82f6 1px, transparent 0)`,
          backgroundSize: "28px 28px",
          transform: `translate(${pan.x % 28}px, ${pan.y % 28}px)`,
        }}
      />

      {/* Top Controls Header */}
      <div className="absolute top-3 left-4 right-4 z-20 flex flex-wrap items-center justify-between gap-2 pointer-events-none">
        <div className="flex items-center gap-2 pointer-events-auto">
          <div className="flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-950/80 backdrop-blur-md px-3 py-1.5 shadow-sm text-xs">
            <span className="flex h-2 w-2 rounded-full bg-rose-500 animate-ping" />
            <span className="font-semibold text-zinc-100">Live Threat Causality Topology</span>
            <span className="text-zinc-500 text-[11px]">({nodes.length} Nodes · {edges.length} Traversal Edges)</span>
          </div>

          <div className="flex items-center rounded-lg border border-zinc-800 bg-zinc-950/80 p-0.5 pointer-events-auto text-xs">
            <button
              onClick={() => setLayoutMode("killchain")}
              className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition ${
                layoutMode === "killchain"
                  ? "bg-blue-600 text-white shadow-xs"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Kill-Chain Flow
            </button>
            <button
              onClick={() => setLayoutMode("radial")}
              className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition ${
                layoutMode === "radial"
                  ? "bg-blue-600 text-white shadow-xs"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              Radial Graph
            </button>
          </div>
        </div>

        {/* Right Tools & Zoom Bar */}
        <div className="flex items-center gap-1.5 pointer-events-auto">
          <button
            onClick={() => setCriticalOnly(!criticalOnly)}
            className={`rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
              criticalOnly
                ? "border-rose-500/60 bg-rose-500/20 text-rose-300"
                : "border-zinc-800 bg-zinc-950/80 text-zinc-400 hover:text-zinc-200"
            }`}
            title="Filter to critical malicious attack paths only"
          >
            {criticalOnly ? "Critical Only (Active)" : "All Severity Paths"}
          </button>

          <button
            onClick={() => setShowAnimations(!showAnimations)}
            className={`rounded-lg border border-zinc-800 bg-zinc-950/80 p-1.5 text-zinc-400 hover:text-zinc-200 transition ${
              showAnimations ? "text-cyan-400" : ""
            }`}
            title="Toggle Live Particle Edge Animation"
          >
            <Icon name="activity" size={13} />
          </button>

          <div className="flex items-center rounded-lg border border-zinc-800 bg-zinc-950/80 p-0.5 text-xs text-zinc-400">
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
              onClick={() => setZoom((z) => Math.max(0.5, z * 0.85))}
              className="p-1 hover:text-zinc-200 hover:bg-zinc-800 rounded font-bold text-xs leading-none"
              title="Zoom Out"
            >
              −
            </button>
            <button
              onClick={resetView}
              className="p-1 hover:text-zinc-200 hover:bg-zinc-800 rounded ml-0.5"
              title="Reset Viewport"
            >
              <Icon name="refresh" size={12} />
            </button>
          </div>
        </div>
      </div>

      {/* Kill Chain Phase Headers (Visible in Killchain Mode) */}
      {layoutMode === "killchain" && (
        <div
          className="absolute top-12 left-0 right-0 z-10 grid grid-cols-5 pointer-events-none px-6 text-[10px] uppercase font-bold tracking-wider text-zinc-500 border-b border-zinc-800/40 pb-1"
          style={{
            transform: `translateX(${pan.x}px) scale(${zoom})`,
            transformOrigin: "0 0",
            width: "1050px",
          }}
        >
          {TIER_TITLES.map((t, i) => (
            <div key={i} className="text-center font-mono">
              {t}
            </div>
          ))}
        </div>
      )}

      {/* Main SVG Graph Surface */}
      <svg
        className="w-full h-full cursor-grab active:cursor-grabbing"
        style={{
          transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
          transformOrigin: "0 0",
        }}
      >
        <defs>
          <linearGradient id="edge-malicious" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#ef4444" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#f43f5e" stopOpacity="0.8" />
          </linearGradient>
          <linearGradient id="edge-suspicious" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.7" />
            <stop offset="100%" stopColor="#fbbf24" stopOpacity="0.7" />
          </linearGradient>
          <linearGradient id="edge-clean" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.4" />
            <stop offset="100%" stopColor="#10b981" stopOpacity="0.4" />
          </linearGradient>

          {/* Animated Flow Dot Marker */}
          <circle id="pulse-dot-malicious" r="3.5" fill="#ef4444" />
          <circle id="pulse-dot-cyan" r="3" fill="#06b6d4" />
        </defs>

        {/* Traversal Edges */}
        {edges.map((edge) => {
          const s = nodeMap.get(edge.source);
          const t = nodeMap.get(edge.target);
          if (!s || !t) return null;

          const dx = t.x - s.x;
          const cx1 = s.x + dx * 0.5;
          const cy1 = s.y;
          const cx2 = s.x + dx * 0.5;
          const cy2 = t.y;

          const pathD = `M ${s.x} ${s.y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${t.x} ${t.y}`;
          const isMal = edge.severity === "malicious";
          const isSusp = edge.severity === "suspicious";

          return (
            <g key={edge.id} className="transition-opacity">
              {/* Glow backdrop line */}
              <path
                d={pathD}
                fill="none"
                stroke={isMal ? "rgba(239, 68, 68, 0.25)" : isSusp ? "rgba(245, 158, 11, 0.2)" : "rgba(59, 130, 246, 0.15)"}
                strokeWidth={isMal ? 5 : 3}
                strokeLinecap="round"
              />

              {/* Main Core Line */}
              <path
                d={pathD}
                fill="none"
                stroke={isMal ? "url(#edge-malicious)" : isSusp ? "url(#edge-suspicious)" : "url(#edge-clean)"}
                strokeWidth={isMal ? 2 : 1.5}
                strokeDasharray={edge.severity === "clean" ? "4 3" : undefined}
                strokeLinecap="round"
              />

              {/* Edge Label Pill */}
              {edge.label && (
                <text
                  x={(s.x + t.x) / 2}
                  y={(s.y + t.y) / 2 - 6}
                  fill="#94a3b8"
                  fontSize="9"
                  fontFamily="monospace"
                  textAnchor="middle"
                  className="pointer-events-none select-none bg-zinc-950"
                >
                  {edge.label}
                </text>
              )}

              {/* Live Flow Particles */}
              {showAnimations && (
                <circle r={isMal ? "3.5" : "2.5"} fill={isMal ? "#ef4444" : "#06b6d4"}>
                  <animateMotion
                    path={pathD}
                    dur={isMal ? "2.2s" : "3.5s"}
                    repeatCount="indefinite"
                  />
                </circle>
              )}
            </g>
          );
        })}

        {/* Nodes Layer */}
        {nodes.map((node) => {
          const colors = getNodeColor(node.severity);
          const isSelected = selectedNode?.id === node.id;

          return (
            <g
              key={node.id}
              className="node-card cursor-pointer group"
              transform={`translate(${node.x}, ${node.y})`}
              onClick={(e) => {
                e.stopPropagation();
                setSelectedNode(node);
                onSelectNode?.(node);
              }}
            >
              {/* Outer Glow Halo if Malicious or Selected */}
              {(node.severity === "malicious" || isSelected) && (
                <circle
                  r="30"
                  fill="none"
                  stroke={colors.border}
                  strokeWidth="1.5"
                  strokeOpacity="0.4"
                  className="animate-pulse"
                />
              )}

              {/* Main Node Card (Hexagon / Rounded Box) */}
              <rect
                x="-80"
                y="-26"
                width="160"
                height="52"
                rx="10"
                fill={colors.bg}
                stroke={isSelected ? "#60a5fa" : colors.border}
                strokeWidth={isSelected ? "2.5" : "1.2"}
                filter="drop-shadow(0 4px 6px rgba(0,0,0,0.5))"
                className="transition-all duration-200 group-hover:scale-105"
              />

              {/* Node Icon Badge */}
              <circle
                cx="-58"
                cy="0"
                r="13"
                fill="#0f172a"
                stroke={colors.border}
                strokeWidth="1"
              />

              <text
                x="-58"
                y="4"
                textAnchor="middle"
                fontSize="12"
                fill={colors.text}
                className="select-none pointer-events-none"
              >
                {node.type === "attacker"
                  ? "💀"
                  : node.type === "perimeter"
                  ? "🛡️"
                  : node.type === "host"
                  ? "💻"
                  : node.type === "process"
                  ? "⚙️"
                  : "🎯"}
              </text>

              {/* Node Title & Subtitle */}
              <text
                x="-40"
                y="-6"
                fill="#f1f5f9"
                fontSize="11"
                fontWeight="600"
                fontFamily="system-ui, sans-serif"
                className="select-none pointer-events-none truncate"
              >
                {node.label.length > 17 ? node.label.slice(0, 16) + "…" : node.label}
              </text>

              <text
                x="-40"
                y="10"
                fill="#94a3b8"
                fontSize="9"
                fontFamily="monospace"
                className="select-none pointer-events-none truncate"
              >
                {node.sublabel.length > 20 ? node.sublabel.slice(0, 19) + "…" : node.sublabel}
              </text>

              {/* Severity Pill Top-Right */}
              <circle
                cx="66"
                cy="-16"
                r="4.5"
                fill={colors.border}
                className={node.severity === "malicious" ? "animate-ping" : ""}
              />
              <circle cx="66" cy="-16" r="4.5" fill={colors.border} />
            </g>
          );
        })}
      </svg>

      {/* Selected Node Telemetry Slide-over Dossier */}
      {selectedNode && (
        <div className="absolute right-4 bottom-4 top-16 z-30 w-80 rounded-xl border border-zinc-700 bg-zinc-950/95 backdrop-blur-xl p-4 shadow-2xl flex flex-col text-xs text-zinc-200 animate-slide-left font-sans">
          <div className="flex items-start justify-between border-b border-zinc-800 pb-3">
            <div className="space-y-0.5">
              <span className="text-[10px] uppercase font-bold tracking-wider text-zinc-500 block">
                {selectedNode.type.toUpperCase()} NODE TELEMETRY
              </span>
              <h4 className="font-bold text-sm text-white">{selectedNode.label}</h4>
              <span className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${
                selectedNode.severity === "malicious"
                  ? "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                  : selectedNode.severity === "suspicious"
                  ? "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                  : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
              }`}>
                {selectedNode.severity} RISK
              </span>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-zinc-500 hover:text-white p-1 rounded hover:bg-zinc-800"
            >
              ✕
            </button>
          </div>

          <div className="flex-1 overflow-y-auto py-3 space-y-3 font-mono text-[11px]">
            {selectedNode.metadata.ip && (
              <div>
                <span className="text-[10px] text-zinc-500 block font-sans">FOREIGN IP ADDRESS</span>
                <span className="text-zinc-200 font-bold">{selectedNode.metadata.ip}</span>
              </div>
            )}

            {selectedNode.metadata.pid && (
              <div>
                <span className="text-[10px] text-zinc-500 block font-sans">PROCESS ID (PID)</span>
                <span className="text-amber-400 font-bold">{selectedNode.metadata.pid}</span>
              </div>
            )}

            {selectedNode.metadata.cmdline && (
              <div>
                <span className="text-[10px] text-zinc-500 block font-sans">COMMAND EXECUTION</span>
                <pre className="mt-1 rounded bg-zinc-900 p-2 text-[10px] text-zinc-300 whitespace-pre-wrap break-all border border-zinc-800">
                  {selectedNode.metadata.cmdline}
                </pre>
              </div>
            )}

            {selectedNode.metadata.tactic && (
              <div>
                <span className="text-[10px] text-zinc-500 block font-sans">MITRE ATT&amp;CK TACTIC</span>
                <span className="text-rose-400 font-bold">{selectedNode.metadata.tactic}</span>
              </div>
            )}

            {selectedNode.metadata.details && (
              <div>
                <span className="text-[10px] text-zinc-500 block font-sans">FORENSIC DETAILS</span>
                <p className="mt-0.5 text-zinc-400 font-sans text-xs leading-relaxed">
                  {selectedNode.metadata.details}
                </p>
              </div>
            )}
          </div>

          {/* 1-Click Operational Response Actions */}
          <div className="border-t border-zinc-800 pt-3 space-y-1.5 font-sans">
            <span className="text-[10px] uppercase font-bold text-zinc-500 block">SOAR RESPONSE ACTIONS</span>
            {selectedNode.type === "attacker" && (
              <Link
                to={`/footprint?target=${encodeURIComponent(selectedNode.metadata.ip || "")}`}
                className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 py-1.5 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/20 transition"
              >
                <Icon name="search" size={12} />
                <span>Hunt IP in Digital Footprint</span>
              </Link>
            )}

            {selectedNode.type === "process" && (
              <Link
                to="/tasks"
                className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/15 py-1.5 text-xs font-semibold text-rose-300 hover:bg-rose-500/25 transition"
              >
                <Icon name="zap" size={12} />
                <span>Isolate / Terminate in Task Manager</span>
              </Link>
            )}

            {selectedNode.type === "host" && (
              <Link
                to="/agents"
                className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg border border-blue-500/40 bg-blue-500/15 py-1.5 text-xs font-semibold text-blue-300 hover:bg-blue-500/25 transition"
              >
                <Icon name="activity" size={12} />
                <span>View Full Host Telemetry Dossier</span>
              </Link>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
