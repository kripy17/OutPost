import React, { useState, useEffect, useRef, useMemo } from "react";
import { Icon } from "./Icon";
import { Chip } from "./ui";

interface GraphNode {
  id: string;
  type: "case" | "host" | "run" | "finding" | "ioc";
  label: string;
  sublabel?: string;
  severity?: "malicious" | "suspicious" | "info" | "clear";
  metadata?: Record<string, any>;
  x: number;
  y: number;
  vx: number;
  vy: number;
}

interface GraphEdge {
  source: string;
  target: string;
  label?: string;
}

interface InvestigationEvidenceGraphProps {
  investigation: any;
  onSelectNode?: (type: string, id: string) => void;
}

export default function InvestigationEvidenceGraph({
  investigation,
  onSelectNode,
}: InvestigationEvidenceGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [filterTypes, setFilterTypes] = useState<Record<string, boolean>>({
    host: true,
    run: true,
    finding: true,
    ioc: true,
  });
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDraggingCanvas, setIsDraggingCanvas] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [draggedNodeId, setDraggedNodeId] = useState<string | null>(null);

  // Build Graph Nodes and Edges from Investigation Dossier
  const { initialNodes, initialEdges } = useMemo(() => {
    if (!investigation) return { initialNodes: [], initialEdges: [] };

    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    const caseId = investigation.id || "case";

    // 1. Root Case Node
    nodes.push({
      id: caseId,
      type: "case",
      label: investigation.id ? `Case #${investigation.id}` : "Investigation Dossier",
      sublabel: `Status: ${investigation.status || "active"}`,
      severity: investigation.severity || "malicious",
      metadata: {
        id: investigation.id,
        created_at: investigation.created_at,
        conclusion: investigation.conclusion,
      },
      x: 450,
      y: 260,
      vx: 0,
      vy: 0,
    });

    const refs = investigation.refs || [];
    const alerts = investigation.alerts || [];

    // 2. Attached Reference Nodes
    refs.forEach((ref: any, idx: number) => {
      const rType = ref.ref_type;
      const rId = ref.ref_id;
      const angle = (idx / Math.max(refs.length, 1)) * 2 * Math.PI;
      const dist = 160 + (idx % 2) * 40;

      const nodeType: GraphNode["type"] =
        rType === "host" ? "host" : rType === "run" ? "run" : rType === "ioc" ? "ioc" : "finding";

      nodes.push({
        id: `${rType}_${rId}`,
        type: nodeType,
        label: rId.length > 20 ? rId.slice(0, 18) + "…" : rId,
        sublabel: rType.toUpperCase(),
        severity: rType === "ioc" ? "suspicious" : "info",
        metadata: ref,
        x: 450 + Math.cos(angle) * dist,
        y: 260 + Math.sin(angle) * dist,
        vx: 0,
        vy: 0,
      });

      edges.push({
        source: caseId,
        target: `${rType}_${rId}`,
        label: rType === "host" ? "targets" : rType === "run" ? "analyzed" : "evidenced",
      });
    });

    // 3. Finding / Alert Nodes
    alerts.forEach((alt: any, idx: number) => {
      const altId = `alert_${alt.id}`;
      const angle = ((idx + 0.5) / Math.max(alerts.length, 1)) * 2 * Math.PI;
      const dist = 240 + (idx % 3) * 30;

      nodes.push({
        id: altId,
        type: "finding",
        label: alt.rule_name || alt.rule_id || `Alert #${alt.id}`,
        sublabel: alt.sample_name || "Telemetry Finding",
        severity: alt.severity === "malicious" ? "malicious" : "suspicious",
        metadata: alt,
        x: 450 + Math.cos(angle) * dist,
        y: 260 + Math.sin(angle) * dist,
        vx: 0,
        vy: 0,
      });

      // Connect finding to corresponding run or case
      const parentRun = refs.find((r: any) => r.ref_type === "run" && r.ref_id === alt.run_id);
      if (parentRun) {
        edges.push({
          source: `run_${parentRun.ref_id}`,
          target: altId,
          label: "triggered",
        });
      } else {
        edges.push({
          source: caseId,
          target: altId,
          label: "findings",
        });
      }
    });

    // Synchronous relaxation passes to prevent node overlap
    for (let step = 0; step < 15; step++) {
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[j].x - nodes[i].x;
          const dy = nodes[j].y - nodes[i].y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          if (dist < 180) {
            const force = ((180 - dist) / 180) * 1.5;
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;
            if (nodes[i].type !== "case") {
              nodes[i].x -= fx;
              nodes[i].y -= fy;
            }
            if (nodes[j].type !== "case") {
              nodes[j].x += fx;
              nodes[j].y += fy;
            }
          }
        }
      }
    }

    return { initialNodes: nodes, initialEdges: edges };
  }, [investigation]);

  const [nodes, setNodes] = useState<GraphNode[]>(initialNodes);
  const [edges, setEdges] = useState<GraphEdge[]>(initialEdges);

  useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, initialEdges]);

  // Filtered nodes
  const activeNodes = useMemo(() => {
    return nodes.filter((n) => n.type === "case" || filterTypes[n.type]);
  }, [nodes, filterTypes]);

  const activeNodeIds = useMemo(() => new Set(activeNodes.map((n) => n.id)), [activeNodes]);

  const activeEdges = useMemo(() => {
    return edges.filter((e) => activeNodeIds.has(e.source) && activeNodeIds.has(e.target));
  }, [edges, activeNodeIds]);

  const getNodeColor = (node: GraphNode) => {
    if (node.type === "case") return "#8b5cf6"; // Violet/Purple
    if (node.type === "host") return "#38bdf8"; // Cyan
    if (node.type === "run") return "#f59e0b"; // Amber
    if (node.type === "finding") {
      return node.severity === "malicious" ? "#ef4444" : "#f59e0b";
    }
    if (node.type === "ioc") return "#10b981"; // Emerald
    return "#94a3b8";
  };

  // Canvas Mouse Pan Handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).tagName === "svg" || (e.target as HTMLElement).id === "bg-rect") {
      setIsDraggingCanvas(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDraggingCanvas) {
      setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    } else if (draggedNodeId) {
      const rect = containerRef.current?.getBoundingClientRect();
      if (!rect) return;
      const mouseX = (e.clientX - rect.left - pan.x) / zoom;
      const mouseY = (e.clientY - rect.top - pan.y) / zoom;
      setNodes((prev) =>
        prev.map((n) => (n.id === draggedNodeId ? { ...n, x: mouseX, y: mouseY } : n))
      );
    }
  };

  const handleMouseUp = () => {
    setIsDraggingCanvas(false);
    setDraggedNodeId(null);
  };

  return (
    <div
      ref={containerRef}
      className="relative flex flex-col h-[580px] w-full rounded-xl border border-border-subtle bg-panel/60 backdrop-blur-md overflow-hidden select-none"
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
    >
      {/* Top Header Controls Bar */}
      <div className="absolute top-3 left-3 z-10 flex flex-wrap items-center gap-2 bg-panel/90 p-2 rounded-lg border border-border-subtle backdrop-blur-md shadow-lg">
        <span className="text-[11px] font-semibold text-text-muted uppercase tracking-wider px-1">
          Evidence Filter:
        </span>
        <button
          onClick={() => setFilterTypes((p) => ({ ...p, host: !p.host }))}
          className={`px-2 py-1 text-xs rounded font-mono flex items-center gap-1.5 transition-colors ${
            filterTypes.host ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40" : "bg-panel-muted text-text-muted opacity-60"
          }`}
        >
          <Icon name="terminal" className="w-3 h-3" /> Hosts
        </button>
        <button
          onClick={() => setFilterTypes((p) => ({ ...p, run: !p.run }))}
          className={`px-2 py-1 text-xs rounded font-mono flex items-center gap-1.5 transition-colors ${
            filterTypes.run ? "bg-amber-500/20 text-amber-400 border border-amber-500/40" : "bg-panel-muted text-text-muted opacity-60"
          }`}
        >
          <Icon name="play" className="w-3 h-3" /> Runs
        </button>
        <button
          onClick={() => setFilterTypes((p) => ({ ...p, finding: !p.finding }))}
          className={`px-2 py-1 text-xs rounded font-mono flex items-center gap-1.5 transition-colors ${
            filterTypes.finding ? "bg-red-500/20 text-red-400 border border-red-500/40" : "bg-panel-muted text-text-muted opacity-60"
          }`}
        >
          <Icon name="alert" className="w-3 h-3" /> Findings
        </button>
        <button
          onClick={() => setFilterTypes((p) => ({ ...p, ioc: !p.ioc }))}
          className={`px-2 py-1 text-xs rounded font-mono flex items-center gap-1.5 transition-colors ${
            filterTypes.ioc ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40" : "bg-panel-muted text-text-muted opacity-60"
          }`}
        >
          <Icon name="target" className="w-3 h-3" /> IOCs
        </button>
      </div>

      {/* Zoom / Pan Controls */}
      <div className="absolute bottom-3 right-3 z-10 flex items-center gap-1 bg-panel/90 p-1.5 rounded-lg border border-border-subtle shadow-lg">
        <button
          onClick={() => setZoom((z) => Math.min(z + 0.15, 2.5))}
          className="p-1.5 rounded hover:bg-white/10 text-text-muted hover:text-text"
          title="Zoom In"
        >
          <Icon name="plus" className="w-4 h-4" />
        </button>
        <button
          onClick={() => setZoom((z) => Math.max(z - 0.15, 0.4))}
          className="p-1.5 rounded hover:bg-white/10 text-text-muted hover:text-text"
          title="Zoom Out"
        >
          <span className="w-4 h-4 flex items-center justify-center text-sm font-bold leading-none select-none">−</span>
        </button>
        <button
          onClick={() => {
            setZoom(1);
            setPan({ x: 0, y: 0 });
          }}
          className="px-2 py-1 text-[11px] font-mono rounded hover:bg-white/10 text-text-muted hover:text-text"
          title="Reset Zoom & Position"
        >
          Reset
        </button>
      </div>

      {/* SVG Force-Directed Canvas */}
      <svg
        aria-hidden="true"
        className="w-full h-full cursor-grab active:cursor-grabbing"
        style={{ backgroundColor: "transparent" }}
      >
        <defs>
          <pattern id="grid-dots" width="24" height="24" patternUnits="userSpaceOnUse">
            <circle cx="2" cy="2" r="1" fill="#ffffff" fillOpacity="0.04" />
          </pattern>
          <marker
            id="edge-arrow"
            viewBox="0 0 10 10"
            refX="22"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto-start-reverse"
          >
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" opacity="0.6" />
          </marker>
        </defs>

        <rect id="bg-rect" width="100%" height="100%" fill="url(#grid-dots)" />

        <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
          {/* Edges */}
          {activeEdges.map((edge, idx) => {
            const src = activeNodes.find((n) => n.id === edge.source);
            const tgt = activeNodes.find((n) => n.id === edge.target);
            if (!src || !tgt) return null;

            return (
              <g key={`edge_${idx}`}>
                <line
                  x1={src.x}
                  y1={src.y}
                  x2={tgt.x}
                  y2={tgt.y}
                  stroke="#475569"
                  strokeWidth="1.5"
                  strokeDasharray={edge.label === "findings" ? "4,4" : undefined}
                  markerEnd="url(#edge-arrow)"
                  opacity="0.5"
                />
                {edge.label && (
                  <text
                    x={(src.x + tgt.x) / 2}
                    y={(src.y + tgt.y) / 2 - 4}
                    fill="#64748b"
                    fontSize="9"
                    fontFamily="monospace"
                    textAnchor="middle"
                    className="select-none pointer-events-none"
                  >
                    {edge.label}
                  </text>
                )}
              </g>
            );
          })}

          {/* Nodes */}
          {activeNodes.map((node) => {
            const color = getNodeColor(node);
            const isSelected = selectedNode?.id === node.id;
            const isRoot = node.type === "case";
            const radius = isRoot ? 28 : 20;

            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                className="cursor-pointer transition-transform hover:scale-110"
                onMouseDown={(e) => {
                  e.stopPropagation();
                  setDraggedNodeId(node.id);
                }}
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedNode(node);
                  if (onSelectNode) {
                    onSelectNode(node.type, node.metadata?.ref_id || node.id);
                  }
                }}
              >
                {/* Node Ring Halo */}
                <circle
                  r={radius + (isSelected ? 8 : 4)}
                  fill={color}
                  fillOpacity={isSelected ? 0.25 : 0.1}
                  stroke={color}
                  strokeWidth={isSelected ? 2 : 1}
                  strokeDasharray={isSelected ? "3,3" : undefined}
                />

                {/* Node Core Circle */}
                <circle
                  r={radius}
                  fill="#0f172a"
                  stroke={color}
                  strokeWidth={isRoot ? 2.5 : 2}
                />

                {/* Center Icon Indicator */}
                <circle r={radius * 0.55} fill={color} fillOpacity="0.2" />

                {/* Label Text */}
                <text
                  y={radius + 14}
                  textAnchor="middle"
                  fill="#f8fafc"
                  fontSize={isRoot ? "12" : "11"}
                  fontWeight={isRoot ? "600" : "500"}
                  fontFamily="system-ui, sans-serif"
                  className="select-none pointer-events-none drop-shadow"
                >
                  {node.type === "case" ? node.label : `[${node.type.toUpperCase()}] ${node.label}`}
                </text>

                {node.sublabel && (
                  <text
                    y={radius + 25}
                    textAnchor="middle"
                    fill="#94a3b8"
                    fontSize="9"
                    fontFamily="monospace"
                    className="select-none pointer-events-none"
                  >
                    {node.sublabel}
                  </text>
                )}
              </g>
            );
          })}
        </g>
      </svg>

      {/* Selected Node Details Drawer */}
      {selectedNode && (
        <div className="absolute top-3 right-3 z-20 w-80 bg-panel/95 rounded-xl border border-border-subtle p-4 shadow-2xl backdrop-blur-xl animate-in fade-in duration-200">
          <div className="flex items-center justify-between pb-3 border-b border-border-subtle">
            <div className="flex items-center gap-2">
              <span
                className="w-2.5 h-2.5 rounded-full"
                style={{ backgroundColor: getNodeColor(selectedNode) }}
              />
              <span className="text-xs font-mono uppercase tracking-wider text-text-muted">
                {selectedNode.type} Details
              </span>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="p-1 rounded hover:bg-white/10 text-text-muted hover:text-text"
            >
              <Icon name="x" className="w-4 h-4" />
            </button>
          </div>

          <div className="mt-3 space-y-2.5 text-xs">
            <div>
              <span className="text-text-muted block text-[10px] uppercase font-mono">Entity Label</span>
              <span className="font-semibold text-text text-sm break-all">{selectedNode.label}</span>
            </div>

            {selectedNode.metadata && (
              <div className="bg-panel-muted/60 p-2.5 rounded-lg border border-border-subtle/50 space-y-1.5 font-mono text-[11px]">
                {Object.entries(selectedNode.metadata).map(([k, v]) => {
                  if (typeof v === "object" || v === undefined) return null;
                  return (
                    <div key={k} className="flex justify-between gap-2 overflow-hidden">
                      <span className="text-text-muted truncate">{k}:</span>
                      <span className="text-text truncate max-w-[150px]">{String(v)}</span>
                    </div>
                  );
                })}
              </div>
            )}

            <div className="pt-2 flex items-center gap-2">
              <Chip
                tone={
                  selectedNode.severity === "malicious"
                    ? "malicious"
                    : selectedNode.severity === "suspicious"
                    ? "suspicious"
                    : "muted"
                }
              >
                {selectedNode.severity || "info"}
              </Chip>
              <span className="text-[10px] text-text-muted font-mono">
                ID: {selectedNode.id}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
