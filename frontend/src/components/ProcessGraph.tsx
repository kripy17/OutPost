import { useState, useMemo, useRef } from "react";
import { Icon } from "./Icon";
import { copyToClipboard } from "../lib/clipboard";
import type { ProcessNode, Alert, EventOut } from "../types";

interface GraphNode {
  node: ProcessNode;
  id: string;
  pid: number;
  ppid: number | null;
  name: string;
  cmdline: string;
  reputation?: string | null;
  ips: string[];
  level: number;
  x: number;
  y: number;
  width: number;
  height: number;
  childIds: string[];
}

interface GraphLink {
  source: GraphNode;
  target: GraphNode;
}

interface ProcessGraphProps {
  nodes: ProcessNode[];
  selectedPid?: number | null;
  onSelectPid?: (pid: number | null) => void;
  alerts?: Alert[];
  events?: EventOut[];
}

const NODE_WIDTH = 240;
const NODE_HEIGHT = 80;
const HORIZONTAL_GAP = 100;
const VERTICAL_GAP = 30;

export function ProcessGraph({
  nodes,
  selectedPid,
  onSelectPid,
  alerts = [],
  events = [],
}: ProcessGraphProps) {
  const [zoom, setZoom] = useState(1);
  const [copied, setCopied] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  // Flatten and calculate 2D hierarchical coordinates
  const { graphNodes, links, totalWidth, totalHeight } = useMemo(() => {
    const list: GraphNode[] = [];
    const linksList: GraphLink[] = [];

    let globalY = 20;

    function layoutSubtree(node: ProcessNode, level: number, ppid: number | null): GraphNode {
      const id = `node-${node.pid}`;
      const childGraphNodes: GraphNode[] = [];

      for (const child of node.children || []) {
        const childGNode = layoutSubtree(child, level + 1, node.pid);
        childGraphNodes.push(childGNode);
      }

      let yPos: number;
      if (childGraphNodes.length === 0) {
        yPos = globalY;
        globalY += NODE_HEIGHT + VERTICAL_GAP;
      } else if (childGraphNodes.length === 1) {
        yPos = childGraphNodes[0].y;
      } else {
        const first = childGraphNodes[0].y;
        const last = childGraphNodes[childGraphNodes.length - 1].y;
        yPos = (first + last) / 2;
      }

      const gNode: GraphNode = {
        node,
        id,
        pid: node.pid,
        ppid: ppid,
        name: node.process_name,
        cmdline: node.command_line || "",
        reputation: node.flagged_reputation,
        ips: node.network_ips || [],
        level,
        x: 40 + level * (NODE_WIDTH + HORIZONTAL_GAP),
        y: yPos,
        width: NODE_WIDTH,
        height: NODE_HEIGHT,
        childIds: childGraphNodes.map((c) => c.id),
      };

      list.push(gNode);

      for (const c of childGraphNodes) {
        linksList.push({ source: gNode, target: c });
      }

      return gNode;
    }

    for (const root of nodes) {
      layoutSubtree(root, 0, root.ppid);
      globalY += 20;
    }

    const maxLevel = Math.max(0, ...list.map((n) => n.level));
    const maxY = Math.max(400, ...list.map((n) => n.y + NODE_HEIGHT + 40));
    const calcWidth = Math.max(800, (maxLevel + 1) * (NODE_WIDTH + HORIZONTAL_GAP) + 100);

    return {
      graphNodes: list,
      links: linksList,
      totalWidth: calcWidth,
      totalHeight: maxY,
    };
  }, [nodes]);

  const activeNode = useMemo(() => {
    if (!selectedPid) return null;
    return graphNodes.find((n) => n.pid === selectedPid) || null;
  }, [selectedPid, graphNodes]);

  const nodeAlerts = useMemo(() => {
    if (!activeNode) return [];
    return alerts.filter(
      (a) => a.related_pid === activeNode.pid || (a.related_pids && a.related_pids.includes(activeNode.pid))
    );
  }, [activeNode, alerts]);

  const nodeEventsCount = useMemo(() => {
    if (!activeNode) return 0;
    return events.filter((e) => e.pid === activeNode.pid).length;
  }, [activeNode, events]);

  return (
    <div className="relative flex flex-col overflow-hidden rounded-2xl border border-border-subtle bg-bg-inset">
      {/* Top Toolbar */}
      <div className="flex flex-wrap items-center justify-between border-b border-border-subtle bg-bg-surface/80 px-4 py-2.5 backdrop-blur-md">
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs font-semibold text-text-primary">
            Process Ancestry Graph
          </span>
          <span className="rounded-full bg-bg-elevated px-2 py-0.5 font-mono text-[10px] text-text-muted">
            {graphNodes.length} nodes · {links.length} relationships
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setZoom((z) => Math.max(0.6, z - 0.15))}
            className="press rounded-lg border border-border-subtle bg-bg-elevated/60 px-2 py-1 font-mono text-xs text-text-muted hover:border-accent/50 hover:text-text-primary"
            title="Zoom out"
          >
            -
          </button>
          <span className="font-mono text-[11px] text-text-faint">{Math.round(zoom * 100)}%</span>
          <button
            onClick={() => setZoom((z) => Math.min(1.6, z + 0.15))}
            className="press rounded-lg border border-border-subtle bg-bg-elevated/60 px-2 py-1 font-mono text-xs text-text-muted hover:border-accent/50 hover:text-text-primary"
            title="Zoom in"
          >
            +
          </button>
          <button
            onClick={() => setZoom(1)}
            className="press ml-1 rounded-lg border border-border-subtle bg-bg-elevated/60 px-2.5 py-1 font-mono text-[11px] text-text-muted hover:border-accent/50 hover:text-accent"
          >
            Reset
          </button>
        </div>
      </div>

      {/* Main Canvas + Inspector Split View */}
      <div className="flex flex-1 overflow-hidden" style={{ minHeight: "480px" }}>
        {/* Graph Canvas */}
        <div
          ref={containerRef}
          className="relative flex-1 overflow-auto p-4 selection:bg-accent/30"
          style={{
            backgroundImage:
              "radial-gradient(circle at 1px 1px, rgba(255,255,255,0.05) 1px, transparent 0)",
            backgroundSize: "24px 24px",
          }}
        >
          {graphNodes.length === 0 ? (
            <div className="flex h-full min-h-[300px] items-center justify-center font-mono text-xs text-text-faint">
              No process activity captured in this run.
            </div>
          ) : (
            <div
              style={{
                width: `${totalWidth}px`,
                height: `${totalHeight}px`,
                transform: `scale(${zoom})`,
                transformOrigin: "0 0",
                transition: "transform 150ms ease-out",
              }}
              className="relative"
            >
              {/* SVG Connecting Links */}
              <svg
                className="pointer-events-none absolute inset-0 h-full w-full"
                style={{ overflow: "visible" }}
              >
                <defs>
                  <linearGradient id="link-grad" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stopColor="#d9a441" stopOpacity="0.6" />
                    <stop offset="100%" stopColor="#4fd1c5" stopOpacity="0.8" />
                  </linearGradient>
                </defs>
                {links.map((l, i) => {
                  const x1 = l.source.x + l.source.width;
                  const y1 = l.source.y + l.source.height / 2;
                  const x2 = l.target.x;
                  const y2 = l.target.y + l.target.height / 2;
                  const dx = (x2 - x1) / 2;
                  const path = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;

                  return (
                    <g key={`link-${i}`}>
                      <path
                        d={path}
                        fill="none"
                        stroke="rgba(255,255,255,0.12)"
                        strokeWidth="2"
                      />
                      <path
                        d={path}
                        fill="none"
                        stroke="url(#link-grad)"
                        strokeWidth="2"
                        strokeDasharray="6 4"
                        className="animate-pulse"
                      />
                    </g>
                  );
                })}
              </svg>

              {/* Interactive Node Cards */}
              {graphNodes.map((gn) => {
                const isSelected = selectedPid === gn.pid;
                const isMalicious = gn.reputation === "malicious";
                const isSuspicious = gn.reputation === "suspicious";

                const borderCls = isSelected
                  ? "border-accent ring-2 ring-accent/50 shadow-[var(--glow-accent)] bg-bg-elevated"
                  : isMalicious
                    ? "border-risk-malicious/60 bg-risk-malicious/10 hover:border-risk-malicious shadow-[var(--glow-malicious)]"
                    : isSuspicious
                      ? "border-risk-suspicious/60 bg-risk-suspicious/10 hover:border-risk-suspicious shadow-[var(--glow-amber)]"
                      : "border-border-subtle bg-bg-surface/90 hover:border-border-strong hover:bg-bg-elevated";

                return (
                  <div
                    key={gn.id}
                    onClick={() => onSelectPid?.(isSelected ? null : gn.pid)}
                    style={{
                      position: "absolute",
                      left: `${gn.x}px`,
                      top: `${gn.y}px`,
                      width: `${gn.width}px`,
                      height: `${gn.height}px`,
                    }}
                    className={`press group cursor-pointer overflow-hidden rounded-xl border p-2.5 backdrop-blur-md transition-all duration-150 ${borderCls}`}
                  >
                    <div className="flex items-center justify-between gap-1.5">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-bg-elevated text-text-muted">
                          <Icon name="terminal" size={11} />
                        </span>
                        <span className="truncate font-mono text-xs font-semibold text-text-primary group-hover:text-accent">
                          {gn.name}
                        </span>
                      </div>
                      <span className="shrink-0 rounded bg-bg-elevated px-1.5 py-0.5 font-mono text-[9px] text-text-muted">
                        PID {gn.pid}
                      </span>
                    </div>

                    <p className="mt-1.5 truncate font-mono text-[10px] text-text-muted">
                      {gn.cmdline || "—"}
                    </p>

                    <div className="mt-1.5 flex items-center gap-1.5">
                      {gn.ips.length > 0 && (
                        <span
                          className={`inline-flex items-center gap-1 rounded-full px-1.5 py-px font-mono text-[9px] ${
                            isMalicious
                              ? "bg-risk-malicious/20 text-risk-malicious"
                              : isSuspicious
                                ? "bg-risk-suspicious/20 text-risk-suspicious"
                                : "bg-signal/20 text-signal"
                          }`}
                        >
                          <span className="h-1 w-1 rounded-full bg-current" />
                          {gn.ips.length} net
                        </span>
                      )}
                      {gn.childIds.length > 0 && (
                        <span className="rounded bg-bg-elevated px-1.5 py-px font-mono text-[9px] text-text-faint">
                          {gn.childIds.length} children
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Selected Node Inspector Drawer */}
        {activeNode && (
          <div className="w-80 border-l border-border-subtle bg-bg-surface p-4 overflow-y-auto">
            <div className="flex items-center justify-between border-b border-border-subtle pb-3">
              <div className="flex items-center gap-2">
                <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-accent/20 text-accent">
                  <Icon name="terminal" size={14} />
                </span>
                <div>
                  <h3 className="font-mono text-xs font-bold text-text-primary">{activeNode.name}</h3>
                  <p className="font-mono text-[10px] text-text-muted">PID {activeNode.pid} · Parent {activeNode.ppid ?? "—"}</p>
                </div>
              </div>
              <button
                onClick={() => onSelectPid?.(null)}
                className="rounded p-1 text-text-faint hover:text-text-primary"
              >
                <Icon name="x" size={13} />
              </button>
            </div>

            <div className="mt-4 space-y-4 font-mono text-xs">
              {/* Command Line */}
              <div>
                <span className="text-[10px] uppercase tracking-wider text-text-faint">Command Line</span>
                <div className="mt-1 rounded-lg border border-border-subtle bg-bg-inset p-2">
                  <p className="break-all font-mono text-[11px] text-text-primary">
                    {activeNode.cmdline || "No arguments recorded"}
                  </p>
                  {activeNode.cmdline && (
                    <button
                      onClick={() => {
                        void copyToClipboard(activeNode.cmdline);
                        setCopied(true);
                        setTimeout(() => setCopied(false), 2000);
                      }}
                      className="mt-2 inline-flex items-center gap-1 text-[10px] text-accent hover:underline"
                    >
                      <Icon name={copied ? "check" : "copy"} size={10} />
                      {copied ? "Copied" : "Copy command line"}
                    </button>
                  )}
                </div>
              </div>

              {/* Detections Triggered */}
              <div>
                <span className="text-[10px] uppercase tracking-wider text-text-faint">
                  Detections Triggered ({nodeAlerts.length})
                </span>
                {nodeAlerts.length === 0 ? (
                  <p className="mt-1 font-mono text-[11px] text-text-muted">No heuristics fired on this PID.</p>
                ) : (
                  <div className="mt-1 space-y-1.5">
                    {nodeAlerts.map((a, i) => (
                      <div
                        key={i}
                        className="rounded-lg border border-risk-malicious/40 bg-risk-malicious/10 p-2 text-[11px] text-risk-malicious"
                      >
                        <p className="font-bold">{a.rule_name || a.rule_id}</p>
                        {a.details && <p className="mt-0.5 text-[10px] text-text-muted">{a.details}</p>}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Sockets */}
              <div>
                <span className="text-[10px] uppercase tracking-wider text-text-faint">
                  Network Sockets ({activeNode.ips.length})
                </span>
                {activeNode.ips.length === 0 ? (
                  <p className="mt-1 font-mono text-[11px] text-text-muted">No network sockets opened.</p>
                ) : (
                  <div className="mt-1 space-y-1">
                    {activeNode.ips.map((ip, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between rounded border border-border-subtle bg-bg-inset px-2 py-1 text-[11px]"
                      >
                        <span className="text-text-primary">{ip}</span>
                        <span className="text-text-faint">outbound</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Total Events count */}
              <div>
                <span className="text-[10px] uppercase tracking-wider text-text-faint">
                  Telemetry Events ({nodeEventsCount})
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
