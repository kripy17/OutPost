// Process tree — the run-detail hero (docs/07): a branching root system where
// any node that touched flagged network infrastructure blooms with a
// risk-colored halo. Backend annotates each node with the worst reputation of
// the destinations it reached (flagged_reputation) and the IP list.

import { useState } from "react";
import { Icon } from "../Icon";
import { QuickAllowlist } from "../TriagePanels/TriagePanels";
import type { ProcessNode, Reputation } from "../../types";

// Default-expand to depth 2 so the initial view stays scannable (docs/07).
const DEFAULT_EXPAND_DEPTH = 2;

// Stable empty set for the default prop — a new Set per render would churn
// (and break referential-stability assumptions if anything memoized on it).
const EMPTY_RECON = new Set<number>();

// Halo colors — dot + left accent border + label, never color alone (docs/07:
// filled-dot-plus-label rule; color-blind analysts must not misread risk).
// All classes are literal so Tailwind v4 generates them.
const HALO: Record<string, { ring: string; text: string; dot: string; label: string }> = {
  malicious: {
    ring: "border-risk-malicious bg-risk-malicious/10",
    text: "text-risk-malicious",
    dot: "bg-risk-malicious",
    label: "malicious net",
  },
  suspicious: {
    ring: "border-risk-suspicious bg-risk-suspicious/10",
    text: "text-risk-suspicious",
    dot: "bg-risk-suspicious",
    label: "suspicious net",
  },
  unknown: {
    ring: "border-text-faint bg-bg-elevated/40",
    text: "text-text-muted",
    dot: "bg-bg-elevated",
    label: "uncharacterized net",
  },
};

// Only risk-bearing reputations count as flagged — clean is not a finding
// (docs/07: halo = risk). Mirrors the backend's annotate_process_tree.
const FLAGGED_RANKS = new Set(["malicious", "suspicious", "unknown"]);

function worstRep(node: ProcessNode): Reputation | null {
  return node.flagged_reputation ?? null;
}

function HaloBadge({ node }: { node: ProcessNode }) {
  const rep = worstRep(node);
  const halo = rep ? HALO[rep] : null;
  if (!halo || (node.network_ips?.length ?? 0) === 0) return null;
  const ips = node.network_ips ?? [];
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1 rounded-full border px-1.5 py-0.5 font-mono text-[9px] ${halo.ring} ${halo.text}`}
      title={`Reached ${ips.length} network destination(s): ${ips.join(", ")}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${halo.dot}`} aria-hidden />
      {halo.label} · {ips.length}
      {rep === "malicious" && <span className="animate-outpost-pulse" aria-hidden>●</span>}
    </span>
  );
}

// Recon highlight — the live Monitor's recon-sweep affordance: when
// enumeration-burst fires, the backend tags the alert with the pids of the
// enumerating processes; the Monitor passes them here and each matching node
// gets a dashed amber "recon" ring + radar dot, distinct from the risk halo.
function ReconBadge() {
  return (
    <span
      className="inline-flex shrink-0 items-center gap-1 rounded-full border border-dashed border-risk-suspicious/70 px-1.5 py-0.5 font-mono text-[9px] text-risk-suspicious"
      title="Performed discovery enumeration (recon sweep)"
    >
      <span className="relative flex h-1.5 w-1.5">
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-risk-suspicious/60" aria-hidden />
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-risk-suspicious" aria-hidden />
      </span>
      recon
    </span>
  );
}

function TreeNode({
  node,
  depth,
  reconPids,
  highlightPid,
  selectedPid,
  onSelect,
  allowlistForRun,
}: {
  node: ProcessNode;
  depth: number;
  reconPids: Set<number>;
  highlightPid?: number | null;
  /** Selected process — the run detail filters its network + timeline to it. */
  selectedPid?: number | null;
  /** Called when the row is clicked (the spec's highest-value interaction:
   *  "what did THIS process do"). The chevron still toggles expansion only. */
  onSelect?: (pid: number) => void;
  /** When set (run detail), each node gets a two-click allowlist quick-add
   *  so a process can be whitelisted for the run without opening the panel. */
  allowlistForRun?: string;
}) {
  const [expanded, setExpanded] = useState(depth < DEFAULT_EXPAND_DEPTH || node.children.length === 0);
  const hasChildren = node.children.length > 0;
  const toggle = () => setExpanded((v) => !v);
  const rep = worstRep(node);
  // Defensive: a stale "clean" value must never crash the row (no halo entry).
  const accent = rep ? (HALO[rep]?.text ?? "") : "";
  const isRecon = node.pid !== undefined && reconPids.has(node.pid);
  // One-shot attention flash — the run-detail recon-actors list jumps here.
  // The parent clears the pid after the animation, so it re-arms on the next.
  // The flash composes with the recon state so an enumerating process keeps
  // its amber ring while the accent ring rings around it.
  const isHighlighted = highlightPid !== null && highlightPid !== undefined && node.pid === highlightPid;
  const isSelected = selectedPid !== null && selectedPid !== undefined && node.pid === selectedPid;

  return (
    <div className="select-none">
      <div
        data-pid={node.pid}
        role={onSelect ? "button" : undefined}
        tabIndex={onSelect ? 0 : undefined}
        onClick={onSelect && node.pid !== undefined ? () => onSelect(node.pid as number) : undefined}
        onKeyDown={
          onSelect && node.pid !== undefined
            ? (e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onSelect(node.pid as number);
                }
              }
            : undefined
        }
        title={onSelect ? "Click to filter this run's network + timeline to this process" : undefined}
        className={`group flex items-baseline gap-2 rounded border-l-2 px-1 py-0.5 transition-colors duration-150 ${
          isHighlighted
            ? "animate-node-flash border-accent bg-accent/10 pl-2"
            : isSelected
              ? "border-accent bg-accent/10 pl-2 ring-1 ring-inset ring-accent/50"
              : rep && HALO[rep]
                ? `${HALO[rep].ring} pl-2`
                : isRecon
                  ? "border-risk-suspicious/70 bg-risk-suspicious/[0.06] pl-2"
                  : "border-transparent pl-3 hover:bg-bg-elevated"
        } ${(isHighlighted || isSelected) && isRecon ? "ring-1 ring-inset ring-risk-suspicious/70" : ""} ${onSelect ? "cursor-pointer" : ""}`}
      >
        {hasChildren ? (
          <button
            onClick={(e) => {
              e.stopPropagation();
              toggle();
            }}
            aria-expanded={expanded}
            className="flex w-4 shrink-0 items-center justify-center text-[11px] text-text-muted transition-transform duration-150 hover:text-accent"
          >
            <Icon name={expanded ? "chevronDown" : "chevronRight"} size={13} />
          </button>
        ) : (
          <span className="w-4 shrink-0 text-center text-[10px] text-text-faint">·</span>
        )}
        <span className={`font-mono text-sm text-text-primary ${rep ? accent : ""}`}>{node.process_name}</span>
        {node.pid !== undefined && (
          <span className="font-mono text-xs text-text-faint">[{node.pid}]</span>
        )}
        {isRecon && <ReconBadge />}
        <HaloBadge node={node} />
        {node.command_line && (
          <span className="truncate font-mono text-xs text-text-muted" title={node.command_line}>
            {node.command_line}
          </span>
        )}
        {allowlistForRun && node.process_name && (
          <span className="ml-auto pl-1">
            <QuickAllowlist runId={allowlistForRun} kind="process" value={node.process_name} />
          </span>
        )}
      </div>
      {expanded && hasChildren && (
        <div className="ml-3 border-l border-border-subtle pl-3">
          {node.children.map((child) => (
            <TreeNode
              key={child.pid}
              node={child}
              depth={depth + 1}
              reconPids={reconPids}
              highlightPid={highlightPid}
              selectedPid={selectedPid}
              onSelect={onSelect}
              allowlistForRun={allowlistForRun}
            />
          ))}
        </div>
      )}
    </div>
  );
}

/** Count how many visible tree nodes match the recon pids. */
function countRecon(ns: ProcessNode[], reconPids: Set<number>): number {
  return ns.reduce(
    (n, x) => n + (x.pid !== undefined && reconPids.has(x.pid) ? 1 : 0) + countRecon(x.children, reconPids),
    0,
  );
}

export default function ProcessTree({
  roots,
  reconPids = EMPTY_RECON,
  highlightPid = null,
  selectedPid = null,
  onSelect,
  allowlistForRun,
}: {
  roots: ProcessNode[];
  reconPids?: Set<number>;
  /** Scroll target for the run-detail recon-actors list (brief flash ring). */
  highlightPid?: number | null;
  /** Selected process — the run detail filters its network + timeline to it. */
  selectedPid?: number | null;
  /** Click-to-filter: the run detail narrows network + timeline to this pid. */
  onSelect?: (pid: number) => void;
  /** Run id for the two-click allowlist quick-add on each node. */
  allowlistForRun?: string;
}) {
  if (roots.length === 0) {
    return <p className="text-sm text-text-muted">No process activity recorded for this run.</p>;
  }

  const total = (ns: ProcessNode[]): number => ns.reduce((n, x) => n + 1 + total(x.children), 0);
  const flagged = (ns: ProcessNode[]): number =>
    ns.reduce(
      (n, x) => n + (FLAGGED_RANKS.has(x.flagged_reputation ?? "") ? 1 : 0) + flagged(x.children),
      0,
    );
  const reconCount = countRecon(roots, reconPids);

  return (
    <div className="font-mono text-sm">
      <div className="mb-2 flex flex-wrap items-baseline gap-x-3 gap-y-1 font-mono text-[10px] text-text-faint">
        <span>
          {total(roots)} process{total(roots) === 1 ? "" : "es"}
        </span>
        {reconCount > 0 && (
          <span className="text-risk-suspicious">
            {reconCount} recon — enumeration sweep (T1082)
          </span>
        )}
        {flagged(roots) > 0 && (
          <span className="text-risk-malicious">
            {flagged(roots)} flagged — reached uncharacterized or known-bad infrastructure
          </span>
        )}
      </div>
      {roots.map((root) => (
        <TreeNode
          key={root.pid}
          node={root}
          depth={0}
          reconPids={reconPids}
          highlightPid={highlightPid}
          selectedPid={selectedPid}
          onSelect={onSelect}
          allowlistForRun={allowlistForRun}
        />
      ))}
    </div>
  );
}
