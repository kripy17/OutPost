// Process tree — the run-detail hero (docs/07): a branching root system where
// any node that touched flagged network infrastructure blooms with a
// risk-colored halo. Backend annotates each node with the worst reputation of
// the destinations it reached (flagged_reputation) and the IP list.

import { useState } from "react";
import type { ProcessNode, Reputation } from "../../types";

// Default-expand to depth 2 so the initial view stays scannable (docs/07).
const DEFAULT_EXPAND_DEPTH = 2;

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

function TreeNode({ node, depth }: { node: ProcessNode; depth: number }) {
  const [expanded, setExpanded] = useState(depth < DEFAULT_EXPAND_DEPTH || node.children.length === 0);
  const hasChildren = node.children.length > 0;
  const toggle = () => setExpanded((v) => !v);
  const rep = worstRep(node);
  // Defensive: a stale "clean" value must never crash the row (no halo entry).
  const accent = rep ? (HALO[rep]?.text ?? "") : "";

  return (
    <div className="select-none">
      <div
        className={`group flex items-baseline gap-2 rounded border-l-2 px-1 py-0.5 transition-colors duration-150 ${
          rep && HALO[rep] ? `${HALO[rep].ring} pl-2` : "border-transparent pl-3 hover:bg-bg-elevated"
        }`}
      >
        {hasChildren ? (
          <button
            onClick={toggle}
            aria-expanded={expanded}
            className="w-4 shrink-0 text-left text-xs text-text-muted transition-transform duration-150 hover:text-accent-amber"
          >
            {expanded ? "▾" : "▸"}
          </button>
        ) : (
          <span className="w-4 shrink-0 text-xs text-text-faint">·</span>
        )}
        <span className={`font-mono text-sm text-text-primary ${rep ? accent : ""}`}>{node.process_name}</span>
        {node.pid !== undefined && (
          <span className="font-mono text-xs text-text-faint">[{node.pid}]</span>
        )}
        <HaloBadge node={node} />
        {node.command_line && (
          <span className="truncate font-mono text-xs text-text-muted" title={node.command_line}>
            {node.command_line}
          </span>
        )}
      </div>
      {expanded && hasChildren && (
        <div className="ml-3 border-l border-border-subtle pl-3">
          {node.children.map((child) => (
            <TreeNode key={child.pid} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

export default function ProcessTree({ roots }: { roots: ProcessNode[] }) {
  if (roots.length === 0) {
    return <p className="text-sm text-text-muted">No process activity recorded for this run.</p>;
  }

  const total = (ns: ProcessNode[]): number => ns.reduce((n, x) => n + 1 + total(x.children), 0);
  const flagged = (ns: ProcessNode[]): number =>
    ns.reduce(
      (n, x) => n + (FLAGGED_RANKS.has(x.flagged_reputation ?? "") ? 1 : 0) + flagged(x.children),
      0,
    );

  return (
    <div className="font-mono text-sm">
      <div className="mb-2 flex items-baseline gap-3 font-mono text-[10px] text-text-faint">
        <span>
          {total(roots)} process{total(roots) === 1 ? "" : "es"}
        </span>
        {flagged(roots) > 0 && (
          <span className="text-risk-malicious">
            {flagged(roots)} flagged — reached uncharacterized or known-bad infrastructure
          </span>
        )}
      </div>
      {roots.map((root) => (
        <TreeNode key={root.pid} node={root} depth={0} />
      ))}
    </div>
  );
}
