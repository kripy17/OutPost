import { useState } from "react";
import { Icon } from "./Icon";

export interface TreeNode {
  pid: number;
  ppid: number;
  name: string;
  cmdline: string;
  exe: string;
  user: string;
  status: string;
  cpu_percent: number;
  memory_mb: number;
  threads: number;
  started_at: string;
  package_status?: string;
  package_label?: string;
  children: TreeNode[];
}

interface ProcessTreeNodeProps {
  node: TreeNode;
  onInspect: (pid: number) => void;
  level?: number;
  searchFilter?: string;
}

export function ProcessTreeNodeItem({
  node,
  onInspect,
  level = 0,
  searchFilter = "",
}: ProcessTreeNodeProps) {
  const [expanded, setExpanded] = useState<boolean>(true);
  const hasChildren = node.children && node.children.length > 0;

  const matchesSelf = !searchFilter || (
    String(node.pid).includes(searchFilter.toLowerCase()) ||
    node.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
    node.cmdline.toLowerCase().includes(searchFilter.toLowerCase()) ||
    node.user.toLowerCase().includes(searchFilter.toLowerCase())
  );

  const hasMatchingDescendant = (n: TreeNode): boolean => {
    if (!searchFilter) return true;
    if (
      String(n.pid).includes(searchFilter.toLowerCase()) ||
      n.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
      n.cmdline.toLowerCase().includes(searchFilter.toLowerCase()) ||
      n.user.toLowerCase().includes(searchFilter.toLowerCase())
    ) return true;
    return n.children.some(hasMatchingDescendant);
  };

  if (searchFilter && !matchesSelf && !hasMatchingDescendant(node)) {
    return null;
  }

  const isSuspicious = node.package_status === "unmanaged_suspicious";

  return (
    <div className="font-mono text-xs select-none">
      <div
        className={`group flex items-center justify-between rounded-xl border p-2.5 transition-all duration-150 ${
          isSuspicious
            ? "border-risk-malicious/50 bg-risk-malicious/10 hover:bg-risk-malicious/15"
            : matchesSelf && searchFilter
            ? "border-accent/60 bg-accent/15"
            : "border-border-subtle bg-bg-surface hover:border-border-strong hover:bg-bg-elevated/40"
        }`}
        style={{ marginLeft: `${level * 22}px` }}
      >
        <div className="flex items-center gap-2.5 min-w-0">
          {hasChildren ? (
            <button
              onClick={() => setExpanded(!expanded)}
              className="flex h-5 w-5 items-center justify-center rounded border border-border-subtle bg-bg-base text-text-muted hover:border-accent/60 hover:text-accent"
              aria-label={expanded ? "Collapse subtree" : "Expand subtree"}
            >
              <span className="text-[10px]">{expanded ? "▼" : "▶"}</span>
            </button>
          ) : (
            <div className="h-5 w-5 flex items-center justify-center text-text-faint">
              <span className="text-[9px]">●</span>
            </div>
          )}

          <div className="flex h-6 w-6 items-center justify-center rounded-lg bg-bg-base text-text-muted">
            <Icon name="process" size={13} className={isSuspicious ? "text-risk-malicious" : "text-accent"} />
          </div>

          <div className="flex items-center gap-2 min-w-0">
            <span className="font-bold text-text-primary truncate max-w-[160px]">{node.name}</span>
            <span className="rounded bg-bg-base px-1.5 py-0.5 text-[10px] font-semibold text-accent">
              PID {node.pid}
            </span>
            <span className="text-[10px] text-text-faint">{node.user}</span>

            {node.package_label && (
              <span className={`rounded px-1.5 py-0.5 text-[9px] truncate max-w-[140px] ${
                isSuspicious
                  ? "bg-risk-malicious/20 text-risk-malicious font-bold border border-risk-malicious/40"
                  : "bg-accent/10 text-accent"
              }`}>
                {node.package_label}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <span className="text-[10px] text-text-muted">
            {node.cpu_percent}% · {node.memory_mb} MB
          </span>
          <button
            onClick={() => onInspect(node.pid)}
            className="press rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-[10px] font-semibold text-text-muted hover:border-accent/60 hover:text-accent"
          >
            Inspect
          </button>
        </div>
      </div>

      {hasChildren && expanded && (
        <div className="mt-1.5 space-y-1.5 border-l border-border-subtle/50 ml-3 pl-1">
          {node.children.map((child) => (
            <ProcessTreeNodeItem
              key={child.pid}
              node={child}
              onInspect={onInspect}
              level={level + 1}
              searchFilter={searchFilter}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export function ProcessTreeGraph({
  tree,
  onInspect,
}: {
  tree: TreeNode[];
  onInspect: (pid: number) => void;
}) {
  const [filter, setFilter] = useState("");

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4 rounded-xl border border-border-subtle bg-bg-surface p-3 font-mono text-xs">
        <div className="relative flex-1">
          <Icon name="search" size={13} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-faint" />
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Search process hierarchy tree by PID, name, or user..."
            className="w-full rounded-lg border border-border-subtle bg-bg-base py-2 pl-9 pr-3 text-xs text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
          />
        </div>
        <span className="text-[11px] text-text-faint shrink-0">
          {tree.length} Root Lineages
        </span>
      </div>

      <div className="max-h-[600px] overflow-y-auto rounded-2xl border border-border-subtle bg-bg-surface/50 p-4 space-y-2">
        {tree.length > 0 ? (
          tree.map((root) => (
            <ProcessTreeNodeItem
              key={root.pid}
              node={root}
              onInspect={onInspect}
              searchFilter={filter}
            />
          ))
        ) : (
          <p className="py-12 text-center font-mono text-xs text-text-faint">
            No process hierarchy tree available.
          </p>
        )}
      </div>
    </div>
  );
}

export default ProcessTreeGraph;
