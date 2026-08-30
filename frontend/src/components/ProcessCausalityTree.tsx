import { useEffect, useState } from "react";
import { Icon } from "./Icon";
import { getProcessTree, controlProcessXRay } from "../lib/api";

export interface ProcessNode {
  pid: number;
  ppid: number;
  name: string;
  cmdline: string;
  user: string;
  cpu_percent?: number;
  memory_mb?: number;
  children?: ProcessNode[];
  findings_count?: number;
  is_active?: boolean;
}

export function ProcessCausalityTree({
  nodes,
  onSelectPid,
  selectedPid,
}: {
  nodes?: ProcessNode[];
  onSelectPid?: (pid: number) => void;
  selectedPid?: number;
}) {
  const [tree, setTree] = useState<ProcessNode[]>(nodes || []);
  const [loading, setLoading] = useState(!nodes);
  const [search, setSearch] = useState("");
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  useEffect(() => {
    if (nodes) {
      setTree(nodes);
      setLoading(false);
    }
  }, [nodes]);

  const fetchTree = async () => {
    if (nodes) return;
    try {
      setLoading(true);
      const data = await getProcessTree();
      setTree(data);
    } catch (err) {
      console.error("Failed to load process causality tree", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!nodes) {
      fetchTree();
    }
  }, [nodes]);

  const handleAction = async (e: React.MouseEvent, pid: number, action: "terminate" | "kill") => {
    e.stopPropagation();
    try {
      setActionMsg(`Sending ${action.toUpperCase()} to PID ${pid}...`);
      const res = await controlProcessXRay(pid, action);
      setActionMsg(res.message);
      fetchTree();
    } catch (err: any) {
      setActionMsg(`Failed: ${err?.message || "Signal rejected"}`);
    }
  };

  const renderNode = (node: ProcessNode, depth = 0): React.ReactNode => {
    const isSelected = selectedPid === node.pid;
    const matchesSearch =
      !search ||
      node.name.toLowerCase().includes(search.toLowerCase()) ||
      String(node.pid).includes(search) ||
      (node.cmdline && node.cmdline.toLowerCase().includes(search.toLowerCase()));

    return (
      <div key={node.pid} className="space-y-1">
        {matchesSearch && (
          <div
            onClick={() => onSelectPid && onSelectPid(node.pid)}
            className={`group flex items-center justify-between rounded-lg border px-2.5 py-1.5 font-mono text-xs transition cursor-pointer ${
              isSelected
                ? "border-accent/70 bg-accent/15 shadow-[var(--glow-accent)] text-accent font-bold"
                : "border-border-subtle bg-bg-surface hover:border-border-strong hover:bg-bg-elevated/40 text-text-primary"
            }`}
            style={{ marginLeft: `${depth * 20}px` }}
          >
            <div className="flex items-center gap-2 min-w-0">
              <span className="text-text-faint">{depth > 0 ? "└──" : "•"}</span>
              <span className="rounded bg-bg-base border border-border-subtle px-1.5 py-0.2 text-[10px] text-text-faint">
                {node.pid}
              </span>
              <span className="font-semibold truncate">{node.name}</span>
              {node.user && (
                <span className="text-[10px] text-text-muted">({node.user})</span>
              )}
              {node.cmdline && node.cmdline !== node.name && (
                <span className="truncate text-[10px] text-text-faint max-w-xs">
                  {node.cmdline}
                </span>
              )}
            </div>

            <div className="flex items-center gap-2 shrink-0">
              {node.memory_mb !== undefined && node.memory_mb > 0 && (
                <span className="text-[10px] text-text-faint">{node.memory_mb.toFixed(1)} MB</span>
              )}
              {node.cpu_percent !== undefined && node.cpu_percent > 0 && (
                <span className="text-[10px] text-accent">{node.cpu_percent.toFixed(1)}% CPU</span>
              )}
              <div className="opacity-0 group-hover:opacity-100 flex items-center gap-1 transition">
                <button
                  onClick={(e) => handleAction(e, node.pid, "terminate")}
                  className="rounded px-1.5 py-0.5 text-[9px] bg-risk-suspicious/15 border border-risk-suspicious/40 text-risk-suspicious hover:bg-risk-suspicious/25"
                  title="SIGTERM"
                >
                  Term
                </button>
                <button
                  onClick={(e) => handleAction(e, node.pid, "kill")}
                  className="rounded px-1.5 py-0.5 text-[9px] bg-risk-malicious/15 border border-risk-malicious/40 text-risk-malicious hover:bg-risk-malicious/25"
                  title="SIGKILL"
                >
                  Kill
                </button>
              </div>
            </div>
          </div>
        )}
        {node.children && node.children.map((child) => renderNode(child, depth + 1))}
      </div>
    );
  };

  return (
    <div className="space-y-3 rounded-2xl border border-border-subtle bg-bg-surface/50 p-4">
      <div className="flex items-center justify-between gap-3 border-b border-border-subtle pb-3">
        <div className="flex items-center gap-2">
          <Icon name="process" size={16} className="text-accent" />
          <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-text-primary">
            Process Causality Lineage & Hierarchy
          </h3>
        </div>
        <div className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Filter process or PID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 font-mono text-xs text-text-primary placeholder:text-text-faint focus:border-accent focus:outline-none"
          />
          <button
            onClick={fetchTree}
            className="rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 text-xs text-text-muted hover:text-text-primary"
            title="Refresh process tree"
          >
            ↻
          </button>
        </div>
      </div>

      {actionMsg && (
        <div className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 font-mono text-[11px] text-accent">
          {actionMsg}
        </div>
      )}

      {loading ? (
        <div className="py-8 text-center font-mono text-xs text-text-faint animate-pulse">
          Tracing host process causality tree...
        </div>
      ) : tree.length === 0 ? (
        <div className="py-6 text-center font-mono text-xs text-text-faint">
          No running processes reported in this scope.
        </div>
      ) : (
        <div className="max-h-[480px] space-y-1.5 overflow-y-auto pr-1">
          {tree.map((root) => renderNode(root, 0))}
        </div>
      )}
    </div>
  );
}
