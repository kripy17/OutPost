import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { getProcessSummary } from "../lib/api";
import { Icon } from "./Icon";
import { platformIconName } from "./iconMeta";
import { DataProvenanceBadge } from "./DataProvenanceBadge";

export function ProcessContextModal({
  pid,
  onClose,
}: {
  pid: number;
  onClose: () => void;
}) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["events", "process-summary", pid],
    queryFn: () => getProcessSummary(pid),
    staleTime: 30_000,
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div
        className="flex max-h-[90vh] w-full max-w-3xl flex-col overflow-hidden rounded-2xl border border-border-subtle bg-bg-surface shadow-[var(--shadow-raised)]"
        role="dialog"
        aria-modal="true"
        aria-labelledby="process-modal-title"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border-subtle bg-bg-elevated/40 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-accent/30 bg-accent/10 text-accent">
              <Icon name="process" size={18} />
            </div>
            <div>
              <h2 id="process-modal-title" className="font-mono text-sm font-bold text-text-primary">
                {data?.process_name ?? `Process PID ${pid}`}
              </h2>
              <div className="flex items-center gap-2 font-mono text-[11px] text-text-faint">
                <span>PID {pid}</span>
                {data?.ppid && <span>· Parent PPID {data.ppid}</span>}
                {data?.host_id && <span>· Host {data.host_id}</span>}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <DataProvenanceBadge source="live" />
            <button
              onClick={onClose}
              className="press rounded-lg p-1.5 text-text-faint hover:bg-bg-elevated hover:text-text-primary"
              aria-label="Close process context modal"
            >
              <Icon name="x" size={16} />
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {isLoading && (
            <div className="space-y-4">
              <div className="skeleton h-12 w-full" />
              <div className="skeleton h-32 w-full" />
              <div className="skeleton h-24 w-full" />
            </div>
          )}

          {isError && (
            <div className="rounded-xl border border-risk-malicious/40 bg-risk-malicious/10 p-4 text-xs font-mono text-risk-malicious">
              Failed to load process context for PID {pid}. The process may have terminated without recorded events.
            </div>
          )}

          {data && (
            <>
              {/* Identity Panel */}
              <div className="rounded-xl border border-border-subtle bg-bg-base/40 p-4 font-mono text-xs space-y-2.5">
                <div className="flex gap-4">
                  <span className="w-28 shrink-0 text-text-faint">Command line</span>
                  <span className="min-w-0 break-words font-semibold text-text-primary">
                    {data.command_line || "—"}
                  </span>
                </div>
                <div className="flex gap-4">
                  <span className="w-28 shrink-0 text-text-faint">Platform</span>
                  <span className="inline-flex items-center gap-1.5 text-text-muted">
                    <Icon name={platformIconName(data.platform)} size={12} />
                    {data.platform}
                  </span>
                </div>
                <div className="flex gap-4">
                  <span className="w-28 shrink-0 text-text-faint">Total Events</span>
                  <span className="text-text-primary">{data.event_count} events recorded</span>
                </div>
                <div className="flex gap-4">
                  <span className="w-28 shrink-0 text-text-faint">Associated Run</span>
                  <Link
                    to={`/runs/${data.run_id}`}
                    onClick={onClose}
                    className="inline-flex items-center gap-1 text-accent hover:underline"
                  >
                    {data.sample_name || data.run_id}
                    <Icon name="external" size={10} className="opacity-60" />
                  </Link>
                </div>
              </div>

              {/* Linked Findings */}
              <div className="space-y-2">
                <h3 className="kicker flex items-center gap-1.5 text-text-primary">
                  <Icon name="alert" size={12} className="text-risk-suspicious" />
                  Detections & Findings ({data.findings?.length ?? data.alert_count ?? 0})
                </h3>
                {data.findings && data.findings.length > 0 ? (
                  <ul className="space-y-1.5">
                    {data.findings.map((f, i) => (
                      <li
                        key={i}
                        className="flex items-center justify-between rounded-lg border border-border-subtle bg-bg-surface p-3 font-mono text-xs"
                      >
                        <div>
                          <span className="font-bold text-text-primary">{f.rule_name}</span>
                          <span className="ml-2 text-[10px] text-text-faint">({f.rule_id})</span>
                          <p className="mt-0.5 text-[11px] text-text-muted">{f.details}</p>
                        </div>
                        <span
                          className={`rounded px-2 py-0.5 text-[10px] font-semibold uppercase ${
                            f.severity === "malicious"
                              ? "border border-risk-malicious/40 bg-risk-malicious/10 text-risk-malicious"
                              : "border border-risk-suspicious/40 bg-risk-suspicious/10 text-risk-suspicious"
                          }`}
                        >
                          {f.severity}
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="rounded-lg border border-border-subtle bg-bg-elevated/20 p-3 font-mono text-xs text-text-faint">
                    No detections or suspicious heuristics flagged for this process.
                  </p>
                )}
              </div>

              {/* Spawned Children Lineage */}
              <div className="space-y-2">
                <h3 className="kicker flex items-center gap-1.5 text-text-primary">
                  <Icon name="process" size={12} className="text-accent" />
                  Child Processes ({data.children?.length ?? 0})
                </h3>
                {data.children && data.children.length > 0 ? (
                  <ul className="space-y-1.5">
                    {data.children.map((c) => (
                      <li
                        key={c.pid}
                        className="flex items-center justify-between rounded-lg border border-border-subtle bg-bg-surface p-2.5 font-mono text-xs"
                      >
                        <div className="min-w-0">
                          <span className="font-semibold text-text-primary">{c.process_name || `PID ${c.pid}`}</span>
                          <span className="ml-2 text-text-faint">PID {c.pid}</span>
                          {c.command_line && (
                            <p className="truncate text-[10px] text-text-muted" title={c.command_line}>
                              {c.command_line}
                            </p>
                          )}
                        </div>
                        <Link
                          to={`/events?pid=${c.pid}`}
                          onClick={onClose}
                          className="press ml-3 inline-flex shrink-0 items-center gap-1 rounded border border-border-subtle px-2 py-1 text-[10px] text-accent hover:border-accent/60"
                        >
                          Trace PID
                          <Icon name="arrowRight" size={10} />
                        </Link>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="rounded-lg border border-border-subtle bg-bg-elevated/20 p-3 font-mono text-xs text-text-faint">
                    No child processes spawned by PID {pid}.
                  </p>
                )}
              </div>

              {/* Sockets & Network Connections */}
              <div className="space-y-2">
                <h3 className="kicker flex items-center gap-1.5 text-text-primary">
                  <Icon name="network" size={12} className="text-sky-400" />
                  Network Sockets ({data.network_connections?.length ?? 0})
                </h3>
                {data.network_connections && data.network_connections.length > 0 ? (
                  <ul className="space-y-1.5">
                    {data.network_connections.map((n, i) => (
                      <li
                        key={i}
                        className="flex items-center justify-between rounded-lg border border-border-subtle bg-bg-surface p-2.5 font-mono text-xs"
                      >
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-text-primary">{n.dest_ip}</span>
                          {n.dest_port && <span className="text-text-faint">:{n.dest_port}</span>}
                          {n.protocol && (
                            <span className="rounded border border-border-subtle px-1 text-[9px] uppercase text-text-faint">
                              {n.protocol}
                            </span>
                          )}
                        </div>
                        <Link
                          to={`/search?q=${encodeURIComponent(n.dest_ip)}`}
                          onClick={onClose}
                          className="press inline-flex items-center gap-1 text-[10px] text-accent hover:underline"
                        >
                          Investigate IOC
                          <Icon name="search" size={9} />
                        </Link>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="rounded-lg border border-border-subtle bg-bg-elevated/20 p-3 font-mono text-xs text-text-faint">
                    No network connections observed for this PID.
                  </p>
                )}
              </div>

              {/* Files Modified */}
              <div className="space-y-2">
                <h3 className="kicker flex items-center gap-1.5 text-text-primary">
                  <Icon name="file" size={12} className="text-amber-400" />
                  Files Created / Modified ({data.files_written?.length ?? 0})
                </h3>
                {data.files_written && data.files_written.length > 0 ? (
                  <ul className="space-y-1">
                    {data.files_written.map((f, i) => (
                      <li
                        key={i}
                        className="truncate rounded border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs text-text-muted"
                        title={f}
                      >
                        {f}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="rounded-lg border border-border-subtle bg-bg-elevated/20 p-3 font-mono text-xs text-text-faint">
                    No file writes recorded for this PID.
                  </p>
                )}
              </div>
            </>
          )}
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between border-t border-border-subtle bg-bg-elevated/40 px-6 py-3">
          <Link
            to={`/events?pid=${pid}`}
            onClick={onClose}
            className="press inline-flex items-center gap-1.5 font-mono text-xs text-accent hover:underline"
          >
            <Icon name="list" size={12} />
            View all {data?.event_count ?? 0} events for PID {pid}
          </Link>
          <div className="flex items-center gap-3">
            <Link
              to={`/investigations?q=pid:${pid}`}
              onClick={onClose}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/50 bg-accent/10 px-3 py-1.5 font-mono text-xs font-semibold text-accent hover:bg-accent/20"
            >
              <Icon name="notes" size={12} />
              Open Case Investigation
            </Link>
            <button
              onClick={onClose}
              className="press rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted hover:bg-bg-elevated hover:text-text-primary"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
