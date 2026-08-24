import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { getNetworkSummary } from "../lib/api";
import { Icon } from "./Icon";
import { DataProvenanceBadge } from "./DataProvenanceBadge";

export function NetworkContextModal({
  ip,
  onClose,
}: {
  ip: string;
  onClose: () => void;
}) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["events", "network-summary", ip],
    queryFn: () => getNetworkSummary(ip),
    staleTime: 30_000,
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div
        className="flex max-h-[90vh] w-full max-w-3xl flex-col overflow-hidden rounded-2xl border border-border-subtle bg-bg-surface shadow-[var(--shadow-raised)]"
        role="dialog"
        aria-modal="true"
        aria-labelledby="network-modal-title"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border-subtle bg-bg-elevated/40 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-sky-500/30 bg-sky-500/10 text-sky-400">
              <Icon name="network" size={18} />
            </div>
            <div>
              <h2 id="network-modal-title" className="font-mono text-sm font-bold text-text-primary">
                {ip}
              </h2>
              <div className="flex items-center gap-2 font-mono text-[11px] text-text-faint">
                <span>Destination IP Indicator</span>
                {data?.watchlist && <span className="text-risk-suspicious">· Tracked in Watchlist</span>}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <DataProvenanceBadge source="live" />
            <button
              onClick={onClose}
              className="press rounded-lg p-1.5 text-text-faint hover:bg-bg-elevated hover:text-text-primary"
              aria-label="Close network context modal"
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
              Failed to load network investigation context for {ip}. No recorded socket events found.
            </div>
          )}

          {data && (
            <>
              {/* Telemetry Overview Panel */}
              <div className="rounded-xl border border-border-subtle bg-bg-base/40 p-4 font-mono text-xs space-y-2.5">
                <div className="flex gap-4">
                  <span className="w-32 shrink-0 text-text-faint">Total Sockets</span>
                  <span className="font-semibold text-text-primary">
                    {data.event_count} connection{data.event_count === 1 ? "" : "s"} observed
                  </span>
                </div>
                <div className="flex gap-4">
                  <span className="w-32 shrink-0 text-text-faint">First Observed</span>
                  <span className="text-text-muted">{data.first_seen || "—"}</span>
                </div>
                <div className="flex gap-4">
                  <span className="w-32 shrink-0 text-text-faint">Last Observed</span>
                  <span className="text-text-muted">{data.last_seen || "—"}</span>
                </div>
                {data.watchlist?.notes && (
                  <div className="flex gap-4 border-t border-border-subtle pt-2">
                    <span className="w-32 shrink-0 text-risk-suspicious font-semibold">Watchlist Note</span>
                    <span className="text-text-primary">{data.watchlist.notes}</span>
                  </div>
                )}
              </div>

              {/* Monitored Hosts */}
              <div className="space-y-2">
                <h3 className="kicker flex items-center gap-1.5 text-text-primary">
                  <Icon name="terminal" size={12} className="text-accent" />
                  Communicating Monitored Hosts ({data.hosts.length})
                </h3>
                {data.hosts.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {data.hosts.map((h) => (
                      <Link
                        key={h}
                        to={`/hosts/${encodeURIComponent(h)}`}
                        onClick={onClose}
                        className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs text-text-primary hover:border-accent/60 hover:text-accent"
                      >
                        <Icon name="terminal" size={11} className="opacity-60" />
                        {h}
                        <Icon name="external" size={9} className="opacity-60" />
                      </Link>
                    ))}
                  </div>
                ) : (
                  <p className="rounded-lg border border-border-subtle bg-bg-elevated/20 p-3 font-mono text-xs text-text-faint">
                    No distinct hosts recorded for this destination.
                  </p>
                )}
              </div>

              {/* Responsible Processes */}
              <div className="space-y-2">
                <h3 className="kicker flex items-center gap-1.5 text-text-primary">
                  <Icon name="process" size={12} className="text-accent" />
                  Responsible Processes ({data.processes.length})
                </h3>
                {data.processes.length > 0 ? (
                  <ul className="space-y-1.5">
                    {data.processes.map((p) => (
                      <li
                        key={p.pid}
                        className="flex items-center justify-between rounded-lg border border-border-subtle bg-bg-surface p-2.5 font-mono text-xs"
                      >
                        <div className="min-w-0">
                          <span className="font-semibold text-text-primary">{p.process_name || `PID ${p.pid}`}</span>
                          <span className="ml-2 text-text-faint">PID {p.pid}</span>
                          {p.command_line && (
                            <p className="truncate text-[10px] text-text-muted" title={p.command_line}>
                              {p.command_line}
                            </p>
                          )}
                        </div>
                        <Link
                          to={`/events?pid=${p.pid}`}
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
                    No process telemetry attached to these connections.
                  </p>
                )}
              </div>

              {/* Observed Ports & Protocols */}
              <div className="space-y-2">
                <h3 className="kicker flex items-center gap-1.5 text-text-primary">
                  <Icon name="target" size={12} className="text-sky-400" />
                  Target Ports & Protocols ({data.ports.length})
                </h3>
                <div className="flex flex-wrap gap-2">
                  {data.ports.map((p, i) => (
                    <span
                      key={i}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1 font-mono text-xs text-text-primary"
                    >
                      <span className="font-semibold">{p.dest_port ?? "—"}</span>
                      {p.protocol && (
                        <span className="rounded border border-border-subtle px-1 text-[9px] uppercase text-text-faint">
                          {p.protocol}
                        </span>
                      )}
                    </span>
                  ))}
                </div>
              </div>

              {/* Correlated Detections */}
              <div className="space-y-2">
                <h3 className="kicker flex items-center gap-1.5 text-text-primary">
                  <Icon name="alert" size={12} className="text-risk-suspicious" />
                  Correlated Findings & Alerts ({data.findings.length})
                </h3>
                {data.findings.length > 0 ? (
                  <ul className="space-y-1.5">
                    {data.findings.map((f) => (
                      <li
                        key={f.id}
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
                    No detections or IOC flags triggered for this destination IP.
                  </p>
                )}
              </div>
            </>
          )}
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between border-t border-border-subtle bg-bg-elevated/40 px-6 py-3">
          <Link
            to={`/search?q=${encodeURIComponent(ip)}`}
            onClick={onClose}
            className="press inline-flex items-center gap-1.5 font-mono text-xs text-accent hover:underline"
          >
            <Icon name="search" size={12} />
            Search IP in Global IOC Intelligence
          </Link>
          <div className="flex items-center gap-3">
            <Link
              to={`/investigations?q=${encodeURIComponent(ip)}`}
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
