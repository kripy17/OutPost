import React from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Icon } from "./Icon";
import { getIocFleetHunt } from "../lib/api";
import type { IocFleetHuntResult } from "../types";

interface IocFleetHuntModalProps {
  iocId: string;
  onClose: () => void;
}

export const IocFleetHuntModal: React.FC<IocFleetHuntModalProps> = ({ iocId, onClose }) => {
  const { data, isLoading, isError } = useQuery<IocFleetHuntResult>({
    queryKey: ["ioc-fleet-hunt", iocId],
    queryFn: () => getIocFleetHunt(iocId),
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
      <div className="flex max-h-[90vh] w-full max-w-4xl flex-col rounded-2xl border border-border-subtle bg-bg-surface shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border-subtle px-6 py-4">
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl border border-signal/40 bg-signal/15 text-signal">
              <Icon name="search" size={18} />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="font-mono text-sm font-bold text-text-primary">
                  {data?.value || "Evaluating..."}
                </h2>
                {data && (
                  <span className="rounded bg-bg-elevated px-2 py-0.5 font-mono text-[10px] uppercase text-text-muted">
                    {data.type}
                  </span>
                )}
              </div>
              <p className="text-xs text-text-muted">
                Enterprise Fleet Compromise Assessment & Historical Telemetry Hunt
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-text-muted hover:bg-bg-elevated hover:text-text-primary"
          >
            <Icon name="x" size={16} />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-16 text-text-muted">
              <Icon name="refresh" size={24} className="animate-spin text-accent mb-3" />
              <span className="font-mono text-xs">Sweeping fleet telemetry and cross-case records...</span>
            </div>
          ) : isError || !data ? (
            <p className="py-12 text-center text-sm text-rose-400">Failed to conduct fleet assessment.</p>
          ) : (
            <>
              {/* Verdict Banner */}
              <div
                className={`flex items-center justify-between rounded-xl border p-4 font-mono text-xs ${
                  data.threat_verdict === "confirmed_threat"
                    ? "border-rose-500/50 bg-rose-500/10 text-rose-300"
                    : data.threat_verdict === "suspicious"
                      ? "border-amber-500/50 bg-amber-500/10 text-amber-300"
                      : data.threat_verdict === "observed_clean"
                        ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                        : "border-border-subtle bg-bg-elevated/40 text-text-muted"
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon
                    name={
                      data.threat_verdict === "confirmed_threat" || data.threat_verdict === "suspicious"
                        ? "alert"
                        : "shield"
                    }
                    size={20}
                  />
                  <div>
                    <div className="font-bold uppercase tracking-wider">
                      Verdict: {data.threat_verdict.replace(/_/g, " ")}
                    </div>
                    <div className="text-[11px] opacity-80">
                      {data.threat_verdict === "confirmed_threat"
                        ? `${data.malicious_findings_count} malicious alert(s) linked to this indicator`
                        : data.threat_verdict === "suspicious"
                          ? `${data.suspicious_findings_count} suspicious alert(s) triggered across endpoints`
                          : data.total_sightings > 0
                            ? `Observed ${data.total_sightings} times in telemetry without alert triggers`
                            : "Zero sightings recorded in historical enterprise database"}
                    </div>
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-xl font-bold">{data.total_sightings}</span>
                  <div className="text-[10px] uppercase opacity-70">Total Sightings</div>
                </div>
              </div>

              {/* Stats Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="rounded-xl border border-border-subtle bg-bg-elevated/30 p-3 font-mono">
                  <div className="text-[10px] uppercase text-text-faint">Impacted Hosts</div>
                  <div className="mt-1 text-lg font-bold text-text-primary">{data.distinct_hosts_count}</div>
                  <div className="text-[10px] text-text-muted truncate">
                    {data.distinct_hosts.join(", ") || "None"}
                  </div>
                </div>
                <div className="rounded-xl border border-border-subtle bg-bg-elevated/30 p-3 font-mono">
                  <div className="text-[10px] uppercase text-text-faint">Impacted Runs</div>
                  <div className="mt-1 text-lg font-bold text-text-primary">{data.distinct_runs_count}</div>
                  <div className="text-[10px] text-text-muted">Unique sessions</div>
                </div>
                <div className="rounded-xl border border-border-subtle bg-bg-elevated/30 p-3 font-mono">
                  <div className="text-[10px] uppercase text-text-faint">Earliest Sighting</div>
                  <div className="mt-1 text-xs font-semibold text-text-primary truncate">
                    {data.earliest_sighting ? data.earliest_sighting.slice(0, 19).replace("T", " ") : "—"}
                  </div>
                  <div className="text-[10px] text-text-faint">First recorded</div>
                </div>
                <div className="rounded-xl border border-border-subtle bg-bg-elevated/30 p-3 font-mono">
                  <div className="text-[10px] uppercase text-text-faint">Latest Sighting</div>
                  <div className="mt-1 text-xs font-semibold text-text-primary truncate">
                    {data.latest_sighting ? data.latest_sighting.slice(0, 19).replace("T", " ") : "—"}
                  </div>
                  <div className="text-[10px] text-text-faint">Most recent</div>
                </div>
              </div>

              {/* Cross-Investigation Correlation */}
              {data.associated_investigations.length > 0 && (
                <div className="space-y-2 rounded-xl border border-accent/40 bg-bg-elevated/20 p-4">
                  <div className="flex items-center gap-2 text-xs font-bold text-accent">
                    <Icon name="notes" size={14} />
                    <span>Cross-Case Linkage ({data.associated_investigations.length} Investigations)</span>
                  </div>
                  <div className="space-y-1.5 pt-1">
                    {data.associated_investigations.map((inv) => (
                      <Link
                        key={inv.id}
                        to={`/investigations/${inv.id}`}
                        className="flex items-center justify-between rounded-lg border border-border-subtle bg-bg-base/60 p-2.5 text-xs transition hover:border-accent/40"
                      >
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-accent font-bold">#{inv.id}</span>
                          <span className="font-semibold text-text-primary">{inv.title}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="rounded bg-bg-elevated px-2 py-0.5 font-mono text-[9px] uppercase text-text-muted">
                            {inv.status}
                          </span>
                          <span className="font-mono text-[10px] text-text-faint">
                            {inv.created_at.slice(0, 10)}
                          </span>
                        </div>
                      </Link>
                    ))}
                  </div>
                </div>
              )}

              {/* Sighting Trail */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold uppercase tracking-wider text-text-primary">
                    Historical Sightings Ledger ({data.sightings.length})
                  </span>
                  <span className="font-mono text-[10px] text-text-faint">Top 50 chronological matches</span>
                </div>

                {data.sightings.length === 0 ? (
                  <p className="py-6 text-center text-xs text-text-muted">
                    No historical events recorded for this indicator.
                  </p>
                ) : (
                  <div className="max-h-64 overflow-y-auto divide-y divide-border-subtle/40 rounded-xl border border-border-subtle bg-bg-base/50 font-mono text-xs">
                    {data.sightings.map((s, idx) => (
                      <div key={idx} className="flex items-start justify-between gap-3 p-3 hover:bg-bg-elevated/30">
                        <div className="space-y-1 min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-text-primary">{s.process_name || "kernel"}</span>
                            <span className="rounded bg-bg-elevated px-1.5 py-0.2 text-[9px] uppercase text-text-faint">
                              {s.event_type}
                            </span>
                            <span className="text-[10px] text-text-faint truncate">Host: {s.host_id}</span>
                          </div>
                          <p className="text-[11px] text-text-muted truncate leading-snug">{s.summary}</p>
                        </div>
                        <div className="text-right shrink-0">
                          <span
                            className={`rounded px-1.5 py-0.2 text-[9px] uppercase font-bold ${
                              s.severity === "malicious"
                                ? "bg-rose-500/20 text-rose-400"
                                : s.severity === "suspicious"
                                  ? "bg-amber-500/20 text-amber-400"
                                  : "bg-bg-elevated text-text-faint"
                            }`}
                          >
                            {s.severity}
                          </span>
                          <div className="mt-1 text-[10px] text-text-faint">
                            {s.timestamp.slice(11, 19)}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-border-subtle px-6 py-4">
          <span className="font-mono text-xs text-text-faint">
            Target: {iocId} · Real-time compromise telemetry sweep
          </span>
          <button
            type="button"
            onClick={onClose}
            className="rounded-xl border border-border-subtle bg-bg-elevated px-4 py-2 font-mono text-xs font-semibold text-text-primary hover:border-accent"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
