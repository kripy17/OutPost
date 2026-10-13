import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../Icon";
import { Panel } from "../ui";
import { NetworkProtocolInspector } from "../NetworkProtocolInspector";
import type { AnalysisObservation } from "../../types";

interface NetworkActivityTabProps {
  observations: AnalysisObservation[];
  runId: string;
}

export function NetworkActivityTab({ observations, runId }: NetworkActivityTabProps) {
  const [protocolFilter, setProtocolFilter] = useState<string>("ALL");
  const [searchFilter, setSearchFilter] = useState<string>("");
  const [copiedIp, setCopiedIp] = useState<string | null>(null);

  const handleCopy = (val: string, e: React.MouseEvent) => {
    e.stopPropagation();
    void navigator.clipboard.writeText(val);
    setCopiedIp(val);
    setTimeout(() => setCopiedIp(null), 1800);
  };

  const networkEvents = useMemo(() => {
    return observations.filter((o) => {
      // Must be a network connection event or contain dest_ip / query / tls_sni
      const isNet = o.event_type === "network_connection" || Boolean(o.dest_ip) || Boolean(o.query) || Boolean(o.tls_sni);
      if (!isNet) return false;

      // Filter by protocol
      if (protocolFilter !== "ALL") {
        const proto = (o.protocol || "TCP").toUpperCase();
        if (proto !== protocolFilter) return false;
      }

      // Filter by search query (IP, domain, port, process)
      if (searchFilter.trim()) {
        const q = searchFilter.toLowerCase();
        const ipMatch = o.dest_ip?.toLowerCase().includes(q) ?? false;
        const queryMatch = o.query?.toLowerCase().includes(q) ?? false;
        const sniMatch = o.tls_sni?.toLowerCase().includes(q) ?? false;
        const procMatch = o.process_name?.toLowerCase().includes(q) ?? false;
        const pidMatch = String(o.pid || "").includes(q);
        if (!ipMatch && !queryMatch && !sniMatch && !procMatch && !pidMatch) return false;
      }

      return true;
    });
  }, [observations, protocolFilter, searchFilter]);

  const uniqueProtocols = useMemo(() => {
    const set = new Set<string>();
    observations.forEach((o) => {
      if (o.dest_ip || o.event_type === "network_connection") {
        set.add((o.protocol || "TCP").toUpperCase());
      }
    });
    return Array.from(set);
  }, [observations]);

  return (
    <div className="space-y-6 font-sans">
      <Panel
        kicker="Network Telemetry"
        title="Chronological Network Observations &amp; Sockets"
        right={
          <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
            <input
              type="text"
              placeholder="Search IP, domain, port, PID…"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              className="w-48 rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 text-[11px] text-text-primary placeholder:text-text-faint outline-none focus:border-accent"
            />
            <div className="flex items-center gap-1">
              <button
                onClick={() => setProtocolFilter("ALL")}
                className={`rounded px-2 py-0.5 text-[10px] font-semibold transition ${
                  protocolFilter === "ALL"
                    ? "bg-accent text-white"
                    : "border border-border-subtle bg-bg-base text-text-muted hover:text-text-primary"
                }`}
              >
                ALL
              </button>
              {uniqueProtocols.map((proto) => (
                <button
                  key={proto}
                  onClick={() => setProtocolFilter(proto)}
                  className={`rounded px-2 py-0.5 text-[10px] font-semibold transition ${
                    protocolFilter === proto
                      ? "bg-accent text-white"
                      : "border border-border-subtle bg-bg-base text-text-muted hover:text-text-primary"
                  }`}
                >
                  {proto}
                </button>
              ))}
            </div>
          </div>
        }
      >
        {networkEvents.length === 0 ? (
          <div className="p-8 text-center font-mono text-xs text-text-muted">
            <Icon name="activity" size={24} className="mx-auto mb-2 text-text-faint" />
            <p className="font-bold text-text-primary">No Network Observations Recorded</p>
            <p className="text-text-faint mt-1">
              Zero outbound network connections or DNS queries were recorded during this execution.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-border-subtle bg-bg-base/70 text-[10px] uppercase text-text-faint font-semibold">
                  <th className="py-2.5 px-3">Timestamp (UTC)</th>
                  <th className="py-2.5 px-3">Originating Process</th>
                  <th className="py-2.5 px-3">Protocol</th>
                  <th className="py-2.5 px-3">Destination Socket / Host</th>
                  <th className="py-2.5 px-3">DNS Query / SNI Handshake</th>
                  <th className="py-2.5 px-3">Egress Type</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/40 text-[11px]">
                {networkEvents.map((evt, idx) => {
                  const destStr = evt.dest_ip ? `${evt.dest_ip}${evt.dest_port ? `:${evt.dest_port}` : ""}` : "—";
                  const isSimulated = evt.dest_ip?.startsWith("127.") || evt.dest_ip === "::1" || evt.protocol === "SIM";

                  return (
                    <tr key={`${evt.id ?? idx}-${idx}`} className="hover:bg-bg-elevated/30 transition">
                      <td className="py-2 px-3 whitespace-nowrap text-text-muted tabular-nums">
                        {evt.timestamp ? evt.timestamp.slice(11, 19) : "—"}
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <span className="font-bold text-text-primary">{evt.process_name || "—"}</span>
                          {evt.pid && (
                            <span className="rounded bg-bg-elevated px-1 py-0.2 text-[9px] text-text-faint">
                              PID {evt.pid}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <span className="rounded border border-border-subtle bg-bg-base px-1.5 py-0.2 text-[10px] uppercase font-semibold text-text-secondary">
                          {evt.protocol || "TCP"}
                        </span>
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <span className="font-bold text-accent select-all">{destStr}</span>
                          {evt.dest_ip && (
                            <button
                              onClick={(e) => handleCopy(evt.dest_ip!, e)}
                              className="press rounded p-0.5 text-text-faint hover:text-text-primary transition"
                              title="Copy Destination IP"
                            >
                              <Icon
                                name={copiedIp === evt.dest_ip ? "check" : "copy"}
                                size={10}
                                className={copiedIp === evt.dest_ip ? "text-emerald-400" : ""}
                              />
                            </button>
                          )}
                        </div>
                      </td>
                      <td className="py-2 px-3 max-w-[240px]">
                        <div className="space-y-0.5 min-w-0">
                          {evt.query && (
                            <div className="truncate text-text-primary" title={`DNS Query: ${evt.query}`}>
                              <span className="text-text-faint text-[9px] uppercase mr-1">DNS:</span>
                              <span className="font-semibold select-all">{evt.query}</span>
                            </div>
                          )}
                          {evt.tls_sni && (
                            <div className="truncate text-sky-400" title={`TLS SNI: ${evt.tls_sni}`}>
                              <span className="text-text-faint text-[9px] uppercase mr-1">SNI:</span>
                              <span className="font-semibold select-all">{evt.tls_sni}</span>
                            </div>
                          )}
                          {!evt.query && !evt.tls_sni && <span className="text-text-faint">—</span>}
                        </div>
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap">
                        <span
                          className={`rounded px-1.5 py-0.2 text-[9px] font-bold uppercase ${
                            isSimulated
                              ? "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                              : "bg-sky-500/15 text-sky-400 border border-sky-500/30"
                          }`}
                        >
                          {isSimulated ? "Simulated / Loopback" : "Live Egress"}
                        </span>
                      </td>
                      <td className="py-2 px-3 whitespace-nowrap text-right">
                        {evt.dest_ip && (
                          <Link
                            to="/watchlist"
                            className="press rounded border border-border-subtle bg-bg-surface px-1.5 py-0.5 text-[9px] text-text-faint hover:text-accent hover:border-accent/40 transition"
                            title="Add to Watchlist"
                          >
                            Watchlist
                          </Link>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/* Network Protocol Deep Inspector Component */}
      <NetworkProtocolInspector runId={runId} />
    </div>
  );
}
