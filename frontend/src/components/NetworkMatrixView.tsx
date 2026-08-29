import { useState } from "react";
import { Icon } from "./Icon";

export interface NetworkMatrixData {
  public_listeners: Array<{
    protocol: string;
    local_ip: string;
    local_port: number;
    remote_ip: string | null;
    remote_port: number | null;
    status: string;
    pid: number | null;
    process_name: string;
    label?: string;
    is_public_bound?: boolean;
  }>;
  loopback_listeners: Array<{
    protocol: string;
    local_ip: string;
    local_port: number;
    remote_ip: string | null;
    remote_port: number | null;
    status: string;
    pid: number | null;
    process_name: string;
    label?: string;
  }>;
  outbound_connections: Array<{
    protocol: string;
    local_ip: string;
    local_port: number;
    remote_ip: string | null;
    remote_port: number | null;
    status: string;
    pid: number | null;
    process_name: string;
    is_external?: boolean;
    is_suspicious_port?: boolean;
    endpoint_type?: string;
  }>;
  multicast_listeners: Array<{
    protocol: string;
    local_ip: string;
    local_port: number;
    remote_ip: string | null;
    remote_port: number | null;
    status: string;
    pid: number | null;
    process_name: string;
    label?: string;
  }>;
  summary: {
    public_listeners_count: number;
    loopback_listeners_count: number;
    outbound_count: number;
    multicast_count: number;
    total_sockets: number;
  };
}

export function NetworkMatrixView({
  matrix,
  onInspectPid,
}: {
  matrix: NetworkMatrixData;
  onInspectPid: (pid: number) => void;
}) {
  const [filter, setFilter] = useState("");
  const [section, setSection] = useState<"all" | "public" | "outbound" | "loopback" | "multicast">("all");

  const filterItem = (item: any) => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    return (
      String(item.local_port).includes(q) ||
      (item.remote_port && String(item.remote_port).includes(q)) ||
      item.local_ip.toLowerCase().includes(q) ||
      (item.remote_ip && item.remote_ip.toLowerCase().includes(q)) ||
      item.process_name.toLowerCase().includes(q) ||
      (item.pid && String(item.pid).includes(q))
    );
  };

  const publicFiltered = matrix.public_listeners.filter(filterItem);
  const outboundFiltered = matrix.outbound_connections.filter(filterItem);
  const loopbackFiltered = matrix.loopback_listeners.filter(filterItem);
  const multicastFiltered = matrix.multicast_listeners.filter(filterItem);

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Summary Pulse Stats */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <div className="rounded-2xl border border-risk-malicious/40 bg-risk-malicious/10 p-4 shadow-sm">
          <span className="text-[10px] font-bold uppercase text-risk-malicious">Public Listeners</span>
          <p className="mt-1 text-lg font-bold text-text-primary">{matrix.summary.public_listeners_count}</p>
          <span className="text-[10px] text-text-muted">Bound to 0.0.0.0 / ::</span>
        </div>

        <div className="rounded-2xl border border-risk-suspicious/40 bg-risk-suspicious/10 p-4 shadow-sm">
          <span className="text-[10px] font-bold uppercase text-risk-suspicious">Outbound / Remote</span>
          <p className="mt-1 text-lg font-bold text-text-primary">{matrix.summary.outbound_count}</p>
          <span className="text-[10px] text-text-muted">Active Remote Sockets</span>
        </div>

        <div className="rounded-2xl border border-border-subtle bg-bg-surface p-4 shadow-sm">
          <span className="text-[10px] font-bold uppercase text-text-faint">Local Loopback</span>
          <p className="mt-1 text-lg font-bold text-text-primary">{matrix.summary.loopback_listeners_count}</p>
          <span className="text-[10px] text-text-muted">127.0.0.1 / ::1 IPC</span>
        </div>

        <div className="rounded-2xl border border-border-subtle bg-bg-surface p-4 shadow-sm">
          <span className="text-[10px] font-bold uppercase text-text-faint">Multicast / Discovery</span>
          <p className="mt-1 text-lg font-bold text-text-primary">{matrix.summary.multicast_count}</p>
          <span className="text-[10px] text-text-muted">mDNS / SSDP Sockets</span>
        </div>
      </div>

      {/* Filter and Section Selector */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-border-subtle bg-bg-surface p-3">
        <div className="flex flex-wrap items-center gap-1.5">
          {(
            [
              { k: "all", label: `All Sockets (${matrix.summary.total_sockets})` },
              { k: "public", label: `Public (${matrix.summary.public_listeners_count})` },
              { k: "outbound", label: `Outbound (${matrix.summary.outbound_count})` },
              { k: "loopback", label: `Loopback (${matrix.summary.loopback_listeners_count})` },
              { k: "multicast", label: `Multicast (${matrix.summary.multicast_count})` },
            ] as const
          ).map((s) => (
            <button
              key={s.k}
              onClick={() => setSection(s.k)}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                section === s.k
                  ? "border border-accent/40 bg-accent/15 text-accent font-bold"
                  : "border border-transparent text-text-muted hover:text-text-primary hover:bg-bg-elevated"
              }`}
            >
              {s.label}
            </button>
          ))}
        </div>

        <div className="relative w-72">
          <Icon name="search" size={13} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-faint" />
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by port, IP, or process..."
            className="w-full rounded-lg border border-border-subtle bg-bg-base py-1.5 pl-9 pr-3 text-xs text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
          />
        </div>
      </div>

      {/* 1. Public Listeners Table */}
      {(section === "all" || section === "public") && (
        <div className="panel overflow-hidden p-0">
          <div className="border-b border-border-subtle bg-risk-malicious/10 px-5 py-3 flex items-center justify-between">
            <span className="font-bold text-text-primary flex items-center gap-2">
              <Icon name="network" size={14} className="text-risk-malicious" />
              Public Network Listeners ({publicFiltered.length})
            </span>
            <span className="text-[11px] text-text-faint">Bound beyond loopback (Accepts external ingress)</span>
          </div>

          <div className="overflow-x-auto max-h-[300px]">
            <table className="w-full text-left">
              <thead className="sticky top-0 border-b border-border-subtle bg-bg-surface text-[10px] uppercase text-text-faint">
                <tr>
                  <th className="p-3">Protocol</th>
                  <th className="p-3">Listening Endpoint</th>
                  <th className="p-3">Scope</th>
                  <th className="p-3">Process</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle text-[11px]">
                {publicFiltered.map((s, i) => (
                  <tr key={i} className="hover:bg-bg-elevated/30">
                    <td className="p-3 font-bold uppercase text-accent">{s.protocol}</td>
                    <td className="p-3 font-bold text-text-primary">{s.local_ip}:{s.local_port}</td>
                    <td className="p-3">
                      <span className="rounded bg-risk-malicious/15 border border-risk-malicious/30 px-2 py-0.5 text-[9px] text-risk-malicious font-bold">
                        {s.label || "Public Bound"}
                      </span>
                    </td>
                    <td className="p-3 text-text-muted">
                      {s.process_name} {s.pid && <span className="text-text-faint font-mono">(PID {s.pid})</span>}
                    </td>
                    <td className="p-3 text-right">
                      {s.pid && (
                        <button
                          onClick={() => onInspectPid(s.pid!)}
                          className="press rounded border border-border-subtle bg-bg-surface px-2 py-1 text-[10px] text-text-muted hover:border-accent/60 hover:text-accent"
                        >
                          Inspect Process
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {publicFiltered.length === 0 && (
                  <tr>
                    <td colSpan={5} className="p-6 text-center text-text-faint">No public network listeners found.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 2. Outbound / Active Remote Connections */}
      {(section === "all" || section === "outbound") && (
        <div className="panel overflow-hidden p-0">
          <div className="border-b border-border-subtle bg-bg-elevated/40 px-5 py-3 flex items-center justify-between">
            <span className="font-bold text-text-primary flex items-center gap-2">
              <Icon name="network" size={14} className="text-risk-suspicious" />
              Active Remote Connections ({outboundFiltered.length})
            </span>
            <span className="text-[11px] text-text-faint">Outbound C2 / Telemetry / Remote Sockets</span>
          </div>

          <div className="overflow-x-auto max-h-[300px]">
            <table className="w-full text-left">
              <thead className="sticky top-0 border-b border-border-subtle bg-bg-surface text-[10px] uppercase text-text-faint">
                <tr>
                  <th className="p-3">Protocol</th>
                  <th className="p-3">Local Address</th>
                  <th className="p-3">Remote Endpoint</th>
                  <th className="p-3">Classification</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Process</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle text-[11px]">
                {outboundFiltered.map((s, i) => (
                  <tr key={i} className="hover:bg-bg-elevated/30">
                    <td className="p-3 font-bold uppercase text-accent">{s.protocol}</td>
                    <td className="p-3 text-text-muted">{s.local_ip}:{s.local_port}</td>
                    <td className="p-3 font-bold text-text-primary">{s.remote_ip}:{s.remote_port}</td>
                    <td className="p-3">
                      <span className={`rounded px-2 py-0.5 text-[9px] font-semibold ${
                        s.is_suspicious_port
                          ? "bg-risk-malicious/20 text-risk-malicious border border-risk-malicious/40"
                          : s.is_external
                          ? "bg-accent/15 text-accent border border-accent/30"
                          : "bg-bg-elevated text-text-muted"
                      }`}>
                        {s.is_suspicious_port ? "⚠️ Suspicious Port" : s.endpoint_type || "LAN"}
                      </span>
                    </td>
                    <td className="p-3">
                      <span className="rounded bg-bg-elevated px-1.5 py-0.5 text-[9px] uppercase text-text-faint">
                        {s.status}
                      </span>
                    </td>
                    <td className="p-3 text-text-muted">
                      {s.process_name} {s.pid && <span className="text-text-faint font-mono">(PID {s.pid})</span>}
                    </td>
                    <td className="p-3 text-right">
                      {s.pid && (
                        <button
                          onClick={() => onInspectPid(s.pid!)}
                          className="press rounded border border-border-subtle bg-bg-surface px-2 py-1 text-[10px] text-text-muted hover:border-accent/60 hover:text-accent"
                        >
                          Inspect Process
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {outboundFiltered.length === 0 && (
                  <tr>
                    <td colSpan={7} className="p-6 text-center text-text-faint">No active outbound connections found.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 3. Loopback Sockets Table */}
      {(section === "all" || section === "loopback") && (
        <div className="panel overflow-hidden p-0">
          <div className="border-b border-border-subtle bg-bg-elevated/20 px-5 py-3 flex items-center justify-between">
            <span className="font-bold text-text-primary flex items-center gap-2">
              <Icon name="activity" size={14} className="text-signal" />
              Local Loopback IPC Sockets ({loopbackFiltered.length})
            </span>
          </div>

          <div className="overflow-x-auto max-h-[250px]">
            <table className="w-full text-left">
              <thead className="sticky top-0 border-b border-border-subtle bg-bg-surface text-[10px] uppercase text-text-faint">
                <tr>
                  <th className="p-3">Protocol</th>
                  <th className="p-3">Endpoint</th>
                  <th className="p-3">Owning Process</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle text-[11px]">
                {loopbackFiltered.map((s, i) => (
                  <tr key={i} className="hover:bg-bg-elevated/30">
                    <td className="p-3 font-bold uppercase text-accent">{s.protocol}</td>
                    <td className="p-3 text-text-primary">{s.local_ip}:{s.local_port}</td>
                    <td className="p-3 text-text-muted">
                      {s.process_name} {s.pid && <span className="text-text-faint font-mono">(PID {s.pid})</span>}
                    </td>
                    <td className="p-3 text-right">
                      {s.pid && (
                        <button
                          onClick={() => onInspectPid(s.pid!)}
                          className="press rounded border border-border-subtle bg-bg-surface px-2 py-1 text-[10px] text-text-muted hover:border-accent/60 hover:text-accent"
                        >
                          Inspect Process
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 4. Multicast & Discovery Sockets Table */}
      {(section === "all" || section === "multicast") && (
        <div className="panel overflow-hidden p-0">
          <div className="border-b border-border-subtle bg-bg-elevated/20 px-5 py-3 flex items-center justify-between">
            <span className="font-bold text-text-primary flex items-center gap-2">
              <Icon name="globe" size={14} className="text-accent" />
              Multicast & Discovery Sockets ({multicastFiltered.length})
            </span>
          </div>

          <div className="overflow-x-auto max-h-[250px]">
            <table className="w-full text-left">
              <thead className="sticky top-0 border-b border-border-subtle bg-bg-surface text-[10px] uppercase text-text-faint">
                <tr>
                  <th className="p-3">Protocol</th>
                  <th className="p-3">Multicast Address</th>
                  <th className="p-3">Owning Process</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle text-[11px]">
                {multicastFiltered.map((s, i) => (
                  <tr key={i} className="hover:bg-bg-elevated/30">
                    <td className="p-3 font-bold uppercase text-accent">{s.protocol}</td>
                    <td className="p-3 text-text-primary">{s.local_ip}:{s.local_port}</td>
                    <td className="p-3 text-text-muted">
                      {s.process_name} {s.pid && <span className="text-text-faint font-mono">(PID {s.pid})</span>}
                    </td>
                    <td className="p-3 text-right">
                      {s.pid && (
                        <button
                          onClick={() => onInspectPid(s.pid!)}
                          className="press rounded border border-border-subtle bg-bg-surface px-2 py-1 text-[10px] text-text-muted hover:border-accent/60 hover:text-accent"
                        >
                          Inspect Process
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {multicastFiltered.length === 0 && (
                  <tr>
                    <td colSpan={4} className="p-6 text-center text-text-faint">No multicast sockets active.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default NetworkMatrixView;
