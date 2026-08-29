import { useEffect, useState } from "react";
import { Icon } from "./Icon";
import { getNetworkMatrix } from "../lib/api";

export interface NetworkMatrixProps {
  onInspectIp?: (ip: string) => void;
}

export function ProcessNetworkMatrix({ onInspectIp }: NetworkMatrixProps) {
  const [matrix, setMatrix] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const fetchMatrix = async () => {
    try {
      setLoading(true);
      const data = await getNetworkMatrix();
      setMatrix(data);
    } catch (err) {
      console.error("Failed to load network matrix", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMatrix();
  }, []);

  const listening = matrix?.listening_ports || [];
  const outbound = matrix?.outbound_connections || [];

  return (
    <div className="space-y-4 rounded-2xl border border-border-subtle bg-bg-surface/50 p-4">
      <div className="flex items-center justify-between border-b border-border-subtle pb-3">
        <div className="flex items-center gap-2">
          <Icon name="network" size={16} className="text-signal" />
          <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-text-primary">
            Process Network Socket & Connection Matrix
          </h3>
        </div>
        <div className="flex items-center gap-2 font-mono text-[10px] text-text-faint">
          <span>{listening.length} listening</span>
          <span>•</span>
          <span>{outbound.length} outbound</span>
          <button
            onClick={fetchMatrix}
            className="rounded border border-border-subtle bg-bg-surface px-1.5 py-0.5 text-text-muted hover:text-text-primary"
          >
            ↻
          </button>
        </div>
      </div>

      {loading ? (
        <div className="py-8 text-center font-mono text-xs text-text-faint animate-pulse">
          Scanning host network sockets and connections...
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {/* Listening Sockets */}
          <div className="space-y-2">
            <span className="font-mono text-[11px] font-bold uppercase tracking-wider text-accent">
              Listening Ports & Services ({listening.length})
            </span>
            <div className="max-h-60 space-y-1.5 overflow-y-auto pr-1">
              {listening.length === 0 ? (
                <div className="py-4 text-center font-mono text-xs text-text-faint">No listening sockets</div>
              ) : (
                listening.map((s: any, i: number) => (
                  <div
                    key={i}
                    className="flex items-center justify-between rounded-xl border border-border-subtle bg-bg-surface p-2.5 font-mono text-xs text-text-primary"
                  >
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-accent/15 border border-accent/30 px-1.5 py-0.5 text-[10px] font-bold text-accent">
                        :{s.port || s.local_port}
                      </span>
                      <span className="font-semibold">{s.process_name || s.process || `PID ${s.pid}`}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-text-muted">{s.address || s.local_address || "0.0.0.0"}</span>
                      <span className="rounded bg-bg-elevated px-1.5 py-0.2 text-[9px] uppercase text-text-faint">
                        {s.protocol || "TCP"}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Outbound & Established */}
          <div className="space-y-2">
            <span className="font-mono text-[11px] font-bold uppercase tracking-wider text-signal">
              Active Remote Sockets ({outbound.length})
            </span>
            <div className="max-h-60 space-y-1.5 overflow-y-auto pr-1">
              {outbound.length === 0 ? (
                <div className="py-4 text-center font-mono text-xs text-text-faint">No outbound sockets</div>
              ) : (
                outbound.map((s: any, i: number) => (
                  <div
                    key={i}
                    className="flex items-center justify-between rounded-xl border border-border-subtle bg-bg-surface p-2.5 font-mono text-xs text-text-primary"
                  >
                    <div className="flex items-center gap-2">
                      <span
                        onClick={() => onInspectIp && (s.remote_ip || s.ip) && onInspectIp(s.remote_ip || s.ip)}
                        className="rounded bg-signal/15 border border-signal/30 px-1.5 py-0.5 text-[10px] font-bold text-signal hover:underline cursor-pointer"
                        title="Inspect IP"
                      >
                        {s.remote_ip || s.ip || s.destination}:{s.remote_port || s.port}
                      </span>
                      <span className="font-semibold truncate max-w-[120px]">{s.process_name || s.process || `PID ${s.pid}`}</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      {s.domain && (
                        <span className="text-[10px] text-text-muted truncate max-w-[100px]">{s.domain}</span>
                      )}
                      <span className="rounded bg-bg-elevated px-1.5 py-0.2 text-[9px] uppercase text-text-faint">
                        {s.status || "ESTABLISHED"}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
