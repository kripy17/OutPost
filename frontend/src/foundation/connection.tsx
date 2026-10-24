import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { RefreshCw, WifiOff } from "lucide-react";

export type HealthStatus = "connected" | "idle" | "polling" | "offline";

export interface ConnectionState {
  apiReachable: boolean;
  streamLive: boolean;
  status: HealthStatus;
  lastEventTime: Date | null;
  lastEventAgeSec: number | null;
  ingestLagMs: number | null;
  errorDetail: string | null;
  retryPing: () => Promise<void>;
  markEventReceived: (eventTimestamp?: string | Date) => void;
  setStreamStatus: (live: boolean) => void;
}

const ConnectionContext = createContext<ConnectionState | null>(null);

export const ConnectionProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [apiReachable, setApiReachable] = useState<boolean>(true);
  const [streamLive, setStreamLive] = useState<boolean>(false);
  const [lastEventTime, setLastEventTime] = useState<Date | null>(null);
  const [ingestLagMs, setIngestLagMs] = useState<number | null>(null);
  const [errorDetail, setErrorDetail] = useState<string | null>(null);
  const [isRetrying, setIsRetrying] = useState<boolean>(false);
  const [backoffSec, setBackoffSec] = useState<number>(2);

  const pingApi = useCallback(async () => {
    try {
      setIsRetrying(true);
      const res = await fetch("/health", { signal: AbortSignal.timeout(3000) });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }
      setApiReachable(true);
      setErrorDetail(null);
      setBackoffSec(2); // reset backoff on success
    } catch (err: unknown) {
      setApiReachable(false);
      setStreamLive(false);
      const msg = err instanceof Error ? err.message : "Connection refused";
      setErrorDetail(msg);
      setBackoffSec((prev) => Math.min(prev * 2, 30)); // exponential backoff
    } finally {
      setIsRetrying(false);
    }
  }, []);

  useEffect(() => {
    pingApi();
    const interval = window.setInterval(pingApi, apiReachable ? 15000 : backoffSec * 1000);
    return () => window.clearInterval(interval);
  }, [pingApi, apiReachable, backoffSec]);

  const markEventReceived = useCallback((eventTimestamp?: string | Date) => {
    const now = new Date();
    setLastEventTime(now);
    setStreamLive(true);
    if (eventTimestamp) {
      const evDate = new Date(eventTimestamp);
      if (!Number.isNaN(evDate.getTime())) {
        setIngestLagMs(Math.max(0, now.getTime() - evDate.getTime()));
      }
    }
  }, []);

  const setStreamStatus = useCallback((live: boolean) => {
    setStreamLive(live);
  }, []);

  // Compute event age in seconds
  const lastEventAgeSec = lastEventTime
    ? Math.max(0, Math.floor((Date.now() - lastEventTime.getTime()) / 1000))
    : null;

  // Determine distinct health state
  let status: HealthStatus = "offline";
  if (apiReachable) {
    if (streamLive) {
      if (lastEventTime && lastEventAgeSec !== null && lastEventAgeSec <= 60) {
        status = "connected";
      } else {
        status = "idle";
      }
    } else {
      status = "polling";
    }
  }

  return (
    <ConnectionContext.Provider
      value={{
        apiReachable,
        streamLive,
        status,
        lastEventTime,
        lastEventAgeSec,
        ingestLagMs,
        errorDetail,
        retryPing: pingApi,
        markEventReceived,
        setStreamStatus,
      }}
    >
      {!apiReachable && (
        <div className="flex items-center justify-between border-b border-[#f85149] bg-[#f85149]/10 px-4 py-1.5 text-[12px] text-[#ff7b72]">
          <div className="flex items-center gap-2 font-mono">
            <WifiOff className="h-4 w-4 shrink-0" />
            <span>API unreachable: {errorDetail ?? "Check backend server status"}</span>
          </div>
          <button
            onClick={() => {
              setBackoffSec(2);
              pingApi();
            }}
            disabled={isRetrying}
            className="flex items-center gap-1.5 rounded-[3px] bg-[#f85149]/20 px-2 py-0.5 text-[11px] font-medium text-white transition hover:bg-[#f85149]/30 disabled:opacity-50"
          >
            <RefreshCw className={`h-3 w-3 ${isRetrying ? "animate-spin" : ""}`} />
            <span>Retry</span>
          </button>
        </div>
      )}
      {children}
    </ConnectionContext.Provider>
  );
};

export const useConnectionState = (): ConnectionState => {
  const ctx = useContext(ConnectionContext);
  if (!ctx) {
    throw new Error("useConnectionState must be used within ConnectionProvider");
  }
  return ctx;
};

export const HealthIndicator: React.FC<{ className?: string }> = ({ className = "" }) => {
  const { status, errorDetail, lastEventAgeSec, ingestLagMs } = useConnectionState();

  if (status === "offline") {
    return (
      <div
        className={`flex items-center gap-1.5 text-[11px] font-mono text-[#ff7b72] ${className}`}
        title={`Offline: ${errorDetail ?? "Unable to contact API"}`}
      >
        <span className="h-2 w-2 rounded-full bg-[#f85149]" />
        <span>offline</span>
      </div>
    );
  }

  if (status === "connected") {
    return (
      <div
        className={`flex items-center gap-1.5 text-[11px] font-mono text-[#56d364] ${className}`}
        title={`API reachable · Stream active · Lag: ${ingestLagMs ?? 0}ms`}
      >
        <span className="h-2 w-2 rounded-full bg-[#3fb950]" />
        <span>connected</span>
        {ingestLagMs !== null && ingestLagMs > 0 && (
          <span className="text-[10px] text-[#7d8590]">({ingestLagMs}ms)</span>
        )}
      </div>
    );
  }

  if (status === "idle") {
    return (
      <div
        className={`flex items-center gap-1.5 text-[11px] font-mono text-[#7d8590] ${className}`}
        title="API reachable · Stream listening · No events received recently"
      >
        <span className="h-2 w-2 rounded-full bg-[#7d8590]" />
        <span>
          idle {lastEventAgeSec !== null ? `(${lastEventAgeSec}s)` : "(0 events)"}
        </span>
      </div>
    );
  }

  return (
    <div
      className={`flex items-center gap-1.5 text-[11px] font-mono text-[#e3b341] ${className}`}
      title="API reachable · Stream disconnected · Polling active"
    >
      <span className="h-2 w-2 rounded-full bg-[#d29922]" />
      <span>polling</span>
    </div>
  );
};
