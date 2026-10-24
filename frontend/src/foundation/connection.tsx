import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { RefreshCw, WifiOff } from "lucide-react";

export type HealthStatus = "healthy" | "degraded" | "offline";

export interface ConnectionState {
  apiReachable: boolean;
  streamLive: boolean;
  status: HealthStatus;
  lastEventTime: Date | null;
  errorDetail: string | null;
  retryPing: () => Promise<void>;
  markEventReceived: () => void;
  setStreamStatus: (live: boolean) => void;
}

const ConnectionContext = createContext<ConnectionState | null>(null);

export const ConnectionProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [apiReachable, setApiReachable] = useState<boolean>(true);
  const [streamLive, setStreamLive] = useState<boolean>(false);
  const [lastEventTime, setLastEventTime] = useState<Date | null>(null);
  const [errorDetail, setErrorDetail] = useState<string | null>(null);
  const [isRetrying, setIsRetrying] = useState<boolean>(false);

  const pingApi = useCallback(async () => {
    try {
      setIsRetrying(true);
      const res = await fetch("/health", { signal: AbortSignal.timeout(3000) });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }
      setApiReachable(true);
      setErrorDetail(null);
    } catch (err: unknown) {
      setApiReachable(false);
      setStreamLive(false);
      const msg = err instanceof Error ? err.message : "Connection refused";
      setErrorDetail(msg);
    } finally {
      setIsRetrying(false);
    }
  }, []);

  useEffect(() => {
    pingApi();
    const interval = window.setInterval(pingApi, 15000);
    return () => window.clearInterval(interval);
  }, [pingApi]);

  const markEventReceived = useCallback(() => {
    setLastEventTime(new Date());
    setStreamLive(true);
  }, []);

  const setStreamStatus = useCallback((live: boolean) => {
    setStreamLive(live);
  }, []);

  const status: HealthStatus = !apiReachable
    ? "offline"
    : streamLive
    ? "healthy"
    : "degraded";

  return (
    <ConnectionContext.Provider
      value={{
        apiReachable,
        streamLive,
        status,
        lastEventTime,
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
            onClick={() => pingApi()}
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
  const { errorDetail, streamLive, apiReachable } = useConnectionState();

  if (!apiReachable) {
    return (
      <div
        className={`flex items-center gap-1.5 text-[11px] font-mono text-[#ff7b72] ${className}`}
        title={`Offline: ${errorDetail}`}
      >
        <span className="h-2 w-2 rounded-full bg-[#f85149]" />
        <span>offline</span>
      </div>
    );
  }

  if (streamLive) {
    return (
      <div
        className={`flex items-center gap-1.5 text-[11px] font-mono text-[#56d364] ${className}`}
        title="API reachable, live stream active"
      >
        <span className="h-2 w-2 rounded-full bg-[#3fb950]" />
        <span>connected</span>
      </div>
    );
  }

  return (
    <div
      className={`flex items-center gap-1.5 text-[11px] font-mono text-[#e3b341] ${className}`}
      title="API reachable, stream reconnecting"
    >
      <span className="h-2 w-2 rounded-full bg-[#d29922]" />
      <span>polling</span>
    </div>
  );
};
