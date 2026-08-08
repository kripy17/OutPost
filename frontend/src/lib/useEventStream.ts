// useEventStream — live push over Server-Sent Events, with a polling fallback.
//
// The backend /events/stream pushes fired alerts; EventSource reconnects
// automatically on drop. If the endpoint is unreachable (backend down, or an
// environment without SSE), the hook simply stops and the app's existing
// react-query polling keeps working — push is an enhancement, never a
// dependency.

import { useEffect, useRef } from "react";
import { BASE_URL, getAuthToken } from "./api";

export interface StreamAlert {
  rule_id: string;
  rule_name: string;
  severity: "suspicious" | "malicious";
  run_id: string;
  details: string;
  triggered_at: string;
  // PIDs behind composite rules — lets the Monitor highlight the actors
  // (recon sweep) immediately on the push, before the next poll.
  related_pids?: number[];
}

export interface WatchlistMatch {
  ioc_type: string;
  ioc_value: string;
  label: string;
  event_type: string | null;
  timestamp: string | null;
}

export interface StreamWatchlist {
  run_id: string;
  sample_name: string;
  platform: string;
  matches: WatchlistMatch[];
}

/**
 * Subscribe to live pushes. `onAlert` fires for every detection alert;
 * `onWatchlist` (optional) fires when a watched IOC appears in a new batch.
 * Returns nothing (lifecycle is managed by React); EventSource auto-reconnects,
 * so no manual retry loop is needed.
 */
export function useEventStream(
  onAlert: (a: StreamAlert) => void,
  onWatchlist?: (w: StreamWatchlist) => void,
): void {
  const alertRef = useRef(onAlert);
  alertRef.current = onAlert;
  const watchlistRef = useRef(onWatchlist);
  watchlistRef.current = onWatchlist;

  useEffect(() => {
    let es: EventSource | null = null;
    try {
      // EventSource can't set Authorization headers — when a token exists,
      // pass it as ?token= (the backend's SSE fallback). With no token the
      // URL is untouched, so the zero-config path stays identical.
      const token = getAuthToken();
      const url = token ? `${BASE_URL}/events/stream?token=${encodeURIComponent(token)}` : `${BASE_URL}/events/stream`;
      es = new EventSource(url);
    } catch {
      return; // SSE unavailable (e.g. non-browser) — polling covers us
    }

    es.addEventListener("alert", (e) => {
      try {
        const data = JSON.parse((e as MessageEvent).data as string) as StreamAlert;
        alertRef.current(data);
      } catch {
        /* malformed frame — ignore, keep the stream alive */
      }
    });

    if (watchlistRef.current) {
      es.addEventListener("watchlist", (e) => {
        try {
          const data = JSON.parse((e as MessageEvent).data as string) as StreamWatchlist;
          watchlistRef.current?.(data);
        } catch {
          /* malformed frame — ignore, keep the stream alive */
        }
      });
    }

    return () => es?.close();
  }, []);
}
