// useEventStream — live push over Server-Sent Events, with a polling fallback.
//
// Thin wrapper over the shared stream hub: the whole app shares ONE
// EventSource (see lib/streamHub.ts — N subscribers used to open N
// connections, stealing HTTP/1.1 pool slots from the cold-start queries).
// The backend /events/stream pushes fired alerts; EventSource reconnects
// automatically on drop. If the endpoint is unreachable (backend down, or an
// environment without SSE), the hook simply stops and the app's existing
// react-query polling keeps working — push is an enhancement, never a
// dependency.

import { useEffect, useRef } from "react";
import {
  subscribeStream,
  type StreamAlert,
  type StreamFleetUpdate,
  type StreamRunUpdate,
  type StreamWatchlist,
} from "./streamHub";

// Re-export the stream payload types so existing callers keep importing them
// from the hook module (the declarations now live in the shared hub).
export type {
  StreamAlert,
  StreamFleetUpdate,
  StreamRunUpdate,
  StreamWatchlist,
  WatchlistMatch,
} from "./streamHub";

/**
 * Subscribe to live pushes. `onAlert` fires for every detection alert;
 * `onWatchlist` (optional) fires when a watched IOC appears in a new batch;
 * `onRunUpdate` (optional) fires when any run gains events or completes;
 * `onFleetUpdate` (optional) fires when an agent heartbeats or a host goes
 * silent — live views use these to refresh instead of waiting for the next
 * poll tick (polling stays as the fallback).
 * Returns nothing (lifecycle is managed by React; the hub's EventSource
 * auto-reconnects, so no manual retry loop is needed).
 */
export function useEventStream(
  onAlert: (a: StreamAlert) => void,
  onWatchlist?: (w: StreamWatchlist) => void,
  onRunUpdate?: (r: StreamRunUpdate) => void,
  onFleetUpdate?: (f: StreamFleetUpdate) => void,
): void {
  const alertRef = useRef(onAlert);
  alertRef.current = onAlert;
  const watchlistRef = useRef(onWatchlist);
  watchlistRef.current = onWatchlist;
  const runUpdateRef = useRef(onRunUpdate);
  runUpdateRef.current = onRunUpdate;
  const fleetUpdateRef = useRef(onFleetUpdate);
  fleetUpdateRef.current = onFleetUpdate;

  useEffect(() => {
    return subscribeStream({
      onAlert: (a) => alertRef.current(a),
      onWatchlist: (w) => watchlistRef.current?.(w),
      onRunUpdate: (r) => runUpdateRef.current?.(r),
      onFleetUpdate: (f) => fleetUpdateRef.current?.(f),
    });
  }, []);
}
