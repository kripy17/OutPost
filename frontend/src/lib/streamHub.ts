// streamHub — ONE EventSource for the whole app, fanned out to subscribers.
//
// Before this existed, every useEventStream caller opened its own long-lived
// SSE connection — three in the shell alone (status cluster, watchlist
// toaster, browser notifications). On HTTP/1.1 (6 connections per origin)
// each permanent stream steals a pool slot forever, queueing the page's
// data queries behind it (measured: the Overview's runs request didn't leave
// the browser until ~200ms because of exactly this). One shared stream keeps
// push semantics identical — EventSource still auto-reconnects — and frees
// the pool for the cold-start queries.
//
// Subscribers register the callbacks they care about; the hub attaches the
// listeners once and fans each frame out to every subscriber that has a
// handler. When the last subscriber disconnects, the stream closes.

import { BASE_URL, getAuthToken } from "./api";

export interface StreamAlert {
  rule_id: string;
  rule_name: string;
  severity: "suspicious" | "malicious";
  run_id: string;
  details: string;
  triggered_at: string;
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

export interface StreamRunUpdate {
  run_id: string;
  events: number;
  completed?: boolean;
  // P0.7 additive extension — the same run-update frame now carries the
  // analysis-job transition (job_id/job_status/progress) and the
  // investigation push (investigation_id + finding_id when a finding was
  // attached/detached; investigation_id alone on create/close/reopen).
  // All optional: old frames and old consumers stay valid.
  job_id?: string;
  job_status?: "queued" | "running" | "completed" | "failed" | "canceled";
  progress?: number;
  investigation_id?: string | null;
  finding_id?: number;
}

export interface StreamFleetUpdate {
  host_id: string;
  online: boolean;
  silent: boolean;
  last_heartbeat?: string | null;
}

export interface StreamSub {
  onAlert?: (a: StreamAlert) => void;
  onWatchlist?: (w: StreamWatchlist) => void;
  onRunUpdate?: (r: StreamRunUpdate) => void;
  onFleetUpdate?: (f: StreamFleetUpdate) => void;
}

let es: EventSource | null = null;
const subs = new Set<StreamSub>();

function ensureStream(): EventSource | null {
  if (es) return es;
  try {
    // EventSource can't set Authorization headers — when a token exists,
    // pass it as ?token= (the backend's SSE fallback). With no token the
    // URL is untouched, so the zero-config path stays identical.
    const token = getAuthToken();
    const url = token
      ? `${BASE_URL}/events/stream?token=${encodeURIComponent(token)}`
      : `${BASE_URL}/events/stream`;
    es = new EventSource(url);
  } catch {
    return null; // SSE unavailable (e.g. non-browser) — polling covers us
  }

  const dispatch = <T,>(name: string, pick: (s: StreamSub) => ((v: T) => void) | undefined) => {
    es!.addEventListener(name, (e) => {
      let data: T;
      try {
        data = JSON.parse((e as MessageEvent).data as string) as T;
      } catch {
        return; // malformed frame — ignore, keep the stream alive
      }
      for (const sub of subs) pick(sub)?.(data);
    });
  };

  dispatch<StreamAlert>("alert", (s) => s.onAlert);
  dispatch<StreamWatchlist>("watchlist", (s) => s.onWatchlist);
  dispatch<StreamRunUpdate>("run-update", (s) => s.onRunUpdate);
  dispatch<StreamFleetUpdate>("fleet-update", (s) => s.onFleetUpdate);

  return es;
}

/** Subscribe to live pushes. Returns an unsubscribe function. */
export function subscribeStream(sub: StreamSub): () => void {
  subs.add(sub);
  ensureStream();
  return () => {
    subs.delete(sub);
    if (subs.size === 0 && es) {
      es.close();
      es = null;
    }
  };
}
