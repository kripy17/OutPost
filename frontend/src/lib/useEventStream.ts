// useEventStream — live push over Server-Sent Events, with a polling fallback.
//
// The backend /events/stream pushes fired alerts; EventSource reconnects
// automatically on drop. If the endpoint is unreachable (backend down, or an
// environment without SSE), the hook simply stops and the app's existing
// react-query polling keeps working — push is an enhancement, never a
// dependency.

import { useEffect, useRef } from "react";
import { BASE_URL } from "./api";

export interface StreamAlert {
  rule_id: string;
  rule_name: string;
  severity: "suspicious" | "malicious";
  run_id: string;
  details: string;
  triggered_at: string;
}

/**
 * Subscribe to live alert pushes. `onAlert` is called for every pushed
 * finding; returns nothing (lifecycle is managed by React). EventSource
 * auto-reconnects, so no manual retry loop is needed.
 */
export function useEventStream(onAlert: (a: StreamAlert) => void): void {
  const handlerRef = useRef(onAlert);
  handlerRef.current = onAlert;

  useEffect(() => {
    let es: EventSource | null = null;
    try {
      es = new EventSource(`${BASE_URL}/events/stream`);
    } catch {
      return; // SSE unavailable (e.g. non-browser) — polling covers us
    }

    es.addEventListener("alert", (e) => {
      try {
        const data = JSON.parse((e as MessageEvent).data as string) as StreamAlert;
        handlerRef.current(data);
      } catch {
        /* malformed frame — ignore, keep the stream alive */
      }
    });

    return () => es?.close();
  }, []);
}
