// WatchlistToaster — the "desktop toast" for watchlist-triggered alerting.
//
// Mounted once in the app Layout so it is alive on every page: the moment a
// new batch touches a watched IOC, the backend pushes a `watchlist` SSE event
// and this renders an amber toast with the matching values. Distinct from the
// Monitor's bottom-right alert toasts (top-right, own visual language), and
// clicking a toast jumps straight to that run's detail page.

import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Icon } from "../Icon";
import { useEventStream, type StreamWatchlist } from "../../lib/useEventStream";

interface Toast {
  key: number;
  sampleName: string;
  platform: string;
  runId: string;
  matches: { iocType: string; iocValue: string; label: string }[];
  at: string;
}

// Same IOC-kind tone used across the app (network/registry/file/process).
const KIND_ICON = {
  ip: "network",
  registry: "registry",
  file: "file",
  process: "process",
} as const;

export default function WatchlistToaster() {
  const navigate = useNavigate();
  const [toasts, setToasts] = useState<Toast[]>([]);
  const keyRef = useRef(0);
  const timers = useRef<number[]>([]);

  useEffect(() => () => timers.current.forEach((t) => window.clearTimeout(t)), []);

  useEventStream(
    () => {
      /* alerts are toasted page-locally (Monitor); this is the watchlist lane */
    },
    (w: StreamWatchlist) => {
      const toast: Toast = {
        key: ++keyRef.current,
        sampleName: w.sample_name,
        platform: w.platform,
        runId: w.run_id,
        matches: w.matches.map((m) => ({ iocType: m.ioc_type, iocValue: m.ioc_value, label: m.label })),
        at: new Date().toLocaleTimeString(),
      };
      setToasts((prev) => [...prev.slice(-2), toast]); // keep the newest 3
      const timer = window.setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.key !== toast.key));
      }, 8000);
      timers.current.push(timer);
    },
  );

  if (toasts.length === 0) return null;

  return (
    <div className="pointer-events-none fixed right-4 top-4 z-50 flex w-80 flex-col gap-2">
      {toasts.map((t) => (
        <div
          key={t.key}
          onClick={() => navigate(`/runs/${t.runId}`)}
          className="animate-outpost-toast-in pointer-events-auto cursor-pointer rounded-lg border border-accent/60 bg-bg-elevated p-3 text-left shadow-lg transition-transform duration-150 hover:-translate-y-0.5"
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === "Enter") navigate(`/runs/${t.runId}`);
          }}
        >
          <div className="flex items-start justify-between gap-2">
            <p className="flex items-center gap-1.5 font-mono text-xs font-semibold text-accent">
              <Icon name="star" size={12} />
              Watchlist hit
            </p>
            <button
              onClick={(e) => {
                e.stopPropagation();
                setToasts((prev) => prev.filter((x) => x.key !== t.key));
              }}
              className="text-text-faint transition-colors hover:text-text-primary"
              aria-label="Dismiss watchlist toast"
            >
              <Icon name="x" size={12} />
            </button>
          </div>
          <p className="mt-1 truncate font-mono text-[11px] text-text-primary" title={t.sampleName}>
            {t.sampleName}
            <span className="ml-1.5 text-text-faint">· {t.platform} · {t.at}</span>
          </p>
          <p className="mt-1.5 flex flex-wrap gap-1">
            {t.matches.map((m) => (
              <span
                key={`${m.iocType}-${m.iocValue}`}
                className="inline-flex items-center gap-1 rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-accent"
              >
                <Icon name={KIND_ICON[m.iocType as keyof typeof KIND_ICON] ?? "list"} size={10} />
                <span className="max-w-[10rem] truncate" title={m.iocValue}>
                  {m.iocValue}
                </span>
                {m.label && m.label !== m.iocValue && (
                  <span className="text-text-faint">({m.label})</span>
                )}
              </span>
            ))}
          </p>
        </div>
      ))}
    </div>
  );
}
