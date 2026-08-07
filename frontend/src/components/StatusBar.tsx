// StatusBar — the deck's live pulse: backend health, latest finding, session
// count. Sticky on desktop (the fixed rail owns the left edge, so top is free);
// on mobile it scrolls away with the content instead of stacking under the
// compact nav. Every value comes from react-query so the bar refreshes itself.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getHealth, getRecentAlerts, getRuns } from "../lib/api";
import { useEventStream } from "../lib/useEventStream";

const REALTIME = { refetchInterval: 10_000 } as const;

function PulseDot({ state }: { state: "online" | "offline" | "connecting" }) {
  const tone =
    state === "online"
      ? "bg-risk-clean"
      : state === "offline"
        ? "bg-risk-malicious"
        : "bg-text-faint";
  return (
    <span className="relative flex h-1.5 w-1.5" aria-hidden>
      {state === "online" && (
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-risk-clean/60" />
      )}
      <span className={`relative inline-flex h-1.5 w-1.5 rounded-full ${tone}`} />
    </span>
  );
}

export default function StatusBar() {
  const queryClient = useQueryClient();

  // Live push: a fired alert instantly refreshes the pulse (last finding +
  // session count) instead of waiting for the next poll tick. Polling remains
  // as the fallback when SSE is unreachable.
  useEventStream(() => {
    void queryClient.invalidateQueries({ queryKey: ["statusbar"] });
    void queryClient.invalidateQueries({ queryKey: ["alerts"] });
    void queryClient.invalidateQueries({ queryKey: ["runs"] });
  });

  const health = useQuery({
    queryKey: ["health"],
    queryFn: getHealth,
    refetchInterval: 5_000,
  });
  const latest = useQuery({
    queryKey: ["statusbar", "latest-finding"],
    queryFn: () => getRecentAlerts(1),
    ...REALTIME,
  });
  const runs = useQuery({
    queryKey: ["statusbar", "runs"],
    queryFn: () => getRuns(),
    ...REALTIME,
  });

  const online = health.data === true;
  const offline = health.data === false || health.isError;
  const state: "online" | "offline" | "connecting" = online ? "online" : offline ? "offline" : "connecting";

  const latestAlert = latest.data?.[0];
  const latestTime = latestAlert ? `${latestAlert.triggered_at.slice(11, 19)} UTC` : null;
  const sessionCount = runs.isLoading ? "…" : runs.data?.length ?? "—";
  const sessions = runs.data?.length;
  const sessionLabel = sessions === 1 ? "session" : "sessions";

  return (
    <div
      role="status"
      className="border-b border-border-subtle bg-bg-base/80 backdrop-blur-md lg:sticky lg:top-0 lg:z-10"
    >
      <div className="mx-auto flex max-w-7xl items-center gap-x-5 gap-y-1 px-6 py-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-text-faint lg:px-10">
        <span className="flex items-center gap-2 whitespace-nowrap">
          <PulseDot state={state} />
          <span className={online ? "text-risk-clean" : offline ? "text-risk-malicious" : ""}>
            {online ? "api online" : offline ? "api offline" : "connecting"}
          </span>
        </span>

        <span className="hidden items-center gap-2 whitespace-nowrap sm:flex">
          <span className="h-3 w-px bg-border-subtle" aria-hidden />
          <span>last finding</span>
          <span className={latestTime ? "text-text-muted" : ""}>{latestTime ?? "no findings"}</span>
        </span>

        <span className="ml-auto flex items-center gap-2 whitespace-nowrap">
          <span className="hidden h-3 w-px bg-border-subtle sm:block" aria-hidden />
          <span>{sessionCount}</span>
          <span className="text-[9px] tracking-widest text-text-faint/80">{sessionLabel}</span>
        </span>
      </div>
    </div>
  );
}
