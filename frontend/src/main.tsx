// Entry point — deliberately exports NOTHING so this module stays on React
// Fast Refresh's happy path: with a non-component export (the old
// `export const router`) HMR re-EXECUTED the module body instead of
// hot-swapping, and the guarded mount ran `createRoot()` again on the same
// container — the "duplicate createRoot" warning + a full app remount on
// every edit. The router (routes + Layout + lazy pages) now lives in
// ./appRouter; this file only wires the QueryClient and mounts.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider } from "react-router-dom";
import { getRuns } from "./lib/api";
import { overviewRunParams } from "./routes/overviewHelpers";
import { router } from "./appRouter";
import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: true, staleTime: 5_000 },
  },
});

// Cold-start warm: fire the session-count queries at MODULE scope — they grab
// browser connections in the very first pool batch (a Layout-effect prefetch
// still queued behind the shell's streams + dynamic chunks: /runs used to
// leave the browser 165-300ms after navigation). Two keys because the
// surfaces disagree on purpose — the Overview is the full picture (synthetic
// visible), the status bar mirrors the archive defaults (synthetic + soak
// hidden). We then AWAIT them (capped at 200ms) before mounting React: the
// count is in the shell's FIRST render instead of arriving as a later
// re-render that queues behind the Overview mount (measured: that re-render
// lag made the cold start bimodal at 320-540ms). First paint barely moves —
// it already waits for main-chunk exec + mount (~130-200ms) anyway.
const runsWarm = Promise.allSettled([
  queryClient.prefetchQuery({
    queryKey: ["runs"],
    queryFn: () => getRuns(overviewRunParams()),
    staleTime: 30_000,
  }),
  queryClient.prefetchQuery({
    queryKey: ["statusbar", "runs", "soak", false],
    queryFn: () => getRuns({ include_synthetic: false, include_soak: false }),
    staleTime: 30_000,
  }),
]);

// The status-bar count is the cold-start anchor: awaiting the prefetches
// (already in flight at module scope, capped at 200ms) before mounting means
// the count is warm in the shell's FIRST commit instead of arriving as a
// re-render that queues behind the Overview mount. allSettled never rejects,
// so a dead backend still mounts on time. The mount is guarded so importing
// this module under test (no #root element) is side-effect-free.
const rootEl = document.getElementById("root");
if (rootEl) {
  void runsWarm.then(() => {
    ReactDOM.createRoot(rootEl).render(
      <React.StrictMode>
        <QueryClientProvider client={queryClient}>
          <RouterProvider router={router} />
        </QueryClientProvider>
      </React.StrictMode>,
    );
  });
}
