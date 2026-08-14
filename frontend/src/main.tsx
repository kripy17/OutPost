import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import React, { Suspense, lazy } from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, Navigate, Outlet, RouterProvider, useLocation } from "react-router-dom";
import { getRuns } from "./lib/api";
import { overviewRunParams } from "./routes/overviewHelpers";
import "./index.css";

import BrowserCheck from "./components/BrowserCheck/BrowserCheck";
import BrowserNotifications from "./components/BrowserNotifications/BrowserNotifications";
import Nav from "./components/Nav";
import WatchlistToaster from "./components/WatchlistToaster/WatchlistToaster";
import { getMe, getMeta } from "./lib/api";

// Route-level code splitting: each page ships as its own chunk so first paint
// only loads the shell + the page you land on (kills the single-bundle chunk
// warning). The Monitor page pulls in the SSE/process-tree machinery, so it
// stays on its own chunk like everything else.
const LoginPage = lazy(() => import("./routes/login"));
const AgentsPage = lazy(() => import("./routes/agents"));
const AuditPage = lazy(() => import("./routes/audit"));
const CampaignsPage = lazy(() => import("./routes/campaigns"));
const CoveragePage = lazy(() => import("./routes/coverage"));
const EventsPage = lazy(() => import("./routes/events"));
const FindingsPage = lazy(() => import("./routes/findings"));
const FootprintPage = lazy(() => import("./routes/footprint"));
const MonitorPage = lazy(() => import("./routes/monitor"));
const NotFoundPage = lazy(() => import("./routes/notFound"));
const RunDetailPage = lazy(() => import("./routes/runDetail"));
const RunHistoryPage = lazy(() => import("./routes/index"));
const OverviewPage = lazy(() => import("./routes/overview"));
const RulesPage = lazy(() => import("./routes/rules"));
const SampleDetailPage = lazy(() => import("./routes/sampleDetail"));
const SamplesPage = lazy(() => import("./routes/samples"));
const SearchPage = lazy(() => import("./routes/search"));
const SettingsPage = lazy(() => import("./routes/settings"));
const WatchlistPage = lazy(() => import("./routes/watchlist"));
const WelcomePage = lazy(() => import("./routes/welcome"));

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

function RouteFallback() {
  return (
    <div className="flex min-h-[40vh] items-center justify-center">
      <p className="animate-pulse text-sm text-text-muted">Loading…</p>
    </div>
  );
}



function Layout() {
  const location = useLocation();

  // Both boot probes run unconditionally (hook order must be stable): the
  // optional-auth gate and the first-run gate below only decide *which*
  // content renders, never whether the hooks run.
  const { data: me } = useQuery({ queryKey: ["me"], queryFn: getMe, staleTime: 30_000, retry: 1 });
  const { data: meta } = useQuery({ queryKey: ["meta"], queryFn: getMeta, staleTime: 30_000, retry: 1 });

  // Optional-auth boot gate: probe /auth/me once. When the backend has auth
  // enabled and we're not authenticated, the login screen replaces all
  // content — with auth disabled (zero-config default) this renders nothing
  // and the app behaves exactly as before.
  const needLogin = me !== undefined && me.enabled && !me.authenticated && location.pathname !== "/login";
  if (needLogin) {
    return (
      <div className="min-h-screen">
        <LoginPage />
      </div>
    );
  }

  // First-run gate: a fresh install (no sessions, no onboarding choice)
  // lands on the welcome screen — seed the labeled demo campaign or start
  // empty with the guided install-agent flow. Once the choice is recorded,
  // /meta reports first_run=false and the gate never fires again.
  if (meta?.first_run && location.pathname !== "/welcome") {
    return <Navigate to="/welcome" replace />;
  }

  return (
    <div className="min-h-screen">
      {/* Narrow-window notice — this is a desk tool, not a phone app (spec).
          CSS-only: hidden on lg+ screens, so it never touches a real desk. */}
      <div className="narrow-notice" role="note">
        Best viewed at 1024px+ — this is a desk tool, not a phone app.
      </div>
      {/* Old-browser warning — only renders when the engine misses the CSS
          floor (see lib/browserSupport.ts); dismissed for the session. */}
      <BrowserCheck />
      <Nav />
      {/* Global watchlist toaster — alive on every page, top-right. */}
      <WatchlistToaster />
      {/* Native browser notifications for high-severity alerts while the tab
          is unfocused (spec). Opt-in via Settings → Browser notifications. */}
      <BrowserNotifications />
      {/* The left rail is fixed; the content column offsets for it (lg+).
          Both widths come from var(--rail-w), so the collapsed icon-only rail
          and the content offset always match. */}
      <main className="transition-[padding] duration-200 ease-out lg:pl-[var(--rail-w)]">
        {/* Route-keyed fade-up: every navigation rises in once, deliberately. */}
        <div key={location.pathname} className="animate-fade-up">
          <Suspense fallback={<RouteFallback />}>
            <Outlet />
          </Suspense>
        </div>
      </main>
    </div>
  );
}

const router = createBrowserRouter([
  {
    element: <Layout />,
    children: [
      { path: "/", element: <OverviewPage /> },
      { path: "/welcome", element: <WelcomePage /> },
      { path: "/history", element: <RunHistoryPage /> },
      { path: "/monitor", element: <MonitorPage /> },
      { path: "/search", element: <SearchPage /> },
      { path: "/watchlist", element: <WatchlistPage /> },
      { path: "/agents", element: <AgentsPage /> },
      { path: "/audit", element: <AuditPage /> },
      { path: "/findings", element: <FindingsPage /> },
      { path: "/triage", element: <Navigate to="/findings" replace /> }, // the queue moved to its own page
      { path: "/campaigns", element: <CampaignsPage /> },
      { path: "/coverage", element: <CoveragePage /> },
      { path: "/rules", element: <RulesPage /> },
      { path: "/settings", element: <SettingsPage /> },
      { path: "/events", element: <EventsPage /> },
      { path: "/footprint", element: <FootprintPage /> },
      { path: "/samples", element: <SamplesPage /> },
      { path: "/samples/:sampleId", element: <SampleDetailPage /> },
      { path: "/runs/:runId", element: <RunDetailPage /> },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
]);

// The status-bar count is the cold-start anchor: awaiting the prefetches
// (already in flight at module scope, capped at 200ms) before mounting means
// the count is warm in the shell's FIRST commit instead of arriving as a
// re-render that queues behind the Overview mount. allSettled never rejects,
// so a dead backend still mounts on time. The root element exists — module
// scripts are deferred, so the DOM is parsed before this runs.
void runsWarm.then(() => {
  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </React.StrictMode>,
  );
});
