import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import React, { Suspense, lazy } from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, Outlet, RouterProvider, useLocation } from "react-router-dom";
import "./index.css";

import Nav from "./components/Nav";
import WatchlistToaster from "./components/WatchlistToaster/WatchlistToaster";
import { getMe } from "./lib/api";

// Route-level code splitting: each page ships as its own chunk so first paint
// only loads the shell + the page you land on (kills the single-bundle chunk
// warning). The Monitor page pulls in the SSE/process-tree machinery, so it
// stays on its own chunk like everything else.
const LoginPage = lazy(() => import("./routes/login"));
const AgentsPage = lazy(() => import("./routes/agents"));
const AuditPage = lazy(() => import("./routes/audit"));
const CampaignsPage = lazy(() => import("./routes/campaigns"));
const ComparePage = lazy(() => import("./routes/compare"));
const CoveragePage = lazy(() => import("./routes/coverage"));
const EventsPage = lazy(() => import("./routes/events"));
const FootprintPage = lazy(() => import("./routes/footprint"));
const MonitorPage = lazy(() => import("./routes/monitor"));
const RunDetailPage = lazy(() => import("./routes/runDetail"));
const RunHistoryPage = lazy(() => import("./routes/index"));
const OverviewPage = lazy(() => import("./routes/overview"));
const RulesPage = lazy(() => import("./routes/rules"));
const SampleDetailPage = lazy(() => import("./routes/sampleDetail"));
const SamplesPage = lazy(() => import("./routes/samples"));
const SearchPage = lazy(() => import("./routes/search"));
const SettingsPage = lazy(() => import("./routes/settings"));
const ThemesPage = lazy(() => import("./routes/themes"));
const WatchlistPage = lazy(() => import("./routes/watchlist"));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: true, staleTime: 5_000 },
  },
});

function RouteFallback() {
  return (
    <div className="flex min-h-[40vh] items-center justify-center">
      <p className="animate-pulse text-sm text-text-muted">Loading…</p>
    </div>
  );
}

function Layout() {
  const location = useLocation();

  // Optional-auth boot gate: probe /auth/me once. When the backend has auth
  // enabled and we're not authenticated, the login screen replaces all
  // content — with auth disabled (zero-config default) this renders nothing
  // and the app behaves exactly as before.
  const { data: me } = useQuery({ queryKey: ["me"], queryFn: getMe, staleTime: 30_000, retry: 1 });
  const needLogin = me !== undefined && me.enabled && !me.authenticated && location.pathname !== "/login";

  if (needLogin) {
    return (
      <div className="min-h-screen">
        <LoginPage />
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      <Nav />
      {/* Global watchlist toaster — alive on every page, top-right. */}
      <WatchlistToaster />
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
      { path: "/history", element: <RunHistoryPage /> },
      { path: "/monitor", element: <MonitorPage /> },
      { path: "/search", element: <SearchPage /> },
      { path: "/compare", element: <ComparePage /> },
      { path: "/watchlist", element: <WatchlistPage /> },
      { path: "/agents", element: <AgentsPage /> },
      { path: "/audit", element: <AuditPage /> },
      { path: "/campaigns", element: <CampaignsPage /> },
      { path: "/coverage", element: <CoveragePage /> },
      { path: "/rules", element: <RulesPage /> },
      { path: "/settings", element: <SettingsPage /> },
      { path: "/themes", element: <ThemesPage /> },
      { path: "/events", element: <EventsPage /> },
      { path: "/footprint", element: <FootprintPage /> },
      { path: "/samples", element: <SamplesPage /> },
      { path: "/samples/:sampleId", element: <SampleDetailPage /> },
      { path: "/runs/:runId", element: <RunDetailPage /> },
    ],
  },
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </React.StrictMode>,
);
