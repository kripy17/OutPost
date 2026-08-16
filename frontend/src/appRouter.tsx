// The app router, extracted out of main.tsx so the entry file exports
// nothing and stays on React Fast Refresh's happy path.
//
// Before this split, `export const router` lived in main.tsx. A non-component
// export makes the entry non-refreshable, so HMR re-EXECUTED the module body
// instead of hot-swapping — and the guarded mount (`if (rootEl) createRoot…`)
// ran again on the same container, producing the "createRoot() on a container
// that already has a root" warning and a full app remount on every edit.
// main.tsx now only mounts; this module owns the routes. Editing THIS file
// still triggers a full reload (it exports non-components), which is correct
// — the route table changes rarely and a reload is the honest refresh.

import { useQuery } from "@tanstack/react-query";
import { Suspense, lazy } from "react";
import { createBrowserRouter, Navigate, Outlet, useLocation } from "react-router-dom";
import BrowserCheck from "./components/BrowserCheck/BrowserCheck";
import BrowserNotifications from "./components/BrowserNotifications/BrowserNotifications";
import Nav from "./components/Nav";
import WatchlistToaster from "./components/WatchlistToaster/WatchlistToaster";
import { getMe, getMeta } from "./lib/api";
import { shouldShowLogin } from "./routes/authGate";

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

  // Optional-auth boot gate (pure decision — see routes/authGate.ts): probe
  // /auth/me once. When the backend has auth enabled and we're not
  // authenticated, the login screen replaces all content — `/login` itself
  // included (it's a real route, so the sign-in screen renders there too,
  // instead of the gate special-casing a path that used to 404). With auth
  // disabled (zero-config default) this renders nothing and the app behaves
  // exactly as before.
  if (shouldShowLogin(me)) {
    return (
      <div className="min-h-screen">
        <Suspense fallback={<RouteFallback />}>
          <LoginPage />
        </Suspense>
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

export const router = createBrowserRouter([
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
      // The sign-in screen is a real route: while unauthenticated the boot
      // gate above short-circuits to it from every path, and once
      // authenticated (or with auth disabled) a direct /login visit renders
      // it in the layout. A dead path here is what made /login 404 — keep it
      // registered.
      { path: "/login", element: <LoginPage /> },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
]);
