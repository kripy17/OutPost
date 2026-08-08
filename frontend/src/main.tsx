import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, Outlet, RouterProvider, useLocation } from "react-router-dom";
import "./index.css";

import Nav from "./components/Nav";
import WatchlistToaster from "./components/WatchlistToaster/WatchlistToaster";
import { getMe } from "./lib/api";
import LoginPage from "./routes/login";
import CampaignsPage from "./routes/campaigns";
import ComparePage from "./routes/compare";
import CoveragePage from "./routes/coverage";
import EventsPage from "./routes/events";
import FootprintPage from "./routes/footprint";
import MonitorPage from "./routes/monitor";
import RunDetailPage from "./routes/runDetail";
import RunHistoryPage from "./routes/index";
import OverviewPage from "./routes/overview";
import RulesPage from "./routes/rules";
import SampleDetailPage from "./routes/sampleDetail";
import SamplesPage from "./routes/samples";
import SearchPage from "./routes/search";
import SettingsPage from "./routes/settings";
import ThemesPage from "./routes/themes";
import WatchlistPage from "./routes/watchlist";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: true, staleTime: 5_000 },
  },
});

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
          <Outlet />
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
