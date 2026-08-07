import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, Outlet, RouterProvider, useLocation } from "react-router-dom";
import "./index.css";

import Nav from "./components/Nav";
import StatusBar from "./components/StatusBar";
import CampaignsPage from "./routes/campaigns";
import ComparePage from "./routes/compare";
import EventsPage from "./routes/events";
import MonitorPage from "./routes/monitor";
import RunDetailPage from "./routes/runDetail";
import RunHistoryPage from "./routes/index";
import OverviewPage from "./routes/overview";
import RulesPage from "./routes/rules";
import SampleDetailPage from "./routes/sampleDetail";
import SamplesPage from "./routes/samples";
import SearchPage from "./routes/search";
import SettingsPage from "./routes/settings";
import WatchlistPage from "./routes/watchlist";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: true, staleTime: 5_000 },
  },
});

function Layout() {
  const location = useLocation();
  return (
    <div className="min-h-screen">
      <Nav />
      {/* The sidebar is fixed, so the content column offsets for it (lg+). */}
      <main className="lg:pl-56">
        <StatusBar />
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
      { path: "/rules", element: <RulesPage /> },
      { path: "/settings", element: <SettingsPage /> },
      { path: "/events", element: <EventsPage /> },
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
