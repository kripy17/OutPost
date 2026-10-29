import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { routes } from "../appRouter";

describe("Offline Resilience Across All Routes", () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
      },
    });
    // Mock global fetch to reject with Connection Refused / Network Error
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("Failed to fetch: Connection refused")));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const testRoutes = [
    "/samples",
    "/monitor",
    "/analysis",
    "/events",
    "/rules",
    "/coverage",
    "/watchlist",
    "/search",
    "/settings",
    "/samples/sample_remcos_01",
    "/runs/dyn_db3a8da614ef",
  ];

  for (const r of testRoutes) {
    it(`renders ${r} without throwing Unexpected Application Error`, async () => {
      const memoryRouter = createMemoryRouter(routes, {
        initialEntries: [r],
      });

      render(
        <QueryClientProvider client={queryClient}>
          <RouterProvider router={memoryRouter} />
        </QueryClientProvider>
      );

      // Check that React Router didn't crash into its default "Unexpected Application Error!" screen
      await waitFor(() => {
        expect(screen.queryByText(/Unexpected Application Error/i)).toBeNull();
      });
    });
  }
});
