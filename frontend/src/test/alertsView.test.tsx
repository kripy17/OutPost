import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { ToastProvider } from "../foundation";
import { AlertsView } from "../features/alerts/AlertsView";
import { AlertItem } from "../features/alerts/types";

// Mock 20 test alerts
const MOCK_ALERTS: AlertItem[] = Array.from({ length: 20 }, (_, i) => ({
  id: i + 1,
  run_id: `run-${100 + i}`,
  rule_id: `RULE-SEC-${1000 + i}`,
  rule_name: `Suspicious Process Execution #${i + 1}`,
  severity: i % 4 === 0 ? "critical" : i % 4 === 1 ? "high" : i % 4 === 2 ? "medium" : "low",
  status: i >= 15 ? "acknowledged" : "open",
  details: `Process spawned anomalous cmd.exe on host-alpha-${i}`,
  triggered_at: "2026-10-24T12:00:00Z",
  occurrence_count: i + 1,
  host_id: `host-alpha-${i}`,
  sample_name: `malware_sample_${i}.exe`,
  related_pid: 4000 + i,
  related_ip: `198.51.100.${i + 1}`,
}));

function renderAlertsView(initialRoute = "/v2/alerts") {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <MemoryRouter initialEntries={[initialRoute]}>
          <Routes>
            <Route path="/v2/alerts" element={<AlertsView />} />
          </Routes>
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>
  );
}

describe("Alerts View & Keyboard Triage", () => {
  let originalClientHeight: PropertyDescriptor | undefined;

  beforeEach(() => {
    originalClientHeight = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientHeight");
    Object.defineProperty(HTMLElement.prototype, "clientHeight", { configurable: true, value: 600 });
    Object.defineProperty(HTMLElement.prototype, "offsetHeight", { configurable: true, value: 600 });

    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((url: string) => {
        if (typeof url === "string" && url.includes("/alerts?limit=")) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve(MOCK_ALERTS),
          });
        }
        if (typeof url === "string" && url.includes("/events?limit=")) {
          return Promise.resolve({
            ok: true,
            json: () =>
              Promise.resolve([
                {
                  id: 991,
                  event_type: "PROCESS_CREATE",
                  timestamp: "2026-10-24T11:59:50Z",
                  process_name: "powershell.exe",
                },
                {
                  id: 992,
                  event_type: "NETWORK_CONNECT",
                  timestamp: "2026-10-24T12:00:05Z",
                  process_name: "powershell.exe",
                },
              ]),
          });
        }
        if (typeof url === "string" && url.includes("/alerts/bulk")) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ updated: 1 }),
          });
        }
        if (typeof url === "string" && url.includes("/fp")) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ status: "feedback_recorded" }),
          });
        }
        if (typeof url === "string" && url.includes("/cases")) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ id: 801, title: "Investigation" }),
          });
        }
        return Promise.reject(new Error(`Unhandled mock fetch url: ${url}`));
      })
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
    if (originalClientHeight) {
      Object.defineProperty(HTMLElement.prototype, "clientHeight", originalClientHeight);
    }
  });

  it("renders queue with severity markers and unreviewed counter", async () => {
    renderAlertsView();

    // 15 out of 20 are open
    await waitFor(() => {
      expect(screen.getByTestId("unreviewed-counter")).toHaveTextContent("15 unreviewed remaining");
    });

    // Verify presence of table grid and rows
    const grid = screen.getByRole("grid");
    expect(grid).toBeInTheDocument();
    expect(within(grid).getByText("Suspicious Process Execution #1")).toBeInTheDocument();
  });

  it("navigates rows with j and k keyboard shortcuts", async () => {
    renderAlertsView();

    await waitFor(() => {
      expect(screen.getByTestId("alert-detail-drawer")).toBeInTheDocument();
    });

    const drawer = screen.getByTestId("alert-detail-drawer");
    expect(within(drawer).getByText("Suspicious Process Execution #1")).toBeInTheDocument();

    // Press 'j' to navigate down to row 2
    fireEvent.keyDown(window, { key: "j" });
    await waitFor(() => {
      expect(within(drawer).getByText("Suspicious Process Execution #2")).toBeInTheDocument();
    });

    // Press 'k' to navigate back up to row 1
    fireEvent.keyDown(window, { key: "k" });
    await waitFor(() => {
      expect(within(drawer).getByText("Suspicious Process Execution #1")).toBeInTheDocument();
    });
  });

  it("acknowledges alert optimistically and auto-advances on 'a' key", async () => {
    renderAlertsView();

    await waitFor(() => {
      expect(screen.getByTestId("unreviewed-counter")).toHaveTextContent("15 unreviewed remaining");
    });

    // Focus is on alert #1 (status: "open")
    fireEvent.keyDown(window, { key: "a" });

    // Optimistically decrements unreviewed counter
    await waitFor(() => {
      expect(screen.getByTestId("unreviewed-counter")).toHaveTextContent("14 unreviewed remaining");
    });

    // Verify network call
    expect(fetch).toHaveBeenCalledWith(
      "/alerts/bulk",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ ids: [1], status: "acknowledged" }),
      })
    );
  });

  it("marks false positive optimistically on 'f' key", async () => {
    renderAlertsView();

    await waitFor(() => {
      expect(screen.getByTestId("alert-detail-drawer")).toBeInTheDocument();
    });

    // Press 'f' to mark false positive
    fireEvent.keyDown(window, { key: "f" });

    // Verify POST call to feedback endpoint
    await waitFor(() => {
      expect(fetch).toHaveBeenCalledWith(
        "/alerts/1/fp",
        expect.objectContaining({
          method: "POST",
        })
      );
    });
  });

  it("opens escalate to case dialog on 'e' key and confirms case creation", async () => {
    renderAlertsView();

    await waitFor(() => {
      expect(screen.getByTestId("alert-detail-drawer")).toBeInTheDocument();
    });

    // Press 'e'
    fireEvent.keyDown(window, { key: "e" });

    // Dialog appears with target and effect
    await waitFor(() => {
      expect(screen.getByText("Open Active Case")).toBeInTheDocument();
    });
    expect(
      screen.getByText(/Suspicious Process Execution #1 \(#1\)/i)
    ).toBeInTheDocument();

    // Confirm dialog
    const createBtn = screen.getByRole("button", { name: "Create Case" });
    fireEvent.click(createBtn);

    await waitFor(() => {
      expect(fetch).toHaveBeenCalledWith(
        "/cases",
        expect.objectContaining({
          method: "POST",
          body: expect.stringContaining("Suspicious Process Execution #1"),
        })
      );
    });
  });

  it("renders detail drawer with defanged entity and correlated events", async () => {
    renderAlertsView("/v2/alerts?selected=1");

    await waitFor(() => {
      expect(screen.getByTestId("alert-detail-drawer")).toBeInTheDocument();
    });

    const drawer = screen.getByTestId("alert-detail-drawer");

    // Defanged IP indicator: 198[.]51[.]100[.]1
    expect(within(drawer).getByText("198[.]51[.]100[.]1")).toBeInTheDocument();

    // Neighboring correlated telemetry events
    await waitFor(() => {
      expect(within(drawer).getByText("PROCESS_CREATE")).toBeInTheDocument();
      expect(within(drawer).getByText("NETWORK_CONNECT")).toBeInTheDocument();
    });
  });

  it("displays error state with retry button on network failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(() =>
        Promise.resolve({
          ok: false,
          status: 503,
          statusText: "Service Unavailable",
        })
      )
    );

    renderAlertsView();

    await waitFor(() => {
      expect(screen.getByText(/HTTP 503: Failed to load alerts/i)).toBeInTheDocument();
    });
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
  });
});
