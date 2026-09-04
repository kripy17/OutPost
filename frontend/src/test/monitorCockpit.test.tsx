import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import MonitorPage from "../routes/monitor";

function renderWithProviders() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <MonitorPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("MonitorPage Live Cockpit", () => {
  it("renders page header and sandbox driver selector", () => {
    renderWithProviders();
    expect(
      screen.getByText("Adversary Simulation & Dynamic Behavioral Sandbox"),
    ).toBeInTheDocument();
    expect(screen.getByText("Sandbox Driver:")).toBeInTheDocument();
  });

  it("renders clean standby terminal state initially without prefilled results", () => {
    renderWithProviders();
    expect(screen.getByText("Sandbox Terminal Standby")).toBeInTheDocument();
    expect(
      screen.getByText(/Select a behavioral canary or vault sample/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/STANDBY · AWAITING TARGET/i)).toBeInTheDocument();
  });

  it("renders real-time behavioral KPI meters in standby", () => {
    renderWithProviders();
    expect(screen.getByText("Files Created")).toBeInTheDocument();
    expect(screen.getByText("Processes")).toBeInTheDocument();
    expect(screen.getByText("Network Sockets")).toBeInTheDocument();
    expect(screen.getByText("Rule Hits")).toBeInTheDocument();
  });

  it("renders detonation gallery tabs for canaries, vault samples, and techniques", () => {
    renderWithProviders();
    expect(
      screen.getByText(/Adversary Canaries & Campaigns/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Vault Executable Samples/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/MITRE Technique Unit Tests/i),
    ).toBeInTheDocument();
  });
});
