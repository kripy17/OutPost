import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import MonitorPage from "../routes/monitor";
import * as api from "../lib/api";

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

  it("renders Attack Chain & Behavioral Execution Story when canary simulation runs", async () => {
    vi.spyOn(api, "getPlaybooks").mockResolvedValue([
      {
        id: "apt29-cloud-intrusion",
        name: "APT-29 / Midnight Blizzard",
        severity: "critical",
        platform: "linux",
        description: "Simulates stealth host discovery",
        techniques: ["T1082"],
        stages_count: 1,
        stages: [
          { name: "Stage 1: Host Fingerprint", cmd: "whoami && id && uname -a" },
        ],
      },
    ]);
    vi.spyOn(api, "runLiveSimulation").mockResolvedValue({
      run_id: "sim_test123",
      scenario_id: "apt29-cloud-intrusion",
      name: "APT-29 / Midnight Blizzard",
      platform: "linux",
      terminal_output: "whoami\nroot",
      terminal_lines: ["whoami", "root"],
      stages: [
        {
          stage: 1,
          name: "Stage 1: Host Fingerprint",
          cmd: "whoami && id && uname -a",
          stdout: "root",
          stderr: "",
          exit_code: 0,
          status: "success",
        },
      ],
      events_count: 3,
      alerts_count: 1,
      alerts: [{ rule_name: "Host Discovery", severity: "suspicious", technique: "T1082" }],
      risk_score: 85,
      process_tree: [],
      dropped_artifacts: [],
      created_files: [{ name: ".sys_cache", size_bytes: 120 }],
      network_connections: [{ ip: "185.220.101.5", port: 443, protocol: "TCP", status: "ESTABLISHED" }],
    });

    renderWithProviders();

    const detonateButtons = await screen.findAllByRole("button", { name: /Detonate Sample/i });
    fireEvent.click(detonateButtons[0]);

    await waitFor(() => {
      expect(screen.getByText("Attack Chain & Execution Story")).toBeInTheDocument();
    });
    expect(screen.getByText(/Executive Causality & Behavioral Attack Narrative/i)).toBeInTheDocument();
    expect(screen.getByText(/Host Fingerprinting & OS Architecture Discovery/i)).toBeInTheDocument();
    expect(screen.getByText(/Executed Subprocess Command/i)).toBeInTheDocument();
    expect(screen.getByText("Raw Terminal Logs")).toBeInTheDocument();
  });
});
