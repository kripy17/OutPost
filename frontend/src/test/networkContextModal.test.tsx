import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { NetworkContextModal } from "../components/NetworkContextModal";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("../lib/api", () => ({
  getNetworkSummary: vi.fn().mockResolvedValue({
    dest_ip: "198.51.100.222",
    event_count: 5,
    first_seen: "2026-08-23T11:00:00Z",
    last_seen: "2026-08-23T11:05:00Z",
    hosts: ["host-alpha", "host-beta"],
    processes: [
      { pid: 7700, process_name: "beacon-client", command_line: "./beacon-client" }
    ],
    ports: [
      { dest_port: 8443, protocol: "tcp" }
    ],
    watchlist: { notes: "Suspicious C2 destination" },
    findings: [
      { id: 1, rule_id: "c2-beacon", rule_name: "C2 Beacon Activity", severity: "malicious", details: "Periodic check-in", run_id: "r1" }
    ],
  }),
}));

describe("NetworkContextModal", () => {
  it("renders network context modal with IP and details", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <NetworkContextModal ip="198.51.100.222" onClose={() => {}} />
        </MemoryRouter>
      </QueryClientProvider>
    );

    expect(screen.getByText("198.51.100.222")).toBeInTheDocument();
    expect(await screen.findByText("host-alpha")).toBeInTheDocument();
    expect(await screen.findByText("beacon-client")).toBeInTheDocument();
    expect(await screen.findByText("C2 Beacon Activity")).toBeInTheDocument();
  });
});
