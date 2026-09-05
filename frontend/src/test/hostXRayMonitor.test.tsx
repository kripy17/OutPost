import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import EventsPage from "../routes/events";
import type { HostXRaySnapshotData } from "../types";

const {
  mockSnapshot,
  mockTreeData,
  mockNetworkMatrix,
  mockExplanations,
  mockDossier,
  controlProcessMock,
  getForensicCapsuleMock,
} = vi.hoisted(() => {
  const snapshot: HostXRaySnapshotData = {
    success: true,
    metrics: {
      timestamp: "2026-09-05T00:00:00Z",
      platform: "linux",
      hostname: "soc-workstation",
      os_release: "Linux 6.1.0-amd64",
      architecture: "x86_64",
      cpu_percent: 24.5,
      cpu_cores: 8,
      memory_used_mb: 4096,
      memory_total_mb: 16384,
      memory_percent: 25.0,
      swap_used_mb: 256,
      swap_total_mb: 4096,
      swap_percent: 6.25,
      disk_total_gb: 512,
      disk_used_gb: 128,
      disk_free_gb: 384,
      disk_percent: 25.0,
      net_kb_in_sec: 142.5,
      net_kb_out_sec: 38.2,
      load_1m: 1.25,
      load_5m: 1.1,
      load_15m: 0.95,
      uptime_seconds: 7200,
      process_count: 142,
      connection_count: 18,
    },
    process_count: 2,
    socket_count: 2,
    processes: [
      {
        pid: 1337,
        ppid: 1,
        name: "systemd-networkd",
        username: "systemd",
        cpu_percent: 1.5,
        memory_percent: 0.8,
        memory_rss_bytes: 32000000,
        status: "running",
        create_time: 1700000000,
        cmdline: ["/lib/systemd/systemd-networkd"],
        exe: "/lib/systemd/systemd-networkd",
        cwd: "/",
        num_threads: 2,
        package_origin: "systemd (native)",
        is_unmanaged: false,
        socket_count: 2,
      },
      {
        pid: 4096,
        ppid: 1337,
        name: "suspicious_beacon",
        username: "kripy",
        cpu_percent: 45.2,
        memory_percent: 12.4,
        memory_rss_bytes: 256000000,
        status: "running",
        create_time: 1700001000,
        cmdline: ["./suspicious_beacon", "--connect", "198.51.100.2"],
        exe: "/tmp/suspicious_beacon",
        cwd: "/tmp",
        num_threads: 4,
        package_origin: "Unmanaged Binary (no package)",
        is_unmanaged: true,
        socket_count: 1,
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
        pid: 1337,
        process_name: "systemd-networkd",
        direction: "LISTEN",
        remote_ip: null,
        remote_port: null,
      },
      {
        fd: 8,
        family: "AF_INET",
        type: "SOCK_STREAM",
        laddr: "10.0.0.2:45022",
        raddr: "198.51.100.2:443",
        status: "ESTABLISHED",
        pid: 4096,
        process_name: "suspicious_beacon",
        direction: "OUTBOUND",
        remote_ip: "198.51.100.2",
        remote_port: 443,
      },
    ],
  };

  const treeData = [
    {
      pid: 1,
      ppid: 0,
      name: "systemd",
      cpu: 0.1,
      memory_mb: 18.2,
      threads: 1,
      started_at: "2026-09-05T00:00:00Z",
      package_status: "installed",
      package_label: "systemd (native)",
      children: [
        {
          pid: 1337,
          ppid: 1,
          name: "systemd-networkd",
          cpu: 1.5,
          memory_mb: 32.0,
          threads: 2,
          started_at: "2026-09-05T00:01:00Z",
          package_status: "installed",
          package_label: "systemd (native)",
          children: [
            {
              pid: 4096,
              ppid: 1337,
              name: "suspicious_beacon",
              cpu: 45.2,
              memory_mb: 256.0,
              threads: 4,
              started_at: "2026-09-05T00:05:00Z",
              package_status: "unmanaged",
              package_label: "Unmanaged Binary (no package)",
              children: [],
            },
          ],
        },
      ],
    },
  ];

  const networkMatrix = {
    summary: {
      total_sockets: 2,
      public_listeners_count: 1,
      loopback_listeners_count: 0,
      outbound_count: 1,
      multicast_count: 0,
    },
    public_listeners: [
      {
        protocol: "TCP",
        local_ip: "0.0.0.0",
        local_port: 8001,
        remote_ip: null,
        remote_port: null,
        status: "LISTEN",
        pid: 1337,
        process_name: "systemd-networkd",
        is_public_bound: true,
        label: "Public Inbound Port 8001",
      },
    ],
    loopback_listeners: [],
    outbound_connections: [
      {
        protocol: "TCP",
        local_ip: "10.0.0.2",
        local_port: 45022,
        remote_ip: "198.51.100.2",
        remote_port: 443,
        status: "ESTABLISHED",
        pid: 4096,
        process_name: "suspicious_beacon",
        is_external: true,
        endpoint_type: "External Remote IP",
      },
    ],
    multicast_listeners: [],
  };

  const explanations = [
    {
      id: "heuristic_unmanaged_proc",
      tone: "critical" as const,
      title: "Unmanaged Executable in Temporary Directory",
      domain: "Process Forensics",
      why: "Process 'suspicious_beacon' is executing from /tmp without package verification.",
      evidence: ["PID: 4096", "Path: /tmp/suspicious_beacon", "CPU: 45.2%"],
      evidence_count: 3,
      next_step: "Isolate network connection or send SIGSTOP/SIGKILL to neutralize.",
    },
  ];

  const dossier = {
    target: {
      pid: 4096,
      ppid: 1337,
      name: "suspicious_beacon",
      cmdline: "./suspicious_beacon --connect 198.51.100.2",
      exe: "/tmp/suspicious_beacon",
      cwd: "/tmp",
      user: "kripy",
      status: "running",
      started_at: "2026-09-05T00:05:00Z",
      create_time: 1700001000,
      threads: 4,
      memory_mb: 256.0,
      memory_gib_str: "0.25 GiB",
      cpu_percent: 45.2,
      disk_io_str: "1.2 MB read / 0.8 MB write",
      gpu_clients_count: 0,
      uptime_str: "2h 00m",
    },
    security: {
      package_provenance: {
        status: "unmanaged_suspicious",
        label: "Unmanaged Binary (no package)",
        managed: false,
      },
      capabilities_effective: [
        { name: "cap_net_raw", is_dangerous: true },
        { name: "cap_sys_ptrace", is_dangerous: true },
      ],
      seccomp: "disabled",
    },
    launch_chain: {
      supervisor: "systemd-networkd",
      service_scope: "user.slice",
      is_grouped: false,
      description: "Launched via subshell invocation from /tmp",
      chain: [
        { id: "1", name: "systemd", role: "Init system", pid: 1, icon: "system" },
        { id: "1337", name: "systemd-networkd", role: "Network Daemon", pid: 1337, icon: "network" },
        { id: "4096", name: "suspicious_beacon", role: "Target Process", pid: 4096, icon: "alert" },
      ],
    },
    device_access: {
      microphone: { in_use: false, devices: [], label: "Microphone" },
      camera: { in_use: false, devices: [], label: "Webcam" },
      screen_capture: { in_use: false, label: "Screen Capture" },
      audio_capture: { in_use: false, label: "Audio Capture" },
      audio_playback: { in_use: false, devices: [], label: "Audio Playback" },
      video_capture: { in_use: false, label: "Video Capture" },
      gpu: { in_use: false, nodes: [], client_count: 0, label: "GPU Acceleration" },
    },
    files_ipc: [
      { fd: 0, type: "CHR", path: "/dev/null", is_deleted: false, is_memfd: false },
      { fd: 1, type: "FIFO", path: "pipe:[123456]", is_deleted: false, is_memfd: false },
      { fd: 3, type: "REG", path: "/tmp/beacon.dat", is_deleted: false, is_memfd: false },
      { fd: 4, type: "MEMFD", path: "/memfd:payload (deleted)", is_memfd: true, is_deleted: true },
    ],
    connections: [
      {
        protocol: "TCP",
        local_ip: "10.0.0.2",
        local_port: 45022,
        remote_ip: "198.51.100.2",
        remote_port: 443,
        status: "ESTABLISHED",
      },
    ],
    findings: [],
  };

  const ctrlMock = vi.fn().mockImplementation((pid: number, action: string) =>
    Promise.resolve({
      pid,
      action,
      signal: action === "kill" ? "SIGKILL" : "SIGTERM",
      success: true,
      message: `Signal ${action.toUpperCase()} delivered to PID ${pid}`,
      timestamp: "2026-09-05T00:10:00Z",
    }),
  );

  const capsuleMock = vi.fn().mockImplementation((pid: number) =>
    Promise.resolve({
      schema_version: "outpost-capsule-v1",
      pid,
      exported_at: "2026-09-05T00:10:00Z",
      dossier,
    }),
  );

  return {
    mockSnapshot: snapshot,
    mockTreeData: treeData,
    mockNetworkMatrix: networkMatrix,
    mockExplanations: explanations,
    mockDossier: dossier,
    controlProcessMock: ctrlMock,
    getForensicCapsuleMock: capsuleMock,
  };
});

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    getHostXRaySnapshot: vi.fn().mockImplementation(() => Promise.resolve(mockSnapshot)),
    getProcessTree: vi.fn().mockImplementation(() => Promise.resolve(mockTreeData)),
    getNetworkMatrix: vi.fn().mockImplementation(() => Promise.resolve(mockNetworkMatrix)),
    getBehavioralExplanations: vi.fn().mockImplementation(() => Promise.resolve(mockExplanations)),
    getXRayFullTargetDossier: vi.fn().mockImplementation((pid: number) => {
      if (pid === 4096) return Promise.resolve(mockDossier);
      return Promise.resolve({
        ...mockDossier,
        target: { ...mockDossier.target, pid, name: `process-${pid}` },
      });
    }),
    controlProcessXRay: controlProcessMock,
    getForensicCapsule: getForensicCapsuleMock,
  };
});

function renderEventsPage(initialUrl = "/events") {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialUrl]}>
        <EventsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Host X-Ray & Live System Monitor", () => {
  it("renders Executive Pulse HUD with real OS telemetry", async () => {
    renderEventsPage();

    expect(await screen.findByText(/Host X-Ray · Live System Monitor/i)).toBeInTheDocument();
    expect(screen.getByText("Live Real-Time")).toBeInTheDocument();

    // OS Identity Badge (wait for snapshot query to resolve)
    expect(await screen.findByText(/soc-workstation/i)).toBeInTheDocument();

    // CPU Pulse
    expect(screen.getByText("CPU Pulse")).toBeInTheDocument();
    expect(screen.getByText("24.5%")).toBeInTheDocument();
    expect(screen.getByText("8 Cores")).toBeInTheDocument();

    // Memory Active
    expect(screen.getByText("Memory Active")).toBeInTheDocument();
    expect(screen.getAllByText("4096").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/16384 MB/i)).toBeInTheDocument();

    // Storage Volume
    expect(screen.getByText("Storage Volume")).toBeInTheDocument();
    expect(screen.getByText("128")).toBeInTheDocument();
    expect(screen.getByText(/\/ 512 GB/i)).toBeInTheDocument();

    // Network & Sockets
    expect(screen.getByText("Network & Sockets")).toBeInTheDocument();
    expect(screen.getByText("142.5 KB/s in")).toBeInTheDocument();
  });

  it("renders live processes table, handles sorting and universal filtering", async () => {
    renderEventsPage();

    // Wait for processes to load
    expect(await screen.findByText("systemd-networkd")).toBeInTheDocument();
    expect(screen.getByText("suspicious_beacon")).toBeInTheDocument();

    // Verify package provenance tag
    expect(screen.getByText("Unmanaged Binary")).toBeInTheDocument();

    // Test universal text filter
    const searchInput = screen.getByPlaceholderText(/Filter by process name, PID, command line/i);
    fireEvent.change(searchInput, { target: { value: "suspicious" } });

    expect(screen.getByText("suspicious_beacon")).toBeInTheDocument();
    expect(screen.queryByText("systemd-networkd")).not.toBeInTheDocument();

    // Reset filter
    fireEvent.change(searchInput, { target: { value: "" } });
    expect(screen.getByText("systemd-networkd")).toBeInTheDocument();

    // Test quick filter button "Unmanaged / Temp Path"
    const unmanagedFilterBtn = screen.getByRole("button", { name: /Unmanaged \/ Temp Path/i });
    fireEvent.click(unmanagedFilterBtn);

    expect(screen.getByText("suspicious_beacon")).toBeInTheDocument();
    expect(screen.queryByText("systemd-networkd")).not.toBeInTheDocument();
  });

  it("switches across sub-view decks (Processes, Tree, Network, Insights, Hardware)", async () => {
    renderEventsPage();

    // Default deck: Live Processes
    expect(await screen.findByText("Live Processes")).toBeInTheDocument();

    // Deck 2: Causality Tree
    const treeTab = screen.getByRole("button", { name: /Causality Tree/i });
    fireEvent.click(treeTab);
    expect(await screen.findByText("Process Causality Tree")).toBeInTheDocument();

    // Deck 3: Network Matrix
    const netTab = screen.getByRole("button", { name: /Network Matrix/i });
    fireEvent.click(netTab);
    expect(await screen.findByText("Public Listeners")).toBeInTheDocument();
    expect(screen.getByText("Outbound Connections")).toBeInTheDocument();

    // Deck 4: Behavioral Insights
    const insightsTab = screen.getByRole("button", { name: /Behavioral Insights/i });
    fireEvent.click(insightsTab);
    expect(await screen.findByText("Unmanaged Executable in Temporary Directory")).toBeInTheDocument();

    // Deck 5: Hardware & Platform Specs
    const hwTab = screen.getByRole("button", { name: /Hardware & Platform/i });
    fireEvent.click(hwTab);
    expect(await screen.findByText("Host System Architecture")).toBeInTheDocument();
    expect(screen.getByText("Linux 6.1.0-amd64")).toBeInTheDocument();
    expect(screen.getByText(/x86_64/i)).toBeInTheDocument();
  });

  it("opens Deep Process X-Ray Drawer and dispatches process lifecycle signals", async () => {
    // Open directly with inspect PID in URL
    renderEventsPage("/events?pid=4096");

    // Drawer header with target PID
    expect(await screen.findByText("PID 4096")).toBeInTheDocument();
    expect(screen.getByText("/tmp/suspicious_beacon")).toBeInTheDocument();
    expect(screen.getByText("/tmp")).toBeInTheDocument();

    // Inspect capabilities and open memfd file
    expect(screen.getByText("cap_net_raw")).toBeInTheDocument();
    expect(screen.getByText(/\/memfd:payload \(deleted\)/i)).toBeInTheDocument();

    // Lifecycle controls: click SIGTERM inside drawer (the second SIGTERM button)
    const termButtons = screen.getAllByRole("button", { name: /SIGTERM/i });
    fireEvent.click(termButtons[termButtons.length - 1]);

    await waitFor(() => {
      expect(controlProcessMock).toHaveBeenCalledWith(4096, "terminate");
    });

    // Lifecycle controls: click SIGKILL inside drawer
    const killButtons = screen.getAllByRole("button", { name: /SIGKILL/i });
    fireEvent.click(killButtons[killButtons.length - 1]);

    await waitFor(() => {
      expect(controlProcessMock).toHaveBeenCalledWith(4096, "kill");
    });

    // Export Capsule
    const exportBtn = screen.getByRole("button", { name: /Export Capsule/i });
    fireEvent.click(exportBtn);

    await waitFor(() => {
      expect(getForensicCapsuleMock).toHaveBeenCalledWith(4096);
    });
  });

  it("allows toggling live telemetry polling and changing polling interval", async () => {
    renderEventsPage();

    const liveToggleBtn = await screen.findByTitle("Pause real-time updates");
    expect(liveToggleBtn).toBeInTheDocument();
    expect(screen.getByText("Live")).toBeInTheDocument();

    // Toggle to Paused
    fireEvent.click(liveToggleBtn);
    expect(screen.getByText("Paused")).toBeInTheDocument();

    // Change polling interval
    const intervalSelect = screen.getByTitle("Telemetry polling frequency");
    fireEvent.change(intervalSelect, { target: { value: "1000" } });
    expect(intervalSelect).toHaveValue("1000");
  });
});
