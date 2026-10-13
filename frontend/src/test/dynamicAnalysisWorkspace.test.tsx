import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { configure, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { ExecutionRunsTable } from "../components/dynamicAnalysis/ExecutionRunsTable";
import { LaunchRunDrawer } from "../components/dynamicAnalysis/LaunchRunDrawer";
import { DynamicRunHeader } from "../components/dynamicAnalysis/DynamicRunHeader";
import { ExecutionSummaryTab } from "../components/dynamicAnalysis/ExecutionSummaryTab";
import { ProcessActivityTab } from "../components/dynamicAnalysis/ProcessActivityTab";
import { NetworkActivityTab } from "../components/dynamicAnalysis/NetworkActivityTab";
import { FileSystemArtifactsTab } from "../components/dynamicAnalysis/FileSystemArtifactsTab";
import { BehavioralEventsTab } from "../components/dynamicAnalysis/BehavioralEventsTab";
import AnalysisDetailPage from "../routes/analysisDetail";
import type { AnalysisJob, AnalysisObservation, Finding, SampleRow } from "../types";

configure({ asyncUtilTimeout: 4000 });

// Hoisted mock data
const mockJob: AnalysisJob = {
  run_id: "dyn_run_998877665544",
  backend: "isolated-outpost",
  status: "completed",
  progress: 100,
  events: 42,
  alerts: 3,
  risk_score: 9,
  sample_name: "ransomware_dropper.bin",
  started_at: "2026-10-10T14:00:00Z",
  finished_at: "2026-10-10T14:00:45Z",
  error: null,
  result: {
    exit_code: 0,
    isolation_driver: "bubblewrap",
  },
};

const mockFindings: Finding[] = [
  {
    id: 101,
    run_id: "dyn_run_998877665544",
    rule_id: "t1059_cmd_spawn",
    rule_name: "Suspicious Child Process Spawning",
    severity: "malicious",
    triggered_at: "2026-10-10T14:00:15Z",
    related_pid: 2048,
    related_ip: null,
    details: "Process spawned hidden cmd.exe with encoded arguments",
    status: "open",
    status_comment: null,
    status_at: null,
    source: "detection",
    confidence: "high",
    disposition: null,
    seen_at: null,
    investigation_id: null,
  },
  {
    id: 102,
    run_id: "dyn_run_998877665544",
    rule_id: "t1071_c2_beacon",
    rule_name: "Fast Flux C2 Beaconing",
    severity: "malicious",
    triggered_at: "2026-10-10T14:00:25Z",
    related_pid: 2048,
    related_ip: "198.51.100.88",
    details: "Repetitive outbound TCP connection to unlisted external C2",
    status: "open",
    status_comment: null,
    status_at: null,
    source: "detection",
    confidence: "high",
    disposition: null,
    seen_at: null,
    investigation_id: null,
  },
];

const mockObservations: AnalysisObservation[] = [
  {
    id: 1,
    run_id: "dyn_run_998877665544",
    timestamp: "2026-10-10T14:00:05Z",
    event_type: "process_create",
    process_name: "dropper.bin",
    pid: 1024,
    ppid: 1,
    command_line: "/sandbox/target/dropper.bin --quiet",
    exe_path: "/sandbox/target/dropper.bin",
    host_id: "outpost-node-01",
    boot_id: "b007-cafe-1234",
    process_start_time: "2026-10-10T14:00:04.990Z",
  },
  {
    id: 2,
    run_id: "dyn_run_998877665544",
    timestamp: "2026-10-10T14:00:12Z",
    event_type: "process_create",
    process_name: "cmd.exe",
    pid: 2048,
    ppid: 1024,
    command_line: "cmd.exe /c echo vssadmin delete shadows",
    exe_path: "C:\\Windows\\System32\\cmd.exe",
    host_id: "outpost-node-01",
    boot_id: "b007-cafe-1234",
    process_start_time: "2026-10-10T14:00:11.850Z",
  },
  {
    id: 3,
    run_id: "dyn_run_998877665544",
    timestamp: "2026-10-10T14:00:18Z",
    event_type: "network_connection",
    process_name: "dropper.bin",
    pid: 1024,
    dest_ip: "198.51.100.88",
    dest_port: 8443,
    protocol: "TCP",
    tls_sni: "c2.evil-operator.cc",
    query: "c2.evil-operator.cc",
  },
  {
    id: 4,
    run_id: "dyn_run_998877665544",
    timestamp: "2026-10-10T14:00:22Z",
    event_type: "file_write",
    process_name: "cmd.exe",
    pid: 2048,
    file_path: "/tmp/dropped_payload.dat",
  },
  {
    id: 5,
    run_id: "dyn_run_998877665544",
    timestamp: "2026-10-10T14:00:28Z",
    event_type: "registry_write",
    process_name: "cmd.exe",
    pid: 2048,
    registry_key: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\payload",
  },
];

const mockSamples: SampleRow[] = [
  {
    sample_id: "samp_001",
    original_name: "suspicious_payload.bin",
    sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    detected_platform: "linux",
    size: 40960,
    created_at: "2026-10-09T10:00:00Z",
    synthetic: false,
    yara_rules: ["backdoor_dropper"],
    vt_detections: 5,
    malware_family: "Mirai",
    family: "botnet",
    runs_count: 1,
  },
];

describe("Dynamic Analysis Modular Workspace", () => {
  it("ExecutionRunsTable renders job rows with exit codes, drivers, and copyable IDs", () => {
    const onCancel = vi.fn();
    render(
      <MemoryRouter>
        <ExecutionRunsTable
          jobs={[mockJob]}
          isLoading={false}
          isError={false}
          onCancelJob={onCancel}
          cancellingId={null}
          statusFilter=""
          backendFilter=""
          searchFilter=""
          severityFilter=""
        />
      </MemoryRouter>,
    );

    expect(screen.getByText("dyn_run_99")).toBeTruthy();
    expect(screen.getByText("ransomware_dropper.bin")).toBeTruthy();
    expect(screen.getByText("bubblewrap")).toBeTruthy();
    expect(screen.getByText("code 0")).toBeTruthy();
    expect(screen.getByText("3 alerts")).toBeTruthy();
    expect(screen.getByText("9")).toBeTruthy(); // risk score in table
  });

  it("LaunchRunDrawer configures isolation boundaries and triggers launch payload", () => {
    const onLaunch = vi.fn();
    const onClose = vi.fn();

    render(
      <LaunchRunDrawer
        isOpen={true}
        onClose={onClose}
        onLaunch={onLaunch}
        isLaunching={false}
        samples={mockSamples}
        drivers={[
          { id: "bubblewrap", name: "Bubblewrap Sandbox", available: true, description: "Linux micro-sandbox", type: "container" },
        ]}
        error={null}
      />,
    );

    // Verify modal elements
    expect(screen.getByText("Detonate Artifact · New Analysis Run")).toBeTruthy();
    expect(screen.getByText("Isolated Dynamic Sandbox", { exact: false })).toBeTruthy();

    // Select dynamic sandbox backend
    fireEvent.click(screen.getByText("Isolated Dynamic Sandbox", { exact: false }));

    // Select artifact from combobox
    const select = screen.getByRole("combobox") as HTMLSelectElement;
    fireEvent.change(select, { target: { value: "samp_001" } });

    // Click launch button
    fireEvent.click(screen.getByText("Launch analysis"));

    expect(onLaunch).toHaveBeenCalledWith(
      expect.objectContaining({
        backend: "isolated-outpost",
        sample_id: "samp_001",
        platform: "linux",
      }),
    );
  });

  it("DynamicRunHeader surfaces compound run metadata and triggers actions", () => {
    const onCancel = vi.fn();
    const onRerun = vi.fn();

    render(
      <MemoryRouter>
        <DynamicRunHeader
          job={mockJob}
          onCancelJob={onCancel}
          isCancelling={false}
          onRerun={onRerun}
          droppedArtifactsCount={2}
        />
      </MemoryRouter>,
    );

    expect(screen.getByText("ransomware_dropper.bin")).toBeTruthy();
    expect(screen.getByText("dyn_run_99")).toBeTruthy();
    expect(screen.getByText("Exit Code 0")).toBeTruthy();
    expect(screen.getByText("Artifacts (2)")).toBeTruthy();
    expect(screen.getByText("Escalate Case")).toBeTruthy();
  });

  it("ExecutionSummaryTab renders threat verdict, timeline facts, and correlated findings", () => {
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter>
          <ExecutionSummaryTab
            job={mockJob}
            findings={mockFindings}
            investigations={[{ id: "inv_42", title: "Ransomware Triage" }]}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    expect(screen.getByText("MALICIOUS SPECIMEN")).toBeTruthy();
    expect(screen.getAllByText(/Suspicious Child Process Spawning/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Fast Flux C2 Beaconing/).length).toBeGreaterThan(0);
    expect(screen.getByText(/Process spawned hidden cmd\.exe/)).toBeTruthy();
  });

  it("ProcessActivityTab builds and renders compound parent-child hierarchy with kernel identity", () => {
    render(
      <ProcessActivityTab
        observations={mockObservations}
        runId={mockJob.run_id}
      />,
    );

    // Both root and child process are rendered in the tree
    expect(screen.getByText("PID 1024")).toBeTruthy();
    expect(screen.getByText("dropper.bin")).toBeTruthy();
    expect(screen.getByText("PID 2048")).toBeTruthy();
    expect(screen.getByText("cmd.exe")).toBeTruthy();
    expect(screen.getByText("PPID 1024")).toBeTruthy();

    // Click on child process to open compound drilldown drawer
    fireEvent.click(screen.getByText("PID 2048"));

    // Check compound process identity
    expect(screen.getByText("outpost-node-01")).toBeTruthy();
    expect(screen.getByText("b007-cafe-1234")).toBeTruthy();
    expect(screen.getAllByText(/vssadmin delete shadows/).length).toBeGreaterThan(0);
    expect(screen.getByText("• /tmp/dropped_payload.dat")).toBeTruthy();
  });

  it("NetworkActivityTab displays chronological sockets and protocol filters", () => {
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter>
          <NetworkActivityTab
            observations={mockObservations}
            runId={mockJob.run_id}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    expect(screen.getByText("198.51.100.88:8443")).toBeTruthy();
    expect(screen.getAllByText("c2.evil-operator.cc").length).toBeGreaterThan(0);
    expect(screen.getByText("Live Egress")).toBeTruthy();
  });

  it("FileSystemArtifactsTab displays file modifications and registry keys", () => {
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter>
          <FileSystemArtifactsTab
            observations={mockObservations}
            runId={mockJob.run_id}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    expect(screen.getByText("/tmp/dropped_payload.dat")).toBeTruthy();
    expect(screen.getByText("WRITE")).toBeTruthy();
    expect(screen.getByText(/RunOnce\\payload/)).toBeTruthy();
    expect(screen.getByText("SET_KEY")).toBeTruthy();
  });

  it("BehavioralEventsTab displays chronological stream and expands JSON view", () => {
    render(
      <MemoryRouter>
        <BehavioralEventsTab
          observations={mockObservations}
          isStatic={false}
        />
      </MemoryRouter>,
    );

    expect(screen.getAllByText("PROCESS_SPAWN").length).toBeGreaterThan(0);
    expect(screen.getByText("NET_CONNECT")).toBeTruthy();
    expect(screen.getByText("FILE_WRITE")).toBeTruthy();
    expect(screen.getByText("REG_SET")).toBeTruthy();

    // Click to expand raw JSON view
    const rawButtons = screen.getAllByText("Raw JSON ▼");
    fireEvent.click(rawButtons[0]);

    expect(screen.getByText("Collapse ▲")).toBeTruthy();
  });
});

describe("AnalysisDetailPage Full Navigation Integration", () => {
  it("allows switching tabs across Process Tree, Network, Files, and Events", async () => {
    // Mock fetch for all endpoints needed by AnalysisDetailPage
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const u = String(input);
        if (u.includes("/auth/me")) {
          return Promise.resolve({ ok: true, status: 200, json: async () => ({ enabled: true, authenticated: true, role: "analyst" }) });
        }
        if (u.includes(`/analysis/${mockJob.run_id}/observations`)) {
          return Promise.resolve({ ok: true, status: 200, json: async () => ({ observations: mockObservations }) });
        }
        if (u.includes(`/analysis/${mockJob.run_id}/findings`)) {
          return Promise.resolve({ ok: true, status: 200, json: async () => mockFindings });
        }
        if (u.includes(`/sandbox/artifacts/${mockJob.run_id}`)) {
          return Promise.resolve({ ok: true, status: 200, json: async () => [{ filename: "payload.elf", size_bytes: 1024, download_url: "/api/download" }] });
        }
        if (u.includes("/investigations")) {
          return Promise.resolve({ ok: true, status: 200, json: async () => ({ investigations: [] }) });
        }
        if (u.includes(`/analysis/${mockJob.run_id}`)) {
          return Promise.resolve({ ok: true, status: 200, json: async () => mockJob });
        }
        return Promise.resolve({ ok: true, status: 200, json: async () => ({}) });
      }),
    );

    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter initialEntries={[`/analysis/${mockJob.run_id}`]}>
          <Routes>
            <Route path="/analysis/:runId" element={<AnalysisDetailPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    // Initial load: summary tab active
    await waitFor(() => expect(screen.getByText("ransomware_dropper.bin")).toBeTruthy());
    expect(screen.getByText("Execution Summary")).toBeTruthy();

    // Switch to Process Tree tab
    fireEvent.click(screen.getByText("Process Tree"));
    await waitFor(() => expect(screen.getByText("PID 1024")).toBeTruthy());
    expect(screen.getByText("PID 2048")).toBeTruthy();

    // Switch to Network Sockets tab
    fireEvent.click(screen.getByText("Network Sockets"));
    await waitFor(() => expect(screen.getByText("198.51.100.88:8443")).toBeTruthy());

    // Switch to Files & Artifacts tab
    fireEvent.click(screen.getByText("Files & Artifacts"));
    await waitFor(() => expect(screen.getByText("payload.elf")).toBeTruthy());

    // Switch to Behavioral Events tab
    fireEvent.click(screen.getByText("Behavioral Events"));
    await waitFor(() => expect(screen.getAllByText("PROCESS_SPAWN").length).toBeGreaterThan(0));
  });
});
