import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import SampleDetailPage from "../routes/sampleDetail";
import type { BehavioralForecast, SampleDetonationResult, SampleRow, SampleStatic } from "../types";

const { mockSample, mockStatic, mockForecast, mockDetonation, mockEvasionDetonation, detonateSampleMock } = vi.hoisted(() => {
  const sample: SampleRow = {
    sample_id: "s_forecast_test",
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    original_name: "c2_dropper.bin",
    size: 40960,
    detected_platform: "linux",
    created_at: "2026-09-05T08:00:00Z",
    synthetic: false,
    yara_rules: ["suspicious_socket_connect", "packed_elf"],
    vt_detections: 7,
    malware_family: "Emotet",
    family: "dropper",
    runs_count: 0,
  };

  const st: SampleStatic = {
    sample_id: "s_forecast_test",
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    available: true,
    size: 40960,
    pe: null,
    elf: null,
    strings: ["/tmp/outpost_canary.sh", "198.51.100.77", "c2.adversary.org"],
    iocs: {
      urls: [],
      ips: ["198.51.100.77"],
      domains: ["c2.adversary.org"],
      hashes: [],
      emails: [],
    },
    entropy: 7.85,
    is_packed: true,
    entropy_histogram: [5.0, 7.8, 7.9],
    static_risk_score: 90,
    static_severity: "malicious",
    risk_factors: ["High entropy packed binary", "Hardcoded command & control IP"],
    capabilities: [{ category: "Command & Control", confidence: "high", matched: ["connect"] }],
  };

  const forecast: BehavioralForecast = {
    sample_id: "s_forecast_test",
    sample_name: "c2_dropper.bin",
    platform: "linux",
    predicted_threat_level: "malicious",
    confidence_score: 92,
    static_risk_score: 90,
    entropy: 7.85,
    is_packed: true,
    summary: "Predicted high-confidence malicious dropper. Expected to initiate outbound socket beaconing to 198.51.100.77 and drop secondary stage scripts into /tmp.",
    explanations: ["High Shannon entropy indicates packing/encryption", "Outbound IP matches known C2 pattern"],
    anticipated_actions: [
      {
        id: "act_c2",
        category: "network",
        title: "Outbound C2 Beaconing",
        severity: "critical",
        description: "Initiates TCP socket communication to external address",
        confidence: "high",
        indicators: ["connect", "socket", "198.51.100.77"],
      },
      {
        id: "act_drop",
        category: "file_drop",
        title: "Secondary Payload Drop",
        severity: "high",
        description: "Writes executable script to ephemeral storage path",
        confidence: "medium",
        indicators: ["/tmp/outpost_canary.sh"],
      },
    ],
    predicted_endpoints: [
      {
        endpoint: "198.51.100.77",
        type: "ipv4",
        protocol: "TCP",
        port: 4444,
        confidence: "high",
      },
    ],
    predicted_mitre_techniques: [
      {
        id: "T1071.001",
        name: "Web Protocols",
        tactic: "Command and Control",
      },
      {
        id: "T1105",
        name: "Ingress Tool Transfer",
        tactic: "Command and Control",
      },
    ],
    predicted_file_drops: [
      {
        path: "/tmp/outpost_canary.sh",
        reason: "Hardcoded staging path in extracted binary strings",
      },
    ],
  };

  const detonation: SampleDetonationResult = {
    run_id: "run_reconcile_001",
    sample_id: "s_forecast_test",
    sample_name: "c2_dropper.bin",
    platform: "linux",
    exit_code: 0,
    terminal_output: "[OutPost Dynamic Sandbox Cage Active]\nExecuting ./c2_dropper.bin\nDropping /tmp/outpost_canary.sh\nConnecting to 198.51.100.77:4444\nExecution complete.",
    terminal_lines: [
      "[OutPost Dynamic Sandbox Cage Active]",
      "Executing ./c2_dropper.bin",
      "Dropping /tmp/outpost_canary.sh",
      "Connecting to 198.51.100.77:4444",
      "Execution complete.",
    ],
    events: [
      { event_type: "process_create", pid: 2001, command_line: "./c2_dropper.bin" },
      { event_type: "file_write", pid: 2001, file_path: "/tmp/outpost_canary.sh" },
      { event_type: "network_connection", pid: 2001, dest_ip: "198.51.100.77", dest_port: 4444 },
    ],
    events_count: 3,
    alerts: [
      {
        id: 1,
        rule_id: "egress_c2",
        rule_name: "Adversary Egress Connection",
        severity: "malicious",
        details: "198.51.100.77:4444",
        run_id: "run_reconcile_001",
      },
    ],
    alerts_count: 1,
    risk_score: 95,
    process_tree: [{ pid: 2001, name: "c2_dropper.bin", cmdline: "./c2_dropper.bin", children: [] }],
    dropped_artifacts: [
      {
        artifact_id: "art_canary",
        filename: "outpost_canary.sh",
        name: "outpost_canary.sh",
        size_bytes: 512,
        entropy: 5.2,
        is_high_entropy: false,
        sha256: "abc1234567890",
        md5: "def12345",
        download_url: "/sandbox/artifacts/run_reconcile_001/outpost_canary.sh",
        preview: ["#!/bin/bash", "echo canary"],
      },
    ],
    forecast,
    reconciliation: {
      accuracy_score: 100,
      confirmed_count: 2,
      dormant_count: 0,
      discovered_count: 1,
      confirmed_predictions: [
        {
          action_id: "act_c2",
          title: "Outbound C2 Beaconing",
          status: "confirmed",
          evidence: "Observed network egress to 198.51.100.77:4444",
        },
        {
          action_id: "act_drop",
          title: "Secondary Payload Drop",
          status: "confirmed",
          evidence: "Observed file write to /tmp/outpost_canary.sh",
        },
      ],
      dormant_predictions: [],
      discovered_runtime_actions: [
        {
          title: "Process Spawn",
          type: "process_create",
          evidence: "PID 2001 spawned ./c2_dropper.bin",
        },
      ],
      evasion_detected: false,
    },
  };

  const evasionDetonation: SampleDetonationResult = {
    ...detonation,
    run_id: "run_evasion_002",
    events_count: 1,
    events: [{ event_type: "process_create", pid: 3001, command_line: "./c2_dropper.bin" }],
    alerts: [],
    alerts_count: 0,
    dropped_artifacts: [],
    reconciliation: {
      accuracy_score: 0,
      confirmed_count: 0,
      dormant_count: 2,
      discovered_count: 0,
      confirmed_predictions: [],
      dormant_predictions: [
        {
          action_id: "act_c2",
          title: "Outbound C2 Beaconing",
          status: "dormant",
          reason: "Did not trigger in isolated observation window",
        },
        {
          action_id: "act_drop",
          title: "Secondary Payload Drop",
          status: "dormant",
          reason: "No file writes observed during execution",
        },
      ],
      discovered_runtime_actions: [],
      evasion_detected: true,
    },
  };

  const detonateMock = vi.fn().mockResolvedValue(detonation);

  return {
    mockSample: sample,
    mockStatic: st,
    mockForecast: forecast,
    mockDetonation: detonation,
    mockEvasionDetonation: evasionDetonation,
    detonateSampleMock: detonateMock,
  };
});

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    getSample: vi.fn().mockImplementation(() => Promise.resolve(mockSample)),
    getSampleStatic: vi.fn().mockImplementation(() => Promise.resolve(mockStatic)),
    getSampleForecast: vi.fn().mockImplementation(() => Promise.resolve(mockForecast)),
    getRuns: vi.fn().mockImplementation(() => Promise.resolve([])),
    getSimilarSamples: vi.fn().mockImplementation(() => Promise.resolve({ sample_id: "s_forecast_test", similar: [] })),
    getSandboxProviders: vi.fn().mockImplementation(() => Promise.resolve({ providers: [] })),
    detonateSample: detonateSampleMock,
    getSandboxArtifactUrl: (runId: string, filename: string) => `/sandbox/artifacts/${runId}/${filename}`,
  };
});

function renderSampleDetail(sampleId = "s_forecast_test") {
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

describe("SampleDetailPage Double-Layer Dynamic Analysis", () => {
  it("renders Layer 1: Pre-Execution Threat Forecast with zero-execution heuristics", async () => {
    renderSampleDetail();

    await waitFor(() => {
      expect(screen.getByText(/Mode 2: Dynamic Sandbox/i)).toBeInTheDocument();
    });

    // Switch to Dynamic Sandbox Tab
    fireEvent.click(screen.getByText(/Mode 2: Dynamic Sandbox/i));

    // Verify Layer 1 Pre-Execution Threat Forecast Header and Badges
    await waitFor(() => {
      expect(screen.getByText(/Layer 1: Pre-Execution Threat Forecast/i)).toBeInTheDocument();
      expect(screen.getByText(/Zero-Execution Heuristics/i)).toBeInTheDocument();
    });

    // Verify threat assessment badges
    await waitFor(() => {
      expect(screen.getByText("MALICIOUS")).toBeInTheDocument();
    });
    expect(screen.getByText(/Confidence:/i)).toBeInTheDocument();
    expect(screen.getByText("92%")).toBeInTheDocument();
    expect(screen.getByText(/Static Score:/i)).toBeInTheDocument();
    expect(screen.getByText("90/100")).toBeInTheDocument();

    // Verify forecast summary and explanations
    expect(screen.getByText(/Predicted high-confidence malicious dropper/i)).toBeInTheDocument();
    expect(screen.getByText(/High Shannon entropy indicates packing/i)).toBeInTheDocument();

    // Verify anticipated behaviors
    expect(screen.getByText("Outbound C2 Beaconing")).toBeInTheDocument();
    expect(screen.getByText("Secondary Payload Drop")).toBeInTheDocument();

    // Verify predicted C2 endpoints
    expect(screen.getAllByText("198.51.100.77").length).toBeGreaterThanOrEqual(1);

    // Verify predicted MITRE techniques
    expect(screen.getByText("T1071.001")).toBeInTheDocument();
    expect(screen.getByText("T1105")).toBeInTheDocument();

    // Verify anticipated file drop path
    expect(screen.getAllByText("/tmp/outpost_canary.sh").length).toBeGreaterThanOrEqual(1);

    // Verify transition action button to Layer 2
    expect(
      screen.getByRole("button", { name: /Proceed to Layer 2: Live Dynamic Sandbox Detonation/i }),
    ).toBeInTheDocument();
  });

  it("proceeds to Layer 2 live sandbox detonation and renders the Forecast Verification Matrix", async () => {
    detonateSampleMock.mockResolvedValueOnce(mockDetonation);
    renderSampleDetail();

    await waitFor(() => {
      expect(screen.getByText(/Mode 2: Dynamic Sandbox/i)).toBeInTheDocument();
    });

    // Switch to Dynamic Sandbox
    fireEvent.click(screen.getByText(/Mode 2: Dynamic Sandbox/i));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Proceed to Layer 2: Live Dynamic Sandbox Detonation/i })).toBeInTheDocument();
    });

    // Click Proceed to Layer 2
    fireEvent.click(screen.getByRole("button", { name: /Proceed to Layer 2: Live Dynamic Sandbox Detonation/i }));

    await waitFor(() => {
      expect(detonateSampleMock).toHaveBeenCalledWith("s_forecast_test", 15, "auto");
    });

    // Verify Forecast Verification Matrix is rendered
    await waitFor(() => {
      expect(screen.getByText(/Forecast Verification Matrix/i)).toBeInTheDocument();
      expect(screen.getByText(/Predicted vs\. Observed Telemetry/i)).toBeInTheDocument();
    });

    // Verify Accuracy Score
    expect(screen.getByText("Accuracy: 100%")).toBeInTheDocument();
    expect(screen.getByText("2 Confirmed")).toBeInTheDocument();
    expect(screen.getByText("1 Discovered")).toBeInTheDocument();

    // Verify confirmed rows in the reconciliation matrix
    expect(screen.getByText("Observed network egress to 198.51.100.77:4444")).toBeInTheDocument();
    expect(screen.getByText("Observed file write to /tmp/outpost_canary.sh")).toBeInTheDocument();
  });

  it("flags anti-analysis evasion alert in the verification matrix when evasion is detected", async () => {
    detonateSampleMock.mockResolvedValueOnce(mockEvasionDetonation);
    renderSampleDetail();

    await waitFor(() => {
      expect(screen.getByText(/Mode 2: Dynamic Sandbox/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText(/Mode 2: Dynamic Sandbox/i));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Proceed to Layer 2: Live Dynamic Sandbox Detonation/i })).toBeInTheDocument();
    });

    // Detonate sample with evasion outcome
    fireEvent.click(screen.getByRole("button", { name: /Proceed to Layer 2: Live Dynamic Sandbox Detonation/i }));

    await waitFor(() => {
      expect(screen.getByText(/ANTI-ANALYSIS WARNING: Potential Sandbox Evasion Detected!/i)).toBeInTheDocument();
      expect(screen.getByText(/Process exited with nominal code 0 and suppressed behaviors/i)).toBeInTheDocument();
    });

    // Verify dormant predictions are rendered
    expect(screen.getByText("2 Dormant")).toBeInTheDocument();
    expect(screen.getByText("Did not trigger in isolated observation window")).toBeInTheDocument();
  });
});
