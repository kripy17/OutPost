import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { configure, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import SampleDetailPage from "../routes/sampleDetail";
import type { SampleRow, SampleStatic } from "../types";

configure({ asyncUtilTimeout: 4000 });

const { mockPeSample, mockPeStatic } = vi.hoisted(() => {
  const sample: SampleRow = {
    sample_id: "s_pe_sample_123",
    sha256: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
    original_name: "payload_dropper.exe",
    size: 65536,
    detected_platform: "windows",
    created_at: "2026-09-15T14:30:00Z",
    synthetic: false,
    yara_rules: ["pe_suspicious_injection", "upx_packer"],
    vt_detections: 12,
    malware_family: "RedLineStealer",
    family: "infostealer",
    runs_count: 2,
  };

  const st: SampleStatic = {
    sample_id: "s_pe_sample_123",
    sha256: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
    available: true,
    size: 65536,
    pe: {
      machine: "IMAGE_FILE_MACHINE_AMD64",
      bits: 64,
      entry_point_rva: 0x1400,
      image_base: "0x140000000",
      subsystem: "WINDOWS_GUI",
      imphash: "f34d5f2d4577ed6d9ceec516c1f5a744",
      mitigations: ["ASLR", "DEP", "Control Flow Guard"],
      authenticode: {
        signed: false,
        cert_size: 0,
      },
      rich_header: {
        present: true,
        hash: "e5f6a1b2c3d4e5f6",
        xor_key: "0xDEADBEEF",
        records_count: 8,
      },
      sections: [
        {
          name: ".text",
          virtual_size: 0x4000,
          raw_size: 0x3800,
          flags: ["MEM_EXECUTE", "MEM_READ"],
          entropy: 6.42,
          permissions: "RX",
          is_rwx: false,
        },
        {
          name: ".data",
          virtual_size: 0x2000,
          raw_size: 0x1000,
          flags: ["MEM_READ", "MEM_WRITE"],
          entropy: 4.12,
          permissions: "RW",
          is_rwx: false,
        },
        {
          name: ".upx1",
          virtual_size: 0x8000,
          raw_size: 0x2000,
          flags: ["MEM_EXECUTE", "MEM_READ", "MEM_WRITE"],
          entropy: 7.88,
          permissions: "RWX",
          is_rwx: true,
        },
      ],
      imports: [
        "KERNEL32.DLL!VirtualAlloc",
        "KERNEL32.DLL!CreateRemoteThread",
        "WS2_32.DLL!connect",
        "ADVAPI32.DLL!RegSetValueExA",
      ],
    },
    elf: null,
    strings: [
      "http://c2.evil-operator.org/gate.php",
      "198.51.100.99",
      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "C:\\Windows\\System32\\cmd.exe",
      "VirtualAlloc",
      "CreateRemoteThread",
    ],
    categorized_strings: {
      network: ["http://c2.evil-operator.org/gate.php", "198.51.100.99"],
      file_paths: ["C:\\Windows\\System32\\cmd.exe"],
      commands: ["cmd.exe /c whoami"],
      registry: ["Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
      security_apis: ["VirtualAlloc", "CreateRemoteThread"],
    },
    iocs: {
      urls: ["http://c2.evil-operator.org/gate.php"],
      ips: ["198.51.100.99"],
      domains: ["evil-operator.org"],
      hashes: ["098f6bcd4621d373cade4e832627b4f6"],
      emails: ["adversary@darkweb.ru"],
    },
    entropy: 7.65,
    is_packed: true,
    static_risk_score: 88,
    static_severity: "malicious",
    risk_factors: [
      "High Shannon entropy indicating UPX packing or encryption",
      "Memory injection primitives observed: VirtualAlloc, CreateRemoteThread",
      "Auto-start registry persistence key identified",
    ],
    capabilities: [
      {
        category: "Process Injection",
        confidence: "high",
        matched: ["VirtualAlloc", "CreateRemoteThread"],
        source: "Static Import Inspection",
      },
      {
        category: "Persistence",
        confidence: "medium",
        matched: ["RegSetValueExA"],
        source: "Static Import Inspection",
      },
    ],
    hex_preview: [
      { offset: "00000000", hex: "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00", ascii: "MZ.............." },
      { offset: "00000010", hex: "B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00", ascii: "........@......." },
    ],
  };

  return { mockPeSample: sample, mockPeStatic: st };
});

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    getSample: vi.fn().mockImplementation(() => Promise.resolve(mockPeSample)),
    getSampleStatic: vi.fn().mockImplementation(() => Promise.resolve(mockPeStatic)),
    getRuns: vi.fn().mockImplementation(() =>
      Promise.resolve([
        {
          run_id: "dyn_run_001",
          started_at: "2026-09-15T14:35:00Z",
          alert_count: 3,
          highest_severity: "malicious",
          risk_score: 95,
        },
      ]),
    ),
    getSimilarSamples: vi.fn().mockImplementation(() =>
      Promise.resolve({
        sample_id: "s_pe_sample_123",
        target_imphash: "f34d5f2d4577ed6d9ceec516c1f5a744",
        target_fuzzy_hash: "1536:abc:xyz",
        similar: [
          {
            sample_id: "s_variant_999",
            original_name: "variant_redline.exe",
            sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            similarity: 84,
            imphash_match: true,
          },
        ],
      }),
    ),
    getSandboxProviders: vi.fn().mockImplementation(() => Promise.resolve({ providers: [] })),
  };
});

function renderWorkspace(sampleId = "s_pe_sample_123") {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
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

describe("Static Malware Analysis Technical Workspace (sampleDetail.tsx)", () => {
  it("renders compact workspace header and structured identification strip", async () => {
    renderWorkspace();

    // Verify breadcrumb
    await waitFor(() => {
      expect(screen.getByText("Malware Analysis")).toBeInTheDocument();
      expect(screen.getAllByText("payload_dropper.exe").length).toBeGreaterThanOrEqual(1);
    });

    // Verify format tag and verdict label
    expect(screen.getByText(/PE32\+ \(IMAGE_FILE_MACHINE_AMD64\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Signature Match: Malicious/i)).toBeInTheDocument();

    // Verify identification strip
    expect(screen.getByText("SHA-256 Fingerprint")).toBeInTheDocument();
    expect(screen.getByText(/inferred from magic bytes/i)).toBeInTheDocument();
    expect(screen.getByText(/2 YARA matches/i)).toBeInTheDocument();
    expect(screen.getByText(/Stored in vault \(bytes retained\)/i)).toBeInTheDocument();
  });

  it("renders Overview tab with assessment, findings table, file facts, and candidate IOCs", async () => {
    renderWorkspace();

    await waitFor(() => {
      expect(screen.getByText(/Analysis Assessment & Threat Inferences/i)).toBeInTheDocument();
    });

    // Check Section 1 assessment metrics
    expect(screen.getByText("88")).toBeInTheDocument(); // risk score
    expect(screen.getByText("7.65")).toBeInTheDocument(); // entropy
    expect(screen.getByText("Suspected Packed")).toBeInTheDocument();

    // Check Section 2 findings requiring inspection table
    expect(screen.getByText("YARA Signature: pe_suspicious_injection")).toBeInTheDocument();
    expect(screen.getByText("RWX Section: .upx1")).toBeInTheDocument();

    // Check Section 3 file facts
    expect(screen.getByText("Portable Executable (PE)")).toBeInTheDocument();
    expect(screen.getByText("RVA 0x1400")).toBeInTheDocument();

    // Check Section 4 candidate IOCs
    expect(screen.getByText("evil-operator.org")).toBeInTheDocument();
    expect(screen.getAllByText("198.51.100.99").length).toBeGreaterThanOrEqual(1);
  });

  it("switches to File Structure tab and inspects PE headers, exploit mitigations, and sections table", async () => {
    renderWorkspace();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /File Structure/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /File Structure/i }));

    // Verify DOS/PE headers
    await waitFor(() => {
      expect(screen.getByText("DOS / PE / Optional Headers")).toBeInTheDocument();
      expect(screen.getByText("IMAGE_FILE_MACHINE_AMD64")).toBeInTheDocument();
      expect(screen.getByText("WINDOWS_GUI")).toBeInTheDocument();
      expect(screen.getByText("0x140000000")).toBeInTheDocument();
    });

    // Verify exploit mitigations
    expect(screen.getByText("Exploit Mitigations & Signature Integrity")).toBeInTheDocument();
    expect(screen.getByText("Data Execution Prevention (DEP / NX)")).toBeInTheDocument();
    expect(screen.getByText("Address Space Layout Randomization (ASLR)")).toBeInTheDocument();

    // Verify sections table with RWX alert
    expect(screen.getByText(".text")).toBeInTheDocument();
    expect(screen.getByText(".upx1")).toBeInTheDocument();
    expect(screen.getByText("RWX")).toBeInTheDocument();
  });

  it("switches to Imports & Capabilities tab and verifies grouped matrix and sensitive API highlights", async () => {
    renderWorkspace();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Imports & Capabilities/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /Imports & Capabilities/i }));

    await waitFor(() => {
      expect(screen.getByText(/Detected Capabilities/i)).toBeInTheDocument();
    });

    // Capabilities
    expect(screen.getAllByText("Process Injection").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("high Confidence")).toBeInTheDocument();

    // Imports Table
    expect(screen.getAllByText("KERNEL32.DLL").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("VirtualAlloc").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("CreateRemoteThread").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("T1055")).toBeInTheDocument();
  });

  it("switches to Strings & Indicators tab and tests category filtering and copy action", async () => {
    renderWorkspace();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Strings & Indicators/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /Strings & Indicators/i }));

    await waitFor(() => {
      expect(screen.getByText(/Extracted ASCII & Wide Strings/i)).toBeInTheDocument();
    });

    // Verify strings exist
    expect(screen.getByText("http://c2.evil-operator.org/gate.php")).toBeInTheDocument();
    expect(screen.getByText("198.51.100.99")).toBeInTheDocument();

    // Test sub-tab switch to IOCs
    fireEvent.click(screen.getByRole("button", { name: /Extracted IOC Indicators/i }));
    await waitFor(() => {
      expect(screen.getByText("IPv4 Address")).toBeInTheDocument();
      expect(screen.getByText("adversary@darkweb.ru")).toBeInTheDocument();
    });
  });

  it("switches to Raw Bytes tab and renders 512-byte hex viewer with jump offsets", async () => {
    renderWorkspace();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Raw Bytes" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Raw Bytes" }));

    await waitFor(() => {
      expect(screen.getByText("Raw Byte & Hex Header Inspector")).toBeInTheDocument();
    });

    // Check hex offsets and bytes
    expect(screen.getByText("00000000")).toBeInTheDocument();
    expect(screen.getByText("MZ..............")).toBeInTheDocument();
    expect(screen.getByText("Copy Hex Dump")).toBeInTheDocument();
    expect(screen.getByText("0x0000 (File Header)")).toBeInTheDocument();
    expect(screen.getByText(/Entry Point \(0x1400\)/i)).toBeInTheDocument();
  });

  it("switches to Analysis History tab and renders execution runs and similarity matches", async () => {
    renderWorkspace();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Analysis History/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /Analysis History/i }));

    await waitFor(() => {
      expect(screen.getByText(/Detonation Runs for payload_dropper.exe/i)).toBeInTheDocument();
    });

    // Check execution run row
    expect(screen.getByText("dyn_run_001")).toBeInTheDocument();
    expect(screen.getByText("95")).toBeInTheDocument(); // risk score

    // Check similarity match
    expect(screen.getByText("variant_redline.exe")).toBeInTheDocument();
    expect(screen.getByText("84%")).toBeInTheDocument();
    expect(screen.getByText("IMPHASH MATCH")).toBeInTheDocument();
  });
});
