import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { configure, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import RulesPage from "../routes/rules";

configure({ asyncUtilTimeout: 4000 });

const mockTuningData = {
  knobs: [
    {
      param: "BEACON_MIN_CONNECTIONS",
      default: 5,
      current: 8,
      type: "int",
      rule_id: "beaconing",
      tuned: true,
    },
    {
      param: "ENUM_BURST_THRESHOLD",
      default: 3,
      current: 3,
      type: "int",
      rule_id: "enum_burst",
      tuned: false,
    },
  ],
};

const mockFpData = {
  threshold: 4,
  default_threshold: 4,
  rules: [
    {
      rule_id: "beaconing",
      count: 5,
      fired_count: 20,
      over_threshold: true,
      last_fp_at: "2026-10-10",
      suggestion: {
        param: "BEACON_MIN_CONNECTIONS",
        suggested: 10,
        detail: "Raise beacon threshold from 8 to 10 to suppress recurring false alerts",
      },
      history: [
        { day: "2026-10-01", fired: 5, fp: 1 },
        { day: "2026-10-02", fired: 10, fp: 3 },
      ],
    },
  ],
};

const mockCustomSigma = [
  {
    id: "sig_custom_001",
    title: "Suspicious Ptrace Memory Injection",
    level: "high",
    severity: "high",
    mitre_tactics: ["defense_evasion"],
    mitre_techniques: ["t1055"],
    description: "Detects memory injection primitives into unmanaged services",
    sigma_yaml: "title: Suspicious Ptrace Memory Injection\nlevel: high\n",
  },
];

const mockCommunitySigma = [
  {
    id: "sigma_comm_002",
    title: "Netcat Reverse Shell Ingress",
    level: "critical",
    severity: "critical",
    mitre_tactics: ["execution"],
    mitre_techniques: ["t1059"],
    description: "Netcat launched with bash redirection flag",
    sigma_yaml: "title: Netcat Reverse Shell Ingress\nlevel: critical\n",
  },
];

const mockYaraRules = {
  count: 1,
  rules: [
    {
      name: "rule_trojan_dropper",
      family: "trojan",
      description: "Embedded dropper strings",
      strings: ["cmd.exe", "powershell"],
      source: "rule rule_trojan_dropper { strings: $a = \"dropper\" condition: $a }",
    },
  ],
};

const mockEnumPatterns = {
  platforms: {
    linux: [{ pattern: "uname -a", label: "Kernel Version" }],
    windows: [{ pattern: "whoami /all", label: "Security Token" }],
    macos: [{ pattern: "system_profiler", label: "System Hardware" }],
  },
  defaults: {
    linux: [{ pattern: "uname -a", label: "Kernel Version" }],
    windows: [{ pattern: "whoami /all", label: "Security Token" }],
    macos: [{ pattern: "system_profiler", label: "System Hardware" }],
  },
};

const mockLogPatterns = {
  kinds: {
    service_stop: {
      linux: [{ pattern: "systemctl stop auditd", label: "Auditd Stop" }],
      windows: [{ pattern: "net stop eventlog", label: "EventLog Service Stop" }],
    },
    log_clear: {
      linux: [{ pattern: "journalctl --vacuum-time", label: "Journal Purge" }],
      windows: [{ pattern: "wevtutil cl System", label: "System Log Purge" }],
    },
  },
  defaults: {
    service_stop: {
      linux: [{ pattern: "systemctl stop auditd", label: "Auditd Stop" }],
      windows: [{ pattern: "net stop eventlog", label: "EventLog Service Stop" }],
    },
    log_clear: {
      linux: [{ pattern: "journalctl --vacuum-time", label: "Journal Purge" }],
      windows: [{ pattern: "wevtutil cl System", label: "System Log Purge" }],
    },
  },
};

function setupMockFetch() {
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string) => {
      const u = String(url);

      const ok = (data: unknown) => ({
        ok: true,
        status: 200,
        json: async () => data,
        blob: async () => new Blob([JSON.stringify(data)]),
      });

      if (u.includes("/rules/tuning")) return Promise.resolve(ok(mockTuningData));
      if (u.includes("/rules/fp")) return Promise.resolve(ok(mockFpData));
      if (u.includes("/rules/sigma/custom")) return Promise.resolve(ok(mockCustomSigma));
      if (u.includes("/rules/sigma/community")) return Promise.resolve(ok(mockCommunitySigma));
      if (u.includes("/yara/rules")) return Promise.resolve(ok(mockYaraRules));
      if (u.includes("/rules/enum-patterns")) return Promise.resolve(ok(mockEnumPatterns));
      if (u.includes("/rules/log-patterns")) return Promise.resolve(ok(mockLogPatterns));
      if (u.includes("/samples")) return Promise.resolve(ok({ samples: [], total: 0 }));

      if (u.includes("/rules/simulate")) {
        return Promise.resolve(
          ok({
            matched: true,
            title: "Simulated Ptrace Injection",
            level: "high",
            severity: "high",
            mitre_tactics: ["defense_evasion"],
            mitre_techniques: ["T1055"],
            diagnostics: [
              {
                original_field: "CommandLine",
                target_field: "process.command_line",
                modifier: "contains",
                expected_values: ["ptrace"],
                event_value: "ptrace -p 1234",
                passed: true,
                is_exclusion: false,
                status: "PASS",
              },
            ],
            simulated_alert: {
              rule_name: "Simulated Ptrace Injection",
              level: "high",
              severity: "high",
              mitre_tactic: "defense_evasion",
              mitre_technique: "T1055",
              details: "Process invoked ptrace syscall against system PID",
            },
            recommendation: "Rule fired cleanly against target telemetry",
          }),
        );
      }

      if (u.includes("/rules/backtest")) {
        return Promise.resolve(
          ok({
            rule_id: "test-rule",
            rule_name: "Suspicious Ptrace Memory Injection",
            tactic: "defense_evasion",
            events_scanned: 1500,
            matches_count: 3,
            match_rate_pct: 0.2,
            affected_runs_count: 2,
            sample_matches: [
              {
                event_id: 1,
                run_id: "run-1",
                event_type: "process",
                process_name: "dropper.exe",
                command_line: "dropper.exe --inject",
                timestamp: "2026-10-10T12:00:00Z",
                match_reason: "Matched injection pattern",
              },
            ],
            estimated_fp_risk: "low",
          }),
        );
      }

      if (u.includes("/rules/test-trigger")) {
        return Promise.resolve(
          ok({
            status: "success",
            run_id: "test-run-123",
            alerts_count: 1,
            alert_id: 88,
            alert: {
              rule_id: "beaconing",
              rule_name: "C2 Network Beaconing",
              severity: "high",
              details: "Alert generated from simulated event",
            },
            findings_url: "/findings",
          }),
        );
      }

      return Promise.resolve(ok({}));
    }),
  );
}

function renderRulesPage(initialEntries = ["/rules"]) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={initialEntries}>
        <Routes>
          <Route path="/rules" element={<RulesPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Detection Rule Engineering Workspace & Studio", () => {
  beforeEach(() => {
    setupMockFetch();
  });

  it("renders Detection Engineering KPI HUD with active signatures and metrics", async () => {
    renderRulesPage();

    expect(screen.getByText("Detection Engineering Studio")).toBeInTheDocument();
    expect(screen.getByText("Active Signatures")).toBeInTheDocument();
    expect(screen.getByText("ATT&CK Tactics")).toBeInTheDocument();
    expect(screen.getByText("Tuning Overrides")).toBeInTheDocument();
    expect(screen.getByText("Detection Precision")).toBeInTheDocument();

    await waitFor(() => {
      // 1 custom + 1 community + 1 yara + 1 enum + 1 log + 5 core = 10 unified rules
      expect(screen.getAllByText("10").length).toBeGreaterThan(0);
    });
  });

  it("renders RuleInventoryTable with format badges, search, and filtering", async () => {
    renderRulesPage();

    await waitFor(() => {
      expect(screen.getByText("Suspicious Ptrace Memory Injection")).toBeInTheDocument();
      expect(screen.getByText("Netcat Reverse Shell Ingress")).toBeInTheDocument();
      expect(screen.getByText("rule_trojan_dropper")).toBeInTheDocument();
      expect(screen.getByText("C2 Network Beaconing")).toBeInTheDocument();
    });

    // Verify format badges
    expect(screen.getAllByText("Sigma AST").length).toBeGreaterThan(0);
    expect(screen.getAllByText("YARA").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Enum Recon").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Log Audit").length).toBeGreaterThan(0);
    expect(screen.getAllByText("OutPost Core").length).toBeGreaterThan(0);

    // Test search filter
    const searchInput = screen.getByPlaceholderText(/search by rule name/i);
    fireEvent.change(searchInput, { target: { value: "Netcat" } });

    expect(screen.getByText("Netcat Reverse Shell Ingress")).toBeInTheDocument();
    expect(screen.queryByText("Suspicious Ptrace Memory Injection")).not.toBeInTheDocument();
  });

  it("opens RuleTestingModal on Simulate button click and executes simulation", async () => {
    renderRulesPage();

    await waitFor(() => {
      expect(screen.getByText("Suspicious Ptrace Memory Injection")).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText(/search by rule name/i);
    fireEvent.change(searchInput, { target: { value: "Ptrace" } });

    const simulateBtns = screen.getAllByRole("button", { name: /^simulate$/i });
    expect(simulateBtns.length).toBe(1);
    fireEvent.click(simulateBtns[0]);

    await waitFor(() => {
      const dialog = screen.getByRole("dialog");
      expect(dialog).toBeInTheDocument();
      expect(within(dialog).getByText(/Dry-Run Rule Simulation/i)).toBeInTheDocument();
    });

    const dialog = screen.getByRole("dialog");
    const runSimBtn = within(dialog).getByRole("button", { name: /run simulation/i });
    fireEvent.click(runSimBtn);

    await waitFor(() => {
      expect(within(dialog).getByText(/RULE MATCHED \(ALERT FIRED\)/i)).toBeInTheDocument();
      expect(within(dialog).getByText(/Process invoked ptrace syscall against system PID/i)).toBeInTheDocument();
      expect(within(dialog).getByText(/CommandLine contains: PASS/i)).toBeInTheDocument();
    });
  });

  it("opens RuleBacktestModal on Backtest button click and executes historical query", async () => {
    renderRulesPage();

    await waitFor(() => {
      expect(screen.getByText("Suspicious Ptrace Memory Injection")).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText(/search by rule name/i);
    fireEvent.change(searchInput, { target: { value: "Ptrace" } });

    const backtestBtns = screen.getAllByRole("button", { name: /^backtest$/i });
    expect(backtestBtns.length).toBe(1);
    fireEvent.click(backtestBtns[0]);

    await waitFor(() => {
      const dialog = screen.getByRole("dialog");
      expect(dialog).toBeInTheDocument();
      expect(within(dialog).getByText(/Historical Rule Backtest/i)).toBeInTheDocument();
    });

    await waitFor(() => {
      const dialog = screen.getByRole("dialog");
      expect(within(dialog).getByText("1,500")).toBeInTheDocument(); // total events
      expect(within(dialog).getByText(/3 \(0.2%\)/)).toBeInTheDocument(); // matches
      expect(within(dialog).getByText("dropper.exe")).toBeInTheDocument();
    });
  });

  it("navigates to Knobs tab and renders RuleTuningDrawer with noise thresholds", async () => {
    renderRulesPage(["/rules?tab=knobs"]);

    await waitFor(() => {
      expect(screen.getByText("Detection Knobs & Tuning")).toBeInTheDocument();
      expect(screen.getByText("Automated False-Positive Feedback Threshold")).toBeInTheDocument();
      expect(screen.getByText("Min connections to flag beaconing")).toBeInTheDocument();
    });

    // Check overridden badge
    expect(screen.getByText("tuned")).toBeInTheDocument();
    // Check FP alert suggestion
    expect(screen.getByText(/Raise beacon threshold from 8 to 10/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /apply suggested/i })).toBeInTheDocument();
  });

  it("navigates to YARA tab and renders YaraHuntingWorkbench with draft editor", async () => {
    renderRulesPage(["/rules?tab=yara"]);

    await waitFor(() => {
      expect(screen.getByText("YARA Threat Hunting & Binary Lab")).toBeInTheDocument();
      expect(screen.getByText("Custom YARA Library (1)")).toBeInTheDocument();
      expect(screen.getByText("rule_trojan_dropper")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /test against vault/i })).toBeInTheDocument();
    });
  });

  it("navigates to Patterns tab and renders TelemetryPatternsWorkbench with OS tables", async () => {
    renderRulesPage(["/rules?tab=patterns"]);

    await waitFor(() => {
      expect(screen.getByText("Process Recon & Enumeration (T1082)")).toBeInTheDocument();
      expect(screen.getByText("Process Enumeration Patterns")).toBeInTheDocument();
      expect(screen.getByText("Linux")).toBeInTheDocument();
      expect(screen.getByText("Windows")).toBeInTheDocument();
      expect(screen.getByText("macOS")).toBeInTheDocument();
    });

    // Switch to Anti-Forensics
    const antiForensicsBtn = screen.getByRole("button", { name: /Anti-Forensics & Log Tamper/i });
    fireEvent.click(antiForensicsBtn);

    await waitFor(() => {
      expect(screen.getByText("Anti-Forensics & Log Tamper Signatures")).toBeInTheDocument();
    });
  });

  it("navigates to Packs tab and renders RulePackManager with export/import controls", async () => {
    renderRulesPage(["/rules?tab=packs"]);

    await waitFor(() => {
      expect(screen.getByText("Versioned Rule Sets & Bundles")).toBeInTheDocument();
      expect(screen.getByText("Export pack (JSON)")).toBeInTheDocument();
      expect(screen.getByText("Export Sigma Bundle (.yml)")).toBeInTheDocument();
      expect(screen.getByText("Import pack (JSON)")).toBeInTheDocument();
      expect(screen.getByText("Factory Reset Rules")).toBeInTheDocument();
    });
  });
});
