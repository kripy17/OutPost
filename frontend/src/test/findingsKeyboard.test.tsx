import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import FindingsPage from "../routes/findings";

const ORIGINAL_FETCH = globalThis.fetch;

const MOCK_QUEUE = {
  total: 2,
  open: 2,
  acknowledged: 0,
  resolved: 0,
  sort: "aging",
  limit: 25,
  offset: 0,
  alerts: [
    {
      id: 101,
      run_id: "run-alpha",
      sample_name: "sample-a.sh",
      rule_id: "beaconing",
      rule_name: "Beaconing to a fixed destination",
      severity: "suspicious",
      triggered_at: "2026-08-16T10:00:00Z",
      status: "open",
      status_comment: null,
      status_at: null,
      assignee: null,
      related_pid: 4010,
      related_ip: "198.51.100.2",
      related_pids: [4010],
      host_ids: ["sensor-box-1"],
      details: "Beacon intervals to 198.51.100.2 (variance 0.05s)",
    },
    {
      id: 102,
      run_id: "run-beta",
      sample_name: "sample-b.sh",
      rule_id: "masquerading",
      rule_name: "Process masquerading as system binary",
      severity: "malicious",
      triggered_at: "2026-08-16T10:05:00Z",
      status: "open",
      status_comment: null,
      status_at: null,
      assignee: null,
      related_pid: null,
      related_ip: null,
      related_pids: [],
      host_ids: ["sensor-box-2"],
      details: "svchost running from /tmp/svchost",
    },
  ],
};

const MOCK_RULES = [
  {
    rule_id: "beaconing",
    rule_name: "Beaconing to a fixed destination",
    technique: "T1071",
    tactic: "Command and Control",
    weight: 60,
    severity: "suspicious",
    remediation: ["Block destination IP", "Kill parent process"],
  },
  {
    rule_id: "masquerading",
    rule_name: "Process masquerading as system binary",
    technique: "T1036",
    tactic: "Defense Evasion",
    weight: 70,
    severity: "malicious",
    remediation: ["Inspect executable hash"],
  },
];

const MOCK_RUN_DETAIL = {
  run: {
    run_id: "run-alpha",
    sample_name: "sample-a.sh",
    platform: "linux",
    session_type: "live",
    started_at: "2026-08-16T10:00:00Z",
    completed_at: null,
    process_count: 2,
    unique_ips: 1,
    alert_count: 1,
    highest_severity: "suspicious",
    risk_score: 60,
  },
  process_tree: [
    {
      pid: 1000,
      ppid: 1,
      process_name: "systemd",
      command_line: "/sbin/init",
      children: [
        {
          pid: 4010,
          ppid: 1000,
          process_name: "beacon_agent",
          command_line: "/opt/beacon_agent --c2 198.51.100.2",
          children: [],
        },
      ],
    },
  ],
  network_connections: [],
  timeline: [
    {
      id: 901,
      run_id: "run-alpha",
      platform: "linux",
      event_type: "socket_connect",
      timestamp: "2026-08-16T10:00:01Z",
      pid: 4010,
      ppid: 1000,
      process_name: "beacon_agent",
      command_line: "/opt/beacon_agent --c2 198.51.100.2",
      dest_ip: "198.51.100.2",
      dest_port: 443,
      protocol: "tcp",
      file_path: null,
      raw_record: '{"event":"connect","target":"198.51.100.2:443"}',
    },
  ],
  alerts: [],
};

describe("Keyboard-First Findings Triage & Evidence Drawer", () => {
  let queryClient: QueryClient;
  let bulkCalls: any[] = [];
  let investigationCalls: any[] = [];

  beforeEach(() => {
    localStorage.clear();
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    bulkCalls = [];
    investigationCalls = [];

    globalThis.fetch = vi.fn((url: string, init?: RequestInit) => {
      const u = String(url);
      const method = init?.method ?? "GET";

      if (u.includes("/alerts/queue")) {
        return Promise.resolve(new Response(JSON.stringify(MOCK_QUEUE), { status: 200 }));
      }
      if (u.includes("/rules/meta")) {
        return Promise.resolve(new Response(JSON.stringify(MOCK_RULES), { status: 200 }));
      }
      if (u.includes("/runs/run-alpha")) {
        return Promise.resolve(new Response(JSON.stringify(MOCK_RUN_DETAIL), { status: 200 }));
      }
      if (u.includes("/runs/run-beta")) {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              run: { run_id: "run-beta", sample_name: "sample-b.sh" },
              process_tree: [],
              timeline: [],
              network_connections: [],
              alerts: [],
            }),
            { status: 200 }
          )
        );
      }
      if (u.includes("/alerts/bulk") && method === "POST") {
        const body = JSON.parse(String(init?.body || "{}"));
        bulkCalls.push(body);
        return Promise.resolve(new Response(JSON.stringify({ updated: body.ids?.length || 1 }), { status: 200 }));
      }
      if (u.includes("/investigations") && method === "POST") {
        const body = JSON.parse(String(init?.body || "{}"));
        investigationCalls.push(body);
        return Promise.resolve(
          new Response(
            JSON.stringify({
              id: "inv-99",
              title: body.title,
              status: "created",
              tags: body.tags,
            }),
            { status: 201 }
          )
        );
      }
      return Promise.resolve(new Response(JSON.stringify({}), { status: 200 }));
    }) as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
    vi.restoreAllMocks();
  });

  function renderPage() {
    return render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/findings?status=open"]}>
          <FindingsPage />
        </MemoryRouter>
      </QueryClientProvider>
    );
  }

  it("renders visible shortcut hints bar and findings list", async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByText("Beaconing to a fixed destination")).toBeInTheDocument();
    });

    const shortcutsBar = screen.getByText("Shortcuts:").parentElement!;
    expect(shortcutsBar).toHaveTextContent("nav");
    expect(shortcutsBar).toHaveTextContent("ack");
    expect(shortcutsBar).toHaveTextContent("escalate");
    expect(shortcutsBar).toHaveTextContent("inspect");
    expect(shortcutsBar).toHaveTextContent("search");
    expect(shortcutsBar).toHaveTextContent("dismiss");
  });

  it("navigates findings with 'j' and 'k' keys", async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByText("Beaconing to a fixed destination")).toBeInTheDocument();
    });

    const rows = screen.getAllByRole("listitem");
    expect(rows).toHaveLength(2);

    // Initial cursor should be at index 0 (Beaconing finding)
    expect(rows[0]).toHaveAttribute("data-cursor-active", "true");
    expect(rows[1]).not.toHaveAttribute("data-cursor-active");

    // Press 'j' -> moves cursor to index 1 (Masquerading finding)
    fireEvent.keyDown(window, { key: "j" });
    expect(rows[0]).not.toHaveAttribute("data-cursor-active");
    expect(rows[1]).toHaveAttribute("data-cursor-active", "true");

    // Press 'j' again -> clamped at index 1
    fireEvent.keyDown(window, { key: "j" });
    expect(rows[1]).toHaveAttribute("data-cursor-active", "true");

    // Press 'k' -> moves back to index 0
    fireEvent.keyDown(window, { key: "k" });
    expect(rows[0]).toHaveAttribute("data-cursor-active", "true");
    expect(rows[1]).not.toHaveAttribute("data-cursor-active");
  });

  it("acknowledges the selected finding with 'x'", async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByText("Beaconing to a fixed destination")).toBeInTheDocument();
    });

    // Press 'x' on active finding #101
    fireEvent.keyDown(window, { key: "x" });

    await waitFor(() => {
      expect(bulkCalls).toHaveLength(1);
    });
    expect(bulkCalls[0]).toEqual(
      expect.objectContaining({ ids: [101], status: "acknowledged" })
    );
  });

  it("escalates the selected finding into an investigation with 'e'", async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByText("Beaconing to a fixed destination")).toBeInTheDocument();
    });

    // Move to second finding (#102) with 'j'
    fireEvent.keyDown(window, { key: "j" });

    // Press 'e'
    fireEvent.keyDown(window, { key: "e" });

    await waitFor(() => {
      expect(investigationCalls).toHaveLength(1);
    });
    expect(investigationCalls[0].title).toContain("Process masquerading as system binary");
  });

  it("opens evidence drawer with 'Enter' and dismisses with 'Esc'", async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByText("Beaconing to a fixed destination")).toBeInTheDocument();
    });

    // Press Enter on finding #101
    fireEvent.keyDown(window, { key: "Enter" });

    // Drawer should open and display evidence sections
    await waitFor(() => {
      expect(screen.getByText("Rule Rationale & Hypothesis")).toBeInTheDocument();
      expect(screen.getByText("Process Lineage & Ancestry")).toBeInTheDocument();
      expect(screen.getByText("Raw Event Evidence")).toBeInTheDocument();
    });

    // Check reconstructed lineage
    await waitFor(() => {
      expect(screen.getByText("beacon_agent")).toBeInTheDocument();
      expect(screen.getByText("systemd")).toBeInTheDocument();
    });

    // Check raw event evidence
    expect(screen.getByText("socket_connect")).toBeInTheDocument();

    // Press 'Esc' to dismiss drawer
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => {
      expect(screen.queryByText("Rule Rationale & Hypothesis")).not.toBeInTheDocument();
    });
  });

  it("clearly indicates missing evidence when process or timeline records are absent", async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByText("Process masquerading as system binary")).toBeInTheDocument();
    });

    // Move to finding #102 which has null related_pid
    fireEvent.keyDown(window, { key: "j" });
    fireEvent.keyDown(window, { key: "Enter" });

    await waitFor(() => {
      expect(screen.getByText("Rule Rationale & Hypothesis")).toBeInTheDocument();
    });

    // Should clearly show missing evidence
    await waitFor(() => {
      expect(
        screen.getByText("Missing evidence: No associated process PID was captured for this finding.")
      ).toBeInTheDocument();
      expect(
        screen.getByText("Missing evidence: No matching raw telemetry events captured in this run timeline.")
      ).toBeInTheDocument();
    });
  });

  it("focuses search input with '/' and ignores shortcuts while typing", async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByText("Beaconing to a fixed destination")).toBeInTheDocument();
    });

    const searchInput = screen.getByLabelText("Search findings");
    expect(searchInput).not.toHaveFocus();

    // Press '/' -> focuses search input
    fireEvent.keyDown(window, { key: "/" });
    expect(searchInput).toHaveFocus();

    // While focused in input, pressing 'j', 'k', 'x', 'e' should NOT trigger navigation or actions
    fireEvent.keyDown(searchInput, { key: "j" });
    fireEvent.keyDown(searchInput, { key: "x" });

    expect(bulkCalls).toHaveLength(0);

    // Pressing 'Escape' in input should blur it
    fireEvent.keyDown(searchInput, { key: "Escape" });
    expect(searchInput).not.toHaveFocus();
  });
});
