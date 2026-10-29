import React, { useState } from "react";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, act, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ColumnDef } from "@tanstack/react-table";
import {
  RAW_COLORS,
  normalizeSeverity,
  FormattedTime,
  formatRelative,
  defangIndicator,
  Entity,
  useKeymap,
  ToastProvider,
  useOptimisticAction,
  ConfirmDialog,
  ConnectionProvider,
  DataTable,
} from "../foundation";

// WCAG Contrast calculation helper
function getContrastRatio(fg: string, bg: string): number {
  const srgbToLin = (c: number) => {
    const s = c / 255.0;
    return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  };
  const getLum = (hex: string) => {
    const clean = hex.replace("#", "");
    const r = parseInt(clean.substring(0, 2), 16);
    const g = parseInt(clean.substring(2, 4), 16);
    const b = parseInt(clean.substring(4, 6), 16);
    return 0.2126 * srgbToLin(r) + 0.7152 * srgbToLin(g) + 0.0722 * srgbToLin(b);
  };
  const l1 = getLum(fg);
  const l2 = getLum(bg);
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
}

describe("Foundation: Design Tokens & WCAG Contrast", () => {
  it("normalizes severity levels deterministically", () => {
    expect(normalizeSeverity("CRITICAL")).toBe("critical");
    expect(normalizeSeverity("p1")).toBe("critical");
    expect(normalizeSeverity("malicious")).toBe("high");
    expect(normalizeSeverity("suspicious")).toBe("medium");
    expect(normalizeSeverity("low")).toBe("low");
    expect(normalizeSeverity("unknown")).toBe("info");
    expect(normalizeSeverity(null)).toBe("info");
  });

  it("satisfies WCAG AA contrast >= 4.5:1 for metadata text across all surfaces", () => {
    const metadataColor = RAW_COLORS.textMetadata; // #7d8590
    const ratioOnBase = getContrastRatio(metadataColor, RAW_COLORS.bgBase);
    const ratioOnSurface = getContrastRatio(metadataColor, RAW_COLORS.bgSurface);
    const ratioOnRaised = getContrastRatio(metadataColor, RAW_COLORS.bgRaised);

    expect(ratioOnBase).toBeGreaterThanOrEqual(4.5);
    expect(ratioOnSurface).toBeGreaterThanOrEqual(4.5);
    expect(ratioOnRaised).toBeGreaterThanOrEqual(4.5);
  });
});

describe("Foundation: FormattedTime & Shared Ticker", () => {
  it("renders relative time with UTC title", () => {
    const d = new Date(Date.now() - 1000 * 60 * 5); // 5 mins ago
    render(<FormattedTime value={d} />);
    expect(screen.getByText("5m ago")).toBeInTheDocument();
  });

  it("handles future timestamps due to clock skew gracefully", () => {
    const nearFuture = new Date(Date.now() + 5000); // 5s in future
    expect(formatRelative(nearFuture)).toBe("just now");

    const farFuture = new Date(Date.now() + 45000); // 45s in future
    expect(formatRelative(farFuture)).toBe("+45s (skew)");
  });

  it("renders calendar date for events older than 7 days", () => {
    const oldDate = new Date(Date.now() - 1000 * 60 * 60 * 24 * 14); // 14 days ago
    const res = formatRelative(oldDate);
    expect(res).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it("handles null or invalid timestamp safely", () => {
    const { container } = render(<FormattedTime value={null} />);
    expect(container.textContent).toBe("—");
  });
});

describe("Foundation: Entity Defanging & Preservation", () => {
  it("defangs URLs, emails, IPv4, and host:port", () => {
    expect(defangIndicator("http://evil.com/payload", "domain")).toBe("hxxp://evil[.]com/payload");
    expect(defangIndicator("https://c2.xyz/drop", "domain")).toBe("hxxps://c2[.]xyz/drop");
    expect(defangIndicator("attacker@badcorp.com", "user")).toBe("attacker[@]badcorp[.]com");
    expect(defangIndicator("192.168.1.100", "ip")).toBe("192[.]168[.]1[.]100");
    expect(defangIndicator("10.0.0.1:8080", "ip")).toBe("10[.]0[.]0[.]1:8080");
  });

  it("NEVER defangs hashes (MD5, SHA1, SHA256)", () => {
    const sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    expect(defangIndicator(sha256, "hash")).toBe(sha256);
  });

  it("handles extreme / malformed inputs without regex backtracking", () => {
    const maliciousInput = "http://" + ".".repeat(5000) + "evil.com";
    const start = performance.now();
    const res = defangIndicator(maliciousInput, "domain");
    const duration = performance.now() - start;

    expect(duration).toBeLessThan(50); // Linear O(n) must execute < 50ms
    expect(res).toContain("[.]");
  });

  it("renders entity component with copy and defang toggle", async () => {
    render(<Entity type="ip" value="192.168.1.100" />);
    expect(screen.getByText("ip:")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.100")).toBeInTheDocument();
  });

  it("triggers pivot callbacks from dropdown menu", async () => {
    const onPivotEvents = vi.fn();
    const onPivotAlerts = vi.fn();
    const onAddCase = vi.fn();

    render(
      <Entity
        type="ip"
        value="10.0.0.5"
        onPivotToEvents={onPivotEvents}
        onPivotToAlerts={onPivotAlerts}
        onAddToCase={onAddCase}
      />
    );

    // Open dropdown menu via keyboard or pointer
    const menuBtn = screen.getAllByRole("button")[1];
    fireEvent.keyDown(menuBtn, { key: "Enter" });

    // Click Pivot to Events
    const pivotEventsItem = await screen.findByText(/Pivot to Events/i);
    fireEvent.click(pivotEventsItem);
    expect(onPivotEvents).toHaveBeenCalledWith("ip", "10.0.0.5");
  });
});

describe("Foundation: Keyboard Navigation Hook (useKeymap)", () => {
  const TestComponent: React.FC<{ bindings: Record<string, () => void> }> = ({ bindings }) => {
    useKeymap(bindings);
    return <input data-testid="test-input" />;
  };

  it("triggers keyboard handler when input is not focused", () => {
    const onAction = vi.fn();
    render(<TestComponent bindings={{ j: onAction }} />);

    fireEvent.keyDown(window, { key: "j" });
    expect(onAction).toHaveBeenCalledTimes(1);
  });

  it("ignores keyboard navigation while an input field is focused", () => {
    const onAction = vi.fn();
    render(<TestComponent bindings={{ j: onAction }} />);

    const input = screen.getByTestId("test-input");
    input.focus();

    fireEvent.keyDown(window, { key: "j" });
    expect(onAction).not.toHaveBeenCalled();
  });

  it("suppresses global keymap when a Radix dialog is open", () => {
    const onAction = vi.fn();
    const dialogDiv = document.createElement("div");
    dialogDiv.setAttribute("role", "dialog");
    document.body.appendChild(dialogDiv);

    try {
      render(<TestComponent bindings={{ j: onAction }} />);
      fireEvent.keyDown(window, { key: "j" });
      expect(onAction).not.toHaveBeenCalled();
    } finally {
      document.body.removeChild(dialogDiv);
    }
  });

  it("supports two-key chord sequences like 'g a'", () => {
    const onNavAlerts = vi.fn();
    render(<TestComponent bindings={{ "g a": onNavAlerts }} />);

    fireEvent.keyDown(window, { key: "g" });
    fireEvent.keyDown(window, { key: "a" });

    expect(onNavAlerts).toHaveBeenCalledTimes(1);
  });
});

describe("Foundation: ConfirmDialog (Radix Destructive Replacement)", () => {
  it("renders confirmation dialog naming target and effect", () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmDialog
        open={true}
        onOpenChange={vi.fn()}
        title="Isolate Host"
        description="Network isolation disconnects all active sessions."
        targetName="workstation-09"
        effectDescription="Host network adapter will be quarantined."
        confirmLabel="Isolate Now"
        isDestructive={true}
        onConfirm={onConfirm}
      />
    );

    expect(screen.getByText("Isolate Host")).toBeInTheDocument();
    expect(screen.getByText("workstation-09")).toBeInTheDocument();
    expect(screen.getByText(/Host network adapter will be quarantined/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Isolate Now" }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});

describe("Foundation: Optimistic Mutation Helper & Undo", () => {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  const MutationTester: React.FC<{
    onMutateFn: () => Promise<string>;
    onUndoSpy?: () => void;
    fail?: boolean;
  }> = ({ onMutateFn, onUndoSpy, fail = false }) => {
    const [state, setState] = useState("initial");
    const { mutate } = useOptimisticAction<string, void, { prev: string }>({
      mutationFn: async () => {
        if (fail) throw new Error("Server reject");
        return onMutateFn();
      },
      optimisticUpdate: () => {
        const prev = state;
        setState("optimistic_updated");
        return { prev };
      },
      rollback: (ctx: any) => {
        if (ctx?.prev) setState(ctx.prev);
      },
      successMessage: "Action successful",
      onUndo: () => {
        setState("undone");
        onUndoSpy?.();
      },
    });

    return (
      <div>
        <span data-testid="state-value">{state}</span>
        <button onClick={() => mutate()}>Trigger</button>
      </div>
    );
  };

  it("applies optimistic update and allows undo from toast", async () => {
    const undoSpy = vi.fn();
    render(
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <MutationTester onMutateFn={async () => "ok"} onUndoSpy={undoSpy} />
        </ToastProvider>
      </QueryClientProvider>
    );

    fireEvent.click(screen.getByRole("button", { name: "Trigger" }));
    expect(screen.getByTestId("state-value").textContent).toBe("optimistic_updated");

    await waitFor(() => {
      expect(screen.getByText("Action successful")).toBeInTheDocument();
    });

    const undoBtn = screen.getByRole("button", { name: /undo/i });
    fireEvent.click(undoBtn);

    expect(undoSpy).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("state-value").textContent).toBe("undone");
  });

  it("rolls back state on mutation error", async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <MutationTester onMutateFn={async () => "ok"} fail={true} />
        </ToastProvider>
      </QueryClientProvider>
    );

    fireEvent.click(screen.getByRole("button", { name: "Trigger" }));
    // Immediately applied
    expect(screen.getByTestId("state-value").textContent).toBe("optimistic_updated");

    // Rolled back after error
    await waitFor(() => {
      expect(screen.getByText(/Changes rolled back/i)).toBeInTheDocument();
    });
    expect(screen.getByTestId("state-value").textContent).toBe("initial");
  });
});

describe("Foundation: Connection & Offline Error State", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("Connection refused (ECONNREFUSED)"))
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows offline banner with specific cause and retry button", async () => {
    render(
      <ConnectionProvider>
        <div>Content</div>
      </ConnectionProvider>
    );

    await act(async () => {});

    expect(screen.getByText(/API unreachable: Connection refused/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
  });
});

describe("Foundation: DataTable Virtualization & 50,000-Row Benchmark", () => {
  interface RowItem {
    id: number;
    title: string;
    count: number;
  }

  const columns: ColumnDef<RowItem, any>[] = [
    { accessorKey: "id", header: "ID" },
    { accessorKey: "title", header: "Title" },
    { accessorKey: "count", header: "Count" },
  ];

  it("renders with ARIA grid semantics and rowcount", () => {
    const data: RowItem[] = [
      { id: 1, title: "Item 1", count: 10 },
      { id: 2, title: "Item 2", count: 20 },
    ];
    render(<DataTable data={data} columns={columns} />);

    const table = screen.getByRole("grid");
    expect(table).toHaveAttribute("aria-rowcount", "2");
    expect(table).toHaveAttribute("aria-colcount", "3");
  });

  it("respects 300ms loading gate without premature flicker", async () => {
    render(<DataTable data={[]} columns={columns} isLoading={true} />);
    // Before 300ms: no loading spinner
    expect(screen.queryByText(/Loading records/i)).not.toBeInTheDocument();

    // After 300ms: loading spinner appears
    await act(async () => {
      await new Promise((r) => setTimeout(r, 350));
    });
    expect(screen.getByText(/Loading records/i)).toBeInTheDocument();
  });

  it("executes 50,000-row benchmark measuring initial render and virtual DOM node bounds", () => {
    // Mock viewport height in jsdom so TanStack Virtual can compute visible range
    const originalClientHeight = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "clientHeight");
    Object.defineProperty(HTMLElement.prototype, "clientHeight", { configurable: true, value: 600 });
    Object.defineProperty(HTMLElement.prototype, "offsetHeight", { configurable: true, value: 600 });

    try {
      // Generate 50,000 items
      const rows50k: RowItem[] = Array.from({ length: 50000 }, (_, i) => ({
        id: i + 1,
        title: `Event Log Item #${i + 1}`,
        count: i * 2,
      }));

      const renderStart = performance.now();
      const { container } = render(
        <div style={{ height: "600px", width: "800px" }}>
          <DataTable data={rows50k} columns={columns} estimateRowHeight={36} />
        </div>
      );
      const initialRenderMs = performance.now() - renderStart;

      // 1. Initial mount of 50,000 rows must be fast (< 4000ms under full parallel test suite load)
      expect(initialRenderMs).toBeLessThan(4000);

      // 2. Virtualizer must only mount visible DOM rows (~15-40) for 50,000 records
      const renderedDomRows = container.querySelectorAll("tbody tr");
      expect(renderedDomRows.length).toBeLessThan(60);
      expect(renderedDomRows.length).toBeGreaterThan(0);

      // 3. Grid semantics confirm total dataset size
      const grid = screen.getByRole("grid");
      expect(grid).toHaveAttribute("aria-rowcount", "50000");
    } finally {
      if (originalClientHeight) {
        Object.defineProperty(HTMLElement.prototype, "clientHeight", originalClientHeight);
      }
    }
  });
});
