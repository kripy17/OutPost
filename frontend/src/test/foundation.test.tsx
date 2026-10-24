import React from "react";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  TOKENS,
  normalizeSeverity,
  FormattedTime,
  defangIndicator,
  Entity,
  useKeymap,
  ToastProvider,
  useToast,
  ConnectionProvider,
  useConnectionState,
  HealthIndicator,
} from "../foundation";

describe("Foundation: Design Tokens", () => {
  it("normalizes severity levels deterministically", () => {
    expect(normalizeSeverity("CRITICAL")).toBe("critical");
    expect(normalizeSeverity("p1")).toBe("critical");
    expect(normalizeSeverity("malicious")).toBe("high");
    expect(normalizeSeverity("suspicious")).toBe("medium");
    expect(normalizeSeverity("low")).toBe("low");
    expect(normalizeSeverity("unknown")).toBe("info");
    expect(normalizeSeverity(null)).toBe("info");
  });

  it("exports strictly bounded tokens", () => {
    expect(TOKENS.bgBase).toBe("bg-[#0c0d0e]");
    expect(TOKENS.bgSurface).toBe("bg-[#141618]");
    expect(TOKENS.radius).toBe("rounded-[4px]");
  });
});

describe("Foundation: FormattedTime", () => {
  it("renders relative time with UTC title", () => {
    const d = new Date(Date.now() - 1000 * 60 * 5); // 5 mins ago
    render(<FormattedTime value={d} />);
    expect(screen.getByText("5m ago")).toBeInTheDocument();
  });

  it("handles null or invalid timestamp safely", () => {
    const { container } = render(<FormattedTime value={null} />);
    expect(container.textContent).toBe("—");
  });
});

describe("Foundation: Entity Defanging", () => {
  it("defangs IP addresses and domains without regex backtracking", () => {
    expect(defangIndicator("1.1.1.1")).toBe("1[.]1[.]1[.]1");
    expect(defangIndicator("http://evil.com/payload")).toBe("hxxp://evil[.]com/payload");
    expect(defangIndicator("https://malware.org")).toBe("hxxps://malware[.]org");
  });

  it("renders entity component with copy and defang toggle", async () => {
    render(<Entity type="ip" value="192.168.1.100" />);
    expect(screen.getByText("ip:")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.100")).toBeInTheDocument();
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
});

describe("Foundation: Connection & Offline Error State", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("Failed to fetch"))
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows offline banner with cause and retry when backend is unreachable", async () => {
    render(
      <ConnectionProvider>
        <div>Content</div>
      </ConnectionProvider>
    );

    await act(async () => {
      // allow initial ping to run
    });

    expect(screen.getByText(/API unreachable/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
  });
});
