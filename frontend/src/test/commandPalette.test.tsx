// CommandPalette — the reset-client-side-state action must be reachable from
// ⌘K anywhere: typing "reset" surfaces it, Enter runs the confirmed wipe
// (same confirm/report wording as Settings), and the palette shows the result
// banner without navigating away.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import CommandPalette from "../components/CommandPalette";
import { writeSavedProvenance } from "../routes/findingsHelpers";

function renderPalette() {
  // jsdom has no layout — the palette's active-item scroll is a no-op here.
  Element.prototype.scrollIntoView = () => {};
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const onClose = vi.fn();
  vi.stubGlobal(
    "fetch",
    vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) })),
  );
  render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <CommandPalette onClose={onClose} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
  return { onClose };
}

const searchBox = () => screen.getByRole("textbox", { name: "Search" });

describe("CommandPalette reset action", () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("surfaces the reset entry when typing 'reset'", () => {
    renderPalette();
    fireEvent.change(searchBox(), { target: { value: "reset" } });
    expect(screen.getByText("Reset client-side state")).toBeInTheDocument();
    expect(screen.getByText(/Wipe saved provenance split/)).toBeInTheDocument();
  });

  it("Enter runs the confirmed wipe and shows the result banner in place", () => {
    writeSavedProvenance("open", "real");
    renderPalette();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    fireEvent.change(searchBox(), { target: { value: "reset" } });
    fireEvent.keyDown(searchBox(), { key: "Enter" });
    expect(window.confirm).toHaveBeenCalled();
    expect(localStorage.getItem("outpost-queue-provenance-open")).toBeNull();
    expect(screen.getByText("Client-side state reset — cleared 1 provenance tab.")).toBeInTheDocument();
  });

  it("a declined confirm leaves the state untouched and shows no banner", () => {
    writeSavedProvenance("open", "real");
    renderPalette();
    vi.spyOn(window, "confirm").mockReturnValue(false);
    fireEvent.change(searchBox(), { target: { value: "reset" } });
    fireEvent.keyDown(searchBox(), { key: "Enter" });
    expect(localStorage.getItem("outpost-queue-provenance-open")).toBe("real");
    expect(screen.queryByText(/Client-side state reset/)).toBeNull();
  });

  it("an empty store reports nothing without throwing", () => {
    renderPalette();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    fireEvent.change(searchBox(), { target: { value: "reset" } });
    fireEvent.keyDown(searchBox(), { key: "Enter" });
    expect(screen.getByText("Client-side state reset — nothing was saved.")).toBeInTheDocument();
  });
});
