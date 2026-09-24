import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import TopCommandBar from "../components/TopCommandBar";

describe("TopCommandBar", () => {
  it("renders breadcrumbs for top-level operational routes", () => {
    render(
      <MemoryRouter initialEntries={["/findings"]}>
        <TopCommandBar />
      </MemoryRouter>,
    );

    expect(screen.getByText("OutPost")).toBeInTheDocument();
    expect(screen.getByText("Live Operations")).toBeInTheDocument();
    expect(screen.getByText("Incident Findings")).toBeInTheDocument();
    expect(screen.getByText("Live Stream")).toBeInTheDocument();
  });

  it("renders hierarchical breadcrumbs with links for detail pages", () => {
    render(
      <MemoryRouter initialEntries={["/investigations/inv-12345678"]}>
        <TopCommandBar />
      </MemoryRouter>,
    );

    const pillarLink = screen.getByRole("link", { name: "Incident Cases" });
    expect(pillarLink).toBeInTheDocument();
    expect(pillarLink).toHaveAttribute("href", "/investigations");
    expect(screen.getByText("Case Dossier (inv-1234)")).toBeInTheDocument();
  });

  it("dispatches keyboard events on shortcut triggers", () => {
    const dispatchSpy = vi.spyOn(window, "dispatchEvent");

    render(
      <MemoryRouter initialEntries={["/events"]}>
        <TopCommandBar />
      </MemoryRouter>,
    );

    const jumpBtn = screen.getByRole("button", { name: /command palette/i });
    fireEvent.click(jumpBtn);
    expect(dispatchSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        key: "k",
        metaKey: true,
      }),
    );

    const shortcutsBtn = screen.getByRole("button", { name: /keyboard shortcuts/i });
    fireEvent.click(shortcutsBtn);
    expect(dispatchSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        key: "?",
      }),
    );

    dispatchSpy.mockRestore();
  });
});
