// Render smoke tests for the aggregated risk-trend chart — the Overview's
// third posture primitive. Needs a router (bars navigate to History).
// Tooltips live in SVG <title> children (not title attributes), so we query
// by text content and interact via the bar's role="link".

import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { RiskTrendBars, type RiskTrendBar } from "../components/Posture/Posture";

const BARS: RiskTrendBar[] = [
  { sample: "evil.exe", peak: 90, count: 3, last: "2026-08-08T12:00:00Z" },
  { sample: "clean.bin", peak: 0, count: 1, last: "2026-08-08T10:00:00Z" },
];

function LocationProbe() {
  const { search } = useLocation();
  return <span data-testid="location">{search}</span>;
}

function renderWithRouter() {
  return render(
    <MemoryRouter>
      <RiskTrendBars bars={BARS} />
      <LocationProbe />
    </MemoryRouter>,
  );
}

describe("RiskTrendBars", () => {
  it("renders one bar per sample with its peak and session count", () => {
    renderWithRouter();
    expect(screen.getByRole("img", { name: /each bar is a binary's peak risk/i })).toBeInTheDocument();
    expect(screen.getAllByRole("link")).toHaveLength(2);
    expect(screen.getByText(/evil\.exe: peak risk 90 \(critical\) · 3 sessions/)).toBeInTheDocument();
  });

  it("shows an empty state with no detonations", () => {
    render(
      <MemoryRouter>
        <RiskTrendBars bars={[]} />
      </MemoryRouter>,
    );
    expect(screen.getByText(/No detonations yet/)).toBeInTheDocument();
  });

  it("navigates to History pre-filtered by sample on click", () => {
    renderWithRouter();
    const evil = screen.getAllByRole("link")[0]; // bars render in order: evil.exe first
    fireEvent.click(evil);
    expect(screen.getByTestId("location").textContent).toContain("q=evil.exe");
  });
});
