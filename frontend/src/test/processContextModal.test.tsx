import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { DataProvenanceBadge } from "../components/DataProvenanceBadge";
import { determineProvenance } from "../lib/provenance";


describe("DataProvenanceBadge", () => {
  it("determines LIVE provenance for collector sources and log channels", () => {
    expect(determineProvenance("live", null)).toBe("LIVE");
    expect(determineProvenance(null, "auditd")).toBe("LIVE");
    expect(determineProvenance(null, "sysmon")).toBe("LIVE");
    expect(determineProvenance(null, "ebpf")).toBe("LIVE");
  });

  it("determines SIMULATION provenance for lab scenarios", () => {
    expect(determineProvenance("simulation", null)).toBe("SIMULATION");
    expect(determineProvenance("monitor", null)).toBe("SIMULATION");
    expect(determineProvenance("seed", null)).toBe("SIMULATION");
  });

  it("determines SANDBOX provenance for external detonation", () => {
    expect(determineProvenance("sandbox:anyrun", null)).toBe("SANDBOX");
    expect(determineProvenance("sandbox", null)).toBe("SANDBOX");
  });

  it("renders live badge with LIVE text", () => {
    render(<DataProvenanceBadge source="live" />);
    expect(screen.getByText("LIVE")).toBeInTheDocument();
  });

  it("renders simulation badge with SIMULATION text", () => {
    render(<DataProvenanceBadge source="simulation" />);
    expect(screen.getByText("SIMULATION")).toBeInTheDocument();
  });
});
