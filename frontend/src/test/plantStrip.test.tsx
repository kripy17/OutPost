import { describe, expect, it } from "vitest";
import { plantIpsFromAlerts } from "../components/PlantStrip/PlantStrip";
import type { Alert } from "../types";

function alert(ruleId: string, details: string, relatedIp: string | null = null): Alert {
  return {
    id: 1,
    run_id: "r1",
    rule_id: ruleId,
    rule_name: ruleId,
    severity: "suspicious",
    triggered_at: "2026-08-10T00:00:00Z",
    details,
    related_ip: relatedIp,
    status: "open",
  } as Alert;
}

describe("plantIpsFromAlerts", () => {
  it("extracts plant IPs with their window counts, highest first", () => {
    const alerts = [
      alert(
        "fanout-recurring",
        "198.51.100.70 crossed the fan-out threshold in 3 distinct 300s windows — a long-running coordinated plant",
        "198.51.100.70",
      ),
      alert(
        "fanout-recurring",
        "198.51.100.71 crossed the fan-out threshold in 5 distinct 300s windows — a long-running coordinated plant",
        "198.51.100.71",
      ),
    ];
    const plants = plantIpsFromAlerts(alerts);
    expect(plants).toEqual([
      { ip: "198.51.100.71", windows: 5 },
      { ip: "198.51.100.70", windows: 3 },
    ]);
  });

  it("ignores non-recurring alerts and alerts without an IP", () => {
    const alerts = [
      alert("fanout-contact", "6 distinct processes contacted 198.51.100.9 inside 300s"),
      alert("fanout-recurring", "crossed the fan-out threshold in 2 distinct 300s windows", null),
    ];
    expect(plantIpsFromAlerts(alerts)).toEqual([]);
  });
});
