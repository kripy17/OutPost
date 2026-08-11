// Triage sort modes — the aging view must put longest-open alerts first, then
// triaged ones newest-first; the time mode keeps the input order untouched.
// Plus the "open since" label helper used on each open card.

import { describe, expect, it } from "vitest";
import { openDuration, sortAlertsForTriage } from "../components/AlertBanner/triage";
import type { Alert } from "../types";

function alert(over: Partial<Alert>): Alert {
  return {
    id: 1,
    run_id: "r1",
    rule_id: "unusual-port",
    rule_name: "Uncommon port",
    severity: "suspicious",
    triggered_at: "2026-08-08T12:00:00Z",
    related_pid: null,
    related_ip: null,
    details: "C2 port",
    status: "open",
    status_comment: null,
    status_at: null,
    ...over,
  };
}

describe("sortAlertsForTriage", () => {
  const oldOpen = alert({ id: 1, status: "open", triggered_at: "2026-08-08T09:00:00Z" });
  const newOpen = alert({ id: 2, status: "open", triggered_at: "2026-08-08T11:00:00Z" });
  const resolved = alert({ id: 3, status: "resolved", triggered_at: "2026-08-08T10:00:00Z" });
  const acked = alert({ id: 4, status: "acknowledged", triggered_at: "2026-08-08T08:00:00Z" });

  it("keeps input order in time mode", () => {
    const input = [newOpen, oldOpen, resolved];
    expect(sortAlertsForTriage(input, "time")).toBe(input);
  });

  it("aging mode: open alerts first, oldest-open on top", () => {
    const sorted = sortAlertsForTriage([newOpen, oldOpen, resolved, acked], "aging");
    expect(sorted.slice(0, 2).map((a) => a.id)).toEqual([oldOpen.id, newOpen.id]);
  });

  it("aging mode: triaged alerts trail newest-first", () => {
    const sorted = sortAlertsForTriage([acked, resolved], "aging");
    expect(sorted.map((a) => a.id)).toEqual([resolved.id, acked.id]);
  });

  it("aging mode never mutates the input", () => {
    const input = [newOpen, oldOpen];
    sortAlertsForTriage(input, "aging");
    expect(input[0]).toBe(newOpen);
  });
});

describe("openDuration", () => {
  const now = new Date("2026-08-08T12:00:00Z").getTime();

  it("labels open alerts by age", () => {
    expect(openDuration(alert({ status: "open", triggered_at: "2026-08-08T11:30:00Z" }), now)).toBe("open since 30m");
    expect(openDuration(alert({ status: "open", triggered_at: "2026-08-08T09:00:00Z" }), now)).toBe("open since 3h");
  });

  it("returns null for non-open alerts", () => {
    expect(openDuration(alert({ status: "resolved" }), now)).toBeNull();
    expect(openDuration(alert({ status: "acknowledged" }), now)).toBeNull();
  });
});
