// Monitor reconciliation helpers — the recon highlight set and kind badges
// recomputed from the run-detail alert set (the poll is the source of truth;
// SSE only fills the sub-second window before the refetch lands).

import { describe, expect, it } from "vitest";
import { reconciledKinds, reconciledReconPids } from "../routes/monitorHelpers";

const burst = (relatedPids: number[], details: string = "3 commands: identity check (whoami)", over: Partial<{ rule_id: string }> = {}) => ({
  rule_id: "enumeration-burst",
  related_pids: relatedPids,
  details,
  ...over,
});

describe("reconciledReconPids", () => {
  it("collects every enumeration pid across all bursts", () => {
    const out = reconciledReconPids([burst([3003, 3004]), burst([3005])]);
    expect(out).not.toBeNull();
    expect([...out!].sort()).toEqual([3003, 3004, 3005]);
  });

  it("dedupes pids shared across bursts", () => {
    const out = reconciledReconPids([burst([3003]), burst([3003, 3004])]);
    expect([...out!].sort()).toEqual([3003, 3004]);
  });

  it("ignores non-enumeration alerts entirely", () => {
    const out = reconciledReconPids([burst([3003]), { rule_id: "beaconing", related_pids: [9999] }]);
    expect([...out!]).toEqual([3003]);
  });

  it("returns null when there are no bursts", () => {
    expect(reconciledReconPids([{ rule_id: "beaconing", related_pids: [9999] }])).toBeNull();
    expect(reconciledReconPids([])).toBeNull();
  });

  it("handles bursts without related_pids", () => {
    expect(reconciledReconPids([burst([], "no pids")])).toBeNull();
  });
});

describe("reconciledKinds", () => {
  it("collects distinct kinds in first-seen order across bursts", () => {
    const out = reconciledKinds([
      burst([3003], "3 commands: identity check (whoami), system info (uname -a)"),
      burst([3005], "3 commands: account enumeration (/etc/passwd), identity check (whoami)"),
    ]);
    expect(out).toEqual(["identity check (whoami)", "system info (uname -a)", "account enumeration (/etc/passwd)"]);
  });

  it("dedupes kinds that repeat across bursts", () => {
    const out = reconciledKinds([
      burst([3003], "3 commands: identity check (whoami)"),
      burst([3004], "3 commands: identity check (whoami)"),
    ]);
    expect(out).toEqual(["identity check (whoami)"]);
  });

  it("returns an empty list for bursts whose details carry no kind list", () => {
    expect(reconciledKinds([burst([3003], "no colon prefix")])).toEqual([]);
  });

  it("returns null when no burst exists", () => {
    expect(reconciledKinds([{ rule_id: "beaconing", details: "" }])).toBeNull();
    expect(reconciledKinds([])).toBeNull();
  });
});
