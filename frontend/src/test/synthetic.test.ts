// Synthetic detonation scenario builders (lib/synthetic.ts) — contract tests
// locking the invariants the Monitor and backend rely on: every event is
// stamped with the run id + platform and a valid timestamp, each platform's
// scenario exercises its own documented rules (PowerShell -enc vs curl|sh,
// Run key vs .bashrc vs LaunchAgent), and all three share the same campaign
// C2 (203.0.113.88) so the cross-sample cluster story holds.

import { describe, expect, it } from "vitest";
import { buildDetonationScenario, detonationSampleName } from "../lib/synthetic";
import type { EventIn, Platform } from "../types";

const EVENT_TYPES = new Set(["process_create", "network_connection", "file_write", "registry_write"]);

function flat(platform: Platform): EventIn[] {
  return buildDetonationScenario("run-x", platform).flatMap((b) => b.events);
}

function commands(platform: Platform): string[] {
  return flat(platform)
    .filter((e) => e.event_type === "process_create")
    .map((e) => e.command_line ?? "");
}

describe("detonationSampleName", () => {
  it("names the sample per platform", () => {
    expect(detonationSampleName("windows")).toBe("detonate-demo.exe");
    expect(detonationSampleName("linux")).toBe("detonate-demo.sh");
    expect(detonationSampleName("macos")).toBe("detonate-demo.app");
  });
});

describe("buildDetonationScenario", () => {
  it("stamps every event with the run id, platform, and a valid timestamp", () => {
    for (const platform of ["windows", "linux", "macos"] as Platform[]) {
      const events = flat(platform);
      expect(events.length).toBeGreaterThan(0);
      for (const e of events) {
        expect(e.run_id).toBe("run-x");
        expect(e.platform).toBe(platform);
        expect(Number.isFinite(new Date(e.timestamp).getTime())).toBe(true);
        expect(EVENT_TYPES.has(e.event_type)).toBe(true);
      }
    }
  });

  it("keeps every batch delay non-negative and non-empty", () => {
    for (const platform of ["windows", "linux", "macos"] as Platform[]) {
      for (const b of buildDetonationScenario("run-x", platform)) {
        expect(b.delayMs).toBeGreaterThanOrEqual(0);
        expect(b.events.length).toBeGreaterThan(0);
      }
    }
  });

  it("has every platform beacon to the same campaign C2", () => {
    for (const platform of ["windows", "linux", "macos"] as Platform[]) {
      const beacons = flat(platform).filter((e) => e.dest_ip === "203.0.113.88");
      expect(beacons.length).toBeGreaterThanOrEqual(5);
      for (const b of beacons) {
        expect(b.dest_port).toBe(4444);
      }
    }
  });

  it("windows exercises PowerShell -enc, the Run key, recon, and a file burst", () => {
    const cmds = commands("windows");
    expect(cmds.some((c) => c.includes("powershell.exe -enc"))).toBe(true);
    const regs = flat("windows").filter((e) => e.event_type === "registry_write").map((e) => e.registry_key);
    expect(regs.some((k) => k?.includes("CurrentVersion\\Run"))).toBe(true);
    expect(cmds.some((c) => c.includes("net user"))).toBe(true);
    expect(cmds.some((c) => c.includes("systeminfo"))).toBe(true);
    expect(cmds.some((c) => c.includes("ipconfig /all"))).toBe(true);
    const burst = flat("windows").filter((e) => e.event_type === "file_write");
    expect(burst.length).toBeGreaterThanOrEqual(12);
  });

  it("linux exercises /tmp masquerade, curl|bash, .bashrc persistence, and a burst", () => {
    const cmds = commands("linux");
    expect(cmds.some((c) => c.includes("/tmp/bash -i"))).toBe(true);
    expect(cmds.some((c) => c.includes("curl") && c.includes("| bash"))).toBe(true);
    const writes = flat("linux").filter((e) => e.event_type === "file_write").map((e) => e.file_path);
    expect(writes.some((p) => p?.endsWith(".bashrc"))).toBe(true);
    expect(writes.length).toBeGreaterThanOrEqual(12);
  });

  it("macos exercises osascript JXA and LaunchAgent persistence", () => {
    const procs = flat("macos")
      .filter((e) => e.event_type === "process_create")
      .map((e) => e.process_name);
    expect(procs).toContain("osascript");
    const writes = flat("macos").filter((e) => e.event_type === "file_write").map((e) => e.file_path);
    expect(writes.some((p) => p?.includes("LaunchAgents") && p?.endsWith(".plist"))).toBe(true);
  });
});
