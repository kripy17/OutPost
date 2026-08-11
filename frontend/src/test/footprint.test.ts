// Footprint topology contract — the pure layout behind the radial map. Locks
// the ring semantics: seed IPs on ring 1 (reputation-bearing), resolutions +
// sibling hosts on ring 2, cohosted passive-DNS domains on ring 3 fanned
// around the seed/sibling they were observed from, with honest provider notes.

import { describe, expect, it } from "vitest";
import { buildTopology, MAP, passiveNote } from "../routes/footprintHelpers";
import type { Footprint } from "../types";

function footprint(over: Partial<Footprint> = {}): Footprint {
  return {
    sample: { sample_id: "s1", name: "evil.bin", sha256: "ab", platform: "windows", family: null },
    runs: [],
    seed_ips: [
      { ip: "203.0.113.88", hits: 4, first_seen: "t1", last_seen: "t2", run_count: 2, reputation: "malicious", abuse_score: 90, vt_malicious_count: 12, checked_at: "t3" },
      { ip: "198.51.100.9", hits: 1, first_seen: "t1", last_seen: "t2", run_count: 1, reputation: "clean", abuse_score: 0, vt_malicious_count: 0, checked_at: "t3" },
    ],
    passive: {
      source: "live",
      resolutions: [{ domain: "host-88.example.net", first_seen: "t1", last_seen: "t2" }],
      passive_dns: [
        { domain: "evil-admin.example.com", first_seen: "t1", last_seen: "t2", source_ip: "203.0.113.88" },
        { domain: "evil-cdn.example.com", first_seen: "t1", last_seen: "t2", source_ip: "203.0.113.88" },
        { domain: "sib-panel.example.org", first_seen: "t1", last_seen: "t2", source_ip: "198.51.100.77" },
        // No source — the fallback bucket, sourceKind "other".
        { domain: "orphan.example.io", first_seen: "t1", last_seen: "t2" },
      ],
      certificates: [],
      sibling_ips: [{ ip: "198.51.100.77", relation: "same /24" }],
      networks: [],
      asn: [],
    },
    status: { roadmap: true, generated: null },
    ...over,
  };
}

describe("buildTopology", () => {
  it("places seed IPs on ring 1 at the seed's radius", () => {
    const t = buildTopology(footprint());
    expect(t.seedPos).toHaveLength(2);
    for (const s of t.seedPos) {
      const r = Math.hypot(s.x - MAP.W / 2, s.y - MAP.H / 2);
      expect(r).toBeCloseTo(MAP.ring1, 3);
    }
    // Reputation survives the layout pass (coloring input for the renderer).
    expect(t.seedPos[0].reputation).toBe("malicious");
  });

  it("places resolutions and siblings on ring 2", () => {
    const t = buildTopology(footprint());
    // 1 resolution + 1 sibling.
    expect(t.midPos).toHaveLength(2);
    for (const n of t.midPos) {
      const r = Math.hypot(n.x - MAP.W / 2, n.y - MAP.H / 2);
      expect(r).toBeCloseTo(MAP.ring2, 3);
    }
    // The sibling is addressable by IP for edge + fan grouping.
    expect(t.sibByIp.get("198.51.100.77")?.kind).toBe("sib");
  });

  it("fans cohosted passive-DNS domains on ring 3 around their observed source", () => {
    const t = buildTopology(footprint());
    const dns = t.dnsPos;
    expect(dns).toHaveLength(4);

    // Both cohosted on the seed are tagged seed and cluster near the seed's angle.
    const onSeed = dns.filter((d) => d.sourceKind === "seed");
    const onSib = dns.filter((d) => d.sourceKind === "sib");
    const orphan = dns.find((d) => d.label === "orphan.example.io");
    expect(onSeed).toHaveLength(2);
    expect(onSib).toHaveLength(1);
    expect(orphan?.sourceKind).toBe("other");

    // Ring 3 radius holds.
    for (const d of dns) {
      const r = Math.hypot(d.x - MAP.W / 2, d.y - MAP.H / 2);
      expect(r).toBeCloseTo(MAP.ring3, 3);
    }
    // The fan is grouped: domains from the same source sit adjacent (within a
    // fixed angular spread), not scattered across the ring.
    const seedAngle = t.seedPos[0].angle;
    const spread = Math.max(...onSeed.map((d) => Math.abs(Math.atan2(d.y - MAP.H / 2, d.x - MAP.W / 2) - seedAngle)));
    expect(spread).toBeLessThan(0.5);
  });

  it("slices to the display caps (8 seeds / 5 mids / 8 dns) without failing on overflow", () => {
    const big = footprint();
    big.seed_ips = Array.from({ length: 12 }, (_, i) => ({ ...big.seed_ips[0], ip: `10.0.0.${i}` }));
    big.passive.passive_dns = Array.from({ length: 12 }, (_, i) => ({ domain: `d${i}.example.com`, first_seen: "t1", last_seen: "t2", source_ip: "203.0.113.88" }));
    const t = buildTopology(big);
    expect(t.seedPos).toHaveLength(8);
    expect(t.dnsPos).toHaveLength(8);
  });
});

describe("passiveNote", () => {
  it("is honest per provider state", () => {
    expect(passiveNote("live", "crt.sh")).toBe("crt.sh · live");
    expect(passiveNote("synthetic_demo", "crt.sh")).toBe("synthetic preview");
    expect(passiveNote("not_configured", "crt.sh")).toBe("offline — not configured");
  });
});
