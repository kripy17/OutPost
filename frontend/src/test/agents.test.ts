// Agents fleet contracts — the pure derivations behind the fleet readout:
// relative-time labels, the channel tone mapping (auditd teal, sysmon amber,
// others muted — same mapping as the Overview panel and CLI chips), and the
// per-channel volume mix (sorted, proportioned).

import { describe, expect, it } from "vitest";
import { channelMix, channelTone, relativeTime } from "../routes/agentsHelpers";

const NOW = new Date("2026-08-11T12:00:00Z").getTime();

describe("relativeTime", () => {
  it("labels the buckets: just now / s / m / h / d", () => {
    expect(relativeTime("2026-08-11T11:59:58Z", NOW)).toBe("just now");
    expect(relativeTime("2026-08-11T11:59:50Z", NOW)).toBe("10s ago");
    expect(relativeTime("2026-08-11T11:50:00Z", NOW)).toBe("10m ago");
    expect(relativeTime("2026-08-11T09:00:00Z", NOW)).toBe("3h ago");
    expect(relativeTime("2026-08-09T12:00:00Z", NOW)).toBe("2d ago");
  });

  it("clamps future timestamps to just now", () => {
    expect(relativeTime("2026-08-11T12:00:05Z", NOW)).toBe("just now");
  });
});

describe("channelTone", () => {
  it("maps auditd teal, sysmon amber, everything else muted", () => {
    expect(channelTone("auditd")).toBe("bg-risk-clean");
    expect(channelTone("sysmon")).toBe("bg-accent");
    for (const c of ["webapp", "custom", ""]) {
      expect(channelTone(c)).toBe("bg-text-faint");
    }
  });
});

describe("channelMix", () => {
  it("sorts channels by volume and proportions each share", () => {
    const mix = channelMix({ webapp: 10731, sysmon: 82, auditd: 1187 });
    expect(mix.map((m) => m.channel)).toEqual(["webapp", "auditd", "sysmon"]);
    const webapp = mix[0];
    expect(webapp.count).toBe(10731);
    // 10731 of 12000 → 89% (rounds to the nearest whole percent).
    expect(webapp.pct).toBe(89);
    expect(mix[1].pct).toBe(10);
    expect(mix[2].pct).toBe(1);
  });

  it("returns empty for no channels and 0% for a zero-total host", () => {
    expect(channelMix({})).toEqual([]);
    // Zero counts: every pct is 0; the stable sort keeps insertion order.
    expect(channelMix({ webapp: 0, sysmon: 0 })).toEqual([{ channel: "webapp", count: 0, pct: 0 }, { channel: "sysmon", count: 0, pct: 0 }]);
  });
});
