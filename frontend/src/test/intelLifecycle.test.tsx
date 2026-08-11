// Intel lifecycle regression tests — locks in the attribution and posture
// logic from the keys/re-enrich batch:
//  1. connectionSources (runDetail) — the WHY behind a reputation verdict:
//     watchlist / AbuseIPDB / VirusTotal / none.
//  2. intelKeyHealth (overview) — configured keys and the rotation-age flag
//     that surfaces as an amber posture item.
//  3. ReputationBadge (NetworkTable) — the tooltip actually carries the
//     source breakdown.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import ReputationBadge from "../components/NetworkTable/ReputationBadge";
import { intelAgeLabel } from "../lib/constants";
import { intelFreshness, intelKeyHealth } from "../routes/overviewHelpers";
import { connectionSources } from "../routes/runDetailHelpers";
import type { IntelKeyStatus, NetworkConnection } from "../types";

function conn(over: Partial<NetworkConnection>): NetworkConnection {
  return {
    dest_ip: "203.0.113.88",
    dest_port: 4444,
    protocol: "TCP",
    first_seen: "2026-08-09T10:00:00Z",
    reputation: "suspicious",
    abuse_score: null,
    vt_malicious_count: null,
    malware_family: null,
    watchlist: null,
    watchlist_label: null,
    checked_at: null,
    ...over,
  };
}

function key(over: Partial<IntelKeyStatus>): IntelKeyStatus {
  return { name: "virustotal", set: true, source: "db", suffix: "abcd", set_at: null, age_days: 0, ...over };
}

describe("connectionSources", () => {
  it("attributes a watchlist hit as personal watchlist with its label", () => {
    const src = connectionSources(conn({ watchlist: true, watchlist_label: "Shelf-Stack C2" }));
    expect(src.join(" · ")).toContain("personal watchlist (Shelf-Stack C2)");
  });

  it("lists AbuseIPDB score and VirusTotal vendor count when present", () => {
    const src = connectionSources(conn({ abuse_score: 63, vt_malicious_count: 4 }));
    expect(src.join(" · ")).toContain("AbuseIPDB score 63");
    expect(src.join(" · ")).toContain("VirusTotal: 4 malicious vendors");
  });

  it("says no external intel configured when no feed contributed", () => {
    expect(connectionSources(conn({}))).toEqual(["no external intel configured"]);
  });
});

describe("intelAgeLabel", () => {
  const NOW = new Date("2026-08-09T12:00:00Z").getTime();

  it("is null when never checked (no age to show)", () => {
    expect(intelAgeLabel(null, NOW)).toBeNull();
  });

  it("says just now for sub-minute freshness", () => {
    expect(intelAgeLabel("2026-08-09T11:59:40Z", NOW)).toBe("checked just now");
  });

  it("formats minutes, hours, and days", () => {
    expect(intelAgeLabel("2026-08-09T11:55:00Z", NOW)).toBe("checked 5m ago");
    expect(intelAgeLabel("2026-08-09T07:00:00Z", NOW)).toBe("checked 5h ago");
    expect(intelAgeLabel("2026-08-07T12:00:00Z", NOW)).toBe("checked 2d ago");
  });

  it("falls back to just now for a future/garbage stamp", () => {
    expect(intelAgeLabel("2099-01-01T00:00:00Z", NOW)).toBe("checked just now");
    expect(intelAgeLabel("not-a-date", NOW)).toBe("checked just now");
  });
});

describe("intelFreshness", () => {
  it("is none with an empty cache (strip hidden)", () => {
    expect(intelFreshness({ total: 0, stale_count: 0, oldest_age_hours: null })).toEqual({ tone: "none", line: null });
  });

  it("is ok and names the oldest verdict age when fresh", () => {
    const h = intelFreshness({ total: 12, stale_count: 0, oldest_age_hours: 5 });
    expect(h.tone).toBe("ok");
    expect(h.line).toContain("12 verdicts");
    expect(h.line).toContain("oldest 5h old");
  });

  it("is stale and counts the past-TTL rows", () => {
    const h = intelFreshness({ total: 12, stale_count: 3, oldest_age_hours: 200 });
    expect(h.tone).toBe("stale");
    expect(h.line).toContain("3 of 12 cached verdicts stale");
  });
});

describe("intelKeyHealth", () => {
  it("is 'none' with no configured keys (strip hidden)", () => {
    expect(intelKeyHealth([key({ set: false, source: "none" })])).toEqual({ tone: "none", items: [] });
  });

  it("is 'ok' with fresh keys", () => {
    const h = intelKeyHealth([key({ name: "virustotal" }), key({ name: "abuseipdb" })]);
    expect(h.tone).toBe("ok");
    expect(h.items.join(" ")).toContain("virustotal key configured");
  });

  it("flags a stored key past the 90-day rotation age as stale", () => {
    const h = intelKeyHealth([key({ age_days: 120 })]);
    expect(h.tone).toBe("stale");
    expect(h.items.join(" ")).toContain("virustotal key 120d old — rotate");
  });
});

describe("ReputationBadge attribution", () => {
  it("carries the source breakdown in its tooltip", () => {
    render(
      <ReputationBadge
        reputation="suspicious"
        abuseScore={63}
        vtCount={4}
        watchlist
        watchlistLabel="C2"
      />,
    );
    const badge = screen.getByTitle(/Reputation: suspicious/);
    expect(badge.title).toContain("AbuseIPDB score 63");
    expect(badge.title).toContain("VirusTotal: 4 malicious vendors");
    expect(badge.title).toContain("personal watchlist (C2)");
  });

  it("says no external intel configured when nothing contributed", () => {
    render(<ReputationBadge reputation="unknown" />);
    expect(screen.getByTitle(/no external intel configured/)).toBeInTheDocument();
  });
});
