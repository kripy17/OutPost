// Audit-trail helpers — the action-chip label/color contract and the filter
// bar's action-kind list. Unknown/future backend actions must render with the
// raw action text, never a hard error.

import { describe, expect, it } from "vitest";
import { actionMeta, auditActionKinds } from "../routes/auditHelpers";

describe("actionMeta", () => {
  it("maps known triage actions to their labels", () => {
    expect(actionMeta("alert.status").label).toBe("triage");
    expect(actionMeta("alert.false-positive").label).toBe("false positive");
  });

  it("maps known auth actions", () => {
    expect(actionMeta("auth.login").label).toBe("login");
    expect(actionMeta("auth.login.failed").label).toBe("login failed");
    expect(actionMeta("auth.password").label).toBe("password");
  });

  it("maps allowlist / suppression / retention / backup actions", () => {
    expect(actionMeta("allowlist.add").label).toBe("allowlist");
    expect(actionMeta("allowlist.remove").label).toBe("allowlist");
    expect(actionMeta("suppression.add").label).toBe("suppress");
    expect(actionMeta("retention.prune").label).toBe("retention");
    expect(actionMeta("backup.create").label).toBe("backup");
    expect(actionMeta("restore.apply").label).toBe("restore");
  });

  it("falls back to the raw action text for unknown actions", () => {
    expect(actionMeta("campaign.link").label).toBe("campaign.link");
  });

  it("gives the fallback the neutral chip styling", () => {
    expect(actionMeta("brand.new.action").cls).toBe("border-border-subtle text-text-muted bg-bg-elevated/60");
  });

  it("every known action carries a chip class", () => {
    for (const a of auditActionKinds().filter(Boolean)) {
      expect(actionMeta(a).cls.length).toBeGreaterThan(0);
    }
  });
});

describe("auditActionKinds", () => {
  it("starts with the all-actions sentinel and lists the known kinds", () => {
    const kinds = auditActionKinds();
    expect(kinds[0]).toBe("");
    expect(kinds).toContain("alert.status");
    expect(kinds).toContain("auth.login");
    expect(kinds).toContain("retention.prune");
  });

  it("has no duplicates", () => {
    const kinds = auditActionKinds();
    expect(new Set(kinds).size).toBe(kinds.length);
  });
});
