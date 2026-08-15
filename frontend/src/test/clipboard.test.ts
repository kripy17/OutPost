// copyToClipboard (lib/clipboard.ts) — best-effort copy with a legacy
// execCommand fallback for non-secure contexts. Locks the secure-context path
// and the fallback across success / rejection / failure modes.

import { afterEach, describe, expect, it, vi } from "vitest";
import { copyToClipboard } from "../lib/clipboard";

afterEach(() => {
  vi.unstubAllGlobals();
});

function setSecure(secure: boolean) {
  Object.defineProperty(window, "isSecureContext", { value: secure, configurable: true });
}

function stubExec(returns: boolean | (() => boolean)) {
  const fn = vi.fn(typeof returns === "function" ? returns : () => returns);
  document.execCommand = fn as never;
  return fn;
}

describe("copyToClipboard", () => {
  it("writes via navigator.clipboard in a secure context", async () => {
    setSecure(true);
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    await expect(copyToClipboard("hello")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("hello");
  });

  it("falls back to execCommand when clipboard.writeText rejects", async () => {
    setSecure(true);
    const writeText = vi.fn().mockRejectedValue(new Error("denied"));
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    const exec = stubExec(true);
    await expect(copyToClipboard("x")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("x");
    expect(exec).toHaveBeenCalledWith("copy");
  });

  it("falls back to execCommand when clipboard is missing entirely", async () => {
    setSecure(true);
    vi.stubGlobal("navigator", {});
    const exec = stubExec(true);
    await expect(copyToClipboard("y")).resolves.toBe(true);
    expect(exec).toHaveBeenCalledWith("copy");
  });

  it("returns false when execCommand fails", async () => {
    setSecure(true);
    vi.stubGlobal("navigator", {});
    stubExec(false);
    await expect(copyToClipboard("z")).resolves.toBe(false);
  });

  it("returns false when execCommand throws", async () => {
    setSecure(true);
    vi.stubGlobal("navigator", {});
    stubExec(() => {
      throw new Error("boom");
    });
    await expect(copyToClipboard("z")).resolves.toBe(false);
  });
});
