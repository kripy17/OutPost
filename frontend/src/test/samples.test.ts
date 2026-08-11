// Shared sample-vault helpers — locks the byte-format contract used by both
// the vault list and the sample detail header (they used to carry two copies).

import { describe, expect, it } from "vitest";
import { formatBytes } from "../routes/samplesHelpers";

describe("formatBytes", () => {
  it("keeps sub-KB sizes in whole bytes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1023)).toBe("1023 B");
  });

  it("switches to KB with one decimal at 1024", () => {
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(45 * 1024)).toBe("45.0 KB");
    expect(formatBytes(2048)).toBe("2.0 KB");
  });

  it("switches to MB past a MiB", () => {
    expect(formatBytes(1024 * 1024)).toBe("1.0 MB");
    expect(formatBytes(3 * 1024 * 1024 + 512 * 1024)).toBe("3.5 MB");
  });
});
