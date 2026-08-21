// Shared sample-vault helpers — locks the byte-format contract used by both
// the vault list and the sample detail header (they used to carry two copies),
// plus the static-analysis derivations (strings filter, IOC totals) the
// detail page's StaticAnalysis panel renders.

import { describe, expect, it } from "vitest";
import { filterStrings, formatBytes, iocTotal } from "../routes/samplesHelpers";

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

describe("filterStrings", () => {
  const strings = ["MZ.exe", "http://evil.example/x.sh", "powershell -enc", "C:\\temp\\data.bin", "HelloWorld"];

  it("returns the full list unchanged for an empty or whitespace query", () => {
    expect(filterStrings(strings, "")).toEqual(strings);
    expect(filterStrings(strings, "   ")).toEqual(strings);
  });

  it("filters case-insensitively", () => {
    expect(filterStrings(strings, "POWERSHELL")).toEqual(["powershell -enc"]);
    expect(filterStrings(strings, "powershell")).toEqual(["powershell -enc"]);
  });

  it("trims surrounding whitespace from the query", () => {
    expect(filterStrings(strings, "  http://evil ")).toEqual(["http://evil.example/x.sh"]);
  });

  it("matches substrings, not just prefixes", () => {
    expect(filterStrings(strings, "evil")).toEqual(["http://evil.example/x.sh"]);
    expect(filterStrings(strings, "data")).toEqual(["C:\\temp\\data.bin"]);
  });

  it("returns an empty array when nothing matches", () => {
    expect(filterStrings(strings, "nomatch")).toEqual([]);
  });

  it("handles an empty string list", () => {
    expect(filterStrings([], "mz")).toEqual([]);
    expect(filterStrings([], "")).toEqual([]);
  });
});

describe("iocTotal", () => {
  it("sums every bucket", () => {
    expect(
      iocTotal({ urls: ["a"], ips: ["1", "2"], domains: [], hashes: ["h", "h2", "h3"], emails: ["e"] }),
    ).toBe(7);
  });

  it("returns zero for empty buckets", () => {
    expect(iocTotal({ urls: [], ips: [], domains: [], hashes: [], emails: [] })).toBe(0);
  });

  it("counts each bucket independently", () => {
    expect(iocTotal({ urls: ["u1"], ips: [], domains: ["d1", "d2"], hashes: [], emails: [] })).toBe(3);
  });
});
