// Shared sample-vault helpers — locks the byte-format contract used by both
// the vault list and the sample detail header (they used to carry two copies),
// plus the static-analysis derivations (strings filter, IOC totals) the
// detail page's StaticAnalysis panel renders.

import { describe, expect, it } from "vitest";
import {
  filterStrings,
  formatBytes,
  getVirusTotalDomainUrl,
  getVirusTotalFileUrl,
  getVirusTotalIocUrl,
  getVirusTotalIpUrl,
  getVirusTotalSearchUrl,
  iocTotal,
} from "../routes/samplesHelpers";

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

describe("VirusTotal URL helpers", () => {
  it("builds valid file lookup URL for SHA-256 / hash", () => {
    expect(getVirusTotalFileUrl("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")).toBe(
      "https://www.virustotal.com/gui/file/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(getVirusTotalFileUrl("  md5hash  ")).toBe("https://www.virustotal.com/gui/file/md5hash");
  });

  it("builds valid domain lookup URL", () => {
    expect(getVirusTotalDomainUrl("c2.evil-corp.com")).toBe(
      "https://www.virustotal.com/gui/domain/c2.evil-corp.com",
    );
    expect(getVirusTotalDomainUrl("  test.org ")).toBe(
      "https://www.virustotal.com/gui/domain/test.org",
    );
  });

  it("builds valid IP lookup URL", () => {
    expect(getVirusTotalIpUrl("198.51.100.42")).toBe(
      "https://www.virustotal.com/gui/ip-address/198.51.100.42",
    );
  });

  it("builds valid search URL for URLs and generic indicators", () => {
    expect(getVirusTotalSearchUrl("http://malware.site/drop.exe")).toBe(
      "https://www.virustotal.com/gui/search/http%3A%2F%2Fmalware.site%2Fdrop.exe",
    );
  });

  it("maps IOC categories to appropriate VirusTotal URLs", () => {
    expect(getVirusTotalIocUrl("hashes", "abcdef")).toBe("https://www.virustotal.com/gui/file/abcdef");
    expect(getVirusTotalIocUrl("domains", "bad.com")).toBe("https://www.virustotal.com/gui/domain/bad.com");
    expect(getVirusTotalIocUrl("ips", "1.2.3.4")).toBe("https://www.virustotal.com/gui/ip-address/1.2.3.4");
    expect(getVirusTotalIocUrl("urls", "https://evil.com/pay")).toBe("https://www.virustotal.com/gui/search/https%3A%2F%2Fevil.com%2Fpay");
    expect(getVirusTotalIocUrl("emails", "hacker@bad.com")).toBe("https://www.virustotal.com/gui/search/hacker%40bad.com");
  });
});
