// Watchlist contracts — the entry-type classification (IP / hash / domain /
// other) and the JSON-or-CSV import parser, so the parsing contract is
// locked without a DOM.

import { describe, expect, it } from "vitest";
import { parseImport, typeOf } from "../routes/watchlistHelpers";

describe("typeOf", () => {
  it("classifies an IPv4 address", () => {
    const t = typeOf("203.0.113.88");
    expect(t.label).toBe("IP");
    expect(t.cls).toContain("text-signal");
  });

  it("classifies hashes (32–64 hex)", () => {
    expect(typeOf("a".repeat(32)).label).toBe("Hash");
    expect(typeOf("ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789").label).toBe("Hash");
  });

  it("classifies domains (including subdomains)", () => {
    expect(typeOf("evil.example.com").label).toBe("Domain");
    expect(typeOf("c2.panel.net").label).toBe("Domain");
  });

  it("falls back to Other for everything else", () => {
    for (const v of ["C:\\temp\\x.exe", "registry-key", "not an ip", "203.0.113.999"]) {
      expect(typeOf(v).label, v).toBe("Other");
    }
  });
});

describe("parseImport", () => {
  it("parses CSV rows into value+label, keeping commas inside the label", () => {
    const rows = parseImport("203.0.113.88,Shelf-Stack C2\n198.51.100.9,\n\n8.8.8.8,plain", true);
    expect(rows).toEqual([
      { value: "203.0.113.88", label: "Shelf-Stack C2" },
      { value: "198.51.100.9", label: undefined },
      { value: "8.8.8.8", label: "plain" },
    ]);
  });

  it("parses the JSON {entries:[…]} shape and drops empty values", () => {
    const rows = parseImport(JSON.stringify({ entries: [{ value: "a.b.c", label: "x" }, { value: "" }, { value: "d.e.f" }] }), false);
    expect(rows).toEqual([
      { value: "a.b.c", label: "x" },
      { value: "d.e.f" },
    ]);
  });

  it("accepts a CSV-shaped file with CRLF line endings", () => {
    const rows = parseImport("1.2.3.4,a\r\n5.6.7.8,b\r\n", true);
    expect(rows).toHaveLength(2);
  });

  it("throws on malformed JSON (the page catches and reports it)", () => {
    expect(() => parseImport("{not json", false)).toThrow();
  });

  it("returns empty for a blank file", () => {
    expect(parseImport("", true)).toEqual([]);
    expect(parseImport("", false)).toEqual([]);
  });
});
