/**
 * CyberDecoder — Forensic Payload Decoding & Deobfuscation Engine.
 *
 * Provides real-time decoding for Base64 (UTF-8 and Windows UTF-16LE / PowerShell),
 * Hex / Shellcode, URL percent-encoding, and IOC defang/refang transformations.
 * Pure TypeScript with zero third-party dependencies.
 */

export interface DecodedCandidate {
  id: string;
  name: string;
  decoded: string;
  confidence: "high" | "medium" | "low";
  description: string;
}

export interface IocMatch {
  type: "ip" | "domain" | "url" | "hash" | "path";
  value: string;
}

export interface CyberDecoderOutput {
  input: string;
  candidates: DecodedCandidate[];
  extractedIocs: IocMatch[];
  isDefanged: boolean;
}

/**
 * Decode standard Base64 string into UTF-8.
 */
export function decodeBase64Utf8(input: string): string | null {
  const cleaned = input.trim().replace(/\s+/g, "");
  if (!cleaned || cleaned.length % 4 !== 0 && cleaned.length % 4 !== 2 && cleaned.length % 4 !== 3) {
    // Might need padding
  }
  try {
    const pad = cleaned.length % 4 === 0 ? cleaned : cleaned + "=".repeat(4 - (cleaned.length % 4));
    if (!/^[A-Za-z0-9+/=]+$/.test(pad)) return null;

    // Use atob if available, or Buffer via globalThis in Node
    const g = globalThis as unknown as { Buffer?: { from: (s: string, enc: string) => { toString: (enc: string) => string } }; atob?: (s: string) => string };
    let binary = "";
    if (typeof g.atob === "function") {
      binary = g.atob(pad);
    } else if (g.Buffer) {
      binary = g.Buffer.from(pad, "base64").toString("binary");
    } else {
      return null;
    }

    // Convert binary to UTF-8 string
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const decoded = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    // Sanity check: must contain reasonable printable chars
    if (/[\x00-\x08\x0E-\x1F]/.test(decoded) && decoded.length > 4) {
      // High density of control chars usually indicates invalid or UTF-16
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

/**
 * Decode PowerShell / Windows UTF-16LE Base64 strings.
 * PowerShell encoded commands (-enc / -EncodedCommand) are UTF-16LE Base64.
 */
export function decodeBase64Utf16Le(input: string): string | null {
  const cleaned = input.trim().replace(/\s+/g, "");
  try {
    const pad = cleaned.length % 4 === 0 ? cleaned : cleaned + "=".repeat(4 - (cleaned.length % 4));
    if (!/^[A-Za-z0-9+/=]+$/.test(pad)) return null;

    const g = globalThis as unknown as { Buffer?: { from: (s: string, enc: string) => { toString: (enc: string) => string } }; atob?: (s: string) => string };
    let binary = "";
    if (typeof g.atob === "function") {
      binary = g.atob(pad);
    } else if (g.Buffer) {
      binary = g.Buffer.from(pad, "base64").toString("binary");
    } else {
      return null;
    }

    if (binary.length < 2 || binary.length % 2 !== 0) return null;

    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const decoded = new TextDecoder("utf-16le", { fatal: false }).decode(bytes);
    // If it looks like valid readable text
    if (decoded && !/[\x00-\x08\x0E-\x1F]/.test(decoded)) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Decode Hex / Shellcode bytes into text (e.g. \x41\x42, 0x41 0x42, or 48656c6c6f).
 */
export function decodeHex(input: string): string | null {
  const cleaned = input.trim();
  if (!cleaned) return null;

  let hexStr = "";
  if (cleaned.includes("\\x") || cleaned.includes("\\X")) {
    hexStr = cleaned.replace(/\\x/gi, "").replace(/\s+/g, "");
  } else if (cleaned.includes("0x") || cleaned.includes("0X")) {
    hexStr = cleaned.replace(/0x/gi, "").replace(/[\s,]+/g, "");
  } else if (/^[0-9a-fA-F\s]+$/.test(cleaned) && cleaned.replace(/\s+/g, "").length >= 4) {
    hexStr = cleaned.replace(/\s+/g, "");
  } else {
    return null;
  }

  if (hexStr.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hexStr)) return null;

  try {
    const bytes = new Uint8Array(hexStr.length / 2);
    for (let i = 0; i < hexStr.length; i += 2) {
      bytes[i / 2] = parseInt(hexStr.substring(i, i + 2), 16);
    }
    const decoded = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    if (!/[\x00-\x08\x0E-\x1F]/.test(decoded) && decoded.length > 0) {
      return decoded;
    }
    // Return ascii representation even if binary
    return decoded;
  } catch {
    return null;
  }
}

/**
 * Decode URL percent-encoding (e.g. %20, %2e%2e%2f).
 */
export function decodeUrl(input: string): string | null {
  const cleaned = input.trim();
  if (!cleaned.includes("%")) return null;
  try {
    const decoded = decodeURIComponent(cleaned);
    if (decoded !== cleaned) return decoded;
    return null;
  } catch {
    return null;
  }
}

/**
 * Defang IOC indicators so they are safe to share in emails/tickets without triggering auto-links.
 * e.g. http://evil.com/payload.exe -> hxxp://evil[.]com/payload[.]exe
 * 192.168.1.1 -> 192[.]168[.]1[.]1
 */
export function defangIoc(input: string): string {
  let s = input;
  s = s.replace(/https:\/\//gi, "hxxps://");
  s = s.replace(/http:\/\//gi, "hxxp://");
  s = s.replace(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/g, "$1[.]$2[.]$3[.]$4");
  s = s.replace(/([a-zA-Z0-9_-]+)\.(com|org|net|io|top|xyz|ru|cn|cc|info|biz|site|live|pw|me)\b/gi, "$1[.]$2");
  return s;
}

/**
 * Refang defanged IOCs back to their actionable forms.
 * e.g. hxxps://evil[.]com -> https://evil.com
 */
export function refangIoc(input: string): string {
  let s = input;
  s = s.replace(/hxxps:\/\//gi, "https://");
  s = s.replace(/hxxp:\/\//gi, "http://");
  s = s.replace(/\[\.\]/g, ".");
  s = s.replace(/\[:\]/g, ":");
  s = s.replace(/\(dot\)/gi, ".");
  s = s.replace(/\[dot\]/gi, ".");
  return s;
}

/**
 * Extract IOCs (IPv4, domains, hashes, URLs) from a text string.
 */
export function extractIocs(text: string): IocMatch[] {
  const matches: IocMatch[] = [];
  const seen = new Set<string>();

  const add = (type: IocMatch["type"], val: string) => {
    const clean = val.trim();
    if (clean && !seen.has(clean.toLowerCase())) {
      seen.add(clean.toLowerCase());
      matches.push({ type, value: clean });
    }
  };

  // IPv4 addresses
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  let m: RegExpExecArray | null;
  while ((m = ipRegex.exec(text)) !== null) {
    if (m[0] !== "127.0.0.1" && m[0] !== "0.0.0.0") {
      add("ip", m[0]);
    }
  }

  // SHA256 (64 hex), SHA1 (40 hex), MD5 (32 hex)
  const hashRegex = /\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b/g;
  while ((m = hashRegex.exec(text)) !== null) {
    add("hash", m[0]);
  }

  // URLs
  const urlRegex = /\bhttps?:\/\/[^\s"'<>]+/gi;
  while ((m = urlRegex.exec(text)) !== null) {
    add("url", m[0]);
  }

  // Domains (common TLDs)
  const domainRegex = /\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:com|org|net|io|top|xyz|ru|cn|cc|info|biz|site|live|pw|me|gov|edu)\b/gi;
  while ((m = domainRegex.exec(text)) !== null) {
    add("domain", m[0]);
  }

  return matches;
}

/**
 * Run all decoders on input string and assemble candidates + IOCs.
 */
export function analyzeAndDecode(input: string): CyberDecoderOutput {
  const trimmed = input.trim();
  const candidates: DecodedCandidate[] = [];

  // Check defang status
  const isDefanged = /hxxp|\[\.\]|\[:\]|\(dot\)/i.test(trimmed);
  if (isDefanged) {
    const refanged = refangIoc(trimmed);
    candidates.push({
      id: "refang",
      name: "Refanged IOCs",
      decoded: refanged,
      confidence: "high",
      description: "Reconstructed live URLs/IPs from defanged format",
    });
  } else {
    candidates.push({
      id: "defang",
      name: "Defanged Output",
      decoded: defangIoc(trimmed),
      confidence: "low",
      description: "Safe-to-share defanged version",
    });
  }

  // PowerShell UTF-16LE Base64
  const utf16 = decodeBase64Utf16Le(trimmed);
  if (utf16 && utf16 !== trimmed) {
    candidates.push({
      id: "b64_utf16",
      name: "PowerShell UTF-16LE Base64",
      decoded: utf16,
      confidence: "high",
      description: "Windows PowerShell EncodedCommand / UTF-16LE stream",
    });
  }

  // UTF-8 Base64
  const utf8 = decodeBase64Utf8(trimmed);
  if (utf8 && utf8 !== trimmed && utf8 !== utf16) {
    candidates.push({
      id: "b64_utf8",
      name: "Base64 (UTF-8 / ASCII)",
      decoded: utf8,
      confidence: "high",
      description: "Standard UTF-8 encoded text payload",
    });
  }

  // Hex decode
  const hex = decodeHex(trimmed);
  if (hex && hex !== trimmed) {
    candidates.push({
      id: "hex",
      name: "Hex / Shellcode Bytes",
      decoded: hex,
      confidence: "medium",
      description: "ASCII representation of raw byte sequence",
    });
  }

  // URL decode
  const url = decodeUrl(trimmed);
  if (url && url !== trimmed) {
    candidates.push({
      id: "url",
      name: "URL Percent-Decoded",
      decoded: url,
      confidence: "high",
      description: "Decoded web/query percent-encoded parameters",
    });
  }

  // Extract IOCs from both raw input and all decoded candidates
  let combined = trimmed + "\n";
  for (const c of candidates) {
    combined += c.decoded + "\n";
  }
  const extractedIocs = extractIocs(combined);

  return {
    input: trimmed,
    candidates,
    extractedIocs,
    isDefanged,
  };
}
