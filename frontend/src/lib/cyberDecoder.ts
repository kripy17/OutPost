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
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u0008\u000e-\u001f]/.test(decoded) && decoded.length > 4) {
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
    // eslint-disable-next-line no-control-regex
    if (decoded && !/[\u0000-\u0008\u000e-\u001f]/.test(decoded)) {
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

  let hexStr: string;
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
    // eslint-disable-next-line no-control-regex
    if (!/[\u0000-\u0008\u000e-\u001f]/.test(decoded) && decoded.length > 0) {
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
 * Decode JSON Web Token (RFC 7519) into structured header and claims payload.
 */
export function decodeJwt(input: string): DecodedCandidate | null {
  const cleaned = input.trim();
  const parts = cleaned.split(".");
  if (parts.length !== 3) return null;
  if (!parts.every((p) => /^[A-Za-z0-9_-]+$/.test(p) && p.length > 0)) return null;

  const b64urlDecode = (str: string): string | null => {
    let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) b64 += "=";
    return decodeBase64Utf8(b64);
  };

  try {
    const headerStr = b64urlDecode(parts[0]);
    const payloadStr = b64urlDecode(parts[1]);
    if (!headerStr || !payloadStr) return null;

    const header = JSON.parse(headerStr);
    const payload = JSON.parse(payloadStr);

    let formatted = `[JWT HEADER]\n${JSON.stringify(header, null, 2)}\n\n[JWT CLAIMS / PAYLOAD]\n${JSON.stringify(payload, null, 2)}`;
    if (typeof payload.exp === "number") {
      const expDate = new Date(payload.exp * 1000).toISOString();
      const isExpired = Date.now() > payload.exp * 1000;
      formatted += `\n\n[EXPIRATION]: ${expDate} (${isExpired ? "EXPIRED" : "VALID"})`;
    }
    if (typeof payload.sub === "string") {
      formatted += `\n[SUBJECT]: ${payload.sub}`;
    }

    return {
      id: "jwt",
      name: "JSON Web Token (JWT Claims)",
      decoded: formatted,
      confidence: "high",
      description: "Decoded RFC 7519 JWT header and claims payload",
    };
  } catch {
    return null;
  }
}

/**
 * Decode ROT13 cipher string.
 */
export function decodeRot13(input: string): string | null {
  const cleaned = input.trim();
  if (cleaned.length < 4 || !/[a-zA-Z]/.test(cleaned)) return null;
  const decoded = cleaned.replace(/[a-zA-Z]/g, (c) => {
    const code = c.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      return String.fromCharCode(((code - 65 + 13) % 26) + 65);
    }
    return String.fromCharCode(((code - 97 + 13) % 26) + 97);
  });
  if (decoded === cleaned) return null;
  return decoded;
}

/**
 * Scan for single-byte XOR obfuscated payloads (0x01 - 0xFF) by matching known threat signatures.
 */
export function scanSingleByteXor(input: string): DecodedCandidate | null {
  const cleaned = input.trim();
  let bytes: Uint8Array | null = null;
  if (/^(\\x[0-9a-fA-F]{2})+$/i.test(cleaned)) {
    const hex = cleaned.replace(/\\x/gi, "");
    bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
  } else if (/^[0-9a-fA-F]{8,}$/.test(cleaned) && cleaned.length % 2 === 0) {
    bytes = new Uint8Array(cleaned.length / 2);
    for (let i = 0; i < cleaned.length; i += 2) {
      bytes[i / 2] = parseInt(cleaned.substring(i, i + 2), 16);
    }
  } else if (cleaned.length >= 8 && cleaned.length <= 512) {
    bytes = new Uint8Array(cleaned.length);
    for (let i = 0; i < cleaned.length; i++) {
      bytes[i] = cleaned.charCodeAt(i);
    }
  }

  if (!bytes || bytes.length < 4) return null;

  const signatures = [
    "http://", "https://", "powershell", "cmd.exe", "/bin/sh",
    "/bin/bash", "whoami", "curl ", "wget ", "select ", "eval(",
  ];
  let bestKey: number | null = null;
  let bestDecoded = "";

  for (let key = 1; key <= 255; key++) {
    const xored = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      xored[i] = bytes[i] ^ key;
    }
    const text = new TextDecoder("utf-8", { fatal: false }).decode(xored);
    const lower = text.toLowerCase();
    if (signatures.some((sig) => lower.includes(sig))) {
      bestKey = key;
      bestDecoded = text;
      break;
    }
  }

  if (bestKey !== null) {
    const keyHex = "0x" + bestKey.toString(16).padStart(2, "0").toUpperCase();
    return {
      id: "xor_single_byte",
      name: `XOR Decrypted (Key: ${keyHex})`,
      decoded: bestDecoded,
      confidence: "high",
      description: `Payload deobfuscated via single-byte XOR key ${keyHex}`,
    };
  }
  return null;
}

/**
 * Decode Unix epoch timestamp into ISO-8601 UTC date string.
 */
export function decodeUnixTimestamp(input: string): DecodedCandidate | null {
  const cleaned = input.trim();
  let ms: number | null = null;
  if (/^\d{10}$/.test(cleaned)) {
    const sec = parseInt(cleaned, 10);
    if (sec >= 946684800 && sec <= 2500000000) {
      ms = sec * 1000;
    }
  } else if (/^\d{13}$/.test(cleaned)) {
    const num = parseInt(cleaned, 10);
    if (num >= 946684800000 && num <= 2500000000000) {
      ms = num;
    }
  }

  if (ms !== null) {
    const date = new Date(ms);
    return {
      id: "timestamp",
      name: "Unix Epoch Timestamp",
      decoded: `UTC: ${date.toISOString()}`,
      confidence: "high",
      description: "Parsed Unix epoch timestamp to ISO-8601 UTC date",
    };
  }
  return null;
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

  // JWT RFC 7519 decode
  const jwt = decodeJwt(trimmed);
  if (jwt) {
    candidates.push(jwt);
  }

  // Single-byte XOR brute-force scan
  const xor = scanSingleByteXor(trimmed);
  if (xor) {
    candidates.push(xor);
  }

  // ROT13 decode
  const rot13 = decodeRot13(trimmed);
  if (rot13 && rot13 !== trimmed) {
    const isSuspicious = /powershell|cmd|http|\/bin\/|curl|wget|select|exec/i.test(rot13);
    candidates.push({
      id: "rot13",
      name: "ROT13 Deobfuscated",
      decoded: rot13,
      confidence: isSuspicious ? "high" : "low",
      description: "Caesar cipher rotation by 13 positions",
    });
  }

  // Unix Epoch Timestamp
  const ts = decodeUnixTimestamp(trimmed);
  if (ts) {
    candidates.push(ts);
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
