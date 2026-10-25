export type IndicatorType = "ip" | "domain" | "url" | "hash" | "email";

export interface ExtractedIndicator {
  raw: string;
  refanged: string;
  defanged: string;
  type: IndicatorType;
  subType?: string; // e.g. "sha256", "md5", "private_ip", "public_ip"
  isPrivate?: boolean;
}

// Defanging / Refanging Utilities
export function refangText(text: string): string {
  return text
    .replace(/\[:\/\/\]/gi, "://")
    .replace(/\[:\]\/\//gi, "://")
    .replace(/hxxps?:\/\//gi, (m) => (m.toLowerCase().startsWith("hxxps") ? "https://" : "http://"))
    .replace(/hxxps?/gi, (m) => (m.toLowerCase().startsWith("hxxps") ? "https" : "http"))
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, ".")
    .replace(/\[:\]|\{:\}/g, ":")
    .replace(/\[@\]|\(@\)|\{@\}/g, "@");
}

export function defangText(text: string): string {
  return text
    .replace(/https:\/\//gi, "hxxps://")
    .replace(/http:\/\//gi, "hxxp://")
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");
}

export function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  return false;
}

export function extractIndicators(inputText: string): ExtractedIndicator[] {
  if (!inputText.trim()) return [];

  // First refang the input so regexes can match standardized patterns
  const normalized = refangText(inputText);
  const results: ExtractedIndicator[] = [];
  const seen = new Set<string>();

  // 1. URLs
  const urlRegex = /https?:\/\/[^\s"'<>)\]}]+/gi;
  const urls = normalized.match(urlRegex) || [];
  for (const u of urls) {
    const clean = u.replace(/[.,;!?]+$/, "");
    if (!seen.has(clean.toLowerCase())) {
      seen.add(clean.toLowerCase());
      results.push({
        raw: clean,
        refanged: clean,
        defanged: defangText(clean),
        type: "url",
      });
    }
  }

  // 2. Email Addresses
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  const emails = normalized.match(emailRegex) || [];
  for (const em of emails) {
    const clean = em.toLowerCase();
    if (!seen.has(clean)) {
      seen.add(clean);
      results.push({
        raw: em,
        refanged: clean,
        defanged: defangText(clean),
        type: "email",
      });
    }
  }

  // 3. IPv4 Addresses
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const ips = normalized.match(ipRegex) || [];
  for (const ip of ips) {
    if (!seen.has(ip)) {
      seen.add(ip);
      const isPriv = isPrivateIpv4(ip);
      results.push({
        raw: ip,
        refanged: ip,
        defanged: defangText(ip),
        type: "ip",
        subType: isPriv ? "private_ip" : "public_ip",
        isPrivate: isPriv,
      });
    }
  }

  // 4. Hashes (SHA256, SHA1, MD5)
  const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
  const sha256s = normalized.match(sha256Regex) || [];
  for (const h of sha256s) {
    const clean = h.toLowerCase();
    if (!seen.has(clean)) {
      seen.add(clean);
      results.push({
        raw: h,
        refanged: clean,
        defanged: clean,
        type: "hash",
        subType: "sha256",
      });
    }
  }

  const sha1Regex = /\b[a-fA-F0-9]{40}\b/g;
  const sha1s = normalized.match(sha1Regex) || [];
  for (const h of sha1s) {
    const clean = h.toLowerCase();
    if (!seen.has(clean)) {
      seen.add(clean);
      results.push({
        raw: h,
        refanged: clean,
        defanged: clean,
        type: "hash",
        subType: "sha1",
      });
    }
  }

  const md5Regex = /\b[a-fA-F0-9]{32}\b/g;
  const md5s = normalized.match(md5Regex) || [];
  for (const h of md5s) {
    const clean = h.toLowerCase();
    if (!seen.has(clean)) {
      seen.add(clean);
      results.push({
        raw: h,
        refanged: clean,
        defanged: clean,
        type: "hash",
        subType: "md5",
      });
    }
  }

  // 5. Domains / FQDNs
  const domainRegex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|mil|io|co|ai|xyz|biz|info|top|ru|cn|me|app|dev|cloud|live|online|site|space|tech|store|cc|to|pw|su|ws|click|link|vip|pro)\b/gi;
  const domains = normalized.match(domainRegex) || [];
  for (const d of domains) {
    const clean = d.toLowerCase().replace(/^[./]+/, "");
    // Skip if already in URL, email or seen
    if (!seen.has(clean) && !clean.includes("@")) {
      seen.add(clean);
      results.push({
        raw: d,
        refanged: clean,
        defanged: defangText(clean),
        type: "domain",
      });
    }
  }

  return results;
}
