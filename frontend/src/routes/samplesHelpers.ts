// Pure helpers shared by the sample vault (list + detail) — extracted so the
// byte-format contract is unit-testable and the two pages can't drift.

/** Human byte size: B / KB / MB, one decimal for KB+ — matches how the vault
 *  list and the sample detail header render file sizes. */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/** Case-insensitive substring filter over the extracted strings list. The
 *  sample detail's strings panel filters live as the analyst types; the
 *  empty query returns the full list unchanged. */
export function filterStrings(strings: string[], query: string): string[] {
  const q = query.trim().toLowerCase();
  return q ? strings.filter((s) => s.toLowerCase().includes(q)) : strings;
}

/** Total candidate-IOC count across every bucket (urls, ips, domains,
 *  hashes, emails) — the number the static panel shows next to "strings". */
export function iocTotal(iocs: {
  urls: string[];
  ips: string[];
  domains: string[];
  hashes: string[];
  emails: string[];
}): number {
  return iocs.urls.length + iocs.ips.length + iocs.domains.length + iocs.hashes.length + iocs.emails.length;
}
