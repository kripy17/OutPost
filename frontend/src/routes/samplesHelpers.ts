// Pure helpers shared by the sample vault (list + detail) — extracted so the
// byte-format contract is unit-testable and the two pages can't drift.

/** Human byte size: B / KB / MB, one decimal for KB+ — matches how the vault
 *  list and the sample detail header render file sizes. */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
