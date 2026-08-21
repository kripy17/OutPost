// Pure derivations for the watchlist page — the entry-type classification
// (IP / hash / domain / other) and the JSON-or-CSV import parser, extracted
// so the parsing contract is unit-testable without a DOM.

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export interface WatchlistImportRow {
  value: string;
  label?: string;
}

/** Best-effort entry type — IP, hash, domain, or other. */
export function typeOf(value: string): { label: string; cls: string } {
  if (IPV4.test(value)) return { label: "IP", cls: "border-signal/40 text-signal" };
  if (/^[a-f0-9]{32,64}$/i.test(value)) return { label: "Hash", cls: "border-accent/40 text-accent" };
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return { label: "Domain", cls: "border-risk-suspicious/40 text-risk-suspicious" };
  return { label: "Other", cls: "border-border-subtle text-text-muted" };
}

/** Parse an import file: CSV rows are "value,label" (comma-splitting the
 *  rest into the label so a label containing commas survives); JSON is the
 *  `{entries: [{value, label?}]}` shape. Rows without a value are dropped. */
export function parseImport(text: string, isCsv: boolean): WatchlistImportRow[] {
  if (!text.trim()) return []; // a blank file (either format) imports nothing
  const rows = isCsv
    ? text
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean)
        .map((l) => {
          const [v, ...rest] = l.split(",");
          return { value: v.trim(), label: rest.join(",").trim() || undefined };
        })
    : (JSON.parse(text).entries as WatchlistImportRow[] | undefined) ?? [];
  return rows.filter((r) => r.value);
}
