import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { PageHeader } from "../components/ui";
import { watchlistAdd, watchlistExport, watchlistImport, watchlistList, watchlistRemove } from "../lib/api";

function download(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export default function WatchlistPage() {
  const { data: entries = [], refetch } = useQuery({ queryKey: ["watchlist"], queryFn: watchlistList });
  const [value, setValue] = useState("");
  const [label, setLabel] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [importMsg, setImportMsg] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    const v = value.trim();
    if (!v) return;
    try {
      await watchlistAdd(v, label.trim());
      setValue("");
      setLabel("");
      setError(null);
      await refetch();
    } catch {
      setError("Could not add entry — is the backend running?");
    }
  };

  const remove = async (v: string) => {
    try {
      await watchlistRemove(v);
      await refetch();
    } catch {
      setError(`Could not remove ${v}`);
    }
  };

  return (
    <div className="mx-auto max-w-3xl px-6 py-10">
      <PageHeader
        kicker="Operations · watchlist"
        title={
          <>
            Personal watchlist <span className="font-normal text-text-muted">— your own tracked infrastructure</span>
          </>
        }
        lede="IPs, domains, or hashes you flag from your own research. Checked against every run's connections during enrichment, independent of AbuseIPDB/VirusTotal — matches get a ★ in the network table."
      />

      <form onSubmit={add} className="mt-6 flex flex-wrap gap-2">
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="value (IP / domain / hash)"
          className="w-56 rounded border border-border-subtle bg-bg-surface px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-faint focus:border-accent-amber/60 focus:outline-none"
        />
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="label (optional) — e.g. C2 from sample X"
          className="flex-1 rounded border border-border-subtle bg-bg-surface px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:border-accent-amber/60 focus:outline-none"
        />
        <button
          type="submit"
          className="press rounded border border-accent-amber/60 px-4 py-2 font-mono text-xs text-accent-amber transition-colors duration-150 hover:bg-accent-amber/10"
        >
          Add
        </button>
      </form>

      {error && <p className="mt-3 text-xs text-risk-malicious">{error}</p>}

      {/* Import / export — roadmap 3.3: shared watchlists as JSON or CSV. */}
      <div className="mt-6 flex flex-wrap items-center gap-2">
        <button
          onClick={() => void watchlistExport("json").then((b) => download(b, "outpost-watchlist.json"))}
          className="press rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent-amber/60 hover:text-accent-amber"
        >
          export JSON
        </button>
        <button
          onClick={() => void watchlistExport("csv").then((b) => download(b, "outpost-watchlist.csv"))}
          className="press rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent-amber/60 hover:text-accent-amber"
        >
          export CSV
        </button>
        <button
          onClick={() => fileRef.current?.click()}
          className="press rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent-amber/60 hover:text-accent-amber"
        >
          import…
        </button>
        <input
          ref={fileRef}
          type="file"
          accept=".json,.csv,application/json,text/csv"
          className="hidden"
          onChange={async (e) => {
            const file = e.target.files?.[0];
            e.target.value = "";
            if (!file) return;
            setImportMsg(null);
            setError(null);
            try {
              const text = await file.text();
              const isCsv = file.name.toLowerCase().endsWith(".csv");
              const parsed: { value: string; label?: string }[] = isCsv
                ? text
                    .split(/\r?\n/)
                    .map((l) => l.trim())
                    .filter(Boolean)
                    .map((l) => {
                      const [v, ...rest] = l.split(",");
                      return { value: v.trim(), label: rest.join(",").trim() };
                    })
                : (JSON.parse(text).entries as { value: string; label?: string }[]) ?? [];
              const res = await watchlistImport(parsed.filter((p) => p.value));
              setImportMsg(`Imported ${res.imported} entr${res.imported === 1 ? "y" : "ies"} from ${file.name}.`);
              await refetch();
            } catch {
              setError("Import failed — expected JSON ({entries:[…]}) or CSV (value,label).");
            }
          }}
        />
      </div>
      {importMsg && <p className="mt-3 text-xs text-accent-amber">{importMsg}</p>}

      <div className="mt-8 overflow-hidden rounded-lg border border-border-subtle">
        <table className="w-full text-left">
          <thead className="border-b border-border-subtle">
            <tr className="text-[10px] uppercase tracking-widest text-text-faint">
              <th className="px-4 py-2">Value</th>
              <th className="px-4 py-2">Label</th>
              <th className="px-4 py-2">Added</th>
              <th className="px-4 py-2" />
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-6 text-sm text-text-muted">
                  Watchlist is empty — add an IP you're tracking.
                </td>
              </tr>
            )}
            {entries.map((e) => (
              <tr key={e.value} className="border-b border-border-subtle/50 transition-colors hover:bg-bg-surface">
                <td className="px-4 py-2 font-mono text-xs text-text-primary">{e.value}</td>
                <td className="px-4 py-2 text-xs text-text-muted">{e.label}</td>
                <td className="px-4 py-2 font-mono text-xs text-text-faint">{e.added_at.slice(0, 19).replace("T", " ")}</td>
                <td className="px-4 py-2 text-right">
                  <button
                    onClick={() => void remove(e.value)}
                    className="press font-mono text-xs text-text-faint transition-colors duration-150 hover:text-risk-malicious"
                  >
                    remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
