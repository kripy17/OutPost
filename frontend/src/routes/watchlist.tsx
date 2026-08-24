import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/ui";
import { watchlistAdd, watchlistExport, watchlistImport, watchlistList, watchlistRemove } from "../lib/api";
import { parseImport, typeOf } from "./watchlistHelpers";
import NetworkContextModal from "../components/NetworkContextModal";

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
  const [inspectIp, setInspectIp] = useState<string | null>(null);
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

  const importFile = async (file: File) => {
    setImportMsg(null);
    setError(null);
    try {
      const text = await file.text();
      const isCsv = file.name.toLowerCase().endsWith(".csv");
      const parsed = parseImport(text, isCsv);
      const res = await watchlistImport(parsed);
      setImportMsg(`Imported ${res.imported} entr${res.imported === 1 ? "y" : "ies"} from ${file.name}.`);
      await refetch();
    } catch {
      setError("Import failed — expected JSON ({entries:[…]}) or CSV (value,label).");
    }
  };

  return (
    <div className="mx-auto max-w-3xl px-5 py-8 lg:px-8">
      <PageHeader
        kicker="Operations · watchlist"
        title={
          <>
            Personal watchlist <span className="font-normal text-text-muted">— your own tracked infrastructure</span>
          </>
        }
        lede="IPs, domains, or hashes you flag from your own research. Checked against every run's connections during enrichment, independent of AbuseIPDB/VirusTotal — matches get a star in the network table."
      />

      <form onSubmit={add} className="mt-6 flex flex-wrap gap-2">
        <div className="relative min-w-56 flex-1">
          <Icon name="search" size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-faint" />
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="value (IP / domain / hash)"
            className="w-full rounded-lg border border-border-subtle bg-bg-surface py-2 pl-8 pr-3 font-mono text-sm text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
          />
        </div>
        <input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="label (optional) — e.g. C2 from sample X"
          className="flex-1 rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
        />
        <button
          type="submit"
          className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 px-4 py-2 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/10"
        >
          <Icon name="plus" size={12} />
          Add
        </button>
      </form>

      {error && <p className="mt-3 text-xs text-risk-malicious">{error}</p>}

      <div className="mt-6 flex flex-wrap items-center gap-2">
        <button
          onClick={() => void watchlistExport("json").then((b) => download(b, "outpost-watchlist.json"))}
          className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
        >
          <Icon name="download" size={12} />
          export JSON
        </button>
        <button
          onClick={() => void watchlistExport("csv").then((b) => download(b, "outpost-watchlist.csv"))}
          className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
        >
          <Icon name="download" size={12} />
          export CSV
        </button>
        <button
          onClick={() => fileRef.current?.click()}
          className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
        >
          <Icon name="plus" size={12} />
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
            if (file) await importFile(file);
          }}
        />
        {importMsg && <span className="inline-flex items-center gap-1 text-xs text-risk-clean"><Icon name="check" size={11} />{importMsg}</span>}
      </div>

      <div className="mt-8 space-y-2">
        {entries.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-border-strong bg-bg-surface/40 p-12 text-center">
            <Icon name="star" size={26} className="mx-auto text-text-faint" />
            <p className="mt-3 text-sm text-text-muted">Watchlist is empty — add an IP you're tracking.</p>
          </div>
        ) : (
          entries.map((e) => {
            const t = typeOf(e.value);
            return (
              <div
                key={e.value}
                className="group flex flex-wrap items-center gap-3 rounded-xl border border-border-subtle bg-bg-surface px-4 py-2.5 transition-colors duration-150 hover:border-accent/30"
              >
                <Icon name="star" size={13} className="shrink-0 text-accent" />
                <span className={`shrink-0 rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wide ${t.cls}`}>
                  {t.label}
                </span>
                <code className="min-w-0 truncate font-mono text-xs text-text-primary">{e.value}</code>
                {e.label && <span className="truncate text-xs text-text-muted">— {e.label}</span>}
                <div className="ml-auto flex shrink-0 items-center gap-2">
                  {t.label === "ip" && (
                    <button
                      onClick={() => setInspectIp(e.value)}
                      className="press inline-flex items-center gap-1 rounded border border-accent/40 bg-accent/10 px-2 py-0.5 font-mono text-[10px] text-accent hover:bg-accent/20"
                      title={`Investigate network context for ${e.value}`}
                    >
                      <Icon name="activity" size={10} />
                      Context
                    </button>
                  )}
                  <Link
                    to={`/search?q=${encodeURIComponent(e.value)}`}
                    className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-elevated/60 px-2 py-0.5 font-mono text-[10px] text-text-muted hover:border-accent/40 hover:text-accent"
                    title={`Search ${e.value} in Global IOC Intelligence`}
                  >
                    <Icon name="search" size={10} />
                    Search
                  </Link>
                  <span className="font-mono text-[10px] text-text-faint">
                    {e.added_at.slice(0, 19).replace("T", " ")}
                  </span>
                  <button
                    onClick={() => void remove(e.value)}
                    className="press flex h-7 w-7 items-center justify-center rounded-lg text-text-faint transition-colors duration-150 hover:bg-risk-malicious/10 hover:text-risk-malicious"
                    aria-label={`Remove ${e.value}`}
                  >
                    <Icon name="x" size={13} />
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      {inspectIp !== null && (
        <NetworkContextModal ip={inspectIp} onClose={() => setInspectIp(null)} />
      )}
    </div>
  );
}
