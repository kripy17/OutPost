import { useState } from "react";
import { getRunExport } from "../../lib/api";

type Status = "idle" | "working" | "done" | "error";

// Fetcher may need a run id (run report/STIX) or not (coverage Navigator
// layer) — a zero-arg fetcher is assignable to this signature, so the same
// button covers both. The id defaults to "" and is simply ignored by fetchers
// that don't need it.
export default function ExportButton({
  runId,
  label = "Export JSON",
  filename,
  fetcher = getRunExport,
}: {
  runId?: string;
  label?: string;
  filename?: string;
  fetcher?: (runId: string) => Promise<Blob>;
}) {
  const [status, setStatus] = useState<Status>("idle");

  const onExport = async () => {
    setStatus("working");
    try {
      const blob = await fetcher(runId ?? "");
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename ?? (runId ? `outpost-report-${runId.slice(0, 12)}.json` : "outpost-export.json");
      a.click();
      URL.revokeObjectURL(url);
      setStatus("done");
      setTimeout(() => setStatus("idle"), 2000);
    } catch {
      setStatus("error");
      setTimeout(() => setStatus("idle"), 3000);
    }
  };

  const text =
    status === "working" ? "Fetching…" : status === "done" ? "Exported ✓" : status === "error" ? "Failed" : label;

  return (
    <button
      onClick={onExport}
      disabled={status === "working"}
      className="press rounded border border-accent/60 px-3 py-1.5 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/10 disabled:opacity-50"
    >
      {text}
    </button>
  );
}
