import { useState } from "react";
import { getRunExport } from "../../lib/api";

type Status = "idle" | "working" | "done" | "error";

export default function ExportButton({
  runId,
  label = "Export JSON",
  filename,
  fetcher = getRunExport,
}: {
  runId: string;
  label?: string;
  filename?: string;
  fetcher?: (runId: string) => Promise<Blob>;
}) {
  const [status, setStatus] = useState<Status>("idle");

  const onExport = async () => {
    setStatus("working");
    try {
      const blob = await fetcher(runId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename ?? `outpost-report-${runId.slice(0, 12)}.json`;
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
      className="press rounded border border-accent-amber/60 px-3 py-1.5 font-mono text-xs text-accent-amber transition-colors duration-150 hover:bg-accent-amber/10 disabled:opacity-50"
    >
      {text}
    </button>
  );
}
