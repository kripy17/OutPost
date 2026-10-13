import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Icon } from "../Icon";
import { Panel } from "../ui";
import { listSandboxArtifacts, getSandboxArtifactUrl } from "../../lib/api";
import type { AnalysisObservation } from "../../types";

interface FileSystemArtifactsTabProps {
  observations: AnalysisObservation[];
  runId: string;
}

export function FileSystemArtifactsTab({ observations, runId }: FileSystemArtifactsTabProps) {
  const [copiedPath, setCopiedPath] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  const { data: artifacts = [], isLoading: isLoadingArtifacts } = useQuery({
    queryKey: ["sandbox", "artifacts", runId],
    queryFn: () => listSandboxArtifacts(runId),
  });

  const handleCopy = (path: string, e: React.MouseEvent) => {
    e.stopPropagation();
    void navigator.clipboard.writeText(path);
    setCopiedPath(path);
    setTimeout(() => setCopiedPath(null), 1800);
  };

  // Extract file system modifications from observations
  const fileEvents = useMemo(() => {
    return observations.filter((o) => o.event_type === "file_write" || Boolean(o.file_path));
  }, [observations]);

  // Extract registry modifications from observations
  const registryEvents = useMemo(() => {
    return observations.filter((o) => o.event_type === "registry_write" || Boolean(o.registry_key));
  }, [observations]);

  const filteredFiles = useMemo(() => {
    if (!filter.trim()) return fileEvents;
    const q = filter.toLowerCase();
    return fileEvents.filter(
      (f) =>
        f.file_path?.toLowerCase().includes(q) ||
        f.process_name?.toLowerCase().includes(q) ||
        String(f.pid || "").includes(q),
    );
  }, [fileEvents, filter]);

  return (
    <div className="space-y-6 font-sans">
      {/* Section 1: Persisted Dropped Forensic Artifacts */}
      <Panel
        kicker="Forensic Extraction"
        title="Dropped Files &amp; Extracted Artifacts"
        right={
          <span className="font-mono text-xs text-text-faint tabular-nums">
            {artifacts.length} artifact{artifacts.length === 1 ? "" : "s"} retained
          </span>
        }
      >
        {isLoadingArtifacts ? (
          <p className="p-4 text-center font-mono text-xs text-text-muted">Loading persisted artifacts…</p>
        ) : artifacts.length === 0 ? (
          <div className="p-6 text-center font-mono text-xs text-text-muted">
            <Icon name="box" size={24} className="mx-auto mb-2 text-text-faint" />
            <p className="font-bold text-text-primary">No Dropped Artifacts Retained</p>
            <p className="text-text-faint mt-1">
              Zero binary or configuration artifacts were written to disk by this detonation run.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-border-subtle bg-bg-base/70 text-[10px] uppercase text-text-faint font-semibold">
                  <th className="py-2.5 px-3">Artifact Filename</th>
                  <th className="py-2.5 px-3">Size (Bytes)</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/40 text-[11px]">
                {artifacts.map((art) => (
                  <tr key={art.filename} className="hover:bg-bg-elevated/30 transition">
                    <td className="py-2 px-3 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <Icon name="box" size={13} className="text-accent shrink-0" />
                        <span className="font-bold text-text-primary select-all">{art.filename}</span>
                      </div>
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap text-text-secondary tabular-nums">
                      {art.size_bytes.toLocaleString()} bytes
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap text-right">
                      <div className="flex items-center justify-end gap-2">
                        <a
                          href={getSandboxArtifactUrl(runId, art.filename)}
                          download={art.filename}
                          className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-surface px-2.5 py-1 text-[10px] font-semibold text-text-primary hover:border-accent hover:text-accent transition shadow-xs"
                          title="Download dropped forensic payload"
                        >
                          <Icon name="download" size={10} />
                          <span>Download</span>
                        </a>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/* Section 2: File System Modifications */}
      <Panel
        kicker="Filesystem Forensics"
        title="Runtime File System Writes &amp; Modifications"
        right={
          <div className="flex items-center gap-2 font-mono text-xs">
            <input
              type="text"
              placeholder="Filter file paths, PID…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="w-44 rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 text-[11px] text-text-primary placeholder:text-text-faint outline-none focus:border-accent"
            />
            <span className="text-text-faint tabular-nums text-[11px]">{filteredFiles.length} writes</span>
          </div>
        }
      >
        {filteredFiles.length === 0 ? (
          <div className="p-6 text-center font-mono text-xs text-text-muted">
            <p className="font-bold text-text-primary">No File Modifications Observed</p>
            <p className="text-text-faint mt-1">Zero file writes matching your filter were recorded.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-border-subtle bg-bg-base/70 text-[10px] uppercase text-text-faint font-semibold">
                  <th className="py-2.5 px-3">Timestamp (UTC)</th>
                  <th className="py-2.5 px-3">Attributed Process</th>
                  <th className="py-2.5 px-3">Action</th>
                  <th className="py-2.5 px-3">Modified Target Path</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/40 text-[11px]">
                {filteredFiles.map((evt, idx) => (
                  <tr key={`${evt.id ?? idx}-${idx}`} className="hover:bg-bg-elevated/30 transition">
                    <td className="py-2 px-3 whitespace-nowrap text-text-muted tabular-nums">
                      {evt.timestamp ? evt.timestamp.slice(11, 19) : "—"}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className="font-bold text-text-primary">{evt.process_name || "—"}</span>
                        {evt.pid && (
                          <span className="rounded bg-bg-elevated px-1 py-0.2 text-[9px] text-text-faint">
                            PID {evt.pid}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.2 text-[9px] font-bold text-amber-400 uppercase">
                        WRITE
                      </span>
                    </td>
                    <td className="py-2 px-3 max-w-[320px]">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <span className="truncate text-text-primary select-all" title={evt.file_path || ""}>
                          {evt.file_path || "—"}
                        </span>
                        {evt.file_path && (
                          <button
                            onClick={(e) => handleCopy(evt.file_path!, e)}
                            className="press rounded p-0.5 text-text-faint hover:text-text-primary transition shrink-0"
                            title="Copy file path"
                          >
                            <Icon
                              name={copiedPath === evt.file_path ? "check" : "copy"}
                              size={10}
                              className={copiedPath === evt.file_path ? "text-emerald-400" : ""}
                            />
                          </button>
                        )}
                      </div>
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap text-right">
                      {evt.file_path && (
                        <Link
                          to="/watchlist"
                          className="press rounded border border-border-subtle bg-bg-surface px-1.5 py-0.5 text-[9px] text-text-faint hover:text-accent hover:border-accent/40 transition"
                          title="Add path to Watchlist"
                        >
                          Watchlist
                        </Link>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/* Section 3: Registry Modifications (Windows) */}
      {registryEvents.length > 0 && (
        <Panel
          kicker="Configuration &amp; Autostart"
          title="Registry Key Modifications"
          right={
            <span className="font-mono text-xs text-text-faint tabular-nums">
              {registryEvents.length} key modifications
            </span>
          }
        >
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-border-subtle bg-bg-base/70 text-[10px] uppercase text-text-faint font-semibold">
                  <th className="py-2.5 px-3">Timestamp (UTC)</th>
                  <th className="py-2.5 px-3">Attributed Process</th>
                  <th className="py-2.5 px-3">Operation</th>
                  <th className="py-2.5 px-3">Target Registry Key</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/40 text-[11px]">
                {registryEvents.map((evt, idx) => (
                  <tr key={`${evt.id ?? idx}-${idx}`} className="hover:bg-bg-elevated/30 transition">
                    <td className="py-2 px-3 whitespace-nowrap text-text-muted tabular-nums">
                      {evt.timestamp ? evt.timestamp.slice(11, 19) : "—"}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <span className="font-bold text-text-primary">{evt.process_name || "—"}</span>
                      {evt.pid && <span className="ml-1 text-[9px] text-text-faint">PID {evt.pid}</span>}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <span className="rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.2 text-[9px] font-bold text-rose-400 uppercase">
                        SET_KEY
                      </span>
                    </td>
                    <td className="py-2 px-3 max-w-[340px]">
                      <span className="truncate block text-text-primary select-all" title={evt.registry_key || ""}>
                        {evt.registry_key || "—"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  );
}
