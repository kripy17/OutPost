import { Icon } from "./Icon";

export interface InodeEntry {
  fd: number;
  path: string;
  clean_path?: string;
  is_deleted?: boolean;
  is_memfd?: boolean;
  kind?: string;
  access?: string;
  pid?: number;
  process_name?: string;
}

export function DeletedInodeInspector({
  files,
  title = "Deleted Inode & Memory-Mapped File Forensics",
}: {
  files: InodeEntry[];
  title?: string;
}) {
  const deletedOrMemfd = files.filter((f) => f.is_deleted || f.is_memfd);
  const regularFiles = files.filter((f) => !f.is_deleted && !f.is_memfd);

  return (
    <div className="space-y-3 rounded-2xl border border-border-subtle bg-bg-surface/50 p-4">
      <div className="flex items-center justify-between border-b border-border-subtle pb-3">
        <div className="flex items-center gap-2">
          <Icon name="file" size={16} className="text-risk-suspicious" />
          <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-text-primary">
            {title}
          </h3>
        </div>
        <div className="flex items-center gap-2 font-mono text-[10px]">
          {deletedOrMemfd.length > 0 && (
            <span className="rounded bg-risk-malicious/15 border border-risk-malicious/40 px-2 py-0.5 text-risk-malicious font-bold">
              ⚠ {deletedOrMemfd.length} stealth unlinked/memfd descriptor(s)
            </span>
          )}
          <span className="text-text-faint">{files.length} total descriptors</span>
        </div>
      </div>

      {files.length === 0 ? (
        <div className="py-6 text-center font-mono text-xs text-text-faint">
          No open file or socket descriptors reported for this context.
        </div>
      ) : (
        <div className="space-y-2">
          {deletedOrMemfd.length > 0 && (
            <div className="space-y-1.5">
              <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-risk-malicious">
                🚨 Unlinked Inodes / Stealth Memory Files
              </span>
              <div className="space-y-1">
                {deletedOrMemfd.map((f, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between rounded-lg border border-risk-malicious/40 bg-risk-malicious/10 p-2 font-mono text-xs text-text-primary"
                  >
                    <div className="flex items-center gap-2 truncate">
                      <span className="rounded bg-bg-base px-1.5 py-0.2 text-[10px] text-risk-malicious font-bold">
                        FD {f.fd}
                      </span>
                      <span className="font-semibold text-risk-malicious truncate">{f.path}</span>
                    </div>
                    <span className="rounded bg-risk-malicious/20 px-1.5 py-0.5 text-[9px] font-bold text-risk-malicious uppercase">
                      {f.is_deleted ? "UNLINKED / DELETED" : "MEMFD MEMORY"}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="mt-3 space-y-1.5">
            <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-text-muted">
              Active Descriptors & Pipes ({regularFiles.length})
            </span>
            <div className="max-h-48 space-y-1 overflow-y-auto pr-1">
              {regularFiles.map((f, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between rounded-lg border border-border-subtle bg-bg-surface p-2 font-mono text-xs text-text-primary"
                >
                  <div className="flex items-center gap-2 truncate">
                    <span className="rounded bg-bg-base px-1.5 py-0.2 text-[10px] text-text-faint">
                      FD {f.fd}
                    </span>
                    <span className="truncate text-text-muted">{f.path}</span>
                  </div>
                  <span className="text-[10px] text-text-faint uppercase">{f.kind || "FILE"}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
