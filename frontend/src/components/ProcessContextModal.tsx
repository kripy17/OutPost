import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { controlProcessXRay, getForensicCapsule, getProcessSummary, getProcessXRay } from "../lib/api";
import { Icon } from "./Icon";

type TabKey = "overview" | "lineage" | "security" | "sockets" | "files" | "libraries" | "env" | "detections";

export function ProcessContextModal({
  pid,
  onClose,
}: {
  pid: number;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<TabKey>("overview");
  const [actionStatus, setActionStatus] = useState<string | null>(null);
  const [libFilter, setLibFilter] = useState("");
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: xrayData, isLoading: isXrayLoading } = useQuery({
    queryKey: ["xray", "process", pid],
    queryFn: () => getProcessXRay(pid),
    retry: false,
    staleTime: 10_000,
  });

  const { data: summaryData, isLoading: isSummaryLoading } = useQuery({
    queryKey: ["events", "process-summary", pid],
    queryFn: () => getProcessSummary(pid),
    staleTime: 30_000,
  });

  const actionMutation = useMutation({
    mutationFn: (action: "freeze" | "resume" | "terminate" | "kill") =>
      controlProcessXRay(pid, action, xrayData?.create_time),
    onSuccess: (res) => {
      setActionStatus(res.message);
      void queryClient.invalidateQueries({ queryKey: ["xray"] });
      void queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
    onError: (err: any) => {
      setActionStatus(`Action error: ${err?.message || "Failed to dispatch process control signal"}`);
    },
  });

  const handleExportCapsule = async () => {
    try {
      setActionStatus("Generating forensic capsule package...");
      const capsule = await getForensicCapsule(pid);
      const blob = new Blob([JSON.stringify(capsule, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `outpost-xray-capsule-pid-${pid}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setActionStatus(`Exported forensic capsule: outpost-xray-capsule-pid-${pid}.json`);
    } catch (err: any) {
      setActionStatus(`Capsule export failed: ${err?.message || "Could not retrieve dossier"}`);
    }
  };

  const isLoading = isXrayLoading && isSummaryLoading;
  const procName = xrayData?.name || summaryData?.process_name || `PID ${pid}`;
  const cmdLine = xrayData?.cmdline || summaryData?.command_line || "—";
  const user = xrayData?.user || "system";
  const ppid = xrayData?.ppid || summaryData?.ppid || 1;
  const status = xrayData?.status || "active";
  const cpu = xrayData?.cpu_percent ?? 0;
  const memMb = xrayData?.memory_mb ?? 0;

  const sockets = xrayData?.sockets || [];
  const openFiles = xrayData?.open_files || [];
  const lineage = xrayData?.lineage || [];
  const findings = summaryData?.findings || xrayData?.correlated_alerts || [];
  const envKeys = Object.keys(xrayData?.environment || {});
  const security = xrayData?.security || {};
  const capsEff = security.capabilities_effective || [];
  const mappedLibs = security.mapped_libraries || [];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-md">
      <div
        className="flex max-h-[94vh] w-full max-w-4xl flex-col overflow-hidden rounded-2xl border border-border-subtle bg-bg-surface shadow-[var(--shadow-raised)]"
        role="dialog"
        aria-modal="true"
        aria-labelledby="xray-process-title"
      >
        {/* Header Bar */}
        <div className="flex flex-wrap items-center justify-between border-b border-border-subtle bg-bg-elevated/50 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-accent/40 bg-accent/15 text-accent shadow-[var(--glow-accent)]">
              <Icon name="process" size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-accent">Process X-Ray</span>
                <span className="rounded-full border border-border-subtle bg-bg-surface px-2 py-0.5 font-mono text-[10px] text-text-faint">
                  PID {pid}
                </span>
                <span className={`rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold uppercase ${
                  status === "running" ? "bg-accent/15 text-accent" : "bg-bg-elevated text-text-faint"
                }`}>
                  {status}
                </span>
                {security.package_provenance?.label && (
                  <span className={`rounded-full px-2 py-0.5 font-mono text-[10px] ${
                    security.package_provenance.managed
                      ? "bg-accent/10 text-accent border border-accent/30"
                      : "bg-risk-suspicious/15 text-risk-suspicious border border-risk-suspicious/30"
                  }`}>
                    {security.package_provenance.label}
                  </span>
                )}
              </div>
              <h2 id="xray-process-title" className="font-mono text-base font-bold text-text-primary">
                {procName}
              </h2>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => {
                onClose();
                navigate(`/events?pid=${pid}`);
              }}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs text-text-muted hover:border-accent/50 hover:text-accent"
              title="Filter all events in Event Manager by this process PID"
            >
              <Icon name="list" size={12} />
              Filter in Events
            </button>

            <button
              onClick={handleExportCapsule}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 font-mono text-xs font-semibold text-accent hover:bg-accent/20"
              title="Download full forensic .xray.json dossier"
            >
              <Icon name="download" size={12} />
              Export Capsule
            </button>

            {/* Process Lifecycle Controls */}
            <button
              onClick={() => actionMutation.mutate("freeze")}
              disabled={actionMutation.isPending}
              className="press inline-flex items-center gap-1 rounded-lg border border-risk-suspicious/40 bg-risk-suspicious/15 px-2.5 py-1.5 font-mono text-xs font-semibold text-risk-suspicious hover:bg-risk-suspicious/25 disabled:opacity-50"
              title="Send SIGSTOP to freeze/pause process execution"
            >
              Freeze
            </button>

            <button
              onClick={() => actionMutation.mutate("resume")}
              disabled={actionMutation.isPending}
              className="press inline-flex items-center gap-1 rounded-lg border border-signal/40 bg-signal/15 px-2.5 py-1.5 font-mono text-xs font-semibold text-signal hover:bg-signal/25 disabled:opacity-50"
              title="Send SIGCONT to resume process execution"
            >
              Resume
            </button>

            <button
              onClick={() => actionMutation.mutate("terminate")}
              disabled={actionMutation.isPending}
              className="press inline-flex items-center gap-1 rounded-lg border border-risk-malicious/40 bg-risk-malicious/15 px-2.5 py-1.5 font-mono text-xs font-semibold text-risk-malicious hover:bg-risk-malicious/25 disabled:opacity-50"
              title="Send SIGTERM to gracefully terminate process"
            >
              Terminate
            </button>

            <button
              onClick={onClose}
              className="press ml-1 rounded-lg p-1.5 text-text-faint hover:bg-bg-elevated hover:text-text-primary"
              aria-label="Close Process X-Ray inspector"
            >
              <Icon name="x" size={18} />
            </button>
          </div>
        </div>

        {/* Quick Resource Bar */}
        <div className="grid grid-cols-2 gap-4 border-b border-border-subtle bg-bg-base/40 px-6 py-2.5 font-mono text-xs sm:grid-cols-4">
          <div>
            <span className="text-[10px] uppercase tracking-wider text-text-faint">User Context</span>
            <p className="font-semibold text-text-primary">{user}</p>
          </div>
          <div>
            <span className="text-[10px] uppercase tracking-wider text-text-faint">Parent PPID</span>
            <p className="font-semibold text-text-primary">{ppid}</p>
          </div>
          <div>
            <span className="text-[10px] uppercase tracking-wider text-text-faint">CPU / Memory</span>
            <p className="font-semibold text-text-primary">{cpu}% · {memMb} MB</p>
          </div>
          <div>
            <span className="text-[10px] uppercase tracking-wider text-text-faint">Sockets / Files</span>
            <p className="font-semibold text-text-primary">{sockets.length} sockets · {openFiles.length} files</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex flex-wrap border-b border-border-subtle bg-bg-surface px-6">
          {(
            [
              { k: "overview", label: "Overview & Cmd" },
              { k: "lineage", label: `Lineage Tree (${lineage.length})` },
              { k: "security", label: `Security Posture (${capsEff.length} caps)` },
              { k: "sockets", label: `Sockets (${sockets.length})` },
              { k: "files", label: `Open Files (${openFiles.length})` },
              { k: "libraries", label: `Libraries (${mappedLibs.length})` },
              { k: "env", label: `Environment (${envKeys.length})` },
              { k: "detections", label: `Findings (${findings.length})` },
            ] as { k: TabKey; label: string }[]
          ).map((t) => (
            <button
              key={t.k}
              onClick={() => setTab(t.k)}
              className={`border-b-2 px-3.5 py-2.5 font-mono text-xs font-medium transition-colors duration-150 ${
                tab === t.k
                  ? "border-accent text-accent font-bold"
                  : "border-transparent text-text-muted hover:text-text-primary"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Action Status Notification */}
        {actionStatus && (
          <div className="border-b border-border-subtle bg-accent/10 px-6 py-2 font-mono text-xs text-accent">
            {actionStatus}
          </div>
        )}

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6">
          {isLoading && (
            <div className="space-y-4">
              <div className="skeleton h-12 w-full" />
              <div className="skeleton h-36 w-full" />
              <div className="skeleton h-24 w-full" />
            </div>
          )}

          {!isLoading && (
            <>
              {/* Tab: Overview */}
              {tab === "overview" && (
                <div className="space-y-5 font-mono text-xs">
                  <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-4 space-y-3">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">Full Command Line</span>
                    <pre className="overflow-x-auto rounded-lg border border-border-subtle bg-bg-inset p-3 text-[11px] leading-relaxed text-text-primary break-all">
                      {cmdLine}
                    </pre>
                  </div>

                  <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                    <div className="rounded-xl border border-border-subtle bg-bg-base/40 p-4 space-y-2">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">Executable Binary Path</span>
                      <p className="text-text-primary break-all">{xrayData?.exe || summaryData?.process_name || "—"}</p>
                    </div>

                    <div className="rounded-xl border border-border-subtle bg-bg-base/40 p-4 space-y-2">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">Working Directory (CWD)</span>
                      <p className="text-text-primary break-all">{xrayData?.cwd || "—"}</p>
                    </div>
                  </div>

                  {summaryData?.run_id && (
                    <div className="flex items-center justify-between rounded-xl border border-border-subtle bg-bg-elevated/40 p-4">
                      <div>
                        <span className="text-[10px] uppercase text-text-faint">Correlated Run Session</span>
                        <p className="font-semibold text-text-primary">{summaryData.sample_name || summaryData.run_id}</p>
                      </div>
                      <Link
                        to={`/runs/${summaryData.run_id}`}
                        onClick={onClose}
                        className="press inline-flex items-center gap-1 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-accent hover:bg-accent/20"
                      >
                        Inspect Run Session
                        <Icon name="external" size={11} />
                      </Link>
                    </div>
                  )}
                </div>
              )}

              {/* Tab: Lineage Tree */}
              {tab === "lineage" && (
                <div className="space-y-4 font-mono text-xs">
                  <h3 className="text-xs font-semibold text-text-primary">Process Hierarchy Lineage</h3>
                  <div className="rounded-xl border border-border-subtle bg-bg-base/50 p-4">
                    {lineage.length > 0 ? (
                      <div className="space-y-2">
                        {lineage.map((node, i) => {
                          const isSelf = node.relation === "self";
                          return (
                            <div
                              key={i}
                              className={`flex items-center gap-3 rounded-lg border p-3 ${
                                isSelf
                                  ? "border-accent/60 bg-accent/15 text-text-primary shadow-[var(--glow-accent)]"
                                  : "border-border-subtle bg-bg-surface text-text-muted"
                              }`}
                              style={{ marginLeft: `${i * 18}px` }}
                            >
                              <Icon name="process" size={14} className={isSelf ? "text-accent" : "text-text-faint"} />
                              <span className="font-bold">{node.name}</span>
                              <span className="rounded bg-bg-elevated px-1.5 py-0.5 text-[10px] text-text-faint">
                                PID {node.pid}
                              </span>
                              <span className="ml-auto text-[10px] uppercase tracking-wider text-text-faint">
                                {node.relation}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <div className="text-center text-text-faint py-6">
                        Single process execution (no parent or child hierarchy recorded).
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Tab: Security Posture */}
              {tab === "security" && (
                <div className="space-y-5 font-mono text-xs">
                  {/* Hardening and Seccomp Cards */}
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                    <div className="rounded-xl border border-border-subtle bg-bg-base/40 p-4 space-y-1.5">
                      <span className="text-[10px] font-bold uppercase text-text-faint">Seccomp Filter</span>
                      <p className={`font-bold ${security.seccomp === "Disabled" ? "text-risk-suspicious" : "text-signal"}`}>
                        {security.seccomp || "Unknown"}
                      </p>
                    </div>

                    <div className="rounded-xl border border-border-subtle bg-bg-base/40 p-4 space-y-1.5">
                      <span className="text-[10px] font-bold uppercase text-text-faint">NoNewPrivs</span>
                      <p className="font-bold text-text-primary">
                        {security.no_new_privs ? "Enabled (Restricted)" : "Disabled"}
                      </p>
                    </div>

                    <div className="rounded-xl border border-border-subtle bg-bg-base/40 p-4 space-y-1.5">
                      <span className="text-[10px] font-bold uppercase text-text-faint">Service / CGroup</span>
                      <p className="font-bold text-text-primary truncate">
                        {security.service_unit || security.cgroup || "None"}
                      </p>
                    </div>
                  </div>

                  {/* Effective Linux Capabilities */}
                  <div className="rounded-xl border border-border-subtle bg-bg-base/50 p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-text-primary">Effective Linux Capabilities ({capsEff.length})</span>
                      <span className="text-[10px] text-text-faint">Decoded from CapEff bitmask</span>
                    </div>
                    {capsEff.length > 0 ? (
                      <div className="flex flex-wrap gap-1.5">
                        {capsEff.map((c: any, i: number) => (
                          <span
                            key={i}
                            className={`rounded-lg px-2.5 py-1 text-[11px] font-semibold border ${
                              c.is_dangerous
                                ? "border-risk-malicious/50 bg-risk-malicious/15 text-risk-malicious"
                                : "border-border-subtle bg-bg-surface text-text-muted"
                            }`}
                          >
                            {c.name}
                            {c.is_dangerous && " ⚠️"}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <p className="text-text-faint text-[11px]">Unprivileged (zero elevated capabilities granted).</p>
                    )}
                  </div>

                  {/* Namespaces Isolation */}
                  {security.namespaces && Object.keys(security.namespaces).length > 0 && (
                    <div className="rounded-xl border border-border-subtle bg-bg-base/40 p-4 space-y-2">
                      <span className="font-bold text-text-primary">Namespace Isolation IDs</span>
                      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[11px]">
                        {Object.entries(security.namespaces).map(([k, v]: [string, any]) => (
                          <div key={k} className="rounded border border-border-subtle bg-bg-surface p-2">
                            <span className="text-[9px] uppercase text-text-faint">{k}</span>
                            <p className="text-text-muted truncate">{v}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Tab: Sockets */}
              {tab === "sockets" && (
                <div className="space-y-3 font-mono text-xs">
                  <h3 className="text-xs font-semibold text-text-primary">Active Network Sockets</h3>
                  {sockets.length > 0 ? (
                    <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-base/40">
                      <table className="w-full text-left text-[11px]">
                        <thead className="border-b border-border-subtle bg-bg-elevated/40 text-text-faint">
                          <tr>
                            <th className="p-3">Protocol</th>
                            <th className="p-3">Local Address</th>
                            <th className="p-3">Remote Address</th>
                            <th className="p-3">State</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border-subtle">
                          {sockets.map((s, i) => (
                            <tr key={i} className="hover:bg-bg-elevated/30">
                              <td className="p-3 font-bold uppercase text-accent">{s.protocol}</td>
                              <td className="p-3 text-text-primary">{s.local_ip}:{s.local_port}</td>
                              <td className="p-3 text-text-muted">{s.remote_ip ? `${s.remote_ip}:${s.remote_port}` : "—"}</td>
                              <td className="p-3">
                                <span className={`rounded px-1.5 py-0.5 text-[9px] uppercase ${
                                  s.status === "LISTEN" ? "bg-accent/15 text-accent" : "bg-bg-elevated text-text-faint"
                                }`}>
                                  {s.status}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p className="rounded-xl border border-border-subtle bg-bg-elevated/20 p-6 text-center text-text-faint">
                      No active network sockets opened by this process.
                    </p>
                  )}
                </div>
              )}

              {/* Tab: Files */}
              {tab === "files" && (
                <div className="space-y-3 font-mono text-xs">
                  <h3 className="text-xs font-semibold text-text-primary">Open File Descriptors</h3>
                  {openFiles.length > 0 ? (
                    <ul className="space-y-1.5">
                      {openFiles.map((f, i) => (
                        <li key={i} className="flex items-center gap-3 rounded-lg border border-border-subtle bg-bg-surface p-2.5 text-[11px]">
                          <Icon name="file" size={13} className="text-text-faint" />
                          <span className="rounded bg-bg-elevated px-1.5 py-0.5 text-[9px] text-text-faint">fd {f.fd}</span>
                          <span className="text-text-primary truncate">{f.path}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="rounded-xl border border-border-subtle bg-bg-elevated/20 p-6 text-center text-text-faint">
                      No open file descriptors captured.
                    </p>
                  )}
                </div>
              )}

              {/* Tab: Libraries */}
              {tab === "libraries" && (
                <div className="space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-semibold text-text-primary">Mapped Shared Libraries (.so)</h3>
                    <input
                      type="text"
                      placeholder="Filter libraries..."
                      value={libFilter}
                      onChange={(e) => setLibFilter(e.target.value)}
                      className="rounded-lg border border-border-subtle bg-bg-base px-2.5 py-1 text-[11px] text-text-primary placeholder:text-text-faint"
                    />
                  </div>
                  {mappedLibs.length > 0 ? (
                    <div className="max-h-80 overflow-y-auto rounded-xl border border-border-subtle bg-bg-base/40 p-2 space-y-1">
                      {mappedLibs
                        .filter((lib: string) => !libFilter || lib.toLowerCase().includes(libFilter.toLowerCase()))
                        .map((lib: string, i: number) => (
                          <div key={i} className="flex items-center gap-2 rounded bg-bg-surface px-3 py-1.5 text-[11px] text-text-muted">
                            <span className="text-[10px] text-text-faint">{i + 1}.</span>
                            <span className="truncate font-mono">{lib}</span>
                          </div>
                        ))}
                    </div>
                  ) : (
                    <p className="rounded-xl border border-border-subtle bg-bg-elevated/20 p-6 text-center text-text-faint">
                      No dynamic shared objects mapped in memory.
                    </p>
                  )}
                </div>
              )}

              {/* Tab: Environment */}
              {tab === "env" && (
                <div className="space-y-3 font-mono text-xs">
                  <h3 className="text-xs font-semibold text-text-primary">Process Environment Variables (Redacted)</h3>
                  {envKeys.length > 0 ? (
                    <div className="max-h-96 overflow-y-auto rounded-xl border border-border-subtle bg-bg-inset p-3 space-y-1 text-[11px]">
                      {envKeys.map((k) => (
                        <div key={k} className="flex gap-2">
                          <span className="text-accent font-bold">{k}=</span>
                          <span className="text-text-muted truncate">{xrayData?.environment[k]}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="rounded-xl border border-border-subtle bg-bg-elevated/20 p-6 text-center text-text-faint">
                      Environment variables restricted or not available.
                    </p>
                  )}
                </div>
              )}

              {/* Tab: Detections */}
              {tab === "detections" && (
                <div className="space-y-3 font-mono text-xs">
                  <h3 className="text-xs font-semibold text-text-primary">Security Detections & Rule Violations</h3>
                  {findings.length > 0 ? (
                    <ul className="space-y-2">
                      {findings.map((f: any, i: number) => (
                        <li key={i} className="flex items-start justify-between rounded-xl border border-border-subtle bg-bg-surface p-4">
                          <div>
                            <div className="flex items-center gap-2">
                              <Icon name="alert" size={14} className="text-risk-malicious" />
                              <span className="font-bold text-text-primary">{f.rule_name}</span>
                              <span className="text-[10px] text-text-faint">({f.rule_id})</span>
                            </div>
                            <p className="mt-1 text-[11px] text-text-muted">{f.details || f.event_type}</p>
                          </div>
                          <span className={`rounded px-2 py-0.5 text-[9px] uppercase font-bold ${
                            f.severity === "malicious"
                              ? "border border-risk-malicious/40 bg-risk-malicious/15 text-risk-malicious"
                              : "border border-risk-suspicious/40 bg-risk-suspicious/15 text-risk-suspicious"
                          }`}>
                            {f.severity}
                          </span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="rounded-xl border border-border-subtle bg-bg-elevated/20 p-6 text-center text-text-faint">
                      Zero security detections or malicious heuristic alerts flagged for this process.
                    </p>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default ProcessContextModal;
