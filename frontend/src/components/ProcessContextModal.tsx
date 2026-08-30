import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { controlProcessXRay, getForensicCapsule, getProcessSummary, getProcessXRay } from "../lib/api";
import { Icon } from "./Icon";

type TabKey = "overview" | "lineage" | "security" | "sockets" | "files" | "libraries" | "env" | "detections";

function SparklineChart({ points }: { points?: Array<{ cpu_percent: number; memory_mb: number; seconds_ago: number }> }) {
  if (!points || points.length < 2) return null;
  const maxCpu = Math.max(10, ...points.map((p) => p.cpu_percent));
  const width = 120;
  const height = 28;
  const step = width / (points.length - 1);

  const cpuPath = points
    .map((p, i) => `${i * step},${height - (p.cpu_percent / maxCpu) * (height - 4)}`)
    .join(" ");

  return (
    <div className="flex items-center gap-2 rounded-lg border border-border-subtle bg-bg-surface px-2.5 py-1">
      <div className="flex flex-col">
        <span className="text-[9px] uppercase font-bold text-accent">60s Trace</span>
        <span className="text-[10px] font-mono text-text-primary">{points[points.length - 1]?.cpu_percent.toFixed(1)}% CPU</span>
      </div>
      <svg width={width} height={height} className="overflow-visible">
        <polyline
          fill="none"
          stroke="var(--color-accent, #3b82f6)"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          points={cpuPath}
        />
      </svg>
    </div>
  );
}

function DeviceAccessPanel({ access }: { access?: any }) {
  if (!access) return null;
  const items = [
    { label: "Microphone", inUse: access.microphone, icon: "mic" },
    { label: "Camera", inUse: access.camera, icon: "video" },
    { label: "Screen Capture", inUse: access.screen_capture, icon: "monitor" },
    { label: "Audio Playback", inUse: access.audio_playback, icon: "volume" },
    { label: "GPU Clients", inUse: access.gpu, count: access.gpu_clients_count, icon: "cpu" },
    { label: "Sleep Inhibition", inUse: access.sleep_inhibition, icon: "shield" },
  ];

  return (
    <div className="rounded-xl border border-border-subtle bg-bg-base/40 p-4 space-y-2.5">
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">App Device & Sensor Access</span>
        <span className="text-[10px] font-mono text-accent">
          {items.filter((i) => i.inUse).length} Live Access Handles
        </span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
        {items.map((item) => (
          <div
            key={item.label}
            className={`flex items-center justify-between rounded-lg border px-2.5 py-2 font-mono text-[11px] ${
              item.inUse
                ? "border-accent/40 bg-accent/10 text-accent font-semibold"
                : "border-border-subtle bg-bg-surface text-text-muted opacity-60"
            }`}
          >
            <span>{item.label}</span>
            <span className={`text-[10px] rounded px-1.5 py-0.5 ${item.inUse ? "bg-accent/20 text-accent font-bold" : "text-text-faint"}`}>
              {item.inUse ? (item.count ? `${item.count} LIVE` : "ACTIVE") : "Not in use"}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function LaunchChainBreadcrumb({ chainInfo }: { chainInfo?: any }) {
  if (!chainInfo?.chain) return null;
  return (
    <div className="rounded-xl border border-border-subtle bg-bg-base/40 p-3.5 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">Launch & Supervisor Chain</span>
        <span className="text-[10px] font-mono text-text-faint">systemd scope / cgroup</span>
      </div>
      <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
        {chainInfo.chain.map((c: any, idx: number) => (
          <div key={idx} className="flex items-center gap-2">
            {idx > 0 && <span className="text-text-faint">→</span>}
            <div className="flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-2 py-1">
              <span className="rounded bg-bg-elevated px-1 text-[9px] font-bold text-accent uppercase">{c.role}</span>
              <span className="text-text-primary text-[11px] font-medium truncate max-w-[180px]">{c.name}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

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
    queryKey: ["forensics", "process", pid],
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
      void queryClient.invalidateQueries({ queryKey: ["forensics"] });
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
      a.download = `outpost-forensic-capsule-pid-${pid}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setActionStatus(`Exported forensic capsule: outpost-forensic-capsule-pid-${pid}.json`);
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
  const threads = xrayData?.threads ?? 1;
  const diskIo = xrayData?.disk_io;

  const sockets = xrayData?.sockets || [];
  const openFiles = xrayData?.detailed_fds || xrayData?.open_files || [];
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
        aria-labelledby="process-forensics-title"
      >
        {/* Header Bar */}
        <div className="flex flex-wrap items-center justify-between border-b border-border-subtle bg-bg-elevated/50 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-accent/40 bg-accent/15 text-accent shadow-[var(--glow-accent)]">
              <Icon name="process" size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-accent">Process Forensics</span>
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
              <h2 id="process-forensics-title" className="font-mono text-base font-bold text-text-primary">
                {procName}
              </h2>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {xrayData?.sparkline && (
              <SparklineChart points={xrayData.sparkline.points} />
            )}

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
              title="Download full forensic dossier"
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
              aria-label="Close Process Forensics inspector"
            >
              <Icon name="x" size={18} />
            </button>
          </div>
        </div>

        {/* Quick Resource Bar */}
        <div className="grid grid-cols-2 gap-4 border-b border-border-subtle bg-bg-base/40 px-6 py-2.5 font-mono text-xs sm:grid-cols-4">
          <div>
            <span className="text-[10px] uppercase tracking-wider text-text-faint">User Context</span>
            <p className="font-semibold text-text-primary">{user} · PPID {ppid}</p>
          </div>
          <div>
            <span className="text-[10px] uppercase tracking-wider text-text-faint">Threads & State</span>
            <p className="font-semibold text-text-primary">{threads} threads · {status}</p>
          </div>
          <div>
            <span className="text-[10px] uppercase tracking-wider text-text-faint">CPU / Memory</span>
            <p className="font-semibold text-text-primary">{cpu}% · {memMb} MB</p>
          </div>
          <div>
            <span className="text-[10px] uppercase tracking-wider text-text-faint">Disk I/O Throughput</span>
            <p className="font-semibold text-text-primary">{diskIo?.read_mb ?? 0} MB R / {diskIo?.write_mb ?? 0} MB W</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex flex-wrap border-b border-border-subtle bg-bg-surface px-6">
          {(
            [
              { k: "overview", label: "Overview & Context" },
              { k: "lineage", label: `Lineage Tree (${lineage.length})` },
              { k: "security", label: `Security Posture (${capsEff.length} caps)` },
              { k: "sockets", label: `Sockets (${sockets.length})` },
              { k: "files", label: `Files & IPC (${openFiles.length})` },
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
                  {/* Supervisor & Launch Chain */}
                  <LaunchChainBreadcrumb chainInfo={xrayData?.launch_chain} />

                  {/* Device & Hardware Sensor Access */}
                  <DeviceAccessPanel access={xrayData?.device_access} />

                  <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">Full Command Line</span>
                      <button
                        onClick={() => {
                          void navigator.clipboard.writeText(cmdLine);
                          setActionStatus("Copied command line to clipboard");
                          setTimeout(() => setActionStatus(null), 2500);
                        }}
                        className="press inline-flex items-center gap-1 text-[10px] text-text-muted hover:text-accent font-mono"
                        title="Copy complete command line arguments"
                      >
                        <Icon name="copy" size={10} />
                        Copy Command
                      </button>
                    </div>
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

                  {xrayData?.cgroup && (
                    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 rounded-xl border border-border-subtle bg-bg-base/40 p-4">
                      <div className="space-y-1">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">Container Runtime</span>
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase ${
                            xrayData.cgroup.is_containerized ? "bg-purple-500/20 text-purple-300 border border-purple-500/30" : "bg-panel-border/60 text-text-muted"
                          }`}>
                            {xrayData.cgroup.container_runtime}
                          </span>
                          {xrayData.cgroup.container_short_id && (
                            <span className="font-mono text-text-primary text-xs">ID: {xrayData.cgroup.container_short_id}</span>
                          )}
                        </div>
                      </div>

                      <div className="space-y-1">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-text-faint">Systemd Service / Slice</span>
                        <div className="font-mono text-text-primary text-xs truncate">
                          {xrayData.cgroup.systemd_service || xrayData.cgroup.cgroup_slice || "Host Process"}
                        </div>
                      </div>
                    </div>
                  )}

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

              {/* Tab: Files & IPC */}
              {tab === "files" && (
                <div className="space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-semibold text-text-primary">Open File Descriptors & Memory Handles</h3>
                    <span className="text-[10px] text-text-faint">{openFiles.length} file descriptors open</span>
                  </div>

                  {openFiles.length > 0 ? (
                    <div className="overflow-x-auto rounded-xl border border-border-subtle bg-bg-base/40">
                      <table className="w-full text-left text-[11px]">
                        <thead className="border-b border-border-subtle bg-bg-elevated/40 text-text-faint">
                          <tr>
                            <th className="p-3 w-16">FD</th>
                            <th className="p-3">Path / Endpoint</th>
                            <th className="p-3 w-24">Kind</th>
                            <th className="p-3 w-28">Access</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border-subtle">
                          {openFiles.map((f: any, i: number) => {
                            const isDeleted = f.is_deleted || f.path?.includes("(deleted)");
                            const isMemfd = f.is_memfd || f.path?.startsWith("/memfd:") || f.path?.startsWith("anon_inode:");
                            return (
                              <tr key={i} className={`hover:bg-bg-elevated/30 ${isDeleted ? "bg-risk-suspicious/5" : ""}`}>
                                <td className="p-3 font-bold text-text-faint font-mono">{f.fd}</td>
                                <td className="p-3 font-mono text-text-primary">
                                  <div className="flex items-center gap-2">
                                    <span className="truncate max-w-md">{f.path}</span>
                                    {isDeleted && (
                                      <span className="rounded bg-risk-suspicious/20 border border-risk-suspicious/40 px-1.5 py-0.2 text-[9px] font-bold uppercase text-risk-suspicious">
                                        DELETED
                                      </span>
                                    )}
                                    {isMemfd && (
                                      <span className="rounded bg-purple-500/20 border border-purple-500/40 px-1.5 py-0.2 text-[9px] font-bold uppercase text-purple-300">
                                        MEMFD / RAM
                                      </span>
                                    )}
                                  </div>
                                </td>
                                <td className="p-3">
                                  <span className={`rounded px-1.5 py-0.5 text-[9px] uppercase font-bold ${
                                    isMemfd ? "bg-purple-500/20 text-purple-300" :
                                    f.kind === "socket" ? "bg-accent/15 text-accent" :
                                    f.kind === "pipe" ? "bg-yellow-500/15 text-yellow-400" :
                                    f.kind === "device" ? "bg-cyan-500/15 text-cyan-300" :
                                    "bg-bg-elevated text-text-muted"
                                  }`}>
                                    {f.kind || "file"}
                                  </span>
                                </td>
                                <td className="p-3">
                                  <span className={`rounded px-1.5 py-0.5 text-[9px] uppercase font-semibold ${
                                    isDeleted ? "text-risk-suspicious font-bold" : "text-text-faint"
                                  }`}>
                                    {f.access || (isDeleted ? "DELETED" : "READ")}
                                  </span>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
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
