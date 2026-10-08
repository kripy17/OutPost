// EDR Fleet & Host Operations — Enterprise endpoint sensor telemetry, active containment & triage.
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { Icon } from "../components/Icon";
import { platformIconName } from "../components/iconMeta";
import { IocFleetHuntModal } from "../components/IocFleetHuntModal";
import { EndpointTaskManager } from "../components/EndpointTaskManager";
import {
  getAgentBootstrapCommands,
  getAgents,
  getHostBaseline,
  getHostContainment,
  getHostSnapshot,
  isolateHost,
  killHostProcess,
  resetHostBaseline,
} from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import type { AgentInfo } from "../types";
import { relativeTime } from "./agentsHelpers";

function HostInspectorDrawer({
  hostId,
  agent,
  onClose,
}: {
  hostId: string;
  agent?: AgentInfo;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<"snapshot" | "sockets" | "baseline" | "deploy">("snapshot");
  const [procFilter, setProcFilter] = useState("");
  const [killMsg, setKillMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  const { data: containment } = useQuery({
    queryKey: ["host-containment", hostId],
    queryFn: () => getHostContainment(hostId),
    refetchInterval: 10_000,
  });

  const { data: snapshot, isLoading: snapLoading } = useQuery({
    queryKey: ["snapshot", hostId],
    queryFn: () => getHostSnapshot(hostId),
    refetchInterval: 10_000,
  });

  const { data: baseline } = useQuery({
    queryKey: ["baseline", hostId],
    queryFn: () => getHostBaseline(hostId),
  });

  const { data: bootstrapData } = useQuery({
    queryKey: ["agent-bootstrap-commands"],
    queryFn: getAgentBootstrapCommands,
  });

  const toggleIsolation = useMutation({
    mutationFn: (isolated: boolean) => isolateHost(hostId, { isolated, reason: "Operator console action" }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["host-containment", hostId] });
      void queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  });

  const queueKill = useMutation({
    mutationFn: (pid: number) => killHostProcess(hostId, { pid }),
    onSuccess: (_, pid) => {
      setKillMsg(`Kill instruction for PID ${pid} queued for next agent heartbeat.`);
      void queryClient.invalidateQueries({ queryKey: ["host-containment", hostId] });
      setTimeout(() => setKillMsg(null), 3000);
    },
  });

  const resetBase = useMutation({
    mutationFn: () => resetHostBaseline(hostId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["baseline", hostId] });
      void queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  });

  const isIsolated = containment?.isolated ?? false;

  const copyCmd = (text: string, label: string) => {
    void navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  };

  const filteredProcesses = (snapshot?.processes || []).filter((p) => {
    if (!procFilter.trim()) return true;
    const q = procFilter.toLowerCase();
    return (
      p.name.toLowerCase().includes(q) ||
      String(p.pid).includes(q) ||
      (p.user || "").toLowerCase().includes(q) ||
      (p.cmdline || "").toLowerCase().includes(q)
    );
  });

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs animate-fade-in"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl bg-bg-surface border-l border-border-subtle flex flex-col h-full shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="p-5 border-b border-border-subtle bg-bg-elevated/40">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 min-w-0">
              <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border ${
                isIsolated
                  ? "border-risk-malicious/60 bg-risk-malicious/15 text-risk-malicious"
                  : agent?.online
                    ? "border-signal/60 bg-signal/15 text-signal"
                    : "border-border-subtle bg-bg-surface text-text-faint"
              }`}>
                <Icon name={agent?.platforms[0] ? platformIconName(agent.platforms[0]) : "terminal"} size={16} />
              </span>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <h2 className="font-mono text-sm font-bold text-text-primary truncate">{hostId}</h2>
                  <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.2 font-mono text-[10px] border ${
                    agent?.online ? "border-signal/50 bg-signal/10 text-signal" : "border-border-subtle text-text-faint"
                  }`}>
                    <span className={`h-1.5 w-1.5 rounded-full ${agent?.online ? "bg-signal animate-outpost-pulse" : "bg-text-faint"}`} />
                    {agent?.online ? "online" : "offline"}
                  </span>
                  {isIsolated && (
                    <span className="rounded bg-risk-malicious/20 border border-risk-malicious/50 px-1.5 py-0.2 font-mono text-[9px] font-bold text-risk-malicious uppercase">
                      ISOLATED
                    </span>
                  )}
                </div>
                <p className="font-mono text-[11px] text-text-faint truncate mt-0.5">
                  {agent?.platforms.join(", ") || "os"} · {agent?.identity || "agent"} · last seen {agent?.last_seen ? relativeTime(agent.last_seen) : "never"}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              {isIsolated ? (
                <button
                  onClick={() => toggleIsolation.mutate(false)}
                  disabled={toggleIsolation.isPending}
                  className="press inline-flex items-center gap-1 rounded-lg border border-signal/60 bg-signal/15 px-3 py-1.5 font-mono text-xs font-bold text-signal hover:bg-signal/25 disabled:opacity-50"
                  title="Lift network containment and restore normal traffic"
                >
                  <Icon name="check" size={12} />
                  <span>Restore Network</span>
                </button>
              ) : (
                <button
                  onClick={() => toggleIsolation.mutate(true)}
                  disabled={toggleIsolation.isPending}
                  className="press inline-flex items-center gap-1 rounded-lg border border-risk-malicious/60 bg-risk-malicious/15 px-3 py-1.5 font-mono text-xs font-bold text-risk-malicious hover:bg-risk-malicious/25 disabled:opacity-50"
                  title="Isolate host from network using kernel firewall rules"
                >
                  <Icon name="alert" size={12} />
                  <span>Isolate Host</span>
                </button>
              )}
              <button
                onClick={onClose}
                className="press rounded-lg p-1.5 text-text-muted hover:text-text-primary hover:bg-bg-elevated"
              >
                <Icon name="x" size={16} />
              </button>
            </div>
          </div>

          {/* Endpoint Hardware & Telemetry HUD */}
          <div className="mt-3.5 rounded-lg border border-border-subtle bg-bg-base/70 p-2.5 font-mono text-[11px] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-bold text-text-faint flex items-center gap-1.5">
                <Icon name="activity" size={11} className="text-accent" />
                <span>Sensor Health &amp; In-Flight Telemetry</span>
              </span>
              <span className="text-[10px] text-text-muted">
                {agent?.agent_id ? (
                  <span className="text-signal flex items-center gap-1">
                    <span className="h-1.5 w-1.5 rounded-full bg-signal" />
                    <span>Enrolled: {agent.agent_id}</span>
                  </span>
                ) : (
                  <span className="text-text-faint">Standard Token Auth</span>
                )}
              </span>
            </div>

            <div className="grid grid-cols-4 gap-2 pt-0.5">
              <div className="rounded bg-bg-surface/80 p-1.5 border border-border-subtle/60">
                <div className="flex justify-between items-center text-[10px] text-text-faint">
                  <span>CPU</span>
                  <span className="font-bold text-text-primary">{agent?.metrics?.cpu_percent ?? 0}%</span>
                </div>
                <div className="mt-1 h-1 w-full bg-bg-elevated rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all ${
                      (agent?.metrics?.cpu_percent ?? 0) > 80
                        ? "bg-risk-malicious"
                        : (agent?.metrics?.cpu_percent ?? 0) > 50
                          ? "bg-amber-400"
                          : "bg-signal"
                    }`}
                    style={{ width: `${Math.min(100, Math.max(0, agent?.metrics?.cpu_percent ?? 0))}%` }}
                  />
                </div>
              </div>

              <div className="rounded bg-bg-surface/80 p-1.5 border border-border-subtle/60">
                <div className="flex justify-between items-center text-[10px] text-text-faint">
                  <span>RAM</span>
                  <span className="font-bold text-text-primary">{agent?.metrics?.memory_percent ?? 0}%</span>
                </div>
                <div className="mt-1 h-1 w-full bg-bg-elevated rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all ${
                      (agent?.metrics?.memory_percent ?? 0) > 85
                        ? "bg-risk-malicious"
                        : (agent?.metrics?.memory_percent ?? 0) > 65
                          ? "bg-amber-400"
                          : "bg-signal"
                    }`}
                    style={{ width: `${Math.min(100, Math.max(0, agent?.metrics?.memory_percent ?? 0))}%` }}
                  />
                </div>
              </div>

              <div className="rounded bg-bg-surface/80 p-1.5 border border-border-subtle/60">
                <span className="text-[10px] text-text-faint block">Spool Backlog</span>
                <span className="font-bold text-text-primary text-[11px] mt-0.5 block">
                  {agent?.metrics?.queue_backlog !== undefined ? `${agent.metrics.queue_backlog} events` : "0 (WAL OK)"}
                </span>
              </div>

              <div className="rounded bg-bg-surface/80 p-1.5 border border-border-subtle/60">
                <span className="text-[10px] text-text-faint block">Sensor Uptime</span>
                <span className="font-bold text-accent text-[11px] mt-0.5 block">
                  {agent?.metrics?.uptime_seconds !== undefined
                    ? `${Math.floor(agent.metrics.uptime_seconds / 60)}m ${agent.metrics.uptime_seconds % 60}s`
                    : "Live"}
                </span>
              </div>
            </div>
          </div>

          {/* Quick Tab Strip */}
          <div className="mt-4 flex rounded-lg border border-border-subtle bg-bg-base/80 p-1 font-mono text-xs">
            <button
              onClick={() => setActiveTab("snapshot")}
              className={`flex-1 py-1.5 text-center rounded-md font-medium transition ${
                activeTab === "snapshot" ? "bg-accent/20 text-accent font-bold" : "text-text-muted hover:text-text-primary"
              }`}
            >
              Processes ({snapshot?.processes.length ?? 0})
            </button>
            <button
              onClick={() => setActiveTab("sockets")}
              className={`flex-1 py-1.5 text-center rounded-md font-medium transition ${
                activeTab === "sockets" ? "bg-accent/20 text-accent font-bold" : "text-text-muted hover:text-text-primary"
              }`}
            >
              Sockets ({snapshot?.listening.length ?? 0})
            </button>
            <button
              onClick={() => setActiveTab("baseline")}
              className={`flex-1 py-1.5 text-center rounded-md font-medium transition ${
                activeTab === "baseline" ? "bg-accent/20 text-accent font-bold" : "text-text-muted hover:text-text-primary"
              }`}
            >
              Baselines
            </button>
            <button
              onClick={() => setActiveTab("deploy")}
              className={`flex-1 py-1.5 text-center rounded-md font-medium transition ${
                activeTab === "deploy" ? "bg-accent/20 text-accent font-bold" : "text-text-muted hover:text-text-primary"
              }`}
            >
              Sensor Setup
            </button>
          </div>
        </div>

        {killMsg && (
          <div className="bg-signal/15 border-b border-signal/40 px-5 py-2 font-mono text-xs text-signal">
            ✓ {killMsg}
          </div>
        )}

        {/* Drawer Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {activeTab === "snapshot" && (
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-3">
                <input
                  type="text"
                  placeholder="Filter processes by name, PID, user, cmdline..."
                  value={procFilter}
                  onChange={(e) => setProcFilter(e.target.value)}
                  className="w-full rounded-lg border border-border-subtle bg-bg-base px-3 py-1.5 font-mono text-xs text-text-primary focus:border-accent/60 focus:outline-none"
                />
              </div>

              {snapLoading ? (
                <p className="py-10 text-center font-mono text-xs text-text-muted">Loading live process telemetry…</p>
              ) : !snapshot || snapshot.processes.length === 0 ? (
                <p className="py-10 text-center font-mono text-xs text-text-muted">
                  No live process telemetry received from this endpoint yet.
                </p>
              ) : (
                <div className="rounded-xl border border-border-subtle overflow-hidden">
                  <table className="w-full text-left font-mono text-[11px]">
                    <thead className="bg-bg-elevated/80 border-b border-border-subtle text-[10px] uppercase text-text-faint">
                      <tr>
                        <th className="px-3 py-2">PID</th>
                        <th className="px-3 py-2">Process</th>
                        <th className="px-3 py-2">User</th>
                        <th className="px-3 py-2 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border-subtle/50">
                      {filteredProcesses.map((p) => (
                        <tr key={p.pid} className="hover:bg-bg-elevated/40 transition">
                          <td className="px-3 py-2 text-text-muted tabular-nums">{p.pid}</td>
                          <td className="px-3 py-2">
                            <span className="font-semibold text-text-primary">{p.name}</span>
                            {p.cmdline && (
                              <p className="text-[10px] text-text-faint truncate max-w-xs" title={p.cmdline}>
                                {p.cmdline}
                              </p>
                            )}
                          </td>
                          <td className="px-3 py-2 text-text-muted">{p.user || "—"}</td>
                          <td className="px-3 py-2 text-right">
                            <button
                              onClick={() => {
                                if (window.confirm(`Queue process termination for ${p.name} (PID ${p.pid})?`)) {
                                  queueKill.mutate(p.pid);
                                }
                              }}
                              className="press rounded border border-border-subtle bg-bg-base px-2 py-0.5 text-[10px] text-text-faint hover:border-risk-malicious/60 hover:text-risk-malicious"
                              title="Terminate process"
                            >
                              Kill
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {activeTab === "sockets" && (
            <div className="space-y-3">
              {!snapshot || snapshot.listening.length === 0 ? (
                <p className="py-10 text-center font-mono text-xs text-text-muted">
                  No open listening ports recorded on this endpoint.
                </p>
              ) : (
                <div className="rounded-xl border border-border-subtle overflow-hidden">
                  <table className="w-full text-left font-mono text-[11px]">
                    <thead className="bg-bg-elevated/80 border-b border-border-subtle text-[10px] uppercase text-text-faint">
                      <tr>
                        <th className="px-3 py-2">Proto</th>
                        <th className="px-3 py-2">Address</th>
                        <th className="px-3 py-2">Port</th>
                        <th className="px-3 py-2">PID</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border-subtle/50">
                      {snapshot.listening.map((s, idx) => (
                        <tr key={idx} className="hover:bg-bg-elevated/40 transition">
                          <td className="px-3 py-2 uppercase font-semibold text-accent">{s.proto}</td>
                          <td className="px-3 py-2 text-text-primary">{s.addr}</td>
                          <td className="px-3 py-2 text-signal tabular-nums font-bold">{s.port}</td>
                          <td className="px-3 py-2 text-text-muted">{s.pid ?? "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {activeTab === "baseline" && (
            <div className="space-y-4 font-mono text-xs">
              <div className="grid grid-cols-3 gap-3">
                <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3">
                  <span className="text-[10px] text-text-faint uppercase">Observations</span>
                  <p className="text-base font-bold text-text-primary mt-1">{baseline?.total_observations ?? 0}</p>
                </div>
                <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3">
                  <span className="text-[10px] text-text-faint uppercase">Processes Learned</span>
                  <p className="text-base font-bold text-accent mt-1">{baseline?.processes.length ?? 0}</p>
                </div>
                <div className="rounded-xl border border-border-subtle bg-bg-base/60 p-3">
                  <span className="text-[10px] text-text-faint uppercase">Anomalies Fired</span>
                  <p className="text-base font-bold text-risk-suspicious mt-1">{baseline?.anomaly_count ?? 0}</p>
                </div>
              </div>

              <div className="flex items-center justify-between pt-2">
                <span className="text-xs text-text-muted">Behavioral Profiling Active</span>
                <button
                  onClick={() => resetBase.mutate()}
                  disabled={resetBase.isPending}
                  className="press rounded border border-border-subtle px-2.5 py-1 text-[11px] text-text-faint hover:border-risk-malicious/60 hover:text-risk-malicious"
                >
                  Reset Learned Baseline
                </button>
              </div>

              {baseline && baseline.processes.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] text-text-faint uppercase">Top Observed Binaries:</span>
                  <div className="max-h-48 overflow-y-auto space-y-1 pr-1">
                    {baseline.processes.slice(0, 15).map((p) => (
                      <div key={p.value} className="flex items-center justify-between rounded bg-bg-base p-1.5 text-[11px]">
                        <span className="text-text-primary truncate">{p.value}</span>
                        <span className="text-text-faint tabular-nums">×{p.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === "deploy" && (
            <div className="space-y-4 font-mono text-xs">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-text-primary flex items-center gap-1.5">
                    <Icon name="linux" size={13} className="text-accent" />
                    Linux Sensor (eBPF / auditd)
                  </span>
                  <button
                    onClick={() => copyCmd(bootstrapData?.linux_command || "curl -sSL http://localhost:8000/install.sh | sudo bash", "linux")}
                    className="press rounded border border-border-subtle px-2 py-0.5 text-[10px] text-text-muted hover:text-accent"
                  >
                    {copied === "linux" ? "Copied ✓" : "Copy"}
                  </button>
                </div>
                <pre className="rounded-lg bg-bg-base p-2.5 text-[11px] text-accent select-all overflow-x-auto border border-border-subtle">
                  {bootstrapData?.linux_command || "curl -sSL http://localhost:8000/install.sh | sudo bash"}
                </pre>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-text-primary flex items-center gap-1.5">
                    <Icon name="windows" size={13} className="text-accent" />
                    Windows Sensor (PowerShell + Sysmon)
                  </span>
                  <button
                    onClick={() => copyCmd(bootstrapData?.windows_command || "irm http://localhost:8000/install.ps1 | iex", "win")}
                    className="press rounded border border-border-subtle px-2 py-0.5 text-[10px] text-text-muted hover:text-accent"
                  >
                    {copied === "win" ? "Copied ✓" : "Copy"}
                  </button>
                </div>
                <pre className="rounded-lg bg-bg-base p-2.5 text-[11px] text-accent select-all overflow-x-auto border border-border-subtle">
                  {bootstrapData?.windows_command || "irm http://localhost:8000/install.ps1 | iex"}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* Drawer Footer */}
        <div className="p-4 border-t border-border-subtle bg-bg-elevated/40 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Link
              to={`/hosts/${encodeURIComponent(hostId)}`}
              className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs text-text-primary hover:border-accent/60"
            >
              <Icon name="activity" size={12} />
              <span>Full Host Timeline</span>
            </Link>
            <Link
              to={`/events?host_id=${encodeURIComponent(hostId)}`}
              className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 font-mono text-xs text-text-primary hover:border-accent/60"
            >
              <Icon name="list" size={12} />
              <span>View All Events</span>
            </Link>
          </div>
          <button
            onClick={onClose}
            className="press rounded-lg border border-border-subtle px-4 py-1.5 font-mono text-xs text-text-muted hover:text-text-primary"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function EnrollSensorDrawer({ onClose }: { onClose: () => void }) {
  const [copied, setCopied] = useState<string | null>(null);
  const { data: bootstrapData } = useQuery({
    queryKey: ["agent-bootstrap-commands"],
    queryFn: getAgentBootstrapCommands,
  });

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  const copyCmd = (text: string, label: string) => {
    void navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  };

  const linuxCmd = bootstrapData?.linux_command || "curl -sSL http://localhost:8000/install.sh | sudo bash";
  const winCmd = bootstrapData?.windows_command || "irm http://localhost:8000/install.ps1 | iex";
  const dockerCmd = "docker run -d --name outpost-agent --pid=host --network=host --cap-add=SYS_PTRACE --cap-add=SYS_ADMIN -v /proc:/host/proc:ro -e OUTPOST_SERVER=http://host.docker.internal:8001 outpost/agent:latest";

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs animate-fade-in"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl bg-bg-surface border-l border-border-subtle flex flex-col h-full shadow-2xl overflow-hidden font-mono"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-5 border-b border-border-subtle bg-bg-elevated/40 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-accent/40 bg-accent/15 text-accent">
              <Icon name="plus" size={18} />
            </span>
            <div>
              <h2 className="text-sm font-bold text-text-primary">Enroll New Endpoint Sensor</h2>
              <p className="text-xs text-text-muted">1-click bootstrap command scripts for Linux, Windows &amp; Docker</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-elevated">
            <Icon name="x" size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-6 text-xs">
          <div className="rounded-xl border border-accent/30 bg-accent/5 p-4 text-[12px] text-text-secondary space-y-2">
            <p className="font-bold text-text-primary flex items-center gap-1.5">
              <Icon name="shield" size={13} className="text-accent" />
              <span>How Endpoint Sensor Enrollment Works:</span>
            </p>
            <ol className="list-decimal list-inside space-y-1 text-text-muted text-[11px]">
              <li>Open an elevated terminal (root on Linux, Administrator PowerShell on Windows).</li>
              <li>Paste and execute the bootstrap command below for your operating system.</li>
              <li>The sensor provisions local eBPF / Sysmon hooks and connects back to OutPost automatically.</li>
              <li>Live process trees, network sockets, and security audit events appear in your console within 5 seconds.</li>
            </ol>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-text-primary flex items-center gap-1.5">
                <Icon name="linux" size={14} className="text-emerald-400" />
                <span>Linux Sensor (eBPF Kernel Probes &amp; auditd)</span>
              </span>
              <button
                onClick={() => copyCmd(linuxCmd, "linux")}
                className="press rounded-md border border-border-subtle bg-bg-base px-2.5 py-1 text-[11px] text-text-secondary hover:text-accent hover:border-accent"
              >
                {copied === "linux" ? "Copied ✓" : "Copy Command"}
              </button>
            </div>
            <pre className="rounded-lg bg-bg-base p-3 text-[11px] text-accent select-all overflow-x-auto border border-border-subtle leading-relaxed">
              {linuxCmd}
            </pre>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-text-primary flex items-center gap-1.5">
                <Icon name="windows" size={14} className="text-cyan-400" />
                <span>Windows Sensor (PowerShell + Sysmon Service)</span>
              </span>
              <button
                onClick={() => copyCmd(winCmd, "windows")}
                className="press rounded-md border border-border-subtle bg-bg-base px-2.5 py-1 text-[11px] text-text-secondary hover:text-accent hover:border-accent"
              >
                {copied === "windows" ? "Copied ✓" : "Copy Command"}
              </button>
            </div>
            <pre className="rounded-lg bg-bg-base p-3 text-[11px] text-accent select-all overflow-x-auto border border-border-subtle leading-relaxed">
              {winCmd}
            </pre>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-text-primary flex items-center gap-1.5">
                <Icon name="box" size={14} className="text-indigo-400" />
                <span>Containerized Sensor (Docker Host-Mode)</span>
              </span>
              <button
                onClick={() => copyCmd(dockerCmd, "docker")}
                className="press rounded-md border border-border-subtle bg-bg-base px-2.5 py-1 text-[11px] text-text-secondary hover:text-accent hover:border-accent"
              >
                {copied === "docker" ? "Copied ✓" : "Copy Command"}
              </button>
            </div>
            <pre className="rounded-lg bg-bg-base p-3 text-[11px] text-accent select-all overflow-x-auto border border-border-subtle leading-relaxed">
              {dockerCmd}
            </pre>
          </div>
        </div>

        <div className="p-4 border-t border-border-subtle bg-bg-elevated/40 flex justify-end">
          <button
            onClick={onClose}
            className="press rounded-lg border border-border-subtle bg-bg-surface px-4 py-1.5 font-mono text-xs text-text-muted hover:text-text-primary"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function FleetIocSearchDrawer({
  onSelectIoc,
  onClose,
}: {
  onSelectIoc: (ioc: string) => void;
  onClose: () => void;
}) {
  const [query, setQuery] = useState("");
  const sampleSuggestions = [
    { label: "C2 Beacon Node", value: "203.0.113.88" },
    { label: "Reverse Shell Egress", value: "185.220.101.34" },
    { label: "Credential Dumper", value: "procdump64.exe" },
    { label: "PowerShell LOLBIN", value: "powershell.exe" },
    { label: "Stager Server", value: "45.33.32.156" },
  ];

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (query.trim()) {
      onSelectIoc(query.trim());
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs animate-fade-in"
      onClick={onClose}
    >
      <div
        className="w-full max-w-xl bg-bg-surface border-l border-border-subtle flex flex-col h-full shadow-2xl overflow-hidden font-mono"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-5 border-b border-border-subtle bg-bg-elevated/40 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-accent/40 bg-accent/15 text-accent">
              <Icon name="search" size={16} />
            </span>
            <div>
              <h2 className="text-sm font-bold text-text-primary">Hunt Fleet Indicator (IOC)</h2>
              <p className="text-xs text-text-muted">Retroactive compromise assessment across all endpoint logs</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-elevated">
            <Icon name="x" size={16} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <div>
            <label className="block text-[11px] font-bold text-text-faint uppercase mb-1.5">
              Target Indicator (IP address, Process Name, or SHA-256):
            </label>
            <div className="relative">
              <Icon name="search" size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-faint" />
              <input
                type="text"
                autoFocus
                placeholder="e.g. 203.0.113.88 or mimikatz.exe"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="w-full rounded-xl border border-border-subtle bg-bg-base py-2.5 pl-9 pr-3 text-xs text-text-primary placeholder:text-text-faint focus:border-accent focus:outline-none"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <span className="text-[10px] text-text-faint uppercase font-bold">Suggested Threat Indicators:</span>
            <div className="flex flex-wrap gap-1.5">
              {sampleSuggestions.map((s) => (
                <button
                  type="button"
                  key={s.value}
                  onClick={() => onSelectIoc(s.value)}
                  className="press rounded-lg border border-border-subtle bg-bg-base px-2 py-1 text-[11px] text-text-secondary hover:border-accent hover:text-accent transition flex items-center gap-1.5"
                >
                  <span className="text-accent">{s.value}</span>
                  <span className="text-text-faint text-[9px]">({s.label})</span>
                </button>
              ))}
            </div>
          </div>

          <div className="pt-4 flex justify-end gap-2 border-t border-border-subtle">
            <button
              type="button"
              onClick={onClose}
              className="press rounded-lg border border-border-subtle px-4 py-1.5 text-xs text-text-muted hover:text-text-primary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!query.trim()}
              className="press rounded-lg bg-accent px-4 py-1.5 text-xs font-bold text-white hover:brightness-110 disabled:opacity-40"
            >
              Launch Fleet Hunt
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function AgentsPage() {
  const queryClient = useQueryClient();
  const [searchParams] = useSearchParams();
  const identity = searchParams.get("identity") ?? "";
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [platformFilter, setPlatformFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedHostId, setSelectedHostId] = useState<string | null>(null);
  const [huntIoc, setHuntIoc] = useState<string | null>(null);
  const [showEnrollDrawer, setShowEnrollDrawer] = useState(false);
  const [showHuntInput, setShowHuntInput] = useState(false);
  const [activeDeck, setActiveDeck] = useState<"fleet" | "task_manager">("fleet");

  const { data, isLoading, isError } = useQuery({
    queryKey: ["agents", identity],
    queryFn: () => getAgents(identity),
    refetchInterval: 15_000,
  });

  useEventStream(
    () => undefined,
    undefined,
    undefined,
    () => {
      void queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  );

  const agents = data?.agents ?? [];
  const totalEvents = agents.reduce((n, a) => n + a.event_count, 0);
  const totalAlerts = agents.reduce((n, a) => n + a.alert_count, 0);

  const filteredAgents = agents.filter((a) => {
    const st = a.silent ? "silent" : a.online ? "online" : "offline";
    if (statusFilter !== "all" && st !== statusFilter) return false;
    if (platformFilter !== "all" && !a.platforms.includes(platformFilter as any)) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        a.host_id.toLowerCase().includes(q) ||
        (a.identity || "").toLowerCase().includes(q) ||
        a.platforms.some((p) => p.toLowerCase().includes(q));
      if (!match) return false;
    }
    return true;
  });

  const selectedAgent = agents.find((a) => a.host_id === selectedHostId);

  const handleExportInventory = () => {
    const header = "Host ID,Status,Identity,Platforms,Event Count,Run Count,Alert Count,Last Seen,Last Heartbeat\n";
    const rows = (agents || []).map((a) => {
      const st = a.silent ? "silent" : a.online ? "online" : "offline";
      return `"${a.host_id}","${st}","${a.identity}","${a.platforms.join(";")}",${a.event_count},${a.run_count},${a.alert_count},"${a.last_seen || ""}","${a.last_heartbeat || ""}"`;
    });
    const blob = new Blob([header + rows.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `fleet-inventory-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="mx-auto max-w-[1440px] px-6 py-8 lg:px-8">
      {showEnrollDrawer && (
        <EnrollSensorDrawer onClose={() => setShowEnrollDrawer(false)} />
      )}
      {showHuntInput && (
        <FleetIocSearchDrawer
          onSelectIoc={(ioc) => {
            setShowHuntInput(false);
            setHuntIoc(ioc);
          }}
          onClose={() => setShowHuntInput(false)}
        />
      )}
      {selectedHostId && (
        <HostInspectorDrawer
          hostId={selectedHostId}
          agent={selectedAgent}
          onClose={() => setSelectedHostId(null)}
        />
      )}
      {huntIoc && (
        <IocFleetHuntModal iocId={huntIoc} onClose={() => setHuntIoc(null)} />
      )}

      {/* Top Console Header */}
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4 border-b border-border-subtle pb-6">
        <div>
          <span className="font-mono text-[10px] uppercase tracking-wider text-accent font-semibold">
            Endpoint Operations · EDR Fleet Console
          </span>
          <h1 className="mt-1 text-xl font-bold font-mono text-text-primary">
            EDR Fleet &amp; Host Management
          </h1>
          <p className="mt-1 text-xs text-text-muted">
            Live telemetry ingestion, host quarantine containment, and multi-sensor management.
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <button
            onClick={() => setShowEnrollDrawer(true)}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-accent bg-accent px-3 py-1.5 font-bold text-white shadow-xs hover:brightness-110"
          >
            <Icon name="plus" size={13} />
            <span>⚡ Enroll New Sensor</span>
          </button>
          <button
            onClick={() => setShowHuntInput(true)}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent/15 px-3 py-1.5 font-bold text-accent hover:bg-accent/25"
          >
            <Icon name="search" size={13} />
            <span>Hunt Fleet IOC</span>
          </button>
          <button
            onClick={handleExportInventory}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-surface px-3 py-1.5 text-text-muted hover:border-accent/40 hover:text-text-primary"
            title="Download CSV inventory"
          >
            <Icon name="download" size={12} />
            <span>Export CSV</span>
          </button>
          <button
            onClick={() => void queryClient.invalidateQueries({ queryKey: ["agents"] })}
            className="press rounded-lg border border-border-subtle bg-bg-surface p-2 text-text-muted hover:border-accent/40 hover:text-text-primary"
            title="Refresh fleet telemetry"
          >
            <Icon name="refresh" size={12} />
          </button>
        </div>
      </div>

      {/* Primary Console Deck Switcher */}
      <div className="mb-6 flex rounded-xl border border-border-subtle bg-bg-surface p-1 font-mono text-xs shadow-xs">
        <button
          onClick={() => setActiveDeck("fleet")}
          className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2 font-medium transition ${
            activeDeck === "fleet"
              ? "bg-accent/15 font-bold text-accent shadow-xs"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="shield" size={13} />
          <span>EDR Fleet Sensor Inventory ({data?.total ?? 0})</span>
        </button>
        <button
          onClick={() => setActiveDeck("task_manager")}
          className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2 font-medium transition ${
            activeDeck === "task_manager"
              ? "bg-accent/15 font-bold text-accent shadow-xs"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="activity" size={13} />
          <span>Live Endpoint Task Manager &amp; Processes</span>
        </button>
      </div>

      {activeDeck === "task_manager" ? (
        <EndpointTaskManager hostId="local" />
      ) : (
        <>
          {/* Beginner Operational Posture Guide */}
      <div className="mb-6 rounded-xl border border-border-subtle/90 bg-bg-surface/60 p-4 font-mono text-xs backdrop-blur-sm space-y-2">
        <div className="flex items-center justify-between">
          <span className="font-bold text-text-primary flex items-center gap-2">
            <Icon name="shield" size={14} className="text-accent" />
            <span>How Endpoint Fleet Sensors &amp; Active Containment Work</span>
          </span>
          <span className="text-[10px] text-text-faint">OutPost Autonomous EDR Architecture</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1 text-[11px] text-text-muted">
          <div className="rounded-lg bg-bg-base/70 p-2.5 border border-border-subtle space-y-1">
            <div className="flex items-center gap-1.5 text-signal font-bold text-[10px] uppercase">
              <span className="h-2 w-2 rounded-full bg-signal" />
              <span>Online Sensor (Healthy)</span>
            </div>
            <p className="text-text-faint text-[10px] leading-relaxed">
              Host continuously transmits heartbeats every 15s and streams live kernel procfs, socket binds, and process creations.
            </p>
          </div>
          <div className="rounded-lg bg-bg-base/70 p-2.5 border border-border-subtle space-y-1">
            <div className="flex items-center gap-1.5 text-risk-malicious font-bold text-[10px] uppercase">
              <span className="h-2 w-2 rounded-full bg-risk-malicious" />
              <span>Silent / Stale (Attention)</span>
            </div>
            <p className="text-text-faint text-[10px] leading-relaxed">
              Host missed expected heartbeat windows. May indicate endpoint powered down, network partitioned, or agent terminated.
            </p>
          </div>
          <div className="rounded-lg bg-bg-base/70 p-2.5 border border-border-subtle space-y-1">
            <div className="flex items-center gap-1.5 text-accent font-bold text-[10px] uppercase">
              <span className="h-2 w-2 rounded-full bg-accent" />
              <span>Instant Host Quarantine</span>
            </div>
            <p className="text-text-faint text-[10px] leading-relaxed">
              Isolate compromised hosts from network communication in 1 click while preserving security analyst remote access channels.
            </p>
          </div>
        </div>
      </div>

      {/* Metric Stat HUD Strip */}
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-5 font-mono">
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5">
          <span className="text-[10px] uppercase text-text-faint">Enrolled Hosts</span>
          <p className="text-xl font-bold text-text-primary mt-1">{data?.total ?? 0}</p>
        </div>
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5">
          <span className="text-[10px] uppercase text-text-faint">Online Sensors</span>
          <p className="text-xl font-bold text-signal mt-1">{data?.online ?? 0}</p>
        </div>
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5">
          <span className="text-[10px] uppercase text-text-faint">Silent / Stale</span>
          <p className={`text-xl font-bold mt-1 ${data?.silent ? "text-risk-malicious" : "text-text-muted"}`}>
            {data?.silent ?? 0}
          </p>
        </div>
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5">
          <span className="text-[10px] uppercase text-text-faint">Telemetry Shipped</span>
          <p className="text-xl font-bold text-text-primary mt-1">{totalEvents.toLocaleString()}</p>
        </div>
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-3.5">
          <span className="text-[10px] uppercase text-text-faint">Correlated Detections</span>
          <p className={`text-xl font-bold mt-1 ${totalAlerts > 0 ? "text-risk-suspicious" : "text-text-muted"}`}>
            {totalAlerts}
          </p>
        </div>
      </div>

      {/* Filter & Command Control Bar */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 font-mono text-xs">
        <div className="flex-1 min-w-64 max-w-md relative">
          <Icon name="search" size={12} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-faint" />
          <input
            type="text"
            placeholder="Filter endpoints by hostname, OS, or role..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-xl border border-border-subtle bg-bg-surface py-1.5 pl-8 pr-3 text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Status filter pills */}
          <div className="flex items-center rounded-lg border border-border-subtle bg-bg-surface p-0.5">
            {(["all", "online", "silent", "offline"] as const).map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`rounded-md px-2 py-0.5 capitalize transition ${
                  statusFilter === st
                    ? "bg-accent/20 font-bold text-accent shadow-xs"
                    : "text-text-muted hover:text-text-primary"
                }`}
              >
                {st}
              </button>
            ))}
          </div>

          {/* Platform filter pills */}
          <div className="flex items-center rounded-lg border border-border-subtle bg-bg-surface p-0.5">
            {(["all", "linux", "windows", "macos"] as const).map((p) => (
              <button
                key={p}
                onClick={() => setPlatformFilter(p)}
                className={`rounded-md px-2 py-0.5 capitalize transition ${
                  platformFilter === p
                    ? "bg-accent/20 font-bold text-accent shadow-xs"
                    : "text-text-muted hover:text-text-primary"
                }`}
              >
                {p}
              </button>
            ))}
          </div>
        </div>
      </div>

      {isLoading && (
        <div className="py-12 text-center font-mono text-xs text-text-muted">
          Loading endpoint inventory…
        </div>
      )}

      {isError && (
        <div className="rounded-xl border border-risk-malicious/40 bg-bg-surface p-4 font-mono text-xs text-risk-malicious">
          Could not communicate with OutPost agent manager — verify backend health.
        </div>
      )}

      {/* Main High-Density Fleet Grid Table */}
      {!isLoading && !isError && (
        <div className="rounded-xl border border-border-subtle bg-bg-surface overflow-hidden shadow-xs">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-bg-elevated/70 border-b border-border-subtle text-[10px] uppercase text-text-faint">
              <tr>
                <th className="px-4 py-2.5">Endpoint Host</th>
                <th className="px-4 py-2.5">OS &amp; Channels</th>
                <th className="px-4 py-2.5">Identity &amp; Auth</th>
                <th className="px-4 py-2.5">Sensor Health &amp; Backlog</th>
                <th className="px-4 py-2.5">Telemetry Volume</th>
                <th className="px-4 py-2.5">Heartbeat Liveness</th>
                <th className="px-4 py-2.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/50">
              {filteredAgents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-text-muted">
                    No endpoint hosts match the current filter criteria.
                  </td>
                </tr>
              ) : (
                filteredAgents.map((a) => {
                  const status = a.silent ? "silent" : a.online ? "online" : "offline";
                  return (
                    <tr
                      key={a.host_id}
                      onClick={() => setSelectedHostId(a.host_id)}
                      className="cursor-pointer hover:bg-bg-elevated/40 transition group"
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2.5">
                          <span
                            className={`h-2 w-2 rounded-full ${
                              status === "online"
                                ? "bg-signal animate-outpost-pulse"
                                : status === "silent"
                                  ? "bg-risk-malicious"
                                  : "bg-text-faint"
                            }`}
                          />
                          <div>
                            <span className="font-bold text-text-primary group-hover:text-accent transition">
                              {a.host_id}
                            </span>
                            <span className="ml-2 font-mono text-[10px] text-text-faint">
                              {a.heartbeat_version || ""}
                            </span>
                          </div>
                        </div>
                      </td>

                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          {a.platforms.map((p) => (
                            <span
                              key={p}
                              className="inline-flex items-center gap-1 rounded bg-bg-base border border-border-subtle px-1.5 py-0.5 text-[10px] text-text-muted capitalize"
                            >
                              <Icon name={platformIconName(p)} size={10} />
                              {p}
                            </span>
                          ))}
                          {a.channels && (
                            <span className="text-[10px] text-text-faint">
                              ({a.channels.join(", ")})
                            </span>
                          )}
                        </div>
                      </td>

                      <td className="px-4 py-3 text-text-muted">
                        <div className="flex flex-col gap-0.5">
                          <div className="flex items-center gap-1">
                            <span className="rounded bg-bg-base border border-border-subtle px-1.5 py-0.5 text-[10px]">
                              {a.identity}
                            </span>
                            {a.last_auth_role && (
                              <span className="text-[10px] text-text-faint">
                                role: {a.last_auth_role}
                              </span>
                            )}
                          </div>
                          {a.agent_id && (
                            <span className="text-[9px] font-mono text-signal truncate max-w-36" title={a.agent_id}>
                              {a.agent_id}
                            </span>
                          )}
                        </div>
                      </td>

                      <td className="px-4 py-3">
                        {a.metrics ? (
                          <div className="flex items-center gap-1.5">
                            <span
                              className={`inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold border ${
                                (a.metrics.cpu_percent ?? 0) > 80
                                  ? "bg-risk-malicious/15 border-risk-malicious/40 text-risk-malicious"
                                  : (a.metrics.cpu_percent ?? 0) > 50
                                    ? "bg-amber-400/15 border-amber-400/40 text-amber-400"
                                    : "bg-signal/15 border-signal/40 text-signal"
                              }`}
                              title={`CPU Load: ${a.metrics.cpu_percent}%`}
                            >
                              <span>CPU {a.metrics.cpu_percent}%</span>
                            </span>
                            <span
                              className={`inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 text-[10px] font-mono font-semibold border ${
                                (a.metrics.memory_percent ?? 0) > 85
                                  ? "bg-risk-malicious/15 border-risk-malicious/40 text-risk-malicious"
                                  : (a.metrics.memory_percent ?? 0) > 65
                                    ? "bg-amber-400/15 border-amber-400/40 text-amber-400"
                                    : "bg-signal/15 border-signal/40 text-signal"
                              }`}
                              title={`RAM: ${a.metrics.memory_percent}% (${a.metrics.memory_used_mb ?? 0} MB / ${a.metrics.memory_total_mb ?? 0} MB)`}
                            >
                              <span>RAM {a.metrics.memory_percent}%</span>
                            </span>
                            <span
                              className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-mono border ${
                                (a.metrics.queue_backlog ?? 0) > 0
                                  ? "bg-amber-400/15 border-amber-400/40 text-amber-400 font-bold"
                                  : "bg-bg-base border-border-subtle text-text-faint"
                              }`}
                              title="Local Spool Backlog"
                            >
                              <span>{a.metrics.queue_backlog ? `! ${a.metrics.queue_backlog} spooled` : "0 spooled"}</span>
                            </span>
                          </div>
                        ) : (
                          <span className="text-[10px] text-text-faint font-mono">—</span>
                        )}
                      </td>

                      <td className="px-4 py-3 tabular-nums">
                        <span className="text-text-primary">{a.event_count.toLocaleString()} events</span>
                        <span className="text-text-faint text-[10px] ml-1.5">· {a.run_count} runs</span>
                      </td>

                      <td className="px-4 py-3 text-text-faint text-[11px]">
                        {a.last_seen ? relativeTime(a.last_seen) : "—"}
                      </td>

                      <td className="px-4 py-3 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => setSelectedHostId(a.host_id)}
                            className="press rounded-md border border-accent/50 bg-accent/10 px-2 py-1 text-[11px] font-semibold text-accent hover:bg-accent/20"
                          >
                            Inspect
                          </button>
                          <Link
                            to={`/hosts/${encodeURIComponent(a.host_id)}`}
                            className="press rounded-md border border-border-subtle bg-bg-base px-2 py-1 text-[11px] text-text-muted hover:border-accent/40 hover:text-text-primary"
                          >
                            Timeline
                          </Link>
                          <Link
                            to={`/events?host_id=${encodeURIComponent(a.host_id)}`}
                            className="press rounded-md border border-border-subtle bg-bg-base px-2 py-1 text-[11px] text-text-muted hover:border-accent/40 hover:text-text-primary"
                          >
                            Events
                          </Link>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      )}
        </>
      )}
    </div>
  );
}
