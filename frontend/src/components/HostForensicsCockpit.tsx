import { useEffect, useState } from "react";
import {
  controlProcessXRay,
  getForensicCapsule,
  getXRayFullTargetDossier,
  getXRayTargetCatalog,
} from "../lib/api";
import { Icon } from "./Icon";

export interface HostForensicsCockpitProps {
  initialPid?: number;
  onInspectExternalPid?: (pid: number) => void;
}

export function HostForensicsCockpit({ initialPid, onInspectExternalPid }: HostForensicsCockpitProps) {
  const [selectedPid, setSelectedPid] = useState<number>(initialPid || 1);
  const [catalog, setCatalog] = useState<any>(null);
  const [dossier, setDossier] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [searchFilter, setSearchFilter] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<"ALL" | "APPS" | "PROC" | "PORTS" | "SYS">("ALL");
  const [actionStatus, setActionStatus] = useState<string | null>(null);

  // Load catalog on mount
  useEffect(() => {
    async function loadCatalog() {
      try {
        const cat = await getXRayTargetCatalog();
        setCatalog(cat);
        if (!initialPid && cat.open_apps && cat.open_apps.length > 0) {
          setSelectedPid(cat.open_apps[0].pid);
        } else if (!initialPid && cat.processes && cat.processes.length > 0) {
          setSelectedPid(cat.processes[0].pid);
        }
      } catch (err) {
        console.error("Failed to load X-Ray catalog", err);
      }
    }
    loadCatalog();
  }, [initialPid]);

  // Load target dossier whenever selectedPid changes
  useEffect(() => {
    async function loadDossier() {
      try {
        setLoading(true);
        setActionStatus(null);
        const data = await getXRayFullTargetDossier(selectedPid);
        setDossier(data);
      } catch (err) {
        console.error(`Failed to load dossier for PID ${selectedPid}`, err);
      } finally {
        setLoading(false);
      }
    }
    if (selectedPid) {
      loadDossier();
    }
  }, [selectedPid]);

  const handleAction = async (action: "freeze" | "resume" | "terminate" | "kill") => {
    try {
      setActionStatus(`Sending ${action.toUpperCase()} signal...`);
      const res = await controlProcessXRay(selectedPid, action);
      setActionStatus(res.message);
      // Reload dossier
      const updated = await getXRayFullTargetDossier(selectedPid);
      setDossier(updated);
    } catch (err: any) {
      setActionStatus(`Action failed: ${err?.message || "Signal could not be delivered"}`);
    }
  };

  const handleExportCapsule = async () => {
    try {
      setActionStatus("Generating .xray.json forensic capsule...");
      const capsule = await getForensicCapsule(selectedPid);
      const blob = new Blob([JSON.stringify(capsule, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `outpost-xray-capsule-pid-${selectedPid}.xray.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setActionStatus(`Capsule downloaded: outpost-xray-capsule-pid-${selectedPid}.xray.json`);
    } catch (err: any) {
      setActionStatus(`Export failed: ${err?.message || "Capsule generation error"}`);
    }
  };

  const target = dossier?.target;
  const launchChain = dossier?.launch_chain;
  const deviceAccess = dossier?.device_access || {
    microphone: { in_use: false, label: "Not in use" },
    camera: { in_use: false, label: "Not in use" },
    screen_capture: { in_use: false, label: "Not in use" },
    audio_capture: { in_use: false, label: "Not in use" },
    audio_playback: { in_use: false, label: "Not in use" },
    video_capture: { in_use: false, label: "Not in use" },
    gpu: { in_use: false, label: "Not in use", client_count: 0 },
    sleep_inhibition: { in_use: false, label: "Not in use" },
  };
  const security = dossier?.security || {};
  const processTree = dossier?.process_tree || [];
  const connections = dossier?.connections || [];
  const filesIpc = dossier?.files_ipc || [];
  const findings = dossier?.findings || [];

  // Filter open apps in sidebar
  const filteredApps = (catalog?.open_apps || []).filter((app: any) => {
    if (!searchFilter) return true;
    const q = searchFilter.toLowerCase();
    return app.name.toLowerCase().includes(q) || String(app.pid).includes(q) || app.title.toLowerCase().includes(q);
  });

  const filteredProcs = (catalog?.processes || []).filter((p: any) => {
    if (!searchFilter) return true;
    const q = searchFilter.toLowerCase();
    return p.name.toLowerCase().includes(q) || String(p.pid).includes(q) || (p.cmdline || "").toLowerCase().includes(q);
  });

  return (
    <div className="flex flex-col xl:flex-row gap-3 bg-[#0d1117] text-[#c9d1d9] rounded-xl border border-[#30363d] p-3 font-mono text-xs overflow-hidden shadow-2xl">
      {/* ── Left Sidebar: TARGET CATALOG ───────────────────────── */}
      <aside className="w-full xl:w-72 shrink-0 flex flex-col bg-[#161b22] rounded-lg border border-[#30363d] p-3 space-y-3">
        <div className="flex items-center justify-between border-b border-[#30363d] pb-2">
          <div>
            <div className="text-[11px] font-bold tracking-wider text-[#8b949e] uppercase">Target Catalog</div>
            <div className="text-[10px] text-[#58a6ff] font-semibold">
              {catalog?.total_targets_count || 0} Targets Available
            </div>
          </div>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#21262d] text-[#8b949e] border border-[#30363d]">
            CTRL K
          </span>
        </div>

        {/* Search Bar */}
        <div className="relative">
          <input
            type="text"
            placeholder="App, PID, :port, service..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="w-full bg-[#0d1117] border border-[#30363d] rounded px-2.5 py-1.5 text-xs text-[#c9d1d9] placeholder-[#484f58] focus:border-[#58a6ff] focus:outline-hidden"
          />
        </div>

        {/* Category Pills */}
        <div className="flex gap-1 border-b border-[#30363d] pb-2">
          {(["ALL", "APPS", "PROC", "PORTS", "SYS"] as const).map((cat) => (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat)}
              className={`px-2 py-0.5 rounded text-[10px] font-bold transition cursor-pointer ${
                categoryFilter === cat
                  ? "bg-[#58a6ff]/20 text-[#58a6ff] border border-[#58a6ff]/40"
                  : "bg-[#21262d] text-[#8b949e] hover:text-[#c9d1d9]"
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Quick Inspect Triggers */}
        <div className="space-y-1">
          <div className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e]">Quick Inspect</div>
          <div className="grid grid-cols-2 gap-1.5">
            <div className="p-1.5 rounded bg-[#0d1117] border border-[#30363d] flex items-center justify-between">
              <span className="text-[11px] text-[#8b949e]">Audio</span>
              <span className="text-[10px] font-bold text-[#58a6ff]">{catalog?.quick_inspect?.audio ?? 0}</span>
            </div>
            <div className="p-1.5 rounded bg-[#0d1117] border border-[#30363d] flex items-center justify-between">
              <span className="text-[11px] text-[#8b949e]">Camera</span>
              <span className="text-[10px] font-bold text-[#58a6ff]">{catalog?.quick_inspect?.camera ?? 0}</span>
            </div>
            <div className="p-1.5 rounded bg-[#0d1117] border border-[#30363d] flex items-center justify-between">
              <span className="text-[11px] text-[#8b949e]">GPU</span>
              <span className="text-[10px] font-bold text-[#58a6ff]">{catalog?.quick_inspect?.gpu ?? 0}</span>
            </div>
            <div className="p-1.5 rounded bg-[#0d1117] border border-[#30363d] flex items-center justify-between">
              <span className="text-[11px] text-[#8b949e]">Microphone</span>
              <span className="text-[10px] font-bold text-[#58a6ff]">{catalog?.quick_inspect?.microphone ?? 0}</span>
            </div>
          </div>
        </div>

        {/* Open Apps Section */}
        <div className="flex-1 overflow-y-auto space-y-1 max-h-72">
          <div className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e]">
            Open Apps ({filteredApps.length})
          </div>
          {filteredApps.map((app: any) => (
            <div
              key={app.pid}
              onClick={() => setSelectedPid(app.pid)}
              className={`p-2 rounded cursor-pointer transition flex flex-col gap-0.5 border ${
                selectedPid === app.pid
                  ? "bg-[#1f6feb]/20 border-[#58a6ff]/50 text-[#58a6ff]"
                  : "bg-[#0d1117] border-[#30363d] hover:bg-[#21262d] text-[#c9d1d9]"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-xs">{app.name}</span>
                <span className="text-[10px] font-mono opacity-70">PID {app.pid}</span>
              </div>
              <div className="text-[10px] text-[#8b949e] truncate">{app.title}</div>
            </div>
          ))}

          {/* Processes list if PROC filter or search active */}
          {(categoryFilter === "PROC" || categoryFilter === "ALL") && (
            <div className="pt-2 space-y-1">
              <div className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e]">
                Processes ({filteredProcs.length})
              </div>
              {filteredProcs.slice(0, 15).map((p: any) => (
                <div
                  key={p.pid}
                  onClick={() => setSelectedPid(p.pid)}
                  className={`p-1.5 rounded cursor-pointer transition flex items-center justify-between text-[11px] ${
                    selectedPid === p.pid
                      ? "bg-[#1f6feb]/20 border border-[#58a6ff]/50 text-[#58a6ff]"
                      : "hover:bg-[#21262d] text-[#8b949e]"
                  }`}
                >
                  <span className="truncate max-w-[140px]">{p.name}</span>
                  <span className="font-mono text-[10px]">PID {p.pid}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </aside>

      {/* ── Right Main Cockpit ──────────────────────────────────── */}
      <main className="flex-1 flex flex-col space-y-3 min-w-0">
        {/* Top Target Telemetry Strip */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-3 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-[#58a6ff]/15 border border-[#58a6ff]/40 flex items-center justify-center text-[#58a6ff]">
              <Icon name="process" size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-[#f0f6fc]">{target?.name || "Select Target"}</span>
                <span className="text-[11px] text-[#8b949e] font-mono">PID {target?.pid}</span>
                <span className="text-[11px] text-[#8b949e]">USER {target?.user}</span>
                <span className="px-1.5 py-0.2 rounded text-[10px] font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                  {target?.status || "LIVE"}
                </span>
                {loading && <span className="text-[10px] text-[#58a6ff] animate-pulse">SYNCING...</span>}
                {onInspectExternalPid && (
                  <button
                    onClick={() => onInspectExternalPid(selectedPid)}
                    className="px-2 py-0.5 rounded text-[10px] bg-[#21262d] hover:bg-[#30363d] text-[#58a6ff] border border-[#30363d] transition cursor-pointer"
                  >
                    Deep Modal ↗
                  </button>
                )}
              </div>
              <div className="text-[10px] text-[#8b949e] truncate max-w-lg font-mono">
                {target?.exe || target?.cmdline || "No path"}
              </div>
            </div>
          </div>

          {/* Metric Tiles */}
          <div className="flex items-center gap-4 text-center">
            <div>
              <div className="text-[10px] text-[#8b949e] uppercase">CPU</div>
              <div className="text-xs font-bold text-[#f0f6fc]">{target?.cpu_percent ?? 0}%</div>
            </div>
            <div className="w-px h-6 bg-[#30363d]" />
            <div>
              <div className="text-[10px] text-[#8b949e] uppercase">MEM</div>
              <div className="text-xs font-bold text-[#f0f6fc]">{target?.memory_gib_str || "0 MB"}</div>
              <div className="text-[9px] text-[#8b949e]">{target?.threads || 1} thr</div>
            </div>
            <div className="w-px h-6 bg-[#30363d]" />
            <div>
              <div className="text-[10px] text-[#8b949e] uppercase">DISK I/O</div>
              <div className="text-xs font-bold text-[#f0f6fc]">{target?.disk_io_str || "read+write"}</div>
            </div>
            <div className="w-px h-6 bg-[#30363d]" />
            <div>
              <div className="text-[10px] text-[#8b949e] uppercase">GPU</div>
              <div className="text-xs font-bold text-[#58a6ff]">{target?.gpu_clients_count || 0} clients</div>
            </div>
            <div className="w-px h-6 bg-[#30363d]" />
            <div>
              <div className="text-[10px] text-[#8b949e] uppercase">60s Live Trace</div>
              <div className="h-6 w-24 flex items-center justify-center">
                {/* SVG Sparkline */}
                <svg className="w-full h-5 stroke-[#58a6ff] fill-none" viewBox="0 0 100 20">
                  <polyline points="0,15 15,12 30,14 45,8 60,11 75,5 90,9 100,7" strokeWidth="2" />
                </svg>
              </div>
            </div>
          </div>
        </div>

        {/* Action Status Banner */}
        {actionStatus && (
          <div className="p-2 rounded bg-[#58a6ff]/15 border border-[#58a6ff]/30 text-[#58a6ff] text-[11px] font-mono">
            {actionStatus}
          </div>
        )}

        {/* ── Upper Grid: Launch Chain, App Device Access, Runtime & Security ── */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Launch Chain */}
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-3 space-y-2">
            <div className="flex items-center justify-between border-b border-[#30363d] pb-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e]">Launch Chain</span>
              <span className="text-[10px] text-[#3fb950] font-semibold">CONFIRMED</span>
            </div>
            <p className="text-[10px] text-[#8b949e]">{launchChain?.description || "Supervised inside systemd"}</p>
            <div className="space-y-1.5 pt-1">
              {(launchChain?.chain || []).map((node: any, idx: number) => (
                <div key={idx} className="flex items-center justify-between p-1.5 rounded bg-[#0d1117] border border-[#30363d]">
                  <div className="flex items-center gap-2 truncate">
                    <span className="text-[11px] text-[#58a6ff]">●</span>
                    <span className="text-xs text-[#f0f6fc] font-semibold truncate">{node.name}</span>
                  </div>
                  <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-[#21262d] text-[#8b949e]">
                    {node.role}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* App Device Access Matrix */}
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-3 space-y-2">
            <div className="flex items-center justify-between border-b border-[#30363d] pb-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e]">App Device Access</span>
              <span className="text-[10px] text-[#58a6ff] font-semibold">8 SENSORS</span>
            </div>
            <div className="grid grid-cols-2 gap-1.5 text-[10px]">
              <div className="p-1.5 rounded bg-[#0d1117] border border-[#30363d]">
                <div className="text-[#8b949e]">Microphone</div>
                <div className={deviceAccess.microphone.in_use ? "text-[#f85149] font-bold" : "text-[#8b949e]"}>
                  {deviceAccess.microphone.label}
                </div>
              </div>
              <div className="p-1.5 rounded bg-[#0d1117] border border-[#30363d]">
                <div className="text-[#8b949e]">Camera</div>
                <div className={deviceAccess.camera.in_use ? "text-[#f85149] font-bold" : "text-[#8b949e]"}>
                  {deviceAccess.camera.label}
                </div>
              </div>
              <div className="p-1.5 rounded bg-[#0d1117] border border-[#30363d]">
                <div className="text-[#8b949e]">Screen capture</div>
                <div className={deviceAccess.screen_capture.in_use ? "text-[#f85149] font-bold" : "text-[#8b949e]"}>
                  {deviceAccess.screen_capture.label}
                </div>
              </div>
              <div className="p-1.5 rounded bg-[#0d1117] border border-[#30363d]">
                <div className="text-[#8b949e]">Audio capture</div>
                <div className={deviceAccess.audio_capture.in_use ? "text-[#f85149] font-bold" : "text-[#8b949e]"}>
                  {deviceAccess.audio_capture.label}
                </div>
              </div>
              <div className="p-1.5 rounded bg-[#0d1117] border border-[#30363d]">
                <div className="text-[#8b949e]">Audio playback</div>
                <div className={deviceAccess.audio_playback.in_use ? "text-[#58a6ff] font-bold" : "text-[#8b949e]"}>
                  {deviceAccess.audio_playback.label}
                </div>
              </div>
              <div className="p-1.5 rounded bg-[#0d1117] border border-[#30363d]">
                <div className="text-[#8b949e]">GPU Render</div>
                <div className={deviceAccess.gpu.in_use ? "text-[#3fb950] font-bold truncate" : "text-[#8b949e]"}>
                  {deviceAccess.gpu.label}
                </div>
              </div>
              <div className="p-1.5 rounded bg-[#0d1117] border border-[#30363d] col-span-2">
                <div className="text-[#8b949e]">Sleep Inhibition</div>
                <div className={deviceAccess.sleep_inhibition.in_use ? "text-[#d29922] font-bold" : "text-[#8b949e]"}>
                  {deviceAccess.sleep_inhibition.label}
                </div>
              </div>
            </div>
          </div>

          {/* Runtime & Security */}
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-3 space-y-2">
            <div className="flex items-center justify-between border-b border-[#30363d] pb-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e]">Runtime & Security</span>
              <span className="text-[10px] text-[#8b949e] font-mono">SECRETS REDACTED</span>
            </div>
            <div className="space-y-1.5 text-[11px]">
              <div className="flex justify-between border-b border-[#30363d]/50 pb-1">
                <span className="text-[#8b949e]">Service</span>
                <span className="font-semibold text-[#f0f6fc] truncate max-w-[140px]">
                  {security.service_unit || dossier?.cgroup?.systemd_service || "session.scope"}
                </span>
              </div>
              <div className="flex justify-between border-b border-[#30363d]/50 pb-1">
                <span className="text-[#8b949e]">Container</span>
                <span className="font-semibold text-[#f0f6fc]">
                  {dossier?.cgroup?.is_containerized ? `${dossier.cgroup.container_runtime} (${dossier.cgroup.container_short_id})` : "No container (Host)"}
                </span>
              </div>
              <div className="flex justify-between border-b border-[#30363d]/50 pb-1">
                <span className="text-[#8b949e]">Identity</span>
                <span className="font-mono text-[#f0f6fc]">UID {security.uid ?? 1000} · GID {security.gid ?? 1000}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#8b949e]">Isolation</span>
                <span className={`font-mono text-[10px] ${security.seccomp === "Disabled" || security.seccomp === "disabled" ? "text-[#f85149]" : "text-[#3fb950]"}`}>
                  Seccomp: {security.seccomp || "Disabled"}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* ── Lower Grid: Nested Process Table, Connections, Files/IPC, Findings ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 flex-1">
          {/* Nested Process Tree Table */}
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-3 space-y-2 flex flex-col">
            <div className="flex items-center justify-between border-b border-[#30363d] pb-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e]">
                Process Tree Hierarchy ({processTree.length} roots)
              </span>
              <span className="text-[10px] text-[#58a6ff] font-mono">$ {target?.exe || target?.name}</span>
            </div>
            <div className="overflow-x-auto flex-1 max-h-56">
              <table className="w-full text-left text-[11px]">
                <thead>
                  <tr className="text-[#8b949e] border-b border-[#30363d] text-[10px]">
                    <th className="py-1">PROGRAM / TREE</th>
                    <th className="py-1">PID</th>
                    <th className="py-1">USER</th>
                    <th className="py-1">THR</th>
                    <th className="py-1">MEM</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#21262d]">
                  {processTree.map((p: any) => (
                    <tr key={p.pid} className="hover:bg-[#21262d]/50">
                      <td className="py-1 font-semibold text-[#f0f6fc] flex items-center gap-1.5">
                        <span className="text-[#58a6ff]">●</span> {p.name}
                      </td>
                      <td className="py-1 font-mono text-[#58a6ff]">{p.pid}</td>
                      <td className="py-1 text-[#8b949e]">{p.user}</td>
                      <td className="py-1 text-[#8b949e]">{p.threads || 1}</td>
                      <td className="py-1 font-mono text-[#f0f6fc]">{int(p.memory_mb || 0)}M</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Sockets & Network Connections */}
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-3 space-y-2 flex flex-col">
            <div className="flex items-center justify-between border-b border-[#30363d] pb-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e]">
                Connections ({connections.length} Sockets)
              </span>
              <span className="text-[10px] text-[#58a6ff]">IP SOCKETS</span>
            </div>
            <div className="overflow-x-auto flex-1 max-h-56">
              {connections.length === 0 ? (
                <div className="py-8 text-center text-[#8b949e] text-xs">No active sockets for this target.</div>
              ) : (
                <table className="w-full text-left text-[11px]">
                  <thead>
                    <tr className="text-[#8b949e] border-b border-[#30363d] text-[10px]">
                      <th className="py-1">TYPE</th>
                      <th className="py-1">LOCAL</th>
                      <th className="py-1">REMOTE</th>
                      <th className="py-1">STATE</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#21262d]">
                    {connections.map((c: any, idx: number) => (
                      <tr key={idx} className="hover:bg-[#21262d]/50">
                        <td className="py-1 uppercase text-[#58a6ff] font-bold">{c.protocol}</td>
                        <td className="py-1 font-mono text-[#f0f6fc]">{c.local_ip}:{c.local_port}</td>
                        <td className="py-1 font-mono text-[#8b949e]">{c.remote_ip ? `${c.remote_ip}:${c.remote_port}` : "—"}</td>
                        <td className="py-1">
                          <span className={`px-1.5 py-0.2 rounded text-[10px] font-semibold ${
                            c.status === "LISTEN" ? "bg-amber-500/20 text-amber-300" : "bg-emerald-500/20 text-emerald-300"
                          }`}>
                            {c.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Files & IPC (Forensic Inode Table) */}
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-3 space-y-2 flex flex-col">
            <div className="flex items-center justify-between border-b border-[#30363d] pb-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e]">
                Files & IPC Inodes ({filesIpc.length} open)
              </span>
              <span className="text-[10px] text-[#f85149] font-bold">
                {filesIpc.filter((i: any) => i.is_deleted).length} DELETED HELD
              </span>
            </div>
            <div className="overflow-x-auto flex-1 max-h-56">
              {filesIpc.length === 0 ? (
                <div className="py-8 text-center text-[#8b949e] text-xs">No open descriptors inspected.</div>
              ) : (
                <table className="w-full text-left text-[11px]">
                  <thead>
                    <tr className="text-[#8b949e] border-b border-[#30363d] text-[10px]">
                      <th className="py-1">FD</th>
                      <th className="py-1">PATH / ENDPOINT</th>
                      <th className="py-1">KIND</th>
                      <th className="py-1">ACCESS</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#21262d]">
                    {filesIpc.map((f: any, idx: number) => (
                      <tr key={idx} className={f.is_deleted ? "bg-[#f85149]/10" : "hover:bg-[#21262d]/50"}>
                        <td className="py-1 font-mono text-[#8b949e]">{f.fd}</td>
                        <td className="py-1 font-mono truncate max-w-xs">
                          <span className={f.is_deleted ? "text-[#f85149] font-bold" : "text-[#c9d1d9]"}>
                            {f.path}
                          </span>
                        </td>
                        <td className="py-1 uppercase text-[10px] text-[#8b949e]">{f.kind}</td>
                        <td className="py-1">
                          <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                            f.is_deleted ? "bg-[#f85149]/20 text-[#f85149] border border-[#f85149]/40" : "bg-[#21262d] text-[#8b949e]"
                          }`}>
                            {f.access}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Real-time Findings Drawer */}
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-3 space-y-2 flex flex-col">
            <div className="flex items-center justify-between border-b border-[#30363d] pb-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e]">
                Target Findings ({findings.length})
              </span>
              <span className="text-[10px] text-[#f85149] font-bold">AUTOMATED REASONING</span>
            </div>
            <div className="space-y-2 flex-1 overflow-y-auto max-h-56">
              {findings.length === 0 ? (
                <div className="py-8 text-center text-[#8b949e] text-xs">No active security anomalies detected.</div>
              ) : (
                findings.map((finding: any) => (
                  <div
                    key={finding.id}
                    className={`p-2 rounded border text-xs space-y-1 ${
                      finding.tone === "critical"
                        ? "bg-[#f85149]/10 border-[#f85149]/30 text-[#f85149]"
                        : "bg-[#d29922]/10 border-[#d29922]/30 text-[#d29922]"
                    }`}
                  >
                    <div className="font-bold flex items-center gap-1.5">
                      <span>⚠️</span> {finding.title}
                    </div>
                    <p className="text-[11px] text-[#c9d1d9] leading-relaxed">{finding.why}</p>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* ── Bottom Action / Control Dock ──────────────────────── */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-lg px-4 py-2.5 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-[11px]">
            <span className="w-2 h-2 rounded-full bg-[#3fb950] animate-pulse" />
            <span className="font-bold text-[#f0f6fc]">LIVE</span>
            <span className="text-[#8b949e]">· SINCE OPENED NO CHANGES</span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleExportCapsule}
              className="px-3 py-1.5 rounded text-xs font-semibold bg-[#21262d] hover:bg-[#30363d] text-[#c9d1d9] border border-[#30363d] transition cursor-pointer"
            >
              📥 Export Capsule
            </button>
            <button
              onClick={() => handleAction("freeze")}
              className="px-3 py-1.5 rounded text-xs font-semibold bg-[#d29922]/20 hover:bg-[#d29922]/30 text-[#d29922] border border-[#d29922]/40 transition cursor-pointer"
            >
              ⏸ Pause (SIGSTOP)
            </button>
            <button
              onClick={() => handleAction("resume")}
              className="px-3 py-1.5 rounded text-xs font-semibold bg-[#3fb950]/20 hover:bg-[#3fb950]/30 text-[#3fb950] border border-[#3fb950]/40 transition cursor-pointer"
            >
              ▶ Resume (SIGCONT)
            </button>
            <button
              onClick={() => handleAction("terminate")}
              className="px-3 py-1.5 rounded text-xs font-semibold bg-[#f85149]/20 hover:bg-[#f85149]/30 text-[#f85149] border border-[#f85149]/40 transition cursor-pointer"
            >
              ⏹ Terminate (SIGTERM)
            </button>
            <button
              onClick={() => handleAction("kill")}
              className="px-3 py-1.5 rounded text-xs font-semibold bg-[#f85149] hover:bg-[#da3633] text-white transition cursor-pointer"
            >
              ☠ Kill (SIGKILL)
            </button>
          </div>
        </div>
      </main>
    </div>
  );
}

function int(val: any): number {
  return Math.round(Number(val) || 0);
}

export const HostXRayCockpit = HostForensicsCockpit;

