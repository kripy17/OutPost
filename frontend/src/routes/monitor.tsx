import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent, type DragEvent } from "react";
import { copyToClipboard } from "../lib/clipboard";
import { Link, useNavigate } from "react-router-dom";
import AlertBanner from "../components/AlertBanner/AlertBanner";
import ExportButton from "../components/ExportButton/ExportButton";
import { Icon } from "../components/Icon";
import { platformIconName } from "../components/iconMeta";
import { PageHeader } from "../components/ui";
import NetworkTable from "../components/NetworkTable/NetworkTable";
import ProcessTree from "../components/ProcessTree/ProcessTree";
import TimelineView from "../components/TimelineView/TimelineView";
import {
  BASE_URL,
  completeRun,
  createRun,
  detonateDynamic,
  getAgents,
  getHostBaseline,
  getPlatform,
  getRunDetail,
  ingestBatch,
  startLocalMonitor,
  stopLocalMonitor,
  uploadSample,
  watchHost,
} from "../lib/api";
import { enumKindsFromDetails } from "../lib/constants";
import { reconciledKinds as reconcileKinds, reconciledReconPids } from "./monitorHelpers";
import { useEventStream } from "../lib/useEventStream";
import AlertRate from "../components/AlertRate/AlertRate";
import { buildDetonationScenario, detonationSampleName } from "../lib/synthetic";
import type { Platform, SampleMeta, Severity } from "../types";

type Mode = "idle" | "live" | "detonate" | "host";

interface Toast {
  key: number;
  ruleName: string;
  severity: Severity;
  details: string;
  at: string;
}

export default function MonitorPage() {
  const navigate = useNavigate();
  const [runId, setRunId] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>("idle");
  // 'Watch a host' mode — the host whose newest session is on screen, plus
  // its behavioral baseline line (observations / anomaly count). The chosen
  // host persists (`outpost-monitor-host`) so returning to Monitor resumes
  // watching the same fleet machine.
  const [hostId, setHostId] = useState<string | null>(() => {
    try {
      return localStorage.getItem("outpost-monitor-host");
    } catch {
      return null;
    }
  });
  useEffect(() => {
    try {
      if (hostId) localStorage.setItem("outpost-monitor-host", hostId);
      else localStorage.removeItem("outpost-monitor-host");
    } catch {
      /* storage unavailable — host watch still works for this visit */
    }
  }, [hostId]);
  const [watchError, setWatchError] = useState<string | null>(null);
  const [streaming, setStreaming] = useState(false);
  const [phase, setPhase] = useState("");
  const [detonating, setDetonating] = useState(false);
  const cancelRef = useRef(false);
  const timerRef = useRef<number | null>(null);

  // Live-alert toast stream: diff each poll's alerts against what we've seen.
  const [toasts, setToasts] = useState<Toast[]>([]);
  const seenAlerts = useRef<Set<number>>(new Set());
  const toastKey = useRef(0);
  const toastTimers = useRef<number[]>([]);

  // Host OS auto-detection (vision): no manual OS picker anywhere. The
  // detected host OS drives live sessions; an uploaded sample's magic-byte
  // detection can override it per-file. macOS hosts resolve to the macos
  // scenario, but the UI never asks the operator to choose.
  const { data: host } = useQuery({ queryKey: ["platform"], queryFn: getPlatform, staleTime: Infinity });
  const hostPlatform: Platform = host?.os === "windows" ? "windows" : host?.os === "macos" ? "macos" : "linux";

  // Fleet hosts for the host picker (the 'watch a host' live mode).
  const { data: fleet } = useQuery({ queryKey: ["agents"], queryFn: () => getAgents(), staleTime: 15_000, refetchInterval: 30_000 });
  // When watching a host, its learned baseline rides along (anomaly count).
  const { data: baseline } = useQuery({
    queryKey: ["baseline", hostId],
    queryFn: () => getHostBaseline(hostId!),
    enabled: mode === "host" && hostId !== null,
    refetchInterval: 15_000,
  });

  // Uploaded sample — OS auto-detected from magic bytes (roadmap 1.4); its
  // platform drives the detonation scenario and its name is used for the run.
  const [sample, setSample] = useState<SampleMeta | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);

  // Effective target: the uploaded sample's OS if one is attached (magic
  // bytes are authoritative for that file), otherwise the detected host OS.
  const targetPlatform: Platform =
    sample && (sample.detected_platform === "windows" || sample.detected_platform === "linux" || sample.detected_platform === "macos")
      ? sample.detected_platform
      : hostPlatform;

  // Shared upload path: the file input and drag-and-drop both land here, so
  // the VT pre-check (below) and OS sniffing behave identically either way.
  const processFile = useCallback(async (file: File) => {
    setUploadError(null);
    try {
      const meta = await uploadSample(file.name, file);
      setSample(meta);
    } catch (err) {
      setSample(null);
      setUploadError(err instanceof Error ? err.message.slice(0, 220) : "Upload failed — backend reachable?");
    }
  }, []);

  const onUpload = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) void processFile(file);
  };

  const onDropFile = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) void processFile(file);
  };

  const { data, refetch } = useQuery({
    queryKey: ["run", runId],
    queryFn: () => getRunDetail(runId!),
    enabled: runId !== null,
    refetchInterval: (query) => {
      const run = query.state.data?.run;
      return run && run.completed_at === null ? 2500 : false;
    },
  });

  // Live push: a fired alert for THIS run triggers an instant refetch, so the
  // toast stream below fires immediately instead of waiting for the next poll
  // tick (2.5 s). Dedup is still the poll effect's id-based `seenAlerts` set,
  // so SSE + polling can never double-toast.
  //
  // Recon sweep: when an enumeration-burst alert arrives, its related_pids are
  // the enumerating processes — highlight them in the live process tree at
  // once, without waiting for the refetch to land. Pids are only accepted
  // while THIS run is still open (completed runs can't highlight); combined
  // with the reset in startLive/startDetonation, highlights can never leak
  // from one analysis into the next.
  const [reconPids, setReconPids] = useState<Set<number>>(new Set());
  const [reconKinds, setReconKinds] = useState<string[]>([]);
  useEventStream(
    (a) => {
      if (a.run_id !== runId) return;
      if (a.rule_id === "enumeration-burst") {
        // Belt-and-suspenders: reconciliation (below) is the source of truth
        // and already prefers the poll data for any run with alerts — this only
        // matters in the sub-second window before the post-completion refetch.
        const run = data?.run;
        if (run && run.completed_at !== null) return;
        const pids = a.related_pids;
        if (pids?.length) setReconPids((prev) => new Set([...prev, ...pids]));
        // Kind chips (CLI parity): capture the distinct enumeration commands
        // from the pushed alert's details so the badges appear the moment the
        // sweep lands, not only after the refetch resolves.
        const kinds = enumKindsFromDetails(a.details);
        if (kinds.length) setReconKinds((prev) => [...new Set([...prev, ...kinds])]);
      }
      void refetch();
    },
    undefined,
    // Run-level push: any batch that lands in THIS run (new tree nodes,
    // connections, timeline entries) refetches instantly — the 2.5 s poll
    // stays as the fallback, push makes it feel live. Completion pushes also
    // land here (a collector-timeout run ends without an alert), so the
    // streaming UI stops the moment the backend closes it.
    (r) => {
      if (r.run_id !== runId) return;
      void refetch();
    },
  );

  // Reconciliation: the run-detail poll is the source of truth for which
  // enumeration pids/kinds exist (SSE may miss an alert if the tab was
  // closed). A fresh fetch recomputes the highlight set + kind badges from
  // the alert's related_pids and details — pure derivations in
  // monitorHelpers.ts.
  const reconciledRecon = useMemo(() => reconciledReconPids(data?.alerts ?? []), [data]);
  const reconciledKinds = useMemo(() => reconcileKinds(data?.alerts ?? []), [data]);
  const effectiveKinds = reconciledKinds ?? reconKinds;
  const effectiveRecon = reconciledRecon ?? reconPids;

  useEffect(() => {
    cancelRef.current = false;
    return () => {
      cancelRef.current = true;
      if (timerRef.current !== null) window.clearTimeout(timerRef.current);
      // The toasts effect appends timers after this mount effect runs, so a
      // body-time copy would be empty and unmount would clear nothing — the
      // ref read at cleanup time is deliberate.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      const timers = toastTimers.current;
      timers.forEach((t) => window.clearTimeout(t));
    };
  }, []);

  // Toast any alert that appears for the first time since we started watching.
  useEffect(() => {
    const alerts = data?.alerts ?? [];
    const fresh = alerts.filter((a) => a.id !== null && !seenAlerts.current.has(a.id as number));
    if (fresh.length === 0) return;

    fresh.forEach((a) => {
      if (a.id !== null) seenAlerts.current.add(a.id as number);
    });
    const now = new Date();
    const incoming: Toast[] = fresh.map((a) => ({
      key: ++toastKey.current,
      ruleName: a.rule_name,
      severity: a.severity,
      details: a.details,
      at: now.toLocaleTimeString(),
    }));

    setToasts((prev) => [...prev, ...incoming].slice(-5));
    incoming.forEach((t) => {
      const timer = window.setTimeout(() => {
        setToasts((prev) => prev.filter((x) => x.key !== t.key));
      }, 6000);
      toastTimers.current.push(timer);
    });
  }, [data]);

  const streamDetonation = async (rid: string, plat: Platform) => {
    const batches = buildDetonationScenario(rid, plat);
    const total = batches.reduce((n, b) => n + b.events.length, 0);
    let sent = 0;
    for (const batch of batches) {
      if (cancelRef.current) return;
      await new Promise<void>((resolve) => {
        timerRef.current = window.setTimeout(resolve, batch.delayMs);
      });
      if (cancelRef.current) return;
      try {
        const res = await ingestBatch(batch.events);
        sent += batch.events.length;
        setPhase(res.alerts > 0 ? `${sent}/${total} events — ${res.alerts} new alert(s)` : `${sent}/${total} events`);
      } catch {
        setPhase(`ingest error at event ${sent + 1} — backend reachable?`);
        return;
      }
    }
    if (cancelRef.current) return;
    setPhase("detonation finished — closing analysis");
    try {
      await completeRun(rid);
    } catch {
      /* ignore */
    }
    setStreaming(false);
    setPhase("analysis complete");
  };

  const startLive = async () => {
    const label = `Live monitor — ${new Date().toISOString().slice(0, 19).replace("T", " ")}`;
    const { run_id } = await createRun(label, hostPlatform, "live");
    setReconPids(new Set());
    setReconKinds([]);
    setRunId(run_id);
    setMode("live");
    setPhase(`live — streaming real host processes & network events (${hostPlatform})`);
    try {
      await startLocalMonitor({ run_id });
    } catch {
      // In-process monitor fallback
    }
  };

  // Watch a fleet host: open its newest session (open live run first, else
  // its most recent) and stream it exactly like a detonation.
  const startWatch = async (hostIdToWatch: string) => {
    setWatchError(null);
    try {
      const { run_id } = await watchHost(hostIdToWatch);
      setReconPids(new Set());
      setReconKinds([]);
      setRunId(run_id);
      setHostId(hostIdToWatch);
      setMode("host");
      setPhase(`watching host ${hostIdToWatch} — its newest session`);
    } catch (e) {
      setWatchError(
        e instanceof Error && !e.message.startsWith("GET")
          ? e.message.slice(0, 160)
          : `No sessions from ${hostIdToWatch} yet — start live monitoring and run the agent on it.`,
      );
    }
  };

  const startDetonation = async () => {
    if (sample?.sample_id) {
      // Real Dynamic Subprocess Detonation
      setMode("detonate");
      setStreaming(true);
      setPhase(`dynamically executing & tracing ${sample.original_name}…`);
      try {
        const result = await detonateDynamic({ sample_id: sample.sample_id });
        if (result.run_id) {
          setRunId(result.run_id);
        }
        setPhase(`dynamic execution complete — exit code ${result.exit_code}`);
      } catch (err) {
        setPhase(`dynamic detonation error: ${err instanceof Error ? err.message : "failed"}`);
      } finally {
        setStreaming(false);
        void refetch();
      }
      return;
    }

    // Synthetic attack scenario fallback if no sample is uploaded
    const name = detonationSampleName(targetPlatform);
    const { run_id } = await createRun(name, targetPlatform, "analysis");
    setReconPids(new Set());
    setReconKinds([]);
    setRunId(run_id);
    setMode("detonate");
    setStreaming(true);
    setPhase(`starting attack simulation (${targetPlatform})…`);
    void streamDetonation(run_id, targetPlatform);
  };

  const endAnalysis = useCallback(async () => {
    if (!runId) return;
    cancelRef.current = true;
    try {
      await stopLocalMonitor();
      await completeRun(runId);
    } catch {
      /* ignore */
    }
    setStreaming(false);
    setPhase("analysis complete");
    void refetch();
  }, [runId, refetch]);


  const run = data?.run;
  const inProgress = run !== undefined && run.completed_at === null;

  // Space ends the current analysis (shortcut for the detonation workflow).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.code !== "Space") return;
      const target = e.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.tagName === "SELECT" ||
          target.isContentEditable)
      ) {
        return;
      }
      if (mode !== "idle" && runId && inProgress) {
        e.preventDefault();
        void endAnalysis();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [mode, runId, inProgress, endAnalysis]);

  const agentCmd =
    hostPlatform === "windows"
      ? `python collectors\\windows\\collector_win.py --backend-url ${BASE_URL} --mode live`
      : `python collectors/${hostPlatform}/collector_${hostPlatform}.py --backend-url ${BASE_URL} --mode live`;
  const [agentCopied, setAgentCopied] = useState(false);

  if (mode === "idle") {
    return (
      <div className="mx-auto max-w-4xl px-6 py-14 lg:px-10">
        <PageHeader
          kicker="Analyze · live"
          title={
            <>
              Live Monitor <span className="font-normal text-text-muted">& dynamic analysis</span>
            </>
          }
          lede="Start a session and watch it unfold in real time — process tree, network connections, timeline, and detection alerts as they fire. The webapp is the primary interface; the CLI mirrors the same API."
        />

        {/* Hero — watch THIS machine live. */}
        <div className="panel relative mt-8 overflow-hidden border-accent/30 bg-gradient-to-br from-accent/10 via-bg-surface/90 to-bg-surface/90 p-6 shadow-[0_8px_32px_-8px_rgba(217,164,65,0.2)]">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-accent/40 bg-accent/20 text-accent shadow-[var(--glow-accent)]">
                <Icon name="activity" size={18} />
              </span>
              <div>
                <span className="font-sans text-sm font-semibold tracking-tight text-text-primary">
                  Watch this machine live
                </span>
                <div className="mt-0.5 flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-accent/50 bg-accent/10 px-2.5 py-0.5 font-mono text-[10px] font-medium text-accent">
                    <Icon name={platformIconName(hostPlatform)} size={11} />
                    {hostPlatform === "macos" ? "macos" : hostPlatform} · auto-detected
                  </span>
                  <span className="rounded-full border border-border-subtle bg-bg-elevated/50 px-2 py-0.5 font-mono text-[10px] text-text-muted">
                    auditd / Sysmon live pipeline
                  </span>
                </div>
              </div>
            </div>
            <Link
              to="/events"
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-elevated/60 px-3 py-2 font-mono text-xs text-text-muted transition-colors hover:border-accent/60 hover:text-accent"
            >
              Event stream
              <Icon name="arrowRight" size={12} />
            </Link>
          </div>

          <p className="mt-3.5 text-xs leading-relaxed text-text-muted">
            Open a live session below to stream real host telemetry (processes, network connections, file access) in real time. Persistent install: <code className="rounded bg-bg-elevated/80 px-1.5 py-0.5 font-mono text-accent">outpost agent install</code>.
          </p>

          <div className="mt-5 flex flex-wrap items-center gap-3">
            <button
              onClick={startLive}
              disabled={hostPlatform === "macos"}
              className="press inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-accent to-accent-soft px-5 py-2.5 font-mono text-xs font-bold text-bg-base shadow-[0_0_20px_rgba(217,164,65,0.35)] transition-all duration-150 hover:scale-105 hover:shadow-[0_0_30px_rgba(217,164,65,0.5)] disabled:cursor-default disabled:opacity-50"
            >
              <Icon name="play" size={13} />
              Start live monitoring
            </button>
            <button
              onClick={() =>
                void copyToClipboard(agentCmd).then(() => {
                  setAgentCopied(true);
                  setTimeout(() => setAgentCopied(false), 1600);
                })
              }
              className="press inline-flex items-center gap-1.5 rounded-xl border border-border-subtle bg-bg-elevated/60 px-3.5 py-2.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
              title="Copy the collector command"
            >
              <Icon name={agentCopied ? "check" : "copy"} size={12} />
              {agentCopied ? "copied" : "copy agent command"}
            </button>
          </div>
          {hostPlatform === "macos" && (
            <p className="mt-2 text-[11px] text-risk-suspicious">
              Live monitoring on macOS isn't supported yet — collector runs on Linux/Windows.
            </p>
          )}
          <code className="mt-4 block overflow-x-auto rounded-xl border border-border-subtle bg-bg-elevated/60 px-3.5 py-2.5 font-mono text-[11px] text-text-primary">
            {agentCmd}
          </code>
        </div>

        <div className="mt-8 grid gap-5 sm:grid-cols-2">
          <div className="panel p-6">
            <button onClick={startDetonation} className="press group w-full text-left">
              <span className="inline-flex items-center gap-2 font-sans text-sm font-semibold text-risk-malicious">
                <Icon name="play" size={15} />
                Detonate synthetic sample
              </span>
              <p className="mt-2 text-xs leading-relaxed text-text-muted">
                Streams a realistic dropper scenario (macro → LOLBin → C2 beacon → file burst → persistence) into a
                fresh run so you can watch detection rules fire live.
              </p>
            </button>
            <div className="mt-4 flex flex-wrap items-center gap-2">
              <span className="text-[11px] font-semibold text-text-faint">Target OS</span>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-accent/50 bg-accent/10 px-2.5 py-1 font-mono text-[11px] text-accent">
                <Icon name={platformIconName(targetPlatform)} size={12} />
                {targetPlatform}
              </span>
              <span className="font-mono text-[10px] text-text-faint">
                {sample ? "from sample magic bytes" : host ? `auto-detected from host (${host.release})` : "detecting host…"}
              </span>
            </div>

            {/* Sample upload */}
            <div
              className={`mt-5 rounded-xl border border-dashed border-border-strong bg-bg-elevated/30 p-4 transition-all duration-150 ${
                dragOver ? "border-accent bg-accent/10 shadow-[var(--glow-accent)]" : "hover:border-accent/50"
              }`}
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={onDropFile}
            >
              <label className="block cursor-pointer">
                <span className="font-sans text-xs font-semibold text-text-primary">
                  Upload binary sample <span className="font-normal text-text-muted">— auto-detect OS</span>
                </span>
                <p className="mt-0.5 text-[11px] text-text-faint">Drag &amp; drop or click to choose .exe, .elf, .dll, .so, scripts</p>
                <input
                  type="file"
                  accept=".exe,.bin,.elf,.dll,.so,.dylib,.docm,.lnk,.py,.sh,.ps1,.bat,.js"
                  onChange={onUpload}
                  className="mt-2 block w-full text-xs text-text-muted file:mr-3 file:rounded-lg file:border file:border-border-subtle file:bg-bg-elevated file:px-3 file:py-1.5 file:font-mono file:text-[11px] file:text-text-primary hover:file:border-accent/60"
                />
              </label>
              {uploadError && <p className="mt-2 text-[11px] text-risk-malicious">{uploadError}</p>}
              {sample && (
                <div className="mt-2 rounded border border-border-subtle bg-bg-elevated/40 px-2.5 py-2 font-mono text-[10px]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-text-primary">{sample.original_name}</span>
                    <span
                      className={`rounded border px-1.5 py-0.5 uppercase tracking-wide ${
                        sample.detected_platform === "windows"
                          ? "border-accent/50 text-accent"
                          : sample.detected_platform === "linux"
                            ? "border-risk-clean/50 text-risk-clean"
                            : "border-text-faint text-text-muted"
                      }`}
                    >
                      {sample.detected_platform}
                    </span>
                  </div>
                  <p className="mt-1 break-all text-text-faint">{sample.sha256}</p>
                  {sample.vt_detections !== null && sample.vt_detections !== undefined && (
                    <p
                      className={`mt-1.5 flex items-center gap-1.5 ${
                        sample.vt_detections > 0 ? "text-risk-malicious" : "text-risk-clean"
                      }`}
                    >
                      <Icon name={sample.vt_detections > 0 ? "alert" : "check"} size={11} />
                      {sample.vt_detections > 0
                        ? `${sample.vt_detections} VirusTotal detection${sample.vt_detections === 1 ? "" : "s"} on this hash — known-bad intel before you spend a run on it`
                        : "VirusTotal hash pre-check: clean (0 detections)"}
                    </p>
                  )}
                  <div className="mt-3 flex items-center gap-2 border-t border-border-subtle pt-2">
                    <button
                      type="button"
                      onClick={async () => {
                        try {
                          setDetonating(true);
                          const res = await detonateDynamic({ sample_id: sample.sample_id });
                          navigate(`/runs/${res.run_id}`);
                        } catch (err: unknown) {
                          const msg = err instanceof Error ? err.message : "Dynamic detonation failed";
                          setUploadError(msg);
                        } finally {
                          setDetonating(false);
                        }
                      }}
                      disabled={detonating}
                      className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent/15 px-3 py-1.5 font-mono text-[11px] font-semibold text-accent hover:bg-accent/25 hover:shadow-[var(--glow-accent)] disabled:opacity-50"
                    >
                      <Icon name="play" size={11} />
                      {detonating ? "Detonating in sandbox..." : "Detonate in dynamic sandbox"}
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="panel p-6">
            {/* 'Watch a host' — the host-centric live view. Pick any fleet
                host; its newest session streams in with its baseline. */}
            <p className="mb-1.5 font-mono text-sm text-accent">
              <Icon name="terminal" size={14} className="mr-1.5" />
              Watch a fleet host
            </p>
            <p className="text-xs leading-relaxed text-text-muted">
              Follow a specific host's live session (process tree, network, baseline deviations) instead of the
              machine above.
            </p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <select
                value={hostId ?? ""}
                onChange={(e) => {
                  setHostId(e.target.value || null);
                  setWatchError(null);
                }}
                className="min-w-44 flex-1 rounded-lg border border-border-subtle bg-bg-surface px-3 py-2 font-mono text-xs text-text-primary transition-colors focus:border-accent/60 focus:outline-none"
                aria-label="Pick a host to watch"
              >
                <option value="">— pick a host —</option>
                {(fleet?.agents ?? [])
                  .slice()
                  .sort((a, z) => Number(z.online) - Number(a.online))
                  .map((a) => (
                    <option key={a.host_id} value={a.host_id}>
                      {a.host_id}
                      {a.silent ? " · silent" : a.online ? " · online" : " · offline"}
                    </option>
                  ))}
              </select>
              <button
                onClick={() => hostId && void startWatch(hostId)}
                disabled={!hostId}
                className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 bg-accent/10 px-3 py-2 font-mono text-xs text-accent transition-all duration-150 hover:shadow-[var(--glow-accent)] disabled:cursor-default disabled:opacity-40"
              >
                <Icon name="activity" size={12} />
                Watch
              </button>
            </div>
            {watchError && <p className="mt-2 text-[11px] text-risk-malicious">{watchError}</p>}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <nav className="mb-6 flex items-center gap-2 text-xs text-text-muted">
        <Link to="/" className="transition-colors hover:text-accent">
          Overview
        </Link>
        <span aria-hidden>/</span>
        <Link to="/history" className="transition-colors hover:text-accent">
          Session history
        </Link>
        <span aria-hidden>/</span>
        <span className="font-mono text-text-primary">{run?.sample_name ?? "…"}</span>
      </nav>

      <header className="mb-6 flex items-start justify-between gap-4">
        <div>
          <h1 className="font-mono text-xl font-semibold text-text-primary">{run?.sample_name ?? "…"}</h1>
          <p className="mt-1 font-mono text-xs text-text-muted">
            {runId ?? "…"}
            {mode === "live" && <span className="ml-2 rounded border border-border-subtle px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-accent">live</span>}
            {mode === "host" && hostId && (
              <span className="ml-2 inline-flex items-center gap-1 rounded border border-accent/50 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-accent">
                <Icon name="terminal" size={10} />
                watching {hostId}
              </span>
            )}
            {mode === "detonate" && streaming && (
              <span className="ml-2 animate-outpost-pulse inline-flex items-center gap-1 rounded border border-signal/50 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-signal shadow-[var(--glow-signal)]">
                <Icon name="activity" size={10} />
                detonating
              </span>
            )}
          </p>
          {phase && <p className="mt-2 text-xs text-text-muted">{phase}</p>}
          {/* Baseline ride-along: the watched host's learned norm + anomalies. */}
          {mode === "host" && hostId && baseline && (
            <p className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[10px] text-text-faint">
              <span>baseline {baseline.total_observations} obs · {baseline.distinct_observations} distinct</span>
              <span
                className={baseline.anomaly_count > 0 ? "text-risk-suspicious" : "text-risk-clean"}
              >
                {baseline.anomaly_count} anomal{baseline.anomaly_count === 1 ? "y" : "ies"}
              </span>
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          {inProgress && (
            <>
              <button
                onClick={() => void endAnalysis()}
                className="rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors hover:border-risk-malicious/60 hover:text-risk-malicious"
              >
                End analysis
              </button>
              <span className="hidden font-mono text-[10px] text-text-faint sm:inline" title="Press Space to end the analysis">
                Space ⏎
              </span>
            </>
          )}
          {runId && (
            <>
              <ExportButton runId={runId} label="Export JSON" />
              <Link
                to={`/runs/${runId}`}
                className="inline-flex items-center gap-1.5 rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors hover:text-accent"
              >
                Full report
                <Icon name="arrowRight" size={12} />
              </Link>
            </>
          )}
        </div>
      </header>

      <div className="mb-6">
        <AlertBanner alerts={data?.alerts ?? []} />
        {/* Live flood gauge — appears the moment the first alert lands and
            grows in real time as the SSE push / poll refetches. On run detail
            this is "how bad was it"; here it's "how fast is it coming" — the
            spike you watch build before the storm cap even trips. */}
        {data && data.alerts.length > 0 && (
          <div className="mt-6">
            <AlertRate alerts={data.alerts} />
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[3fr_2fr]">
        <section className="min-w-0 rounded-lg border border-border-subtle bg-bg-surface p-4">
          <h2 className="mb-3 flex items-center gap-2 text-xs font-semibold text-text-muted">
            Process tree
            {effectiveRecon.size > 0 && (
              <span className="inline-flex items-center gap-1 rounded-full border border-dashed border-risk-suspicious/70 px-1.5 py-0.5 font-mono text-[9px] text-risk-suspicious">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-risk-suspicious" aria-hidden />
                recon sweep — {effectiveRecon.size} process{effectiveRecon.size === 1 ? "" : "es"}
              </span>
            )}
          </h2>
          {/* Kind badges (CLI parity) — the distinct enumeration commands,
              same chips as the run-detail ReconActorsPanel. */}
          {effectiveKinds.length > 0 && (
            <p className="mb-3 flex flex-wrap gap-1.5">
              {effectiveKinds.map((k) => (
                <span
                  key={k}
                  className="rounded border border-risk-suspicious/40 bg-risk-suspicious/10 px-1.5 py-0.5 font-mono text-[9px] text-risk-suspicious"
                >
                  {k}
                </span>
              ))}
            </p>
          )}
          {data ? (
            <ProcessTree roots={data.process_tree} reconPids={effectiveRecon} />
          ) : (
            <p className="text-sm text-text-muted">Waiting for first events…</p>
          )}
        </section>

        <div className="min-w-0 space-y-6">
          <section className="rounded-lg border border-border-subtle bg-bg-surface p-4">
            <h2 className="mb-3 text-xs font-semibold text-text-muted">Network connections</h2>
            <NetworkTable connections={data?.network_connections ?? []} />
          </section>

          <section className="rounded-lg border border-border-subtle bg-bg-surface p-4">
            <h2 className="mb-3 text-xs font-semibold text-text-muted">Timeline</h2>
            <TimelineView events={data?.timeline ?? []} />
          </section>
        </div>
      </div>

      {/* Live-alert toast stream — newest findings slide in as they fire. */}
      <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2 print:hidden">
        {toasts.map((t) => (
          <div
            key={t.key}
            className={`animate-outpost-toast-in pointer-events-auto rounded-lg border bg-bg-elevated p-3 shadow-lg ${
              t.severity === "malicious" ? "border-risk-malicious/60" : "border-risk-suspicious/60"
            }`}
          >
            <div className="flex items-start justify-between gap-2">
              <p
                className={`font-mono text-xs font-semibold ${
                  t.severity === "malicious" ? "text-risk-malicious" : "text-risk-suspicious"
                }`}
              >
                {t.ruleName}
              </p>
              <button
                onClick={() => setToasts((prev) => prev.filter((x) => x.key !== t.key))}
                className="text-text-faint transition-colors hover:text-text-primary"
                aria-label="Dismiss alert"
              >
                <Icon name="x" size={12} />
              </button>
            </div>
            <p className="mt-1 text-[11px] leading-snug text-text-muted">{t.details}</p>
            <p className="mt-1 text-[10px] text-text-faint">{t.at} · {t.severity}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
