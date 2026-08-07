import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState, type ChangeEvent } from "react";
import { Link } from "react-router-dom";
import AlertBanner from "../components/AlertBanner/AlertBanner";
import ExportButton from "../components/ExportButton/ExportButton";
import { PageHeader } from "../components/ui";
import NetworkTable from "../components/NetworkTable/NetworkTable";
import ProcessTree from "../components/ProcessTree/ProcessTree";
import TimelineView from "../components/TimelineView/TimelineView";
import { completeRun, createRun, getRunDetail, ingestBatch, uploadSample } from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import { buildDetonationScenario, detonationSampleName } from "../lib/synthetic";
import type { Platform, SampleMeta, Severity } from "../types";

type Mode = "idle" | "live" | "detonate";

interface Toast {
  key: number;
  ruleName: string;
  severity: Severity;
  details: string;
  at: string;
}

export default function MonitorPage() {
  const [runId, setRunId] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>("idle");
  const [streaming, setStreaming] = useState(false);
  const [phase, setPhase] = useState("");
  const cancelRef = useRef(false);
  const timerRef = useRef<number | null>(null);

  // Live-alert toast stream: diff each poll's alerts against what we've seen.
  const [toasts, setToasts] = useState<Toast[]>([]);
  const seenAlerts = useRef<Set<number>>(new Set());
  const toastKey = useRef(0);
  const toastTimers = useRef<number[]>([]);

  // OS selector for the synthetic detonation (roadmap 1.2) — each platform
  // streams a scenario that exercises that platform's own detection rules.
  const [platform, setPlatform] = useState<Platform>("windows");

  // Uploaded sample — OS auto-detected from magic bytes (roadmap 1.4); its
  // platform pre-fills the selector and its name is used for the run.
  const [sample, setSample] = useState<SampleMeta | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const onUpload = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadError(null);
    try {
      const meta = await uploadSample(file.name, file);
      setSample(meta);
      setPlatform(meta.detected_platform === "windows" || meta.detected_platform === "linux" ? meta.detected_platform : "linux");
    } catch (err) {
      setSample(null);
      setUploadError(err instanceof Error ? err.message.slice(0, 220) : "Upload failed — backend reachable?");
    }
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
  useEventStream((a) => {
    if (a.run_id === runId) void refetch();
  });

  useEffect(() => {
    cancelRef.current = false;
    return () => {
      cancelRef.current = true;
      if (timerRef.current !== null) window.clearTimeout(timerRef.current);
      toastTimers.current.forEach((t) => window.clearTimeout(t));
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
    const { run_id } = await createRun(label, "windows", "live");
    setRunId(run_id);
    setMode("live");
    setPhase("live — waiting for collector events");
  };

  const startDetonation = async () => {
    const name = sample?.original_name ?? detonationSampleName(platform);
    const { run_id } = await createRun(name, platform, "analysis");
    setRunId(run_id);
    setMode("detonate");
    setStreaming(true);
    setPhase("starting detonation…");
    void streamDetonation(run_id, platform);
  };

  const endAnalysis = useCallback(async () => {
    if (!runId) return;
    cancelRef.current = true;
    try {
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

        <div className="mt-10 grid gap-4 sm:grid-cols-2">
          <button
            onClick={startLive}
            className="press panel group p-6 text-left transition-all duration-150 hover:-translate-y-0.5 hover:border-accent-amber/60 hover:shadow-[var(--shadow-raised)]"
          >
            <span className="font-mono text-sm text-accent-amber">● Start live monitoring</span>
            <p className="mt-2 text-xs leading-relaxed text-text-muted">
              Opens a continuous session. Feed it events from a real collector (Sysmon / auditd) on any machine, or keep
              it open while one streams in.
            </p>
          </button>
          <div className="panel p-6">
            <button
              onClick={startDetonation}
              className="press group w-full text-left"
            >
              <span className="font-mono text-sm text-risk-malicious">▸ Detonate synthetic sample</span>
              <p className="mt-2 text-xs text-text-muted">
                Streams a realistic dropper scenario (macro → LOLBin → C2 beacon → file burst → persistence) into a
                fresh run so you can watch the detection rules fire live — no collector or VM needed.
              </p>
            </button>
            <div className="mt-4 flex items-center gap-2" role="radiogroup" aria-label="Detonation platform">
              <span className="font-mono text-[10px] uppercase tracking-wide text-text-faint">Platform</span>
              {(["windows", "linux", "macos"] as Platform[]).map((p) => (
                <button
                  key={p}
                  role="radio"
                  aria-checked={platform === p}
                  onClick={() => setPlatform(p)}
                  className={`rounded border px-2.5 py-1 font-mono text-[11px] transition-colors ${
                    platform === p
                      ? "border-accent-amber/60 text-accent-amber"
                      : "border-border-subtle text-text-muted hover:text-text-primary"
                  }`}
                >
                  {p === "windows" ? "⊞ Windows" : p === "linux" ? "⎈ Linux" : " Mac"}
                </button>
              ))}
            </div>

            {/* Sample upload — OS auto-detection (roadmap 1.4) */}
            <div className="mt-4 border-t border-border-subtle pt-3">
              <label className="block">
                <span className="font-mono text-[10px] uppercase tracking-wide text-text-faint">
                  Upload sample — auto-detect OS
                </span>
                <input
                  type="file"
                  accept=".exe,.bin,.elf,.dll,.so,.dylib,.docm,.lnk"
                  onChange={(e) => void onUpload(e)}
                  className="mt-1.5 block w-full text-xs text-text-muted file:mr-3 file:rounded file:border file:border-border-subtle file:bg-bg-elevated file:px-3 file:py-1.5 file:font-mono file:text-[11px] file:text-text-muted hover:file:border-accent-amber/60"
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
                          ? "border-accent-amber/50 text-accent-amber"
                          : sample.detected_platform === "linux"
                            ? "border-risk-clean/50 text-risk-clean"
                            : "border-text-faint text-text-muted"
                      }`}
                    >
                      {sample.detected_platform}
                    </span>
                  </div>
                  <p className="mt-1 break-all text-text-faint">{sample.sha256}</p>
                  {sample.detected_platform === "macos" && (
                    <p className="mt-1 text-risk-suspicious">macOS scenario selected — LaunchAgent + osascript rules.</p>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <nav className="mb-6 flex items-center gap-2 text-xs text-text-muted">
        <Link to="/" className="transition-colors hover:text-accent-amber">
          Overview
        </Link>
        <span aria-hidden>/</span>
        <Link to="/history" className="transition-colors hover:text-accent-amber">
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
            {mode === "live" && <span className="ml-2 rounded border border-border-subtle px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-accent-amber">live</span>}
            {mode === "detonate" && streaming && (
              <span className="ml-2 animate-outpost-pulse rounded border border-risk-malicious/50 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-risk-malicious">detonating</span>
            )}
          </p>
          {phase && <p className="mt-2 text-xs text-text-muted">{phase}</p>}
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
                className="rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors hover:text-accent-amber"
              >
                Full report →
              </Link>
            </>
          )}
        </div>
      </header>

      <div className="mb-6">
        <AlertBanner alerts={data?.alerts ?? []} />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[3fr_2fr]">
        <section className="rounded-lg border border-border-subtle bg-bg-surface p-4">
          <h2 className="mb-3 text-[10px] uppercase tracking-widest text-text-faint">Process tree</h2>
          {data ? (
            <ProcessTree roots={data.process_tree} />
          ) : (
            <p className="text-sm text-text-muted">Waiting for first events…</p>
          )}
        </section>

        <div className="space-y-6">
          <section className="rounded-lg border border-border-subtle bg-bg-surface p-4">
            <h2 className="mb-3 text-[10px] uppercase tracking-widest text-text-faint">Network connections</h2>
            <NetworkTable connections={data?.network_connections ?? []} />
          </section>

          <section className="rounded-lg border border-border-subtle bg-bg-surface p-4">
            <h2 className="mb-3 text-[10px] uppercase tracking-widest text-text-faint">Timeline</h2>
            <TimelineView events={data?.timeline ?? []} />
          </section>
        </div>
      </div>

      {/* Live-alert toast stream — newest findings slide in as they fire. */}
      <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2">
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
                ×
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
