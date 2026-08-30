import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { browserNotifyEnabled, browserPermission, setBrowserNotifyEnabled } from "../components/BrowserNotifications/notify";
import { Icon } from "../components/Icon";
import { PageHeader, Panel } from "../components/ui";
import {
  clearIntelKey,
  downloadBackup,
  getIntelFreshness,
  getIntelKeys,
  getMe,
  getNotificationSettings,
  getRateLimitStatus,
  getRetention,
  pruneRuns,
  refreshStaleIntel,
  resetStore,
  restoreBackup,
  saveBlob,
  setAuthToken,
  setIntelKey,
  setNotificationSettings,
  setPassword,
  setRetention,
  testIntelKey,
} from "../lib/api";
import { lockedIpsText, rateLimitBadge, runResetFlow } from "./settingsHelpers";
import { anyClientState, clientStateSummary, readClientState, resetClientState, type ClientStateReport } from "./resetClientState";
import { provenanceLabel, readSavedProvenance, STATUS_TABS } from "./findingsHelpers";
import AuditPage from "./audit";
import type { NotificationSettings, NotificationSettingsIn } from "../types";

const inputCls =
  "w-full rounded border border-border-subtle bg-bg-base px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none";

/* Numbered section divider — keeps the growing settings page scannable:
   each cluster gets a numbered heading so the eye can land anywhere. */
function SectionHeader({ n, title, desc }: { n: string; title: string; desc: string }) {
  return (
    <div className="mb-4 mt-2 flex items-baseline gap-3 border-b border-border-subtle pb-2">
      <span className="font-mono text-[11px] font-semibold text-accent">{n}</span>
      <div>
        <h2 className="text-[13px] font-semibold text-text-primary">{title}</h2>
        <p className="mt-0.5 text-[11px] text-text-faint">{desc}</p>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  type = "text",
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
}) {
  return (
    <label className="block">
      <span className="kicker mb-1 block">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={inputCls}
      />
    </label>
  );
}

/** Theme & palette — the former /themes Theme Lab folded into Settings.
 *  The rail footer toggles dark/light; this picks the dark accent/base
 *  palette. Applied instantly to <html data-palette> and persisted. */
import { THEME_PRESETS, THEME_PALETTES } from "../components/ThemePalettePopover";

const MONO_FONTS = [
  { id: "default", name: "IBM Plex Mono", desc: "Default SOC typography" },
  { id: "jetbrains", name: "JetBrains Mono", desc: "Developer ligatures" },
  { id: "fira", name: "Fira Code", desc: "Clean geometric" },
  { id: "cascadia", name: "Cascadia Code", desc: "Microsoft terminal" },
  { id: "source", name: "Source Code Pro", desc: "Adobe readable" },
  { id: "system", name: "System Monospace", desc: "Native OS fallback" },
];

const UI_DENSITIES = [
  { id: "compact", name: "Compact (90%)", desc: "High density for multi-monitor SOCs" },
  { id: "default", name: "Standard (100%)", desc: "Optimal balance" },
  { id: "comfortable", name: "Comfortable (110%)", desc: "Enlarged for wallboards and high-DPI" },
];

function ThemePalettePanel() {
  const [activeTheme, setActiveTheme] = useState(() => document.documentElement.dataset.theme ?? "dark");
  const [activePalette, setActivePalette] = useState(() => document.documentElement.dataset.palette ?? "");
  const [activeFont, setActiveFont] = useState(() => document.documentElement.dataset.fontMono ?? "default");
  const [activeDensity, setActiveDensity] = useState(() => document.documentElement.dataset.uiDensity ?? "default");
  const [customTitle, setCustomTitle] = useState(() => {
    try {
      return localStorage.getItem("outpost-custom-title") || "OutPost";
    } catch {
      return "OutPost";
    }
  });
  const [titleSaved, setTitleSaved] = useState(false);

  const applyTheme = (id: string) => {
    document.documentElement.dataset.theme = id;
    localStorage.setItem("outpost-theme-v2", id);
    if (id === "light") {
      delete document.documentElement.dataset.palette;
      localStorage.removeItem("outpost-palette");
      setActivePalette("");
    }
    setActiveTheme(id);
  };

  const applyPalette = (id: string) => {
    if (activeTheme === "light") {
      applyTheme("dark");
    }
    if (id) {
      document.documentElement.dataset.palette = id;
      localStorage.setItem("outpost-palette", id);
    } else {
      delete document.documentElement.dataset.palette;
      localStorage.removeItem("outpost-palette");
    }
    setActivePalette(id);
  };

  const applyFont = (id: string) => {
    if (id === "default") {
      delete document.documentElement.dataset.fontMono;
      localStorage.removeItem("outpost-font-mono");
    } else {
      document.documentElement.dataset.fontMono = id;
      localStorage.setItem("outpost-font-mono", id);
    }
    setActiveFont(id);
  };

  const applyDensity = (id: string) => {
    if (id === "default") {
      delete document.documentElement.dataset.uiDensity;
      localStorage.removeItem("outpost-ui-density");
    } else {
      document.documentElement.dataset.uiDensity = id;
      localStorage.setItem("outpost-ui-density", id);
    }
    setActiveDensity(id);
  };

  const saveCustomTitle = (newTitle: string) => {
    const trimmed = newTitle.trim() || "OutPost";
    setCustomTitle(trimmed);
    localStorage.setItem("outpost-custom-title", trimmed);
    document.title = `${trimmed} — Behavioral Security Monitor`;
    window.dispatchEvent(new CustomEvent("outpost-title-changed"));
    setTitleSaved(true);
    setTimeout(() => setTitleSaved(false), 2000);
  };

  return (
    <Panel
      kicker="Appearance & Quality of Life"
      title="Theme, Typography & Customization Studio"
      right={
        <div className="flex items-center gap-2">
          <span className="rounded bg-accent/15 px-2 py-0.5 font-mono text-[10px] font-bold text-accent uppercase">
            {THEME_PRESETS.find((t) => t.id === activeTheme)?.name ?? activeTheme}
          </span>
          {activePalette && (
            <span className="rounded bg-bg-surface border border-border-subtle px-2 py-0.5 font-mono text-[10px] text-text-faint">
              accent: {THEME_PALETTES.find((p) => p.id === activePalette)?.name ?? activePalette}
            </span>
          )}
        </div>
      }
    >
      <p className="mb-4 text-xs leading-relaxed text-text-muted">
        Customize the console title branding, color themes, monospace typography, and layout scale. Applied instantly across the interface and persisted in your browser.
      </p>

      {/* 1. Project / Deployment Branding */}
      <div className="mb-6 rounded-xl border border-border-subtle bg-bg-elevated/40 p-4">
        <span className="font-mono text-[11px] font-bold uppercase tracking-wider text-text-faint">
          Console Branding &amp; Deployment Title
        </span>
        <p className="mt-1 text-xs text-text-muted">
          Rename the console title for your SOC team, customer engagement, or threat hunting lab.
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <input
            type="text"
            value={customTitle}
            onChange={(e) => setCustomTitle(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") saveCustomTitle(customTitle);
            }}
            placeholder="e.g., Acme Defense SOC"
            className="w-72 rounded-lg border border-border-subtle bg-bg-base px-3 py-1.5 font-mono text-xs text-text-primary focus:border-accent/60 focus:outline-none"
          />
          <button
            onClick={() => saveCustomTitle(customTitle)}
            className="press rounded-lg border border-accent/60 bg-accent/10 px-3.5 py-1.5 font-mono text-xs font-semibold text-accent hover:bg-accent/20"
          >
            Apply Title
          </button>
          {customTitle !== "OutPost" && (
            <button
              onClick={() => saveCustomTitle("OutPost")}
              className="press rounded-lg border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted hover:text-text-primary"
            >
              Reset to Default
            </button>
          )}
          {titleSaved && <span className="font-mono text-xs text-risk-clean">✓ Title updated across console</span>}
        </div>
        <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
          <span className="font-mono text-[10px] text-text-faint">Presets:</span>
          {["OutPost SOC", "Red Team Operations", "Sentinel Threat Lab", "Incident Response Cockpit"].map((p) => (
            <button
              key={p}
              onClick={() => saveCustomTitle(p)}
              className="press rounded border border-border-subtle bg-bg-surface px-2 py-0.5 font-mono text-[10px] text-text-muted hover:border-accent/50 hover:text-accent"
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* 2. Theme Presets */}
      <div className="mb-6">
        <span className="font-mono text-[11px] font-bold uppercase tracking-wider text-text-faint">
          Full Theme Presets
        </span>
        <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {THEME_PRESETS.map((t) => {
            const isCurrent = activeTheme === t.id;
            return (
              <button
                key={t.id}
                onClick={() => applyTheme(t.id)}
                aria-pressed={isCurrent}
                className={`press flex flex-col justify-between rounded-xl border p-3 text-left transition-all ${
                  isCurrent
                    ? "border-accent/70 bg-accent/15 shadow-[var(--glow-accent)]"
                    : "border-border-subtle bg-bg-surface hover:border-accent/40"
                }`}
              >
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-base">{t.icon}</span>
                    <span className="rounded bg-bg-elevated px-1.5 py-0.5 font-mono text-[9px] font-semibold text-text-muted uppercase">
                      {t.badge}
                    </span>
                  </div>
                  <div className="mt-2 text-xs font-bold text-text-primary">{t.name}</div>
                  <p className="mt-0.5 text-[10px] text-text-muted">{t.desc}</p>
                </div>

                <div className="mt-3 flex items-center justify-between border-t border-border-subtle/60 pt-2">
                  <div className="flex items-center gap-1.5">
                    <span className={`h-3 w-3 rounded-full border border-border-strong ${t.bgDot}`} />
                    <span className={`h-3 w-3 rounded-full ${t.accentDot}`} />
                  </div>
                  {isCurrent && (
                    <span className="font-mono text-[9px] font-bold text-accent uppercase">
                      ✓ Active
                    </span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* 3. Accent Overrides */}
      <div className="mb-6">
        <span className="font-mono text-[11px] font-bold uppercase tracking-wider text-text-faint">
          Accent Palette Overrides
        </span>
        <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-8">
          {THEME_PALETTES.map((p) => {
            const isCurrent = activePalette === p.id;
            return (
              <button
                key={p.id || "default"}
                onClick={() => applyPalette(p.id)}
                aria-pressed={isCurrent}
                className={`press flex flex-col items-center gap-1.5 rounded-xl border p-2.5 text-center transition ${
                  isCurrent
                    ? "border-accent/70 bg-accent/15 font-bold text-accent shadow-[var(--glow-accent)]"
                    : "border-border-subtle bg-bg-surface text-text-muted hover:border-border-strong"
                }`}
              >
                <span className={`h-4 w-4 rounded-full shadow-sm ${p.dot}`} />
                <span className="text-[11px] font-medium text-text-primary truncate">{p.name}</span>
                {isCurrent && (
                  <span className="font-mono text-[8px] uppercase tracking-wider text-accent">Active</span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* 4. Typography & Monospace Engine */}
      <div className="mb-6">
        <span className="font-mono text-[11px] font-bold uppercase tracking-wider text-text-faint">
          Monospace Font Family
        </span>
        <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {MONO_FONTS.map((f) => {
            const isCurrent = activeFont === f.id;
            return (
              <button
                key={f.id}
                onClick={() => applyFont(f.id)}
                aria-pressed={isCurrent}
                className={`press flex items-center justify-between rounded-xl border p-3 text-left transition ${
                  isCurrent
                    ? "border-accent/70 bg-accent/15 font-bold text-accent shadow-sm"
                    : "border-border-subtle bg-bg-surface text-text-muted hover:border-accent/40"
                }`}
              >
                <div>
                  <div className="font-mono text-xs text-text-primary">{f.name}</div>
                  <div className="text-[10px] text-text-faint">{f.desc}</div>
                </div>
                {isCurrent && <span className="font-mono text-xs text-accent">✓</span>}
              </button>
            );
          })}
        </div>
      </div>

      {/* 5. UI Scale / Density */}
      <div>
        <span className="font-mono text-[11px] font-bold uppercase tracking-wider text-text-faint">
          Display Density &amp; UI Scale
        </span>
        <div className="mt-2 grid grid-cols-1 gap-2 sm:grid-cols-3">
          {UI_DENSITIES.map((d) => {
            const isCurrent = activeDensity === d.id;
            return (
              <button
                key={d.id}
                onClick={() => applyDensity(d.id)}
                aria-pressed={isCurrent}
                className={`press flex items-center justify-between rounded-xl border p-3 text-left transition ${
                  isCurrent
                    ? "border-accent/70 bg-accent/15 font-bold text-accent shadow-sm"
                    : "border-border-subtle bg-bg-surface text-text-muted hover:border-accent/40"
                }`}
              >
                <div>
                  <div className="text-xs font-semibold text-text-primary">{d.name}</div>
                  <div className="text-[10px] text-text-faint">{d.desc}</div>
                </div>
                {isCurrent && <span className="font-mono text-xs text-accent">✓</span>}
              </button>
            );
          })}
        </div>
      </div>
    </Panel>
  );
}

/** Read-only view of the login brute-force guard — the env-tunable knobs
 *  (AUTH_MAX_ATTEMPTS / AUTH_WINDOW_SECONDS / AUTH_LOCKOUT_SECONDS) plus the
 *  live state: how many IPs are tracked and currently locked out. Polls so
 *  an admin watching a live attack sees the lockout counter move. */
function LoginRateLimitPanel() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["auth", "ratelimit"],
    queryFn: getRateLimitStatus,
    refetchInterval: 15_000,
  });

  const knob = (label: string, env: string, value: number | undefined, unit = "") => (
    <div className="rounded-lg border border-border-subtle bg-bg-elevated/40 px-3 py-2.5">
      <p className="kicker">{label}</p>
      <p className="mt-0.5 font-mono text-lg font-semibold tabular-nums text-text-primary">
        {value ?? "…"}
        <span className="text-xs font-normal text-text-faint"> {unit}</span>
      </p>
      <p className="mt-0.5 font-mono text-[9px] text-text-faint">{env}</p>
    </div>
  );

  return (
    <Panel
      kicker="Access · security"
      title="Login brute-force guard"
      right={
        data ? (
          <span
            className={`rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${
              data.enabled ? "border-accent/50 text-accent" : "border-border-subtle text-text-faint"
            }`}
          >
            {rateLimitBadge(data.enabled)}
          </span>
        ) : null
      }
    >
      {isError && (
        <p className="text-xs text-risk-malicious">Couldn't read the guard status — is the backend running?</p>
      )}
      {isLoading && <p className="text-xs text-text-muted">Reading guard status…</p>}
      {data && (
        <div className="space-y-3">
          <p className="text-xs leading-relaxed text-text-muted">
            Failed logins are counted per IP in a sliding window; crossing the threshold locks the IP out for the
            cooldown — even a correct password is refused during it. Values come from env at server start (read-only
            here; tune in the backend's environment).
          </p>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {knob("Max attempts", "AUTH_MAX_ATTEMPTS", data.max_attempts, "per window")}
            {knob("Window", "AUTH_WINDOW_SECONDS", data.window_seconds, "s")}
            {knob("Lockout", "AUTH_LOCKOUT_SECONDS", data.lockout_seconds, "s")}
            {knob("Tracked IPs", "live", data.tracked_ips)}
          </div>
          <div className="flex items-center gap-2 rounded-lg border border-border-subtle bg-bg-elevated/40 px-3 py-2.5">
            <Icon name="shield" size={13} className={data.locked_ips > 0 ? "text-risk-malicious" : "text-risk-clean"} />
            <span className="text-xs text-text-muted">{lockedIpsText(data.locked_ips)}</span>
          </div>
          {data.locked.length > 0 && (
            <ul className="divide-y divide-border-subtle/60 rounded-lg border border-border-subtle">
              {data.locked.map((l) => (
                <li key={l.ip} className="flex items-center gap-2 px-3 py-2 font-mono text-[11px]">
                  <Icon name="x" size={11} className="text-risk-malicious" />
                  <span className="text-text-primary">{l.ip}</span>
                  <span className="ml-auto tabular-nums text-text-faint">locked for {l.remaining_seconds}s</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Panel>
  );
}

/** Retention & backup — the store can't grow forever. Set the retention
 *  window, prune old runs on demand, download a SQLite backup, or restore
 *  from one (the server keeps a safety copy of the pre-restore store). */
const SCHEDULE_LABELS: Record<string, string> = {
  off: "Off (manual only)",
  hourly: "Hourly",
  daily: "Daily",
};

function RetentionPanel() {
  const { data, isLoading } = useQuery({ queryKey: ["retention"], queryFn: getRetention });
  const queryClient = useQueryClient();
  const [days, setDays] = useState<string>("0");
  const [schedule, setSchedule] = useState<"off" | "hourly" | "daily">("off");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  // Sync the picker with the server's stored schedule once it loads.
  useEffect(() => {
    if (data) setSchedule(data.auto_prune);
  }, [data]);

  const save = async () => {
    const d = Math.max(0, Math.floor(Number(days) || 0));
    setBusy("saving");
    try {
      const fresh = await setRetention(d, schedule);
      setDays(String(fresh.retention_days));
      void queryClient.invalidateQueries({ queryKey: ["retention"] });
      setMsg({
        ok: true,
        text:
          schedule === "off"
            ? `Retention set to ${fresh.retention_days}d — applied on the next manual prune.`
            : `Retention set to ${fresh.retention_days}d — auto-pruning ${schedule} from now on.`,
      });
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Couldn't save retention." });
    } finally {
      setBusy(null);
    }
  };

  const prune = async () => {
    setBusy("prune");
    try {
      const out = await pruneRuns(days ? Math.floor(Number(days)) || undefined : undefined);
      setMsg({ ok: true, text: `Pruned ${out.deleted_runs} run(s) older than ${out.days}d (cutoff ${out.cutoff.slice(0, 19).replace("T", " ")}).` });
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Prune failed." });
    } finally {
      setBusy(null);
    }
  };

  const backup = async () => {
    setBusy("backup");
    try {
      const blob = await downloadBackup();
      saveBlob(blob, `outpost-backup-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.db`);
      setMsg({ ok: true, text: "Backup downloaded — keep it somewhere safe." });
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Backup failed." });
    } finally {
      setBusy(null);
    }
  };

  // Start fresh — the honest reset. Wipes every run that isn't THIS machine's
  // collector telemetry (seeds, webapp-synthetic detonations, sandbox demos,
  // CLI test runs) and flips demo_mode off. The store is small; a full reload
  // shows the surviving local-host data cleanly. The flow lives in
  // runResetFlow (exported) so the confirm/cancel/error branches are tested.
  const reset = () => {
    void runResetFlow({
      confirm: () =>
        window.confirm("Clear ALL demo/synthetic data? This keeps only THIS machine's real collector sessions and deletes everything else (seeds, webapp detonations, sandbox demos, test runs). Continue?"),
      resetStore: () => resetStore("demo"),
      setBusy,
      setMsg,
      reload: () => window.location.reload(),
    });
  };

  const factoryReset = async () => {
    if (!window.confirm("FACTORY RESET: Wipe ALL sessions, telemetry, alerts, investigations, and uploaded sample binaries? This resets OutPost to a 100% clean factory state.")) return;
    setBusy("reset");
    try {
      await resetStore("all", true);
      setMsg({ ok: true, text: "Database and sample vault completely wiped." });
      window.location.reload();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Factory reset failed." });
    } finally {
      setBusy(null);
    }
  };

  const onRestoreFile = async (file: File | undefined) => {
    if (!file) return;
    if (!window.confirm("Restore replaces the ENTIRE store with this backup. Continue?")) return;
    setBusy("restore");
    try {
      const out = await restoreBackup(await file.arrayBuffer());
      setMsg({ ok: true, text: `Restored from ${file.name} — safety copy saved as ${out.safety_copy}.` });
      window.location.reload();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Restore failed." });
    } finally {
      setBusy(null);
    }
  };

  return (
    <Panel
      kicker="Operations · store"
      title="Retention & backup"
      right={
        <span className="flex items-center gap-2">
          {data?.auto_prune_enabled && (
            <span className="rounded-full border border-accent/50 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide text-accent">
              auto {data.auto_prune}
            </span>
          )}
          <span className="rounded-full border border-border-subtle px-2 py-0.5 font-mono text-[10px] text-text-faint">
            {isLoading ? "…" : `${data?.retention_days ?? 0}d retention`}
          </span>
        </span>
      }
    >
      <div className="grid gap-5 lg:grid-cols-2">
        <div className="space-y-3">
          <p className="kicker">Retention</p>
          <p className="text-xs leading-relaxed text-text-muted">
            Runs older than the window are pruned with their events, alerts, notes, and allowlists — the sample vault is
            never touched. 0 keeps everything (the default). Pick a schedule to prune on an interval instead of only on
            demand.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="number"
              min={0}
              value={days}
              onChange={(e) => setDays(e.target.value)}
              className="w-24 rounded border border-border-subtle bg-bg-base px-3 py-2 font-mono text-sm text-text-primary focus:border-accent/60 focus:outline-none"
              aria-label="Retention days"
            />
            <span className="text-xs text-text-muted">days</span>
            <select
              value={schedule}
              onChange={(e) => setSchedule(e.target.value as "off" | "hourly" | "daily")}
              className="rounded border border-border-subtle bg-bg-base px-2 py-2 font-mono text-xs text-text-primary focus:border-accent/60 focus:outline-none"
              aria-label="Auto-prune schedule"
            >
              {Object.entries(SCHEDULE_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
            <button
              onClick={() => void save()}
              disabled={busy !== null}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/60 px-3 py-2 font-mono text-xs text-accent transition-colors hover:bg-accent/10 disabled:opacity-50"
            >
              <Icon name="check" size={12} />
              {busy === "saving" ? "Saving…" : "Save window"}
            </button>
            <button
              onClick={() => void prune()}
              disabled={busy !== null}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors hover:border-accent/60 hover:text-accent disabled:opacity-50"
              title="Prune runs older than retention immediately"
            >
              <Icon name="refresh" size={12} />
              {busy === "prune" ? "Pruning…" : "Prune now"}
            </button>
          </div>
          {data?.auto_prune_enabled && (
            <p className="font-mono text-[10px] text-text-faint">
              last auto-prune: {data.last_prune_at ? data.last_prune_at.slice(0, 19).replace("T", " ") + "Z" : "never"}
              {data.next_prune_in_seconds !== null &&
                ` · next in ~${Math.floor(data.next_prune_in_seconds / 3600)}h ${Math.floor((data.next_prune_in_seconds % 3600) / 60)}m`}
            </p>
          )}
        </div>
        <div className="space-y-3">
          <p className="kicker">Backup & restore</p>
          <p className="text-xs leading-relaxed text-text-muted">
            Download a consistent SQLite snapshot of the whole store, or restore from one. Restoring replaces everything
            and the pre-restore store is kept as a safety copy.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => void backup()}
              disabled={busy !== null}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors hover:border-accent/60 hover:text-accent disabled:opacity-50"
            >
              <Icon name="download" size={12} />
              {busy === "backup" ? "Backing up…" : "Download backup"}
            </button>
            <label className="press inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors hover:border-risk-malicious/50 hover:text-risk-malicious disabled:opacity-50">
              <Icon name="file" size={12} />
              {busy === "restore" ? "Restoring…" : "Restore from file"}
              <input
                type="file"
                accept=".db,application/octet-stream"
                className="hidden"
                onChange={(e) => void onRestoreFile(e.target.files?.[0])}
              />
            </label>
          </div>
        </div>
      </div>
      <div className="mt-5 rounded-lg border border-dashed border-risk-malicious/30 bg-risk-malicious/5 px-4 py-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="min-w-0 flex-1">
            <p className="kicker">Start fresh & database reset</p>
            <p className="text-xs leading-relaxed text-text-muted">
              Clear demo data to wipe simulated traces while preserving real machine telemetry, or perform a full factory reset to completely wipe all historical runs, alerts, and sample binaries.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void reset()}
              disabled={busy !== null}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-risk-malicious/50 px-3 py-2 font-mono text-xs text-risk-malicious transition-colors hover:bg-risk-malicious/10 disabled:opacity-50"
              title="Delete all demo/synthetic data (real local-host telemetry survives)"
            >
              <Icon name="x" size={12} />
              {busy === "reset" ? "Clearing…" : "Clear demo data"}
            </button>
            <button
              onClick={() => void factoryReset()}
              disabled={busy !== null}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-risk-malicious bg-risk-malicious/20 px-3 py-2 font-mono text-xs font-semibold text-risk-malicious transition-colors hover:bg-risk-malicious/30 disabled:opacity-50"
              title="Wipe ALL data (factory reset)"
            >
              <Icon name="alert" size={12} />
              Factory reset (Wipe all)
            </button>
          </div>
        </div>
      </div>
      {msg && <p className={`mt-3 text-xs ${msg.ok ? "text-accent" : "text-risk-malicious"}`}>{msg.text}</p>}
    </Panel>
  );
}

/* ── Threat-intel API keys — AbuseIPDB / VirusTotal, DB-backed with masked
   status (never a raw key in the payload), env fallback, and a per-key live
   test. Applies to the next enrichment call — no backend restart. */
const KEY_LABELS: Record<string, string> = {
  abuseipdb: "AbuseIPDB",
  virustotal: "VirusTotal",
};
const KEY_HINTS: Record<string, string> = {
  abuseipdb: "IP reputation lookups (abuseConfidenceScore per destination)",
  virustotal: "IP + file-hash reputation (malicious-vendor counts on run detail)",
};

function IntelKeysPanel() {
  const queryClient = useQueryClient();
  const { data } = useQuery({ queryKey: ["intel-keys"], queryFn: getIntelKeys });
  const { data: freshness } = useQuery({ queryKey: ["intel-freshness"], queryFn: getIntelFreshness, staleTime: 30_000 });
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [results, setResults] = useState<Record<string, { ok: boolean; detail: string }>>({});
  const [busy, setBusy] = useState<Record<string, "saving" | "testing" | undefined>>({});

  const sweep = useMutation({
    mutationFn: () => refreshStaleIntel(50),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["intel-freshness"] }),
  });

  const keys = data?.keys ?? [];
  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["intel-keys"] });

  const save = async (name: string) => {
    const value = (drafts[name] ?? "").trim();
    if (!value) return;
    setBusy((b) => ({ ...b, [name]: "saving" }));
    try {
      await setIntelKey(name, value);
      setDrafts((d) => ({ ...d, [name]: "" }));
      await invalidate();
    } catch {
      setResults((prev) => ({ ...prev, [name]: { ok: false, detail: "Couldn't store the key — backend reachable?" } }));
    }
    setBusy((b) => ({ ...b, [name]: undefined }));
  };

  const clear = async (name: string) => {
    await clearIntelKey(name);
    setResults((prev) => ({ ...prev, [name]: { ok: false, detail: "" } }));
    await invalidate();
  };

  const test = async (name: string) => {
    setBusy((b) => ({ ...b, [name]: "testing" }));
    try {
      const r = await testIntelKey(name);
      setResults((prev) => ({ ...prev, [name]: { ok: r.ok, detail: r.detail } }));
    } catch {
      setResults((prev) => ({ ...prev, [name]: { ok: false, detail: "Test failed — is the backend running?" } }));
    }
    setBusy((b) => ({ ...b, [name]: undefined }));
  };

  return (
    <Panel title="Threat-intel keys" right={<ChannelBadge active={keys.some((k) => k.set)} />}>
      <p className="text-xs leading-relaxed text-text-muted">
        AbuseIPDB and VirusTotal keys drive IP and file-hash enrichment (reputation badges on run detail and the
        hash pre-check on upload). Stored in the backend's settings table — the raw value is never shown back to the
        browser, and the env vars (<span className="font-mono">ABUSEIPDB_API_KEY</span> /{" "}
        <span className="font-mono">VIRUSTOTAL_API_KEY</span>) remain the zero-config fallback. A key applies to the
        next enrichment call — no restart.
      </p>
      <div className="mt-4 space-y-4">
        {keys.map((k) => {
          return (
            <div key={k.name} className="rounded-lg border border-border-subtle bg-bg-elevated/30 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[13px] font-semibold text-text-primary">{KEY_LABELS[k.name] ?? k.name}</span>
                <span
                  className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-[10px] ${
                    k.source === "db"
                      ? "border-risk-clean/50 bg-risk-clean/10 text-risk-clean"
                      : k.source === "env"
                        ? "border-accent/50 bg-accent/10 text-accent"
                        : "border-border-subtle bg-bg-elevated/60 text-text-faint"
                  }`}
                >
                  {k.set ? (k.source === "db" ? `configured · …${k.suffix}` : `env fallback · …${k.suffix}`) : "not configured"}
                </span>
                <span className="ml-auto font-mono text-[10px] text-text-faint">{KEY_HINTS[k.name] ?? ""}</span>
              </div>
              <div className="mt-2.5 flex flex-wrap items-center gap-2">
                <input
                  type="password"
                  value={drafts[k.name] ?? ""}
                  onChange={(e) => setDrafts((d) => ({ ...d, [k.name]: e.target.value }))}
                  placeholder={k.source === "db" ? "•••••••• (keep existing — enter a new one to replace)" : "paste key"}
                  className="w-64 rounded border border-border-subtle bg-bg-base px-2.5 py-1.5 font-mono text-xs text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
                  aria-label={`${k.name} key`}
                  autoComplete="off"
                />
                <button
                  onClick={() => void save(k.name)}
                  disabled={busy[k.name] === "saving" || !(drafts[k.name] ?? "").trim()}
                  className="press rounded border border-accent/60 bg-accent/10 px-3 py-1.5 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/15 disabled:cursor-default disabled:opacity-40"
                >
                  {busy[k.name] === "saving" ? "Saving…" : "Save"}
                </button>
                <button
                  onClick={() => void test(k.name)}
                  disabled={!k.set || busy[k.name] === "testing"}
                  className="press rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent disabled:cursor-default disabled:opacity-40"
                  title="Live probe of the effective key against the provider (costs one quota unit on free tiers)"
                >
                  {busy[k.name] === "testing" ? "Testing…" : "Test key"}
                </button>
                {k.source === "db" && (
                  <button
                    onClick={() => void clear(k.name)}
                    className="press rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-risk-malicious/50 hover:text-risk-malicious"
                    title="Remove the stored key — the env fallback (if any) becomes effective again"
                  >
                    Clear
                  </button>
                )}
              </div>
              {results[k.name]?.detail && (
                <p className={`mt-2 font-mono text-[10px] ${results[k.name]?.ok ? "text-risk-clean" : "text-risk-malicious"}`}>
                  {results[k.name]?.ok ? "✓ " : "✗ "}
                  {results[k.name]?.detail}
                </p>
              )}
              {/* Rotation hint — a stored key past 90 days is flagged so
                  credentials don't go stale unnoticed (best practice for
                  third-party API keys). */}
              {k.source === "db" && k.age_days !== null && k.age_days > 90 && (
                <p className="mt-2 inline-flex items-center gap-1.5 font-mono text-[10px] text-risk-suspicious">
                  <Icon name="alert" size={10} />
                  stored {k.age_days} days ago — consider rotating this key
                </p>
              )}
            </div>
          );
        })}

        {/* Stale-only maintenance sweep — re-query just the cache rows past
            the TTL (oldest first), leaving fresh verdicts untouched. */}
        <div className="mt-4 border-t border-border-subtle/60 pt-3">
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => sweep.mutate()}
              disabled={sweep.isPending || !freshness || freshness.stale_count === 0}
              className="press inline-flex items-center gap-1.5 rounded border border-accent/50 px-2.5 py-1 font-mono text-[11px] text-accent transition-colors hover:bg-accent/10 disabled:cursor-not-allowed disabled:opacity-40"
              title="Re-query only the cached verdicts older than the TTL (stale-only sweep) — fresh rows are left untouched"
            >
              <Icon name="refresh" size={11} className={sweep.isPending ? "animate-spin" : ""} />
              {sweep.isPending ? "Refreshing stale…" : "Refresh stale intel"}
            </button>
            {freshness && (
              <span className="font-mono text-[10px] text-text-faint">
                {freshness.stale_count} of {freshness.total} cached verdicts past the{" "}
                {freshness.oldest_age_hours !== null ? `${freshness.oldest_age_hours}h-old oldest · ` : ""}TTL
              </span>
            )}
          </div>
          {sweep.data && (
            <p className="mt-2 font-mono text-[10px] text-risk-clean">
              ✓ refreshed {sweep.data.refreshed} stale verdict{sweep.data.refreshed === 1 ? "" : "s"}
            </p>
          )}
        </div>
      </div>
    </Panel>
  );
}

function ChannelBadge({ active }: { active: boolean }) {
  return (
    <span
      className={`rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${
        active ? "border-accent/50 text-accent" : "border-border-subtle text-text-faint"
      }`}
    >
      {active ? "enabled" : "off"}
    </span>
  );
}

/** Client-side state — the per-status-tab provenance split the sweep
 *  remembers plus the IOC search / YARA / enum / log drafts. Purely
 *  client-side: a read-only chip per category shows what's saved, and one
 *  confirmed click wipes everything back to the fresh-install defaults. */
function ClientStatePanel() {
  const [state, setState] = useState<ClientStateReport>(readClientState);
  const [msg, setMsg] = useState<string | null>(null);

  const reset = () => {
    if (
      !window.confirm(
        "Reset ALL client-side state? This clears the per-tab provenance split, the IOC search draft, and the YARA / enum / log-pattern drafts saved in this browser. Continue?",
      )
    )
      return;
    const cleared = resetClientState();
    setState(readClientState());
    setMsg(`Client-side state reset — ${clientStateSummary(cleared)}.`);
    setTimeout(() => setMsg(null), 5000);
  };

  const customized = anyClientState(state);

  const draftChip = (label: string, present: boolean, detail: string) => (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono text-[10px] ${
        present ? "border-accent/50 bg-accent/10 text-accent" : "border-border-subtle bg-bg-elevated/40 text-text-faint"
      }`}
    >
      <span className="uppercase tracking-wide">{label}</span>
      <span>{detail}</span>
    </span>
  );

  return (
    <Panel
      kicker="Triage · preferences"
      title="Client-side state"
      right={
        <span
          className={`rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${
            customized ? "border-accent/50 text-accent" : "border-border-subtle text-text-faint"
          }`}
        >
          {customized ? "customized" : "defaults"}
        </span>
      }
    >
      <p className="mb-3 text-xs leading-relaxed text-text-muted">
        The Open Findings sweep remembers a provenance split per status tab ("real hosts first", "synthetic only"),
        and the search and rules pages keep in-progress drafts. All of it lives in this browser only — wipe it all in
        one confirmed click.
      </p>
      <p className="kicker mb-1.5">Queue provenance split</p>
      <div className="mb-3 flex flex-wrap items-center gap-1.5">
        {STATUS_TABS.map((t) => (
          <span
            key={t.v}
            className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono text-[10px] ${
              readSavedProvenance(t.v) ? "border-accent/50 bg-accent/10 text-accent" : "border-border-subtle bg-bg-elevated/40 text-text-faint"
            }`}
          >
            <span className="uppercase tracking-wide">{t.label}</span>
            <span>{provenanceLabel(readSavedProvenance(t.v))}</span>
          </span>
        ))}
      </div>
      <p className="kicker mb-1.5">Drafts</p>
      <div className="mb-3 flex flex-wrap items-center gap-1.5">
        {draftChip("Search", state.searchDraft, state.searchDraft ? "draft" : "—")}
        {draftChip("YARA", state.yaraDraft, state.yaraDraft ? "draft" : "—")}
        {draftChip("Enum patterns", state.enumPlatforms > 0, state.enumPlatforms ? `${state.enumPlatforms} table${state.enumPlatforms === 1 ? "" : "s"}` : "—")}
        {draftChip("Log patterns", state.logKinds > 0, state.logKinds ? `${state.logKinds} table${state.logKinds === 1 ? "" : "s"}` : "—")}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <button
          onClick={reset}
          disabled={!customized}
          className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-risk-malicious/50 hover:text-risk-malicious disabled:cursor-default disabled:opacity-40"
          title="Reset every saved preference and draft in this browser (localStorage only)"
        >
          <Icon name="x" size={12} />
          Reset client-side state
        </button>
        {msg && <p className="text-xs text-accent">{msg}</p>}
      </div>
    </Panel>
  );
}

export default function SettingsPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<"settings" | "audit">("settings");
  const { data: me } = useQuery({ queryKey: ["me"], queryFn: getMe, staleTime: 30_000 });
  const { data, isLoading, isError } = useQuery({
    queryKey: ["notifications"],
    queryFn: getNotificationSettings,
  });

  // Local draft — initialized when settings load, saved in one shot. Typed as
  // the full settings shape so read-only flags like smtp_pass_set survive edits.
  const [draft, setDraft] = useState<NotificationSettings | null>(null);
  const [saved, setSaved] = useState(false);

  const signOut = () => {
    setAuthToken(null);
    void queryClient.invalidateQueries({ queryKey: ["me"] });
  };

  const save = useMutation({
    mutationFn: (body: NotificationSettingsIn) => setNotificationSettings(body),
    onSuccess: (fresh) => {
      setDraft(fresh);
      void queryClient.invalidateQueries({ queryKey: ["notifications"] });
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    },
  });

  // Password rotation (admin only) — stored server-side as a salted PBKDF2 hash.
  const [newPass, setNewPass] = useState("");
  const [confirmPass, setConfirmPass] = useState("");
  const [pwMsg, setPwMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const rotate = useMutation({
    mutationFn: ({ role, password }: { role: "admin" | "analyst"; password: string }) =>
      setPassword(role, password),
    onSuccess: () => {
      setNewPass("");
      setConfirmPass("");
      setPwMsg({ ok: true, text: "Password stored as a salted PBKDF2 hash — use it on the login screen from now on." });
      setTimeout(() => setPwMsg(null), 4000);
    },
    onError: (e: unknown) => {
      setPwMsg({ ok: false, text: e instanceof Error ? e.message : "Couldn't change the password." });
    },
  });
  const submitPassword = () => {
    if (newPass.length < 8) {
      setPwMsg({ ok: false, text: "Password must be at least 8 characters." });
      return;
    }
    if (newPass !== confirmPass) {
      setPwMsg({ ok: false, text: "Passwords don't match." });
      return;
    }
    rotate.mutate({ role: "admin", password: newPass });
  };

  const ready = (draft ?? data) as NotificationSettings | undefined;
  const set = (patch: Partial<NotificationSettingsIn>) =>
    setDraft((d) => ({ ...(d ?? (data as NotificationSettings)), ...patch }));

  // Browser notifications (native desktop-toast equivalent) — opt-in via this
  // panel, stored client-side; the Layout-level listener does the rest.
  const [notifyPref, setNotifyPref] = useState(browserNotifyEnabled());
  const [perm, setPerm] = useState<NotificationPermission>(browserPermission());
  const toggleNotify = () => {
    const next = !notifyPref;
    setBrowserNotifyEnabled(next);
    setNotifyPref(next);
  };
  const requestPerm = async () => {
    try {
      setPerm(await Notification.requestPermission());
    } catch {
      /* non-secure context / unsupported — stays denied */
    }
  };

  const webhookActive = Boolean(ready?.webhook_url);
  const slackActive = Boolean(ready?.slack_webhook);
  const discordActive = Boolean(ready?.discord_webhook);
  const telegramActive = Boolean(ready?.telegram_bot_token && ready?.telegram_chat_id);
  const smtpActive = Boolean(ready?.smtp_host && ready?.smtp_to);

  const [testingChannel, setTestingChannel] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ channel: string; msg: string; ok: boolean } | null>(null);

  const testChannelPayload = async (channel: "webhook" | "slack" | "discord", url?: string) => {
    if (!url) {
      setTestResult({ channel, msg: "Please enter a destination URL first", ok: false });
      return;
    }
    setTestingChannel(channel);
    setTestResult(null);
    try {
      let body: any;
      if (channel === "slack") {
        body = JSON.stringify({
          text: `🚨 *[OutPost Connectivity Test]* - Verification payload sent from SOC console at ${new Date().toLocaleTimeString()}`,
        });
      } else if (channel === "discord") {
        body = JSON.stringify({
          content: `🚨 **[OutPost Connectivity Test]** - Verification payload sent at ${new Date().toLocaleTimeString()}`,
          embeds: [
            {
              title: "OutPost Channel Test",
              description: "Live connectivity test verified successfully.",
              color: 65280,
            },
          ],
        });
      } else {
        body = JSON.stringify({
          event: "connectivity_test",
          source: "OutPost SOC Settings",
          status: "verified",
          timestamp: new Date().toISOString(),
        });
      }

      await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
        mode: "no-cors",
      });
      setTestResult({ channel, msg: "Test payload dispatched successfully!", ok: true });
    } catch (e: any) {
      setTestResult({ channel, msg: `Failed: ${e?.message || "Network error"}`, ok: false });
    } finally {
      setTestingChannel(null);
    }
  };

  return (
    <div className="mx-auto max-w-3xl px-6 py-10">
      <PageHeader
        kicker="Administration · settings & governance"
        title={
          <>
            Settings &amp; Audit <span className="font-normal text-text-muted">— preferences, integrations &amp; governance</span>
          </>
        }
        lede="Tune theme styling and telemetry settings, manage threat-intel API credentials, configure alert webhooks, and inspect the tamper-evident audit log."
      />

      {/* Main Tab Switcher */}
      <div className="mb-8 flex rounded-xl border border-border-subtle bg-bg-surface p-1 font-mono text-xs shadow-sm">
        <button
          onClick={() => setActiveTab("settings")}
          className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2.5 font-medium transition ${
            activeTab === "settings"
              ? "bg-accent/15 font-bold text-accent shadow-sm"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="sliders" size={13} />
          <span>Console Settings &amp; Themes</span>
        </button>
        <button
          onClick={() => setActiveTab("audit")}
          className={`flex flex-1 items-center justify-center gap-2 rounded-lg py-2.5 font-medium transition ${
            activeTab === "audit"
              ? "bg-accent/15 font-bold text-accent shadow-sm"
              : "text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="file" size={13} />
          <span>System Audit Log</span>
        </button>
      </div>

      {activeTab === "audit" ? (
        <AuditPage />
      ) : (
        <>
      <SectionHeader n="01" title="Look & feel" desc="Theme, palette, and client-side triage preferences — the instrument-panel look." />
      <div className="mb-6">
        <ThemePalettePanel />
      </div>
      <div className="mb-8">
        <ClientStatePanel />
      </div>

      <SectionHeader n="02" title="Access & security" desc="Optional auth: one password gates the console; login rate limiting protects it." />

      {me?.enabled && (
        <div className="mb-6">
          <Panel
            kicker="Access"
            title="Session"
            right={
              <span
                className={`rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${
                  me.authenticated
                    ? me.read_only
                      ? "border-risk-suspicious/50 text-risk-suspicious"
                      : "border-accent/50 text-accent"
                    : "border-border-subtle text-text-faint"
                }`}
              >
                {me.authenticated ? (me.read_only ? "analyst · read-only" : "admin · full access") : "signed out"}
              </span>
            }
          >
            <div className="flex flex-wrap items-center gap-2">
              <Icon name="shield" size={13} className={me.authenticated ? "text-accent" : "text-text-faint"} />
              <span className="text-xs text-text-muted">
                {me.authenticated
                  ? `Signed in as ${me.read_only ? "analyst" : "admin"}${me.read_only ? " — reads allowed, mutations blocked by the API gate." : " — full read/write access."}`
                  : "This server requires a password. Sign in to continue."}
              </span>
              {me.authenticated && (
                <button
                  onClick={signOut}
                  className="press ml-auto inline-flex items-center gap-1.5 rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-risk-malicious/60 hover:text-risk-malicious"
                >
                  <Icon name="x" size={11} />
                  Sign out
                </button>
              )}
            </div>
          </Panel>
        </div>
      )}

      <div className="mb-6">
        <LoginRateLimitPanel />
      </div>

      <SectionHeader n="03" title="Store & intel" desc="Retention, backup, restore, and the threat-intel keys used for enrichment." />

      <div className="mb-6">
        <RetentionPanel />
      </div>

      <div className="mb-8">
        <IntelKeysPanel />
      </div>

      <SectionHeader n="04" title="Alert channels" desc="Where findings are routed — webhook, Slack, Discord, Telegram, email, and browser notifications." />

      {me?.enabled && me.authenticated && !me.read_only && (
        <div className="mb-6">
          <Panel
            kicker="Access · credentials"
            title="Change password"
            right={
              <span className="rounded-full border border-accent/40 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide text-accent">
                {me.credential_mode === "hash" ? "stored as salted hash" : "plaintext env (legacy)"}
              </span>
            }
          >
            <div className="flex flex-wrap items-end gap-2">
              <label className="block min-w-40 flex-1">
                <span className="kicker mb-1 block">Password</span>
                <input
                  type="password"
                  value={newPass}
                  onChange={(e) => setNewPass(e.target.value)}
                  placeholder="at least 8 characters"
                  className="w-full rounded border border-border-subtle bg-bg-base px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
                />
              </label>
              <label className="block min-w-40 flex-1">
                <span className="kicker mb-1 block">Confirm</span>
                <input
                  type="password"
                  value={confirmPass}
                  onChange={(e) => setConfirmPass(e.target.value)}
                  placeholder="repeat it"
                  className="w-full rounded border border-border-subtle bg-bg-base px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
                />
              </label>
              <button
                onClick={submitPassword}
                disabled={rotate.isPending}
                className="press rounded-lg border border-accent/60 bg-accent/10 px-4 py-2 font-mono text-xs font-medium text-accent transition-colors duration-150 hover:shadow-[var(--glow-accent)] disabled:opacity-50"
              >
                {rotate.isPending ? "Storing…" : "Set password"}
              </button>
            </div>
            <p className="mt-2 text-[11px] text-text-muted">
              One optional password for the whole console — stored server-side as a salted PBKDF2 hash, never in
              plaintext. Rotating it invalidates existing sessions.
            </p>
            {pwMsg && <p className={`mt-2 text-xs ${pwMsg.ok ? "text-accent" : "text-risk-malicious"}`}>{pwMsg.text}</p>}
          </Panel>
        </div>
      )}

      {isLoading && <p className="mt-6 text-sm text-text-muted">Loading settings…</p>}
      {isError && <p className="mt-6 text-sm text-risk-malicious">Couldn't load settings — is the backend running?</p>}

      {ready && (
        <div className="mt-6 space-y-4">
          <Panel
            title="Webhook endpoint"
            right={
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => testChannelPayload("webhook", ready.webhook_url)}
                  disabled={!ready.webhook_url || testingChannel === "webhook"}
                  className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-base px-2 py-0.5 font-mono text-[10px] text-text-muted hover:border-accent/50 hover:text-accent disabled:opacity-40"
                >
                  <Icon name={testingChannel === "webhook" ? "refresh" : "zap"} size={10} className={testingChannel === "webhook" ? "animate-spin" : ""} />
                  Test Payload
                </button>
                <ChannelBadge active={webhookActive} />
              </div>
            }
          >
            <div className="space-y-3">
              <Field
                label="Webhook URL"
                value={ready.webhook_url ?? ""}
                onChange={(v) => set({ webhook_url: v })}
                placeholder="https://hooks.example.com/outpost"
              />
              <p className="font-mono text-[10px] text-text-faint">
                Receives the raw JSON payload: {"{ event, severity, rule_id, rule_name, run_id, details, triggered_at }"} per
                alert — compatible with ntfy, your own sink, or any generic receiver.
              </p>
              {testResult?.channel === "webhook" && (
                <p className={`font-mono text-xs ${testResult.ok ? "text-risk-clean" : "text-risk-malicious"}`}>
                  {testResult.msg}
                </p>
              )}
            </div>
          </Panel>

          <Panel
            title="Slack"
            right={
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => testChannelPayload("slack", ready.slack_webhook)}
                  disabled={!ready.slack_webhook || testingChannel === "slack"}
                  className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-base px-2 py-0.5 font-mono text-[10px] text-text-muted hover:border-accent/50 hover:text-accent disabled:opacity-40"
                >
                  <Icon name={testingChannel === "slack" ? "refresh" : "zap"} size={10} className={testingChannel === "slack" ? "animate-spin" : ""} />
                  Test Payload
                </button>
                <ChannelBadge active={slackActive} />
              </div>
            }
          >
            <Field
              label="Incoming webhook URL"
              value={ready.slack_webhook ?? ""}
              onChange={(v) => set({ slack_webhook: v })}
              placeholder="https://hooks.slack.com/services/T000/B000/XXXX"
            />
            <p className="mt-2 font-mono text-[10px] text-text-faint">Posts a text message per finding.</p>
            {testResult?.channel === "slack" && (
              <p className={`mt-2 font-mono text-xs ${testResult.ok ? "text-risk-clean" : "text-risk-malicious"}`}>
                {testResult.msg}
              </p>
            )}
          </Panel>

          <Panel
            title="Discord"
            right={
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => testChannelPayload("discord", ready.discord_webhook)}
                  disabled={!ready.discord_webhook || testingChannel === "discord"}
                  className="press inline-flex items-center gap-1 rounded border border-border-subtle bg-bg-base px-2 py-0.5 font-mono text-[10px] text-text-muted hover:border-accent/50 hover:text-accent disabled:opacity-40"
                >
                  <Icon name={testingChannel === "discord" ? "refresh" : "zap"} size={10} className={testingChannel === "discord" ? "animate-spin" : ""} />
                  Test Payload
                </button>
                <ChannelBadge active={discordActive} />
              </div>
            }
          >
            <Field
              label="Webhook URL"
              value={ready.discord_webhook ?? ""}
              onChange={(v) => set({ discord_webhook: v })}
              placeholder="https://discord.com/api/webhooks/…/…"
            />
            <p className="mt-2 font-mono text-[10px] text-text-faint">Posts an embed colored by severity (red = malicious, amber = suspicious).</p>
            {testResult?.channel === "discord" && (
              <p className={`mt-2 font-mono text-xs ${testResult.ok ? "text-risk-clean" : "text-risk-malicious"}`}>
                {testResult.msg}
              </p>
            )}
          </Panel>

          <Panel
            title="Telegram"
            right={<ChannelBadge active={telegramActive} />}
          >
            <div className="grid gap-3 sm:grid-cols-2">
              <Field
                label="Bot token"
                value={ready.telegram_bot_token ?? ""}
                onChange={(v) => set({ telegram_bot_token: v })}
                placeholder="123456:ABC-DEF…"
              />
              <Field
                label="Chat ID"
                value={ready.telegram_chat_id ?? ""}
                onChange={(v) => set({ telegram_chat_id: v })}
                placeholder="-1001234567890"
              />
            </div>
            <p className="mt-2 font-mono text-[10px] text-text-faint">
              Bot must be allowed to message the chat. Create one with @BotFather.
            </p>
          </Panel>

          <Panel
            title="SMTP email"
            right={<ChannelBadge active={smtpActive} />}
          >
            <div className="grid gap-3 sm:grid-cols-2">
              <Field
                label="Host"
                value={ready.smtp_host ?? ""}
                onChange={(v) => set({ smtp_host: v })}
                placeholder="smtp.example.com"
              />
              <Field
                label="Port"
                value={String(ready.smtp_port ?? 587)}
                onChange={(v) => set({ smtp_port: v })}
                placeholder="587"
              />
              <Field label="User" value={ready.smtp_user ?? ""} onChange={(v) => set({ smtp_user: v })} />
              <Field
                label="Password"
                type="password"
                value=""
                onChange={(v) => set({ smtp_pass: v })}
                placeholder={ready.smtp_pass_set ? "•••••••• (kept)" : "password"}
              />
              <Field
                label="From"
                value={ready.smtp_from ?? ""}
                onChange={(v) => set({ smtp_from: v })}
                placeholder="outpost@example.com"
              />
              <Field
                label="To (comma-separated)"
                value={ready.smtp_to ?? ""}
                onChange={(v) => set({ smtp_to: v })}
                placeholder="soc@example.com, analyst@example.com"
              />
            </div>
            <p className="mt-2 font-mono text-[10px] text-text-faint">
              Plain-text email per finding. Port 465 uses implicit TLS; 587 upgrades with STARTTLS. Blank password keeps
              the stored one.
            </p>
          </Panel>

          <div className="flex items-center gap-3 pt-1">
            <button
              onClick={() => save.mutate((draft ?? (data as NotificationSettings)) as NotificationSettingsIn)}
              disabled={save.isPending || Boolean(me?.enabled && me.read_only)}
              className="press inline-flex items-center gap-2 rounded-lg border border-accent/60 bg-accent/10 px-5 py-2.5 font-mono text-sm font-medium text-accent transition-all duration-150 hover:shadow-[var(--glow-accent)] disabled:cursor-default disabled:opacity-50"
            >
              <Icon name={save.isPending ? "refresh" : "check"} size={13} className={save.isPending ? "animate-spin" : ""} />
              {save.isPending ? "Saving…" : "Save channels"}
            </button>
            {saved && <p className="text-xs text-accent">Saved — live from the next alert.</p>}
            {me?.enabled && me.read_only && (
              <p className="text-xs text-text-muted">Read-only analyst — changes blocked by the API gate.</p>
            )}
          </div>

          <Panel
            title="Browser notifications"
            right={<ChannelBadge active={notifyPref && perm === "granted"} />}
          >
            <p className="text-xs leading-relaxed text-text-muted">
              The webapp's desktop-toast equivalent: while this tab is unfocused, a fired suspicious or malicious
              alert raises a native browser notification (deduped per run + rule — clicking it jumps to the run).
              Purely client-side, no backend channel involved. Requires the browser's permission below.
            </p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button
                onClick={toggleNotify}
                className={`press inline-flex items-center gap-1.5 rounded-lg border px-3 py-2 font-mono text-xs transition-colors duration-150 ${
                  notifyPref
                    ? "border-accent/60 bg-accent/10 text-accent"
                    : "border-border-subtle text-text-muted hover:border-accent/60 hover:text-accent"
                }`}
              >
                <Icon name="bell" size={12} />
                {notifyPref ? "Enabled — click to disable" : "Enable browser notifications"}
              </button>
              {perm !== "granted" && (
                <button
                  onClick={() => void requestPerm()}
                  className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
                >
                  Allow notifications
                </button>
              )}
              <span className="font-mono text-[10px] text-text-faint">permission: {perm}</span>
            </div>
          </Panel>
        </div>
      )}
        </>
      )}

    </div>
  );
}
