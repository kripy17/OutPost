import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Icon } from "../Icon";
import { Panel } from "../ui";
import {
  getEnumPatterns,
  getLogPatterns,
  setEnumPatterns,
  setLogPatterns,
} from "../../lib/api";
import {
  clearEnumDrafts,
  clearLogDrafts,
  readEnumDrafts,
  readLogDrafts,
  writeEnumDrafts,
  writeLogDrafts,
} from "../../routes/rulesDrafts";
import type { EnumPatternRow, LogPatternKind } from "../../types";

const PLATFORM_LABELS: Record<string, string> = {
  windows: "Windows",
  linux: "Linux",
  macos: "macOS",
};

export function EnumPatternsEditor() {
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["enum-patterns"],
    queryFn: getEnumPatterns,
  });

  const [drafts, setDrafts] = useState<Record<string, EnumPatternRow[]>>(() => readEnumDrafts() ?? {});
  const [saved, setSaved] = useState(false);
  const dirty = Object.keys(drafts).length > 0;

  useEffect(() => {
    writeEnumDrafts(drafts);
  }, [drafts]);

  const save = useMutation({
    mutationFn: (platforms: Record<string, EnumPatternRow[]>) => setEnumPatterns(platforms),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["enum-patterns"] });
      setDrafts({});
      clearEnumDrafts();
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2000);
    },
  });

  if (isLoading) return <p className="mt-4 font-mono text-sm text-text-muted">Loading enumeration patterns…</p>;
  if (isError) return <p className="mt-4 font-mono text-sm text-risk-malicious">Couldn't load enumeration patterns.</p>;
  if (!data) return null;

  const platforms = Object.keys(data.platforms);
  const current = (platform: string): EnumPatternRow[] => {
    if (drafts[platform]) return drafts[platform];
    return data.platforms[platform];
  };
  const patch = (platform: string, rows: EnumPatternRow[]) => {
    setDrafts((d) => ({ ...d, [platform]: rows }));
  };

  return (
    <div className="space-y-4 font-sans">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border-subtle pb-3">
        <div>
          <p className="kicker">Discovery · T1082</p>
          <h3 className="mt-0.5 text-base font-semibold text-text-primary">Process Enumeration Patterns</h3>
          <p className="mt-1 text-xs leading-relaxed text-text-muted">
            The per-OS recon command signatures behind the enumeration-burst rule. Each row is a regex matched against a
            process command line plus its human label; a run sweeping enough <em>distinct</em> labels fires the alert.
            Edits apply to the next ingested batch — no backend restart required.
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {saved && (
            <span className="inline-flex items-center gap-1 font-mono text-[11px] text-risk-clean">
              <Icon name="check" size={11} />
              <span>Saved</span>
            </span>
          )}
          {dirty && (
            <button
              onClick={() => {
                if (!window.confirm("Discard ALL unsaved enumeration-pattern edits?")) return;
                setDrafts({});
                clearEnumDrafts();
              }}
              className="press rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-faint transition-colors duration-150 hover:border-risk-malicious/50 hover:text-risk-malicious"
              title="Throw away every unsaved recon-pattern edit (and any restored draft)"
            >
              Discard drafts
            </button>
          )}
          <button
            onClick={() =>
              save.mutate(
                Object.fromEntries(platforms.map((p) => [p, drafts[p] ?? data.platforms[p]])),
              )
            }
            disabled={!dirty || save.isPending}
            className="press rounded border border-accent/60 bg-accent/10 px-3 py-1.5 font-mono text-xs font-semibold text-accent transition-colors duration-150 hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Save all platforms
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {platforms.map((platform) => {
          const rows = current(platform);
          const defaults = data.defaults[platform];
          const isCustom = (r: EnumPatternRow) =>
            defaults.some((d) => d.pattern === r.pattern && d.label === r.label) === false;

          return (
            <Panel key={platform} title={PLATFORM_LABELS[platform] ?? platform}>
              <div className="space-y-2.5">
                {rows.map((row, i) => (
                  <div key={i} className="flex flex-col gap-1.5 rounded-lg border border-border-subtle/60 bg-bg-base/60 p-2">
                    <div className="flex items-center gap-2">
                      <input
                        value={row.pattern}
                        onChange={(e) => {
                          const next = [...rows];
                          next[i] = { ...row, pattern: e.target.value };
                          patch(platform, next);
                        }}
                        className="min-w-0 flex-1 rounded border border-border-subtle bg-bg-surface px-2 py-1 font-mono text-[11px] text-text-primary focus:border-accent/60 focus:outline-none"
                        aria-label={`${platform} pattern regex`}
                        placeholder="regex signature…"
                      />
                      <button
                        onClick={() => patch(platform, rows.filter((_, j) => j !== i))}
                        className="press rounded p-1 text-text-faint transition-colors hover:text-risk-malicious"
                        aria-label={`Remove ${platform} pattern`}
                      >
                        <Icon name="x" size={12} />
                      </button>
                    </div>
                    <div className="flex items-center justify-between gap-2">
                      <input
                        value={row.label}
                        onChange={(e) => {
                          const next = [...rows];
                          next[i] = { ...row, label: e.target.value };
                          patch(platform, next);
                        }}
                        className="flex-1 rounded border border-border-subtle bg-bg-surface px-2 py-1 font-mono text-[11px] text-text-muted focus:border-accent/60 focus:outline-none"
                        aria-label={`${platform} pattern label`}
                        placeholder="human label…"
                      />
                      {isCustom(row) && (
                        <span className="shrink-0 rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wide text-accent">
                          custom
                        </span>
                      )}
                    </div>
                  </div>
                ))}
                <div className="flex items-center justify-between pt-1">
                  <button
                    onClick={() => patch(platform, [...rows, { pattern: "", label: "" }])}
                    className="press inline-flex items-center gap-1.5 rounded border border-dashed border-border-subtle px-2.5 py-1 font-mono text-[11px] text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
                  >
                    <Icon name="plus" size={11} />
                    Add pattern
                  </button>
                  {drafts[platform] && (
                    <button
                      onClick={() => {
                        const next = { ...drafts };
                        delete next[platform];
                        setDrafts(next);
                      }}
                      className="press rounded border border-border-subtle px-2 py-1 font-mono text-[10px] text-text-faint transition-colors duration-150 hover:text-text-muted"
                    >
                      Revert {PLATFORM_LABELS[platform] ?? platform}
                    </button>
                  )}
                </div>
              </div>
            </Panel>
          );
        })}
      </div>
    </div>
  );
}

const LOG_KIND_LABELS: Record<LogPatternKind, { title: string; tactic: string; blurb: string }> = {
  service_stop: {
    title: "Logging-service stop patterns",
    tactic: "Defense Evasion · T1070.001",
    blurb: "The signatures behind log-service-stop — commands that silence the logging stack itself (auditd/rsyslog disabled, the Windows Event Log service stopped). Edits apply to the next ingested batch.",
  },
  log_clear: {
    title: "Log-purge patterns",
    tactic: "Defense Evasion · T1070.001",
    blurb: "The signatures behind log-clearing — wevtutil / Clear-EventLog, journal vacuuming, mass log deletion. Edits apply to the next ingested batch.",
  },
};

const EMPTY_LOG_DRAFTS = {} as Record<LogPatternKind, Record<string, EnumPatternRow[]>>;

export function LogPatternsEditor() {
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["log-patterns"],
    queryFn: getLogPatterns,
  });
  const [kind, setKind] = useState<LogPatternKind>("service_stop");
  const [drafts, setDrafts] = useState<Record<LogPatternKind, Record<string, EnumPatternRow[]>>>(
    () => readLogDrafts() ?? EMPTY_LOG_DRAFTS,
  );
  const [saved, setSaved] = useState(false);
  const dirty = Object.keys(drafts).length > 0;

  useEffect(() => {
    writeLogDrafts(drafts);
  }, [drafts]);

  const save = useMutation({
    mutationFn: (patterns: Record<LogPatternKind, Record<string, EnumPatternRow[]>>) => setLogPatterns(patterns),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["log-patterns"] });
      setDrafts(EMPTY_LOG_DRAFTS);
      clearLogDrafts();
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2000);
    },
  });

  if (isLoading) return <p className="mt-4 font-mono text-sm text-text-muted">Loading anti-forensics patterns…</p>;
  if (isError) return <p className="mt-4 font-mono text-sm text-risk-malicious">Couldn't load log patterns.</p>;
  if (!data) return null;

  const platforms = Object.keys(data.kinds[kind]);
  const current = (platform: string): EnumPatternRow[] => drafts[kind]?.[platform] ?? data.kinds[kind][platform];
  const patch = (platform: string, rows: EnumPatternRow[]) => {
    setDrafts((d) => ({ ...d, [kind]: { ...(d[kind] ?? {}), [platform]: rows } }));
  };
  const revertPlatform = (platform: string) => {
    setDrafts((d) => {
      const next = { ...d };
      const cur = { ...(next[kind] ?? {}) };
      delete cur[platform];
      if (Object.keys(cur).length) next[kind] = cur;
      else delete next[kind];
      return next;
    });
  };

  return (
    <div className="space-y-4 font-sans">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border-subtle pb-3">
        <div>
          <p className="kicker">{LOG_KIND_LABELS[kind].tactic}</p>
          <h3 className="mt-0.5 text-base font-semibold text-text-primary">Anti-Forensics &amp; Log Tamper Signatures</h3>
          <p className="mt-1 text-xs leading-relaxed text-text-muted">{LOG_KIND_LABELS[kind].blurb}</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {saved && (
            <span className="inline-flex items-center gap-1 font-mono text-[11px] text-risk-clean">
              <Icon name="check" size={11} />
              <span>Saved</span>
            </span>
          )}
          {dirty && (
            <button
              onClick={() => {
                if (!window.confirm("Discard ALL unsaved anti-forensics pattern edits?")) return;
                setDrafts(EMPTY_LOG_DRAFTS);
                clearLogDrafts();
              }}
              className="press rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-faint transition-colors duration-150 hover:border-risk-malicious/50 hover:text-risk-malicious"
              title="Throw away every unsaved log-pattern edit (and any restored draft)"
            >
              Discard drafts
            </button>
          )}
          <button
            onClick={() =>
              save.mutate(
                Object.fromEntries(
                  (Object.keys(data.kinds) as LogPatternKind[]).map((k) => [
                    k,
                    Object.fromEntries(
                      Object.keys(data.kinds[k]).map((p) => [p, drafts[k]?.[p] ?? data.kinds[k][p]]),
                    ),
                  ]),
                ) as Record<LogPatternKind, Record<string, EnumPatternRow[]>>,
              )
            }
            disabled={!dirty || save.isPending}
            className="press rounded border border-accent/60 bg-accent/10 px-3 py-1.5 font-mono text-xs font-semibold text-accent transition-colors duration-150 hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Save all platforms
          </button>
        </div>
      </div>

      <div className="flex items-center gap-1.5">
        {(Object.keys(LOG_KIND_LABELS) as LogPatternKind[]).map((k) => (
          <button
            key={k}
            onClick={() => setKind(k)}
            className={`rounded-lg px-3 py-1.5 font-mono text-xs uppercase tracking-wider transition ${
              kind === k ? "bg-accent/15 font-bold text-accent border border-accent/40" : "text-text-muted hover:text-text-primary border border-border-subtle"
            }`}
          >
            {LOG_KIND_LABELS[k].title}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {platforms.map((platform) => {
          const rows = current(platform);
          const defaults = data.defaults[kind][platform];
          const isCustom = (r: EnumPatternRow) =>
            defaults.some((d) => d.pattern === r.pattern && d.label === r.label) === false;

          return (
            <Panel key={platform} title={PLATFORM_LABELS[platform] ?? platform}>
              <div className="space-y-2.5">
                {rows.map((row, i) => (
                  <div key={i} className="flex flex-col gap-1.5 rounded-lg border border-border-subtle/60 bg-bg-base/60 p-2">
                    <div className="flex items-center gap-2">
                      <input
                        value={row.pattern}
                        onChange={(e) => {
                          const next = [...rows];
                          next[i] = { ...row, pattern: e.target.value };
                          patch(platform, next);
                        }}
                        className="min-w-0 flex-1 rounded border border-border-subtle bg-bg-surface px-2 py-1 font-mono text-[11px] text-text-primary focus:border-accent/60 focus:outline-none"
                        aria-label={`${platform} ${kind} pattern regex`}
                        placeholder="regex…"
                      />
                      <button
                        onClick={() => patch(platform, rows.filter((_, j) => j !== i))}
                        className="press rounded p-1 text-text-faint transition-colors hover:text-risk-malicious"
                        aria-label={`Remove ${kind} pattern ${i + 1}`}
                      >
                        <Icon name="x" size={12} />
                      </button>
                    </div>
                    <div className="flex items-center justify-between gap-2">
                      <input
                        value={row.label}
                        onChange={(e) => {
                          const next = [...rows];
                          next[i] = { ...row, label: e.target.value };
                          patch(platform, next);
                        }}
                        className="flex-1 rounded border border-border-subtle bg-bg-surface px-2 py-1 font-mono text-[11px] text-text-muted focus:border-accent/60 focus:outline-none"
                        aria-label={`${platform} ${kind} pattern label`}
                        placeholder="label…"
                      />
                      {isCustom(row) && (
                        <span className="shrink-0 rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wide text-accent">
                          custom
                        </span>
                      )}
                    </div>
                  </div>
                ))}
                <div className="flex items-center justify-between pt-1">
                  <button
                    onClick={() => patch(platform, [...rows, { pattern: "", label: "" }])}
                    className="press inline-flex items-center gap-1.5 rounded border border-dashed border-border-subtle px-2.5 py-1 font-mono text-[11px] text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
                  >
                    <Icon name="plus" size={11} />
                    Add pattern
                  </button>
                  {isCustom(rows[0] ?? { pattern: "", label: "" }) && (
                    <button
                      onClick={() => revertPlatform(platform)}
                      className="press rounded border border-border-subtle px-2 py-1 font-mono text-[10px] text-text-faint transition-colors duration-150 hover:text-text-muted"
                    >
                      Revert {PLATFORM_LABELS[platform] ?? platform}
                    </button>
                  )}
                </div>
              </div>
            </Panel>
          );
        })}
      </div>
    </div>
  );
}

export function TelemetryPatternsWorkbench() {
  const [activeSubTab, setActiveSubTab] = useState<"enum" | "log">("enum");

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 border-b border-border-subtle pb-3 font-mono text-xs">
        <button
          onClick={() => setActiveSubTab("enum")}
          className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 border transition ${
            activeSubTab === "enum"
              ? "border-cyan-500/50 bg-cyan-500/15 text-cyan-400 font-bold"
              : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="terminal" size={12} />
          <span>Process Recon &amp; Enumeration (T1082)</span>
        </button>
        <button
          onClick={() => setActiveSubTab("log")}
          className={`press inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 border transition ${
            activeSubTab === "log"
              ? "border-amber-500/50 bg-amber-500/15 text-amber-400 font-bold"
              : "border-border-subtle bg-bg-surface text-text-muted hover:text-text-primary"
          }`}
        >
          <Icon name="shield" size={12} />
          <span>Anti-Forensics &amp; Log Tamper (T1070)</span>
        </button>
      </div>

      {activeSubTab === "enum" && <EnumPatternsEditor />}
      {activeSubTab === "log" && <LogPatternsEditor />}
    </div>
  );
}
