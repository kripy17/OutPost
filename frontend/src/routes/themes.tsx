// Theme Lab — compare dark palettes side by side before committing. Each card
// wraps the same console mock in a .palette-root with a data-palette value so
// the CSS-var tokens re-scope locally; "Use this palette" applies it to the
// whole app (documentElement + localStorage) and it survives reload.

import { useState } from "react";
import { Icon } from "../components/Icon";
import { RiskGauge, RiskSparkline, SeverityDonut } from "../components/Posture/Posture";
import { PageHeader } from "../components/ui";

const PALETTES = [
  {
    id: "",
    name: "Graphite",
    tag: "current",
    note: "Deep graphite base · violet accent · cyan signal",
  },
  {
    id: "slate",
    name: "Slate",
    tag: "cooler base",
    note: "Cool blue-gray base, same violet accent — changes the atmosphere only",
  },
  {
    id: "ocean",
    name: "Ocean",
    tag: "base + accent",
    note: "Deep navy base with a blue accent — a different hue language entirely",
  },
  {
    id: "teal",
    name: "Teal",
    tag: "accent only",
    note: "Same graphite base, teal accent + sky signal — accent drives the change",
  },
];

// The mock console every palette renders — real primitives, token-scoped.
function ConsoleMock() {
  const runs = [
    { run_id: "a", sample_name: "alpha.exe", started_at: "2026-08-01T10:00:00Z", risk_score: 100, highest_severity: "malicious" as const, alert_count: 6 },
    { run_id: "b", sample_name: "beta.sh", started_at: "2026-08-02T11:00:00Z", risk_score: 45, highest_severity: "suspicious" as const, alert_count: 3 },
    { run_id: "c", sample_name: "gamma.docm", started_at: "2026-08-03T12:00:00Z", risk_score: 82, highest_severity: "malicious" as const, alert_count: 5 },
    { run_id: "d", sample_name: "delta.bin", started_at: "2026-08-04T13:00:00Z", risk_score: 12, highest_severity: "clean" as const, alert_count: 0 },
    { run_id: "e", sample_name: "epsilon.lnk", started_at: "2026-08-05T14:00:00Z", risk_score: 63, highest_severity: "suspicious" as const, alert_count: 4 },
    { run_id: "f", sample_name: "zeta.exe", started_at: "2026-08-06T15:00:00Z", risk_score: 90, highest_severity: "malicious" as const, alert_count: 7 },
  ];
  return (
    <div>
      {/* mock top bar */}
      <div className="mb-4 flex items-center gap-2 border-b border-border-subtle pb-3">
        <span className="h-5 w-5 rounded-md bg-accent/20" aria-hidden />
        <span className="text-[13px] font-bold text-text-primary">OutPost</span>
        <span className="ml-2 rounded-md bg-accent/15 px-2 py-0.5 text-[11px] font-semibold text-accent">Overview</span>
        <span className="rounded-md px-2 py-0.5 text-[11px] text-text-muted">Live Monitor</span>
        <span className="rounded-md px-2 py-0.5 text-[11px] text-text-muted">Event Log</span>
        <span className="ml-auto flex items-center gap-1 text-[10px] text-risk-clean">
          <span className="h-1.5 w-1.5 rounded-full bg-risk-clean" /> Online
        </span>
      </div>

      {/* posture row */}
      <div className="mb-4 grid grid-cols-1 gap-3 lg:grid-cols-3">
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-4">
          <RiskGauge score={87} />
        </div>
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-4">
          <SeverityDonut malicious={12} suspicious={4} clean={6} />
        </div>
        <div className="rounded-xl border border-border-subtle bg-bg-surface p-4">
          <RiskSparkline runs={runs} />
        </div>
      </div>

      {/* findings mock */}
      <div className="rounded-xl border border-border-subtle bg-bg-surface p-3">
        <p className="kicker mb-2">Live feed</p>
        {[
          { sev: "malicious", rule: "beaconing", det: "5x C2 beacon to 203.0.113.88:4444" },
          { sev: "suspicious", rule: "lolbin-abuse", det: "powershell.exe -enc SQBFAFgAAGgBdAA=" },
          { sev: "malicious", rule: "rename-burst", det: "12 files renamed in Documents" },
        ].map((f) => (
          <div key={f.rule} className="relative mb-1.5 overflow-hidden rounded-lg border border-border-subtle bg-bg-elevated/30 py-1.5 pl-3 pr-2 last:mb-0">
            <span
              className={`absolute inset-y-0 left-0 w-1 ${f.sev === "malicious" ? "bg-risk-malicious" : "bg-risk-suspicious"}`}
              aria-hidden
            />
            <p className="font-mono text-[11px] font-semibold text-text-primary">
              {f.rule} <span className="font-normal text-text-muted">· {f.det}</span>
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function ThemesPage() {
  const [current, setCurrent] = useState(() => document.documentElement.dataset.palette ?? "");

  const apply = (id: string) => {
    document.documentElement.dataset.theme = "dark"; // palettes are dark-only
    if (id) {
      document.documentElement.dataset.palette = id;
      localStorage.setItem("outpost-palette", id);
      localStorage.setItem("outpost-theme-v2", "dark");
    } else {
      delete document.documentElement.dataset.palette;
      localStorage.removeItem("outpost-palette");
    }
    setCurrent(id);
  };

  return (
    <div className="mx-auto max-w-[1400px] px-5 py-8 lg:px-8">
      <PageHeader
        kicker="Settings · theme lab"
        title={
          <>
            Theme Lab <span className="font-normal text-text-muted">— compare dark palettes side by side</span>
          </>
        }
        lede="Every card renders the same console with real tokens, scoped per palette. Pick one and it becomes the app-wide dark theme — applied instantly and saved across reloads."
        actions={
          <span className="inline-flex items-center gap-1.5 rounded-full border border-signal/40 bg-signal/10 px-3 py-1 font-mono text-[10px] text-signal">
            <Icon name="activity" size={11} />
            {current ? `active: ${PALETTES.find((p) => p.id === current)?.name ?? current}` : "active: graphite (default)"}
          </span>
        }
      />

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
        {PALETTES.map((p) => {
          const active = current === p.id;
          return (
            <div
              key={p.id || "graphite"}
              data-palette={p.id}
              className={`palette-root flex flex-col rounded-2xl border p-4 transition-colors duration-150 ${
                active ? "border-accent/60 shadow-[var(--glow-accent)]" : "border-border-subtle"
              }`}
              style={{ background: "var(--bg-base)" }}
            >
              <div className="mb-3 flex items-center gap-2">
                <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-accent/15 text-accent">
                  <Icon name="grid" size={14} />
                </span>
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-text-primary">{p.name}</p>
                  <p className="truncate font-mono text-[10px] uppercase tracking-wide text-text-faint">{p.tag}</p>
                </div>
                {p.id === "" && (
                  <span className="rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[9px] uppercase text-text-faint">
                    default
                  </span>
                )}
                {active && (
                  <span className="ml-auto inline-flex items-center gap-1 rounded-full border border-risk-clean/40 bg-risk-clean/10 px-2 py-0.5 font-mono text-[9px] uppercase text-risk-clean">
                    <Icon name="check" size={10} />
                    active
                  </span>
                )}
              </div>
              <p className="mb-3 text-[11px] leading-relaxed text-text-muted">{p.note}</p>
              <ConsoleMock />
              <button
                onClick={() => apply(p.id)}
                disabled={active}
                className={`press mt-4 inline-flex items-center justify-center gap-1.5 rounded-lg border px-3 py-2 font-mono text-xs transition-all duration-150 ${
                  active
                    ? "cursor-default border-border-subtle text-text-faint"
                    : "border-accent/60 text-accent hover:bg-accent/10 hover:shadow-[var(--glow-accent)]"
                }`}
              >
                <Icon name={active ? "check" : "arrowRight"} size={12} />
                {active ? "Applied" : "Use this palette"}
              </button>
            </div>
          );
        })}
      </div>

      <p className="mt-6 text-center text-[11px] text-text-faint">
        Palettes apply to dark mode. The toggle in the top bar still switches dark ↔ light; light keeps its own tokens.
      </p>
    </div>
  );
}
