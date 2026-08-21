// Design-system primitives (docs/07 + v2 deck) — one vocabulary across every
// route: Kicker, PageHeader, Panel, Chip, Stat. Built on the token classes in
// index.css (.panel, .kicker, .well) so pages stop hand-rolling surfaces.

import type { ReactNode } from "react";

/** Micro label with a leading amber tick — the instrument voice. */
export function Kicker({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <p className={`kicker ${className}`}>{children}</p>;
}

/** Standard page header: kicker + display title + lede, actions right-aligned. */
export function PageHeader({
  kicker,
  title,
  lede,
  actions,
  className = "",
}: {
  kicker: string;
  title: ReactNode;
  lede?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <header className={`mb-8 ${className}`}>
      <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-4">
        <div className="min-w-0">
          <Kicker>{kicker}</Kicker>
          <h1 className="display mt-1.5">{title}</h1>
          {lede && <p className="mt-2 max-w-2xl text-pretty text-sm leading-relaxed text-text-muted">{lede}</p>}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </div>
    </header>
  );
}

/** The elevated card — hairline border + layered shadow + glass top edge. */
export function Panel({
  title,
  kicker,
  right,
  children,
  className = "",
  bodyClassName = "",
  pad = true,
  id,
}: {
  title?: ReactNode;
  kicker?: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  pad?: boolean;
  id?: string;
}) {
  return (
    <section id={id} className={`panel ${className}`}>
      {(title || kicker || right) && (
        <header className="panel-header">
          <div className="min-w-0">
            {kicker && <Kicker className="mb-1">{kicker}</Kicker>}
            {title && <h2 className="panel-title">{title}</h2>}
          </div>
          {right && <div className="flex shrink-0 items-center gap-2">{right}</div>}
        </header>
      )}
      <div className={pad ? `p-4 ${bodyClassName}` : bodyClassName}>{children}</div>
    </section>
  );
}

/** Severity / reputation chip — dot + label, never color alone. */
export function Chip({
  tone = "muted",
  dot,
  children,
  title,
  glow = false,
  className = "",
}: {
  tone?: "clean" | "suspicious" | "malicious" | "muted" | "accent";
  dot?: boolean;
  children: ReactNode;
  title?: string;
  glow?: boolean;
  className?: string;
}) {
  const tones: Record<string, string> = {
    clean: "border-risk-clean/40 text-risk-clean",
    suspicious: "border-risk-suspicious/40 text-risk-suspicious",
    malicious: "border-risk-malicious/40 text-risk-malicious",
    accent: "border-accent/50 text-accent",
    muted: "border-border-subtle text-text-muted",
  };
  const dots: Record<string, string> = {
    clean: "bg-risk-clean",
    suspicious: "bg-risk-suspicious",
    malicious: "bg-risk-malicious",
    accent: "bg-accent",
    muted: "bg-text-faint",
  };
  // Literal classes only — Tailwind generates what appears in source, and a
  // runtime-built `shadow-[var(--glow-…)]` would never be scanned (the same
  // dynamic-class bug we fixed in ProcessTree).
  const glows: Record<string, string> = {
    clean: "shadow-[var(--glow-clean)]",
    suspicious: "shadow-[var(--glow-amber)]",
    malicious: "shadow-[var(--glow-malicious)]",
    accent: "shadow-[var(--glow-accent)]",
    muted: "",
  };
  return (
    <span
      title={title}
      className={`inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wide ${tones[tone]} ${glow ? glows[tone] : ""} ${className}`}
    >
      {dot && <span className={`h-1.5 w-1.5 rounded-full ${dots[tone]}`} aria-hidden />}
      {children}
    </span>
  );
}

/** Run provenance badge — where a run came from. Values mirror the backend's
 *  `source` column (monitor / live / cli / seed / sandbox:<provider>). */
const SOURCE_META: Record<string, { label: string; tone: "clean" | "suspicious" | "malicious" | "muted" | "accent"; title: string }> = {
  // Legacy rows from before the honest label existed (webapp synthetic runs
  // used to default to "monitor") — kept so old badges don't break.
  monitor: { label: "MON", tone: "muted", title: "Webapp Monitor session (legacy source tag)" },
  // Honest label for new webapp-synthetic detonations: generated, not host telemetry.
  "webapp-demo": { label: "DEMO", tone: "suspicious", title: "Webapp-synthetic detonation — generated, not host telemetry" },
  live: { label: "LIVE", tone: "clean", title: "Live host-collector session" },
  cli: { label: "CLI", tone: "muted", title: "Created from the outpost CLI" },
  seed: { label: "SEED", tone: "muted", title: "Seeded demo data" },
  "sandbox:demo": { label: "DEMO", tone: "suspicious", title: "Sandbox detonation · local demo (no API key)" },
  "sandbox:anyrun": { label: "ANYRUN", tone: "accent", title: "Sandbox detonation · Any.Run" },
  "sandbox:triage": { label: "TRIAGE", tone: "accent", title: "Sandbox detonation · Hatching Triage" },
  "sandbox:joe": { label: "JOE", tone: "accent", title: "Sandbox detonation · Joe Sandbox" },
};

export function SourceBadge({ source }: { source?: string }) {
  const meta = SOURCE_META[source ?? "monitor"] ?? SOURCE_META.monitor;
  return (
    <Chip tone={meta.tone} title={meta.title}>
      {meta.label}
    </Chip>
  );
}

// The synthetic provenance split — same set the History archive hides by
// default and the Findings queue's provenance filter uses (seed / webapp-demo
// / legacy monitor / sandbox:demo). Sandbox detonations (anyrun/triage/joe)
// are real external runs, so they read REAL.
const SYNTHETIC_SOURCES = new Set(["seed", "webapp-demo", "monitor", "sandbox:demo"]);

export function ProvenanceBadge({ source }: { source?: string }) {
  const synthetic = SYNTHETIC_SOURCES.has(source ?? "monitor");
  return (
    <Chip
      tone={synthetic ? "accent" : "clean"}
      title={
        synthetic
          ? "Synthetic/demo provenance — treat this run's alerts accordingly"
          : "Real host or sandbox telemetry"
      }
    >
      {synthetic ? "synthetic" : "real"}
    </Chip>
  );
}

/** Deck stat — dt/dd pair (label above a tabular value). Must sit inside a
    `<dl>` (optionally wrapped in a `<div>` per the HTML spec) so screen
    readers keep the label ↔ value pairing. */
export function Stat({
  label,
  value,
  tone = "default",
  sub,
  icon,
}: {
  label: string;
  value: ReactNode;
  tone?: "default" | "malicious" | "accent" | "clean";
  sub?: ReactNode;
  icon?: ReactNode;
}) {
  const valueTone =
    tone === "malicious" ? "text-risk-malicious" : tone === "accent" ? "text-accent" : tone === "clean" ? "text-risk-clean" : "text-text-primary";
  return (
    <>
      <dt className="flex items-center gap-1.5">
        {icon && <span className="text-text-faint" aria-hidden>
          {icon}
        </span>}
        <span className="text-[11px] font-semibold text-text-faint">{label}</span>
      </dt>
      <dd className={`mt-1 font-mono text-2xl font-semibold tabular-nums ${valueTone}`}>{value}</dd>
      {sub && <dd className="mt-0.5 text-[11px] text-text-faint">{sub}</dd>}
    </>
  );
}

/** Animated Live status pulse for real-time telemetry */
export function LivePulse({
  active = true,
  tone = "clean",
  label,
}: {
  active?: boolean;
  tone?: "clean" | "accent" | "malicious";
  label?: string;
}) {
  const tones = {
    clean: "bg-risk-clean",
    accent: "bg-accent",
    malicious: "bg-risk-malicious",
  };
  const rings = {
    clean: "border-risk-clean/40",
    accent: "border-accent/40",
    malicious: "border-risk-malicious/40",
  };

  return (
    <span className="inline-flex items-center gap-2 font-mono text-xs text-text-muted">
      <span className="relative flex h-2.5 w-2.5 items-center justify-center">
        {active && (
          <span
            className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-75 ${tones[tone]}`}
          />
        )}
        <span className={`relative inline-flex h-2 w-2 rounded-full border ${rings[tone]} ${tones[tone]}`} />
      </span>
      {label && <span>{label}</span>}
    </span>
  );
}

/** Standard tactical EmptyState container */
export function EmptyState({
  icon,
  title,
  description,
  action,
  className = "",
}: {
  icon?: ReactNode;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`flex flex-col items-center justify-center rounded-xl border border-dashed border-border-subtle bg-bg-surface/50 p-8 text-center sm:p-12 ${className}`}
    >
      {icon && <div className="mb-3 text-text-faint">{icon}</div>}
      <h3 className="font-sans text-sm font-semibold text-text-primary">{title}</h3>
      {description && (
        <p className="mt-1.5 max-w-md text-balance font-sans text-xs leading-relaxed text-text-muted">
          {description}
        </p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

/** Tactical Segmented Progress Bar */
export function ProgressBar({
  value,
  max = 100,
  tone = "accent",
  className = "",
}: {
  value: number;
  max?: number;
  tone?: "clean" | "accent" | "malicious";
  className?: string;
}) {
  const percent = Math.min(100, Math.max(0, Math.round((value / max) * 100)));
  const barColors = {
    clean: "bg-risk-clean",
    accent: "bg-accent",
    malicious: "bg-risk-malicious",
  };

  return (
    <div className={`h-1.5 w-full overflow-hidden rounded-full bg-bg-base border border-border-subtle ${className}`}>
      <div
        className={`h-full transition-all duration-300 ${barColors[tone]}`}
        style={{ width: `${percent}%` }}
      />
    </div>
  );
}

