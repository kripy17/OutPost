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
}: {
  title?: ReactNode;
  kicker?: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  pad?: boolean;
}) {
  return (
    <section className={`panel ${className}`}>
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
