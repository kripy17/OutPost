# UI Design System

## Direction

The subject is a live instrument panel, not a marketing dashboard: process activity and network connections flow through it constantly, and when something's wrong, it should be unmistakable at a glance. The design should feel like a forensics lab's monitoring station — clinical, dense, legible under scrutiny — not a generic admin template. Avoid the current AI-design defaults: no cream-background-serif-terracotta look, no near-black-with-one-neon-accent look, no hairline-broadsheet-newspaper look. This is a working tool an analyst stares at for hours (sometimes continuously, in live-monitoring mode), so optimize for legibility and quiet confidence over decoration.

**Signature element:** the process tree is the hero of the run-detail page — not a marketing hero, a *functional* one. It should render like a branching root system, with risk-colored halos blooming on any node that touched a flagged network connection. That single visual is what someone remembers about this tool.

## Color Tokens

```css
:root {
  /* Base */
  --bg-base: #14171C;        /* deep slate-charcoal, not pure black */
  --bg-surface: #1C2028;     /* panel/card background */
  --bg-elevated: #242933;    /* modals, dropdowns */

  /* Text */
  --text-primary: #E4E7EB;
  --text-muted: #7A8290;
  --text-faint: #4B5261;

  /* Signature accent */
  --accent-amber: #D9A441;   /* specimen-glass amber — active/in-progress state, primary CTA */

  /* Risk scale — functional, not decorative. Used consistently everywhere risk appears. */
  --risk-clean: #3FA796;      /* desaturated teal, not bootstrap green */
  --risk-suspicious: #D9A441; /* same amber as accent, intentional reuse */
  --risk-malicious: #C4453B;  /* desaturated brick red, not neon */

  /* Structure */
  --border-subtle: #2A2F3A;
}
```

Why this palette: teal/amber/brick reads as lab-instrument rather than traffic-light-generic, and reusing the amber accent for both "active" UI state and "suspicious" risk level is deliberate — it makes amber mean "pay attention" consistently across the whole app instead of being arbitrary.

## Typography

| Role | Face | Usage |
|---|---|---|
| Display/headers | IBM Plex Sans (600/700 weight) | Page titles, section headers only — used with restraint |
| Body | IBM Plex Sans (400/500 weight) | All prose, labels, UI copy |
| Data/technical | IBM Plex Mono | PIDs, IPs, hashes, command lines, timestamps — anywhere raw technical data appears |

The monospace face isn't decorative — it's functional. Command lines and IPs need to be visually distinct from prose so an analyst's eye can jump straight to the data that matters, and monospace naturally aligns columns in tables (PID columns, port numbers) in a way proportional fonts can't.

Type scale: keep it restrained — 4 sizes total (12px data/caption, 14px body, 16px UI labels/emphasis, 24px page headers). Dense data screens fail when there are too many competing sizes.

## Layout Concepts

**Run History (`/`):** A specimen log, not a card grid. Dense table rows — sample name (mono), platform icon, risk badge, timestamp (mono), process/IP counts. Rows are scannable at a glance; no unnecessary whitespace between them.

```
┌─────────────────────────────────────────────────────┐
│ sample.exe    [win]  ●malicious   14 procs  6 ips  → │
│ dropper.elf   [nix]  ●suspicious   4 procs  2 ips  → │
│ test.bin      [win]  ●clean        2 procs  0 ips  → │
└─────────────────────────────────────────────────────┘
```

**Run Detail (`/runs/:id`):** Split view. Process tree dominant on the left (the hero), network connections + timeline as tabs or a right rail.

```
┌───────────────────────┬───────────────────────┐
│                         │  Network Connections    │
│    [Process Tree]       │  ● 185.220.x.x  malicious│
│      sample.exe          │  ● 8.8.8.8      clean    │
│      ├─ cmd.exe           │                          │
│      │   └─ powershell.exe│  ─────────────────────  │
│      └─ svchost.exe        │  Timeline                │
│                         │  12:00:01 process_create │
│                         │  12:00:03 network_conn   │
└───────────────────────┴───────────────────────┘
```

Numbered step markers (01/02/03) are appropriate **only** in the timeline, since it's genuinely sequential — don't use them decoratively anywhere else (e.g. don't number the network connections table, order there isn't meaningful).

## Interaction Notes

- Process tree nodes: collapsible, default-expanded to depth 2 (deeper trees collapse by default so the initial view stays scannable)
- Reputation badges: filled dot + label (`● malicious`), never color alone — color-blind accessibility matters more here than in a typical app, since misreading a risk color has real consequences
- Loading states while a run is still in progress: show a subtle pulsing amber indicator on the run, not a generic spinner — reinforces the "still tracing" state
- Respect `prefers-reduced-motion` — this is a working tool, not a showcase; skip anything beyond functional transitions

## What to avoid

- No gradient hero banners, no marketing-style illustrations
- No decorative icons without function — every icon should communicate platform, risk, or action, nothing purely ornamental
- Don't reach for a charting library for the process tree — a well-built recursive component in your own design language will look more intentional than a generic tree-graph library's default styling
