// CommandPalette — ⌘K quick-jump. One modal for navigation, actions, and run
// lookup. Arrow keys + Enter to run, Esc to close, "/" also opens it. This is
// the app's new way to move around fast — no hunting through menus.

import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getRuns } from "../lib/api";
import { clientStateSummary, resetClientState } from "../routes/resetClientState";
import { Icon, type IconName } from "./Icon";

interface Item {
  kind: "nav" | "run" | "action";
  label: string;
  hint: string;
  icon: IconName;
  to?: string;
  onRun?: () => void;
}

const NAV_ITEMS: Item[] = [
  { kind: "nav", label: "Overview", hint: "Console home & threat posture", icon: "grid", to: "/" },
  { kind: "nav", label: "Host X-Ray Command Cockpit", hint: "Deep kernel & process forensics cockpit", icon: "box", to: "/events" },
  { kind: "nav", label: "Simulation Lab", hint: "Adversary emulation & live rule testing", icon: "activity", to: "/monitor" },
  { kind: "nav", label: "Findings Queue", hint: "SOC alert triage & allowlisting", icon: "alert", to: "/findings" },
  { kind: "nav", label: "Investigations", hint: "Incident response cases & evidence locker", icon: "notes", to: "/investigations" },
  { kind: "nav", label: "Threat Campaigns", hint: "Adversary tracking & IOC graph", icon: "flag", to: "/campaigns" },
  { kind: "nav", label: "Sample Vault", hint: "Binary static/dynamic detonation analyzer", icon: "box", to: "/samples" },
  { kind: "nav", label: "ATT&CK Matrix", hint: "Enterprise tactic coverage & gap heatmap", icon: "target", to: "/coverage" },
  { kind: "nav", label: "Detection Rules", hint: "Sigma / YAML rules engine & test runner", icon: "shield", to: "/rules" },
  { kind: "nav", label: "Sensor Fleet", hint: "eBPF, Auditd & Sysmon host endpoints", icon: "terminal", to: "/agents" },
  { kind: "nav", label: "Threat Watchlist", hint: "Real-time IOC surveillance", icon: "star", to: "/watchlist" },
  { kind: "nav", label: "Forensic Search", hint: "Deep query syntax hunting", icon: "search", to: "/search" },
  { kind: "nav", label: "Audit Log", hint: "Immutable write provenance trail", icon: "notes", to: "/audit" },
  { kind: "nav", label: "Settings", hint: "Air-gap, webhooks & preferences", icon: "sliders", to: "/settings" },
];

export default function CommandPalette({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const [result, setResult] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  const { data: runs } = useQuery({ queryKey: ["palette", "runs"], queryFn: () => getRuns(), staleTime: 15_000 });

  const handleReset = useCallback(() => {
    if (
      !window.confirm(
        "Reset ALL client-side state? This clears the per-tab provenance split, the IOC search draft, and saved drafts in this browser. Continue?",
      )
    )
      return;
    const cleared = resetClientState();
    setResult(`Client-side state reset — ${clientStateSummary(cleared)}.`);
    window.setTimeout(() => setResult(null), 4000);
  }, []);

  const items = useMemo<Item[]>(() => {
    const q = query.trim().toLowerCase();
    
    // Check for direct syntax queries
    const syntaxItems: Item[] = [];
    if (q.startsWith("pid:") || /^\d+$/.test(q)) {
      const pidNum = q.replace("pid:", "").trim();
      syntaxItems.push({
        kind: "action",
        label: `Inspect PID ${pidNum} in Host X-Ray`,
        hint: `Open deep kernel dossier & device access for PID ${pidNum}`,
        icon: "process" as IconName,
        to: `/events`,
      });
    }

    if (q.startsWith(":") || (q.startsWith("port:") && q.length > 5)) {
      syntaxItems.push({
        kind: "action",
        label: `Search Network Socket Port ${q}`,
        hint: `Filter all listening and remote sockets on ${q}`,
        icon: "network" as IconName,
        to: `/events`,
      });
    }

    const base: Item[] = [
      ...syntaxItems,
      {
        kind: "action",
        label: "🌓 Toggle Theme (Dark / Light)",
        hint: "Switch between Dark tactical mode and Clean Light mode",
        icon: "sun" as IconName,
        onRun: () => {
          const cur = document.documentElement.dataset.theme === "dark" ? "dark" : "light";
          const next = cur === "dark" ? "light" : "dark";
          document.documentElement.dataset.theme = next;
          localStorage.setItem("outpost-theme-v2", next);
          if (next === "light") {
            delete document.documentElement.dataset.palette;
            localStorage.removeItem("outpost-palette");
          }
          setResult(`Theme switched to ${next.toUpperCase()} mode.`);
        },
      },
      {
        kind: "action",
        label: "⚡ Theme: Phosphor Matrix (Hacker)",
        hint: "CRT terminal obsidian & phosphor emerald glow",
        icon: "sliders" as IconName,
        onRun: () => {
          document.documentElement.dataset.theme = "matrix";
          localStorage.setItem("outpost-theme-v2", "matrix");
          setResult("Switched to Phosphor Matrix theme.");
        },
      },
      {
        kind: "action",
        label: "🌆 Theme: Cyberpunk Neon (Synthwave)",
        hint: "Night City abyss, neon rose & laser cyan",
        icon: "sliders" as IconName,
        onRun: () => {
          document.documentElement.dataset.theme = "cyberpunk";
          localStorage.setItem("outpost-theme-v2", "cyberpunk");
          setResult("Switched to Cyberpunk Neon theme.");
        },
      },
      {
        kind: "action",
        label: "🛰️ Theme: Mission Control (Aerospace)",
        hint: "Deep space navy & telemetry gold",
        icon: "sliders" as IconName,
        onRun: () => {
          document.documentElement.dataset.theme = "mission";
          localStorage.setItem("outpost-theme-v2", "mission");
          setResult("Switched to Mission Control theme.");
        },
      },
      {
        kind: "action",
        label: "🟣 Theme: Amethyst Void (Cyber)",
        hint: "Royal violet obsidian & radiant magenta",
        icon: "sliders" as IconName,
        onRun: () => {
          document.documentElement.dataset.theme = "amethyst";
          localStorage.setItem("outpost-theme-v2", "amethyst");
          setResult("Switched to Amethyst Void theme.");
        },
      },
      {
        kind: "action",
        label: "❄️ Theme: Nordic Glacier (Nord Frost)",
        hint: "Polar night & aurora cyan atmosphere",
        icon: "sliders" as IconName,
        onRun: () => {
          document.documentElement.dataset.theme = "nordic";
          localStorage.setItem("outpost-theme-v2", "nordic");
          setResult("Switched to Nordic Glacier theme.");
        },
      },
      {
        kind: "action",
        label: "🪵 Theme: Monokai Carbon (Pro Dark)",
        hint: "Warm charcoal & studio amber gold",
        icon: "sliders" as IconName,
        onRun: () => {
          document.documentElement.dataset.theme = "monokai";
          localStorage.setItem("outpost-theme-v2", "monokai");
          setResult("Switched to Monokai Carbon theme.");
        },
      },
      {
        kind: "action",
        label: "🎨 Palette: Emerald (Cyber Green)",
        hint: "High-contrast phosphor green tactical palette",
        icon: "sliders" as IconName,
        onRun: () => {
          document.documentElement.dataset.theme = "dark";
          document.documentElement.dataset.palette = "emerald";
          localStorage.setItem("outpost-theme-v2", "dark");
          localStorage.setItem("outpost-palette", "emerald");
          setResult("Applied Emerald Cyber Palette.");
        },
      },
      {
        kind: "action",
        label: "🎨 Palette: Amber (Tactical Gold)",
        hint: "Industrial gold & tactical telemetry palette",
        icon: "sliders" as IconName,
        onRun: () => {
          document.documentElement.dataset.theme = "dark";
          document.documentElement.dataset.palette = "amber";
          localStorage.setItem("outpost-theme-v2", "dark");
          localStorage.setItem("outpost-palette", "amber");
          setResult("Applied Amber Tactical Palette.");
        },
      },
      {
        kind: "action",
        label: "🎨 Palette: Amethyst (Cyber Violet)",
        hint: "Deep purple & neon violet palette",
        icon: "sliders" as IconName,
        onRun: () => {
          document.documentElement.dataset.theme = "dark";
          document.documentElement.dataset.palette = "amethyst";
          localStorage.setItem("outpost-theme-v2", "dark");
          localStorage.setItem("outpost-palette", "amethyst");
          setResult("Applied Amethyst Violet Palette.");
        },
      },
      {
        kind: "action",
        label: "⚡ Run Live Adversary Emulation",
        hint: "Trigger real-time attack simulation in the sandbox",
        icon: "activity" as IconName,
        to: "/monitor",
      },
      {
        kind: "action",
        label: "📦 Upload & Detonate Binary Sample",
        hint: "Execute suspicious file in isolated dynamic environment",
        icon: "box" as IconName,
        to: "/samples",
      },
      ...NAV_ITEMS,
      {
        kind: "action",
        label: "Reset client-side state",
        hint: "Wipe saved provenance split + search / YARA / log drafts",
        icon: "x",
        onRun: handleReset,
      },
      ...(runs ?? []).slice(0, 6).map<Item>((r) => ({
        kind: "run" as const,
        label: r.sample_name,
        hint: `run ${r.run_id.slice(0, 8)} · ${r.highest_severity ?? "clean"} · risk ${r.risk_score ?? 0}`,
        icon: "clock" as IconName,
        to: `/runs/${r.run_id}`,
      })),
    ];
    const filtered = q ? base.filter((i) => `${i.label} ${i.hint}`.toLowerCase().includes(q)) : base;
    return filtered.slice(0, 14);
  }, [query, runs, handleReset]);

  useEffect(() => {
    inputRef.current?.focus();
    setActive(0);
  }, []);

  useEffect(() => {
    setActive((a) => Math.min(a, items.length - 1));
  }, [items.length]);

  useEffect(() => {
    listRef.current
      ?.querySelector<HTMLElement>(`[data-index="${active}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [active]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const run = (item: Item) => {
    if (item.kind === "action") {
      item.onRun?.();
      return; // keep the palette open so the result banner is visible
    }
    onClose();
    if (item.to) navigate(item.to);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, items.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const item = items[active];
      if (item) run(item);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center px-4 pt-[12vh]" role="dialog" aria-modal="true" aria-label="Command palette">
      <div className="absolute inset-0 bg-black/30 backdrop-blur-sm" onClick={onClose} aria-hidden />
      <div className="animate-palette-in relative w-full max-w-xl overflow-hidden rounded-2xl border border-border-subtle bg-bg-overlay shadow-[var(--shadow-raised)]">
        <div className="flex items-center gap-3 border-b border-border-subtle px-4">
          <Icon name="command" size={15} className="text-text-faint" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            onKeyDown={onKeyDown}
            placeholder="Jump to a page, sample, or run…"
            className="h-12 w-full bg-transparent text-sm text-text-primary placeholder:text-text-faint focus:outline-none"
            aria-label="Search"
          />
          <kbd className="rounded border border-border-subtle bg-bg-elevated px-1.5 py-0.5 font-mono text-[10px] text-text-faint">esc</kbd>
        </div>

        {result && (
          <p
            role="status"
            className="border-b border-accent/20 bg-accent/5 px-4 py-2 font-mono text-[11px] text-accent"
          >
            {result}
          </p>
        )}

        <ul ref={listRef} className="max-h-80 overflow-y-auto p-1.5" role="listbox">
          {items.length === 0 && <li className="px-3 py-6 text-center text-sm text-text-faint">No matches for “{query}”.</li>}
          {items.map((item, i) => (
            <li key={`${item.kind}-${item.label}`} data-index={i} role="option" aria-selected={i === active}>
              <button
                onClick={() => run(item)}
                onMouseEnter={() => setActive(i)}
                className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left ${
                  i === active ? "bg-accent/10" : ""
                }`}
              >
                <span className={`flex h-7 w-7 items-center justify-center rounded-md border border-border-subtle ${i === active ? "border-accent/40 text-accent" : "text-text-muted"}`}>
                  <Icon name={item.icon} size={14} />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-[13px] font-medium text-text-primary">{item.label}</span>
                  <span className="block truncate text-[11px] text-text-faint">{item.hint}</span>
                </span>
                {item.kind === "run" && (
                  <span className="rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wide text-text-faint">
                    run
                  </span>
                )}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
