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
  { kind: "nav", label: "Overview", hint: "Console home", icon: "grid", to: "/" },
  { kind: "nav", label: "Live Monitor", hint: "Watch this machine + detonate in real time", icon: "activity", to: "/monitor" },
  { kind: "nav", label: "Event Log", hint: "System activity viewer", icon: "list", to: "/events" },
  { kind: "nav", label: "Session history", hint: "All runs + compare two samples", icon: "clock", to: "/history" },
  { kind: "nav", label: "IOC search", hint: "IP / hash / domain lookup", icon: "search", to: "/search" },
  { kind: "nav", label: "Campaigns", hint: "Clustered by shared infrastructure", icon: "flag", to: "/campaigns" },
  { kind: "nav", label: "Digital footprint", hint: "Passive infrastructure mapping", icon: "globe", to: "/footprint" },
  { kind: "nav", label: "Watchlist", hint: "Track known-bad infrastructure", icon: "star", to: "/watchlist" },
  { kind: "nav", label: "Open findings", hint: "Triage queue across every run", icon: "alert", to: "/findings" },
  { kind: "nav", label: "Detection rules", hint: "Suricata / Sigma + tuning", icon: "shield", to: "/rules" },
  { kind: "nav", label: "Settings", hint: "Notifications and behavior", icon: "sliders", to: "/settings" },
  // Tools — reachable, but not destinations
  { kind: "nav", label: "Sample vault", hint: "Uploaded binaries", icon: "box", to: "/samples" },
  { kind: "nav", label: "ATT&CK coverage", hint: "The tactic matrix we see — and the gaps", icon: "target", to: "/coverage" },
  { kind: "nav", label: "Audit log", hint: "Admin write trail", icon: "notes", to: "/audit" },
];

export default function CommandPalette({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const [result, setResult] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  const { data: runs } = useQuery({ queryKey: ["palette", "runs"], queryFn: () => getRuns(), staleTime: 15_000 });

  // The one-click client-state wipe, reachable from anywhere — same confirm
  // and report as the Settings panel. The palette stays open so the result
  // banner is visible; the message auto-clears.
  const handleReset = useCallback(() => {
    if (
      !window.confirm(
        "Reset ALL client-side state? This clears the per-tab provenance split, the IOC search draft, and the YARA / enum / log-pattern drafts saved in this browser. Continue?",
      )
    )
      return;
    const cleared = resetClientState();
    setResult(`Client-side state reset — ${clientStateSummary(cleared)}.`);
    window.setTimeout(() => setResult(null), 4000);
  }, []);

  const items = useMemo<Item[]>(() => {
    const q = query.trim().toLowerCase();
    const base: Item[] = [
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
    return filtered.slice(0, 12);
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
