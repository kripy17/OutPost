import React, { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Command } from "cmdk";
import {
  ShieldAlert,
  Activity,
  Server,
  FolderLock,
  Binary,
  FileCode,
  Settings as SettingsIcon,
  Search,
  Clock,
  HelpCircle,
} from "lucide-react";
import { HealthIndicator } from "./connection";
import { useKeymap } from "./keymap";
import { TOKENS } from "./tokens";

export interface NavItem {
  name: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  keyChord: string;
}

export const NAV_ITEMS: NavItem[] = [
  { name: "Alerts", href: "/alerts", icon: ShieldAlert, keyChord: "g a" },
  { name: "Events", href: "/events", icon: Activity, keyChord: "g e" },
  { name: "Hosts", href: "/hosts", icon: Server, keyChord: "g h" },
  { name: "Cases", href: "/cases", icon: FolderLock, keyChord: "g c" },
  { name: "Samples", href: "/samples", icon: Binary, keyChord: "g s" },
  { name: "Rules", href: "/rules", icon: FileCode, keyChord: "g r" },
  { name: "Settings", href: "/settings", icon: SettingsIcon, keyChord: "g ," },
];

export const Shell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [timeRange, setTimeRange] = useState("24h");

  // Global keymaps for navigation and shortcuts
  useKeymap({
    "/": () => setPaletteOpen(true),
    "meta+k": () => setPaletteOpen(true),
    "ctrl+k": () => setPaletteOpen(true),
    "?": () => setShortcutsOpen(true),
    "g a": () => navigate("/alerts"),
    "g e": () => navigate("/events"),
    "g h": () => navigate("/hosts"),
    "g c": () => navigate("/cases"),
    "g s": () => navigate("/samples"),
    "g r": () => navigate("/rules"),
    "g ,": () => navigate("/settings"),
  });

  return (
    <div className={`flex h-screen flex-col ${TOKENS.bgBase} text-[#e6edf3] font-sans antialiased select-none`}>
      {/* Top Header */}
      <header className="flex h-10 shrink-0 items-center justify-between border-b border-[#26292e] bg-[#141618] px-3">
        {/* Brand / Title & Plain Navigation */}
        <div className="flex items-center gap-4">
          <span className="font-mono text-[13px] font-semibold tracking-wider text-[#e6edf3]">
            OUTPOST
          </span>

          <nav className="flex items-center gap-1">
            {NAV_ITEMS.map((item) => {
              const isActive = location.pathname.startsWith(item.href);
              const IconComp = item.icon;
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`flex items-center gap-1.5 rounded-[4px] px-2.5 py-1 text-[12px] font-medium transition ${
                    isActive
                      ? "bg-[#1a1d20] text-[#e6edf3] border-b-2 border-[#2f81f7]"
                      : "text-[#8b949e] hover:bg-[#1a1d20]/50 hover:text-[#e6edf3]"
                  }`}
                >
                  <IconComp className="h-3.5 w-3.5" />
                  <span>{item.name}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Global Controls: Search, Time Range, Health Indicator */}
        <div className="flex items-center gap-3">
          {/* Quick search button */}
          <button
            onClick={() => setPaletteOpen(true)}
            className="flex items-center gap-2 rounded-[4px] border border-[#26292e] bg-[#0c0d0e] px-2.5 py-1 text-[11px] text-[#8b949e] hover:border-[#388bfd] hover:text-[#e6edf3]"
          >
            <Search className="h-3 w-3" />
            <span>Search or command…</span>
            <kbd className="rounded border border-[#26292e] px-1 py-0.2 font-mono text-[10px]">
              /
            </kbd>
          </button>

          {/* Single Time-Range Selector */}
          <div className="flex items-center rounded-[3px] border border-[#26292e] bg-[#0c0d0e] p-0.5 text-[11px] font-mono">
            <Clock className="mx-1 h-3 w-3 text-[#8b949e]" />
            {(["15m", "1h", "24h", "7d", "30d"] as const).map((r) => (
              <button
                key={r}
                onClick={() => setTimeRange(r)}
                className={`rounded-[2px] px-1.5 py-0.5 ${
                  timeRange === r
                    ? "bg-[#2f81f7] text-white"
                    : "text-[#8b949e] hover:text-[#e6edf3]"
                }`}
              >
                {r}
              </button>
            ))}
          </div>

          {/* Single Health Indicator */}
          <HealthIndicator />

          {/* Help modal trigger */}
          <button
            onClick={() => setShortcutsOpen(true)}
            className="text-[#8b949e] hover:text-[#e6edf3]"
            title="Keyboard shortcuts (?)"
          >
            <HelpCircle className="h-4 w-4" />
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 min-h-0 overflow-hidden">{children}</main>

      {/* Command Palette Modal (cmdk) */}
      {paletteOpen && (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 pt-20">
          <div className="w-full max-w-lg rounded-[6px] border border-[#26292e] bg-[#141618] p-2 shadow-2xl">
            <Command
              className="w-full"
              onKeyDown={(e) => {
                if (e.key === "Escape") setPaletteOpen(false);
              }}
            >
              <div className="flex items-center border-b border-[#26292e] px-2 pb-2">
                <Search className="mr-2 h-4 w-4 text-[#8b949e]" />
                <Command.Input
                  placeholder="Type a command or jump to page…"
                  className="w-full bg-transparent text-[13px] text-[#e6edf3] outline-none"
                  autoFocus
                />
              </div>
              <Command.List className="max-h-64 overflow-auto p-1 text-[12px]">
                <Command.Empty className="p-3 text-center text-[#8b949e]">
                  No matching commands
                </Command.Empty>
                <Command.Group heading="Navigation" className="text-[11px] text-[#8b949e] px-1 py-1">
                  {NAV_ITEMS.map((item) => (
                    <Command.Item
                      key={item.href}
                      onSelect={() => {
                        navigate(item.href);
                        setPaletteOpen(false);
                      }}
                      className="flex cursor-pointer items-center justify-between rounded-[3px] px-2 py-1.5 text-[#e6edf3] hover:bg-[#2f81f7] hover:text-white"
                    >
                      <div className="flex items-center gap-2">
                        <item.icon className="h-3.5 w-3.5" />
                        <span>{item.name}</span>
                      </div>
                      <span className="font-mono text-[10px] text-[#8b949e]">{item.keyChord}</span>
                    </Command.Item>
                  ))}
                </Command.Group>
              </Command.List>
            </Command>
          </div>
        </div>
      )}

      {/* Shortcuts Sheet */}
      {shortcutsOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
          onClick={() => setShortcutsOpen(false)}
        >
          <div
            className="w-full max-w-sm rounded-[6px] border border-[#26292e] bg-[#141618] p-4 text-[12px]"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="font-medium text-[#e6edf3] mb-3">Keyboard Shortcuts</h3>
            <div className="space-y-1.5 text-[#8b949e]">
              <div className="flex justify-between"><span>Next / Prev row</span><kbd className="font-mono text-[#e6edf3]">j / k</kbd></div>
              <div className="flex justify-between"><span>Open detail</span><kbd className="font-mono text-[#e6edf3]">Enter</kbd></div>
              <div className="flex justify-between"><span>Select row</span><kbd className="font-mono text-[#e6edf3]">x</kbd></div>
              <div className="flex justify-between"><span>Acknowledge</span><kbd className="font-mono text-[#e6edf3]">a</kbd></div>
              <div className="flex justify-between"><span>Escalate</span><kbd className="font-mono text-[#e6edf3]">e</kbd></div>
              <div className="flex justify-between"><span>Mark Benign</span><kbd className="font-mono text-[#e6edf3]">f</kbd></div>
              <div className="flex justify-between"><span>Search / Filter</span><kbd className="font-mono text-[#e6edf3]">/</kbd></div>
              <div className="flex justify-between"><span>Go to Page</span><kbd className="font-mono text-[#e6edf3]">g + [a/e/h/c/s/r/,]</kbd></div>
            </div>
            <button
              onClick={() => setShortcutsOpen(false)}
              className="mt-4 w-full rounded-[4px] bg-[#26292e] py-1 text-[11px] text-[#e6edf3] hover:bg-[#32363d]"
            >
              Close (Esc)
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
