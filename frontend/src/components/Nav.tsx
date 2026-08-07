import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";

const STORAGE_KEY = "outpost-theme";

// Grouped navigation — a SOC console's information architecture:
// analyze → hunt → operate.
const GROUPS: { label: string; links: { to: string; label: string; end?: boolean }[] }[] = [
  {
    label: "Analyze",
    links: [
      { to: "/", label: "Overview", end: true },
      { to: "/monitor", label: "Monitor" },
    ],
  },
  {
    label: "Intelligence",
    links: [
      { to: "/events", label: "Events" },
      { to: "/search", label: "IOC Search" },
      { to: "/compare", label: "Compare" },
      { to: "/campaigns", label: "Campaigns" },
      { to: "/samples", label: "Samples" },
    ],
  },
  {
    label: "Operations",
    links: [
      { to: "/watchlist", label: "Watchlist" },
      { to: "/rules", label: "Rules" },
      { to: "/settings", label: "Settings" },
      { to: "/history", label: "History" },
    ],
  },
];

function useTheme() {
  const [theme, setTheme] = useState<"dark" | "light">(() =>
    document.documentElement.dataset.theme === "light" ? "light" : "dark",
  );

  const toggle = () => {
    const next = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    localStorage.setItem(STORAGE_KEY, next);
    setTheme(next);
  };

  // Stay in sync if the theme changes elsewhere (another tab / devtools).
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY && (e.newValue === "light" || e.newValue === "dark")) setTheme(e.newValue);
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  return { theme, toggle };
}

// Radar mark — the deck's signature glyph: a sweep across concentric rings.
function RadarMark() {
  return (
    <svg viewBox="0 0 24 24" className="h-5 w-5" aria-hidden>
      <circle cx="12" cy="12" r="9" fill="none" stroke="var(--border-strong)" strokeWidth="1" />
      <circle cx="12" cy="12" r="5.5" fill="none" stroke="var(--border-strong)" strokeWidth="1" />
      <circle cx="12" cy="12" r="2" fill="none" stroke="var(--accent-amber)" strokeWidth="1" opacity="0.7" />
      <line x1="12" y1="12" x2="19" y2="5" stroke="var(--accent-amber)" strokeWidth="1.4" />
      <circle cx="19" cy="5" r="1.6" fill="var(--accent-amber)" />
      <circle cx="12" cy="12" r="1.1" fill="var(--text-primary)" />
    </svg>
  );
}

function Brand() {
  return (
    <span className="flex items-center gap-2.5">
      <RadarMark />
      <span className="font-mono text-sm font-semibold tracking-tight text-text-primary">OUTPOST</span>
      <span className="hidden rounded border border-border-subtle px-1 py-0.5 font-mono text-[9px] uppercase tracking-widest text-text-faint xl:inline">
        SOC
      </span>
    </span>
  );
}

function ThemeToggle({ theme, toggle }: { theme: "dark" | "light"; toggle: () => void }) {
  const next = theme === "dark" ? "light" : "dark";
  return (
    <button
      onClick={toggle}
      aria-label={`Switch to ${next} theme`}
      title={`Switch to ${next} theme`}
      className="press flex h-8 w-8 items-center justify-center rounded-md border border-border-subtle text-sm text-text-muted transition-colors duration-150 hover:border-accent-amber/60 hover:text-accent-amber"
    >
      {theme === "dark" ? "☀" : "☾"}
    </button>
  );
}

export default function Nav() {
  const { theme, toggle } = useTheme();

  return (
    <>
      {/* Desktop — fixed left rail */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-56 flex-col border-r border-border-subtle bg-bg-surface/70 backdrop-blur-md lg:flex">
        <div className="px-5 pb-4 pt-6">
          <Brand />
        </div>
        <nav className="flex-1 overflow-y-auto px-3" aria-label="Primary">
          {GROUPS.map((group) => (
            <div key={group.label} className="mb-5">
              <p className="kicker px-2 pb-2">{group.label}</p>
              <div className="space-y-0.5">
                {group.links.map((link) => (
                  <NavLink
                    key={link.to}
                    to={link.to}
                    end={link.end}
                    className={({ isActive }) =>
                      `group relative flex items-center rounded-md py-1.5 pl-3 pr-2 font-mono text-xs transition-colors duration-150 ${
                        isActive
                          ? "bg-bg-elevated font-medium text-accent-amber shadow-[var(--glow-amber)]"
                          : "text-text-muted hover:bg-bg-elevated/50 hover:text-text-primary"
                      }`
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {/* Accent bar — the active position reads like a breaker tripped. */}
                        <span
                          className={`absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-accent-amber transition-opacity duration-150 ${
                            isActive ? "opacity-100" : "opacity-0 group-hover:opacity-40"
                          }`}
                        />
                        {link.label}
                      </>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>
        <div className="border-t border-border-subtle px-4 py-3">
          <div className="flex items-center gap-2">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-risk-clean/60" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-risk-clean" />
            </span>
            <span className="font-mono text-[10px] uppercase tracking-widest text-text-faint">deck online</span>
            <span className="ml-auto">
              <ThemeToggle theme={theme} toggle={toggle} />
            </span>
          </div>
        </div>
      </aside>

      {/* Mobile / narrow — compact top bar */}
      <header className="sticky top-0 z-30 border-b border-border-subtle bg-bg-base/80 backdrop-blur lg:hidden">
        <div className="flex items-center gap-4 px-4 py-2.5">
          <Brand />
          <nav className="flex flex-1 items-center gap-0.5 overflow-x-auto text-xs" aria-label="Primary">
            {GROUPS.flatMap((g) => g.links).map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                end={link.end}
                className={({ isActive }) =>
                  `whitespace-nowrap rounded-md px-2 py-1.5 transition-colors duration-150 ${
                    isActive ? "bg-bg-elevated font-medium text-accent-amber" : "text-text-muted hover:text-text-primary"
                  }`
                }
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
          <ThemeToggle theme={theme} toggle={toggle} />
        </div>
      </header>
    </>
  );
}
