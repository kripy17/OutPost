// Posture primitives — the Overview console's visual vocabulary, shared with
// the Theme Lab so palettes can be previewed side by side. Everything is
// token-driven via CSS var() so a wrapper with a data-palette attribute
// re-scopes the colors instantly (no JS color plumbing).

import { useNavigate } from "react-router-dom";
import { riskBand } from "../../lib/constants";
import { toneFill } from "../../lib/fillPatterns";
import type { RunSummary } from "../../types";

/* ── Risk gauge — semicircular arc, colored by band ────────────────────── */

export function RiskGauge({ score }: { score: number }) {
  const band = riskBand(score);
  const s = score ?? 0;
  const arcLen = Math.PI * 54; // half-circle, r=54
  const frac = Math.min(1, Math.max(0, s / 100));
  const tone = band.color.replace("text-risk-", "");
  return (
    <div className="flex items-center gap-4">
      <svg viewBox="0 0 140 78" className="h-[88px] w-[158px] shrink-0" role="img" aria-label={`Peak risk ${score}/100, ${band.label}`}>
        <path d="M 16 70 A 54 54 0 0 1 124 70" fill="none" stroke="var(--border-strong)" strokeOpacity="0.5" strokeWidth="11" strokeLinecap="round" />
        <path
          d="M 16 70 A 54 54 0 0 1 124 70"
          fill="none"
          stroke={`var(--risk-${tone})`}
          strokeWidth="11"
          strokeLinecap="round"
          strokeDasharray={`${frac * arcLen} ${arcLen}`}
        />
        <text x="70" y="58" textAnchor="middle" className="fill-current font-mono" fontSize="22" fontWeight="700">
          {s}
        </text>
        <text x="70" y="73" textAnchor="middle" fontSize="9" fill="var(--text-faint)">
          / 100
        </text>
      </svg>
      <div className="min-w-0">
        <p className="kicker">Peak risk</p>
        <p className="mt-1 text-[15px] font-semibold capitalize text-text-primary">{band.label}</p>
        <p className="mt-0.5 text-[12px] leading-relaxed text-text-muted">Highest score across every session on this machine.</p>
      </div>
    </div>
  );
}

/* ── Severity donut ────────────────────────────────────────────────────── */

export function SeverityDonut({ malicious, suspicious, clean }: { malicious: number; suspicious: number; clean: number }) {
  const total = Math.max(1, malicious + suspicious + clean);
  const C = 2 * Math.PI * 44;
  // Pattern-encoded segments (deck-wide fill language): malicious is SOLID,
  // suspicious is a diagonal hatch, clean is a vertical hatch — so the mix
  // stays readable for color-blind viewers, not just tinted.
  const segs = [
    { n: malicious, color: "var(--risk-malicious)" },
    { n: suspicious, color: "url(#dp-fill-diag)" },
    { n: clean, color: "url(#dp-fill-vert)" },
  ];
  let offset = 0;
  return (
    <div className="flex items-center gap-4">
      <svg viewBox="0 0 120 120" className="h-[84px] w-[84px] shrink-0" role="img" aria-label="Severity mix across sessions — solid = malicious, hatched = suspicious, vertical = clean">
        <defs>
          <pattern id="dp-fill-diag" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
            <line x1="0" y1="0" x2="0" y2="4" stroke="var(--risk-suspicious)" strokeWidth="1.6" />
          </pattern>
          <pattern id="dp-fill-vert" width="4" height="7" patternUnits="userSpaceOnUse">
            <line x1="0" y1="0" x2="0" y2="7" stroke="var(--risk-clean)" strokeWidth="1.6" />
          </pattern>
        </defs>
        <circle cx="60" cy="60" r="44" fill="none" stroke="var(--bg-elevated)" strokeWidth="13" />
        {segs.map((s, i) => {
          const frac = s.n / total;
          const dash = `${Math.max(0, frac * C - 2)} ${C}`;
          const el = (
            <circle
              key={i}
              cx="60"
              cy="60"
              r="44"
              fill="none"
              stroke={s.color}
              strokeWidth="13"
              strokeLinecap="round"
              strokeDasharray={dash}
              strokeDashoffset={-offset * C}
              transform="rotate(-90 60 60)"
            />
          );
          offset += frac;
          return el;
        })}
        <text x="60" y="57" textAnchor="middle" fontSize="20" fontWeight="700" className="fill-current font-mono">
          {malicious + suspicious + clean}
        </text>
        <text x="60" y="72" textAnchor="middle" fontSize="9" fill="var(--text-faint)">
          sessions
        </text>
      </svg>
      <ul className="space-y-1.5 text-[12px]">
        {[
          { label: "Malicious", n: malicious, color: "text-risk-malicious", tone: "critical" as const },
          { label: "Suspicious", n: suspicious, color: "text-risk-suspicious", tone: "elevated" as const },
          { label: "Clean / none", n: clean, color: "text-risk-clean", tone: "low" as const },
        ].map((row) => (
          <li key={row.label} className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full" style={toneFill(row.tone)} aria-hidden />
            <span className="text-text-muted">{row.label}</span>
            <span className={`ml-auto font-mono tabular-nums ${row.color}`}>{row.n}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ── Risk trend — aggregated by sample ────────────────────────────────────
 * One bar per unique binary, sized by its peak risk and colored by band, so
 * the console reads "which samples are the worst" at a glance instead of 60
 * near-identical session dots. Per-session detail lives on History; clicking
 * a bar jumps there pre-filtered to that sample. */

export interface RiskTrendBar {
  sample: string;
  peak: number;
  count: number;
  last: string;
}

export function RiskTrendBars({ bars }: { bars: RiskTrendBar[] }) {
  const navigate = useNavigate();
  if (bars.length === 0) {
    return <p className="py-10 text-center text-sm text-text-muted">No detonations yet — risk appears here as samples run.</p>;
  }
  const W = 100;
  const H = 36;
  const max = Math.max(100, ...bars.map((b) => b.peak));
  const step = W / bars.length;
  const bw = Math.max(0.9, step * 0.66);
  return (
    <div>
      <div className="flex items-center justify-between">
        <p className="kicker">Risk trend</p>
        <p className="font-mono text-[10px] text-text-faint">
          {bars.length} sample{bars.length === 1 ? "" : "s"} · peak per binary
        </p>
      </div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="mt-1 h-[46px] w-full"
        preserveAspectRatio="none"
        role="img"
        aria-label="Risk trend by sample — each bar is a binary's peak risk"
      >
        {[0, 0.5, 1].map((f) => (
          <line
            key={f}
            x1="0"
            x2={W}
            y1={H - f * (H - 4) - 2}
            y2={H - f * (H - 4) - 2}
            stroke="var(--border-subtle)"
            strokeDasharray="2 3"
            strokeWidth="0.5"
          />
        ))}
        {bars.map((b, i) => {
          const band = riskBand(b.peak);
          const h = Math.max(1.5, (b.peak / max) * (H - 4));
          const x = i * step;
          return (
            <g
              key={b.sample}
              role="link"
              tabIndex={0}
              className="cursor-pointer"
              onClick={() => navigate(`/history?q=${encodeURIComponent(b.sample)}`)}
              onKeyDown={(e) => {
                if (e.key === "Enter") navigate(`/history?q=${encodeURIComponent(b.sample)}`);
              }}
            >
              <title>{`${b.sample}: peak risk ${b.peak} (${band.label}) · ${b.count} session${b.count === 1 ? "" : "s"} — open its sessions`}</title>
              <rect
                x={x}
                y={H - h - 2}
                width={bw}
                height={h}
                fill={`var(--risk-${band.color.replace("text-risk-", "")})`}
                fillOpacity="0.9"
                rx="0.6"
              />
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* ── Risk sparkline ────────────────────────────────────────────────────── */

export function RiskSparkline({ runs }: { runs: Pick<RunSummary, "risk_score" | "started_at" | "sample_name">[] }) {
  if (runs.length === 0) return <p className="py-10 text-center text-sm text-text-muted">No sessions yet — risk appears here as they complete.</p>;
  const chrono = [...runs].sort((a, b) => a.started_at.localeCompare(b.started_at));
  const values = chrono.map((r) => r.risk_score ?? 0);
  const max = Math.max(100, ...values);
  const W = 100;
  const H = 36;
  const step = values.length > 1 ? W / (values.length - 1) : W / 2;
  const pts = values.map((v, i) => `${(i * step).toFixed(2)},${(H - (v / max) * (H - 4) - 2).toFixed(2)}`);
  return (
    <div>
      <div className="flex items-center justify-between">
        <p className="kicker">Risk trend</p>
        <p className="font-mono text-[10px] text-text-faint">{chrono.length} sessions · chronological</p>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="mt-1 h-[46px] w-full" preserveAspectRatio="none" role="img" aria-label="Risk score trend across sessions">
        {[0, 0.5, 1].map((f) => (
          <line key={f} x1="0" x2={W} y1={H - f * (H - 4) - 2} y2={H - f * (H - 4) - 2} stroke="var(--border-subtle)" strokeDasharray="2 3" strokeWidth="0.5" />
        ))}
        <polyline points={pts.join(" ")} fill="none" stroke="var(--accent)" strokeWidth="1.4" vectorEffect="non-scaling-stroke" />
        {pts.map((p, i) => {
          const [x, y] = p.split(",").map(Number);
          const band = riskBand(values[i]);
          return (
            <circle
              key={i}
              cx={x}
              cy={y}
              r={values.length > 14 ? 1 : 2.2}
              fill={`var(--risk-${band.color.replace("text-risk-", "")})`}
              stroke="var(--bg-surface)"
              strokeWidth="1"
              vectorEffect="non-scaling-stroke"
            >
              <title>{`${chrono[i].sample_name}: risk ${values[i]} (${band.label})`}</title>
            </circle>
          );
        })}
      </svg>
    </div>
  );
}
