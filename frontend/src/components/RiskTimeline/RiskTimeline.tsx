// Risk-over-time chart for the History page (the analytical view — it lives
// with the session archive, not on the lean Overview dashboard).
//
// Pure SVG — no chart library. Bars are individual sessions, colored by risk
// band; the line is the mean risk per hourly bucket over the trailing 24h.
// Colors are read from the CSS design tokens at runtime and re-read whenever
// the data-theme attribute changes, so the chart re-themes with the toggle.

import { useCallback, useEffect, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Panel } from "../ui";
import { fmtDayShort, riskBand, TREND_WINDOWS, type TrendWindow } from "../../lib/constants";
import { toneFill, toneForRiskBand, type FillTone } from "../../lib/fillPatterns";
import { useThemeColors, type ThemeColors } from "../../lib/theme";
import type { RunSummary } from "../../types";

const DAY_MS = 86_400_000;
const HEIGHT = 200;
const PAD = { top: 14, right: 12, bottom: 26, left: 34 };
const BASELINE = 60; // risk ≥ 60 is critical (see lib/constants riskBand)

// SVG fill for a risk band — pattern-encoded (the deck-wide vocabulary in
// lib/fillPatterns.ts): critical is SOLID, elevated is a diagonal hatch,
// none/low is a vertical hatch. The hatches reference SVG <pattern> defs
// below, whose strokes resolve from the theme at render time.
function bandFill(band: { label: string }, colors: ThemeColors): string {
  const tone = toneForRiskBand(band.label);
  if (tone === "critical") return colors.malicious;
  if (tone === "elevated") return "url(#op-fill-diag)";
  return "url(#op-fill-vert)"; // none / low
}

function fmtHour(ts: number): string {
  return new Date(ts).toISOString().slice(11, 16) + "Z";
}

function fmtDay(ts: number): string {
  return new Date(ts).toISOString().slice(5, 16).replace("T", " ") + "Z";
}

export default function RiskTimeline({ runs, windowKey }: { runs: RunSummary[]; windowKey: TrendWindow }) {
  const colors = useThemeColors();
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const roRef = useRef<ResizeObserver | null>(null);
  const [width, setWidth] = useState(720);

  // Combined ref: the plain ref backs the hover-tooltip geometry reads, and
  // the observer attaches when the chart node MOUNTS (the chart renders only
  // after runs arrive, so a mount-time effect with a [] dep would early-return
  // on a null ref and never re-attach — the SVG would stay at its initial
  // width and overflow a squeezed column).
  const setWrap = useCallback((el: HTMLDivElement | null) => {
    wrapRef.current = el;
    roRef.current?.disconnect();
    roRef.current = null;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width;
      if (w) setWidth(Math.round(w));
    });
    ro.observe(el);
    roRef.current = ro;
  }, []);

  useEffect(() => () => roRef.current?.disconnect(), []);

  // -- interaction: click-to-open + rich hover tooltip ----------------------
  const navigate = useNavigate();
  const [hover, setHover] = useState<{ run: RunSummary; x: number } | null>(null);
  const [tip, setTip] = useState<{ run: RunSummary; left: number; top: number } | null>(null);

  const TOOLTIP_W = 220;
  const TOOLTIP_H = 100;
  const onBarMove = (run: RunSummary, e: ReactMouseEvent) => {
    const el = wrapRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const px = e.clientX - rect.left;
    const py = e.clientY - rect.top;
    const rawLeft = px + 16 + TOOLTIP_W > rect.width ? px - TOOLTIP_W - 16 : px + 16;
    const left = Math.max(4, Math.min(rawLeft, rect.width - TOOLTIP_W - 4));
    const top = Math.max(4, Math.min(py - TOOLTIP_H / 2, HEIGHT - TOOLTIP_H - 4));
    setHover({ run, x: px });
    setTip({ run, left, top });
  };
  const clearHover = () => {
    setHover(null);
    setTip(null);
  };

  const cfg = TREND_WINDOWS.find((w) => w.key === windowKey) ?? TREND_WINDOWS[0];
  const now = Date.now();
  const oldest = runs.length ? Math.min(...runs.map((r) => new Date(r.started_at).getTime())) : now;
  // Explicit window: start at now−span, extending back only to fit the oldest
  // run (never truncating a bar). "all" spans the full recorded history.
  const windowStart = windowKey === "all" ? oldest : Math.max(oldest, now - cfg.spanMs);
  const windowMs = Math.max(cfg.bucketMs, now - windowStart);
  const windowed = runs.filter((r) => new Date(r.started_at).getTime() >= windowStart);

  // -- geometry -------------------------------------------------------------
  const plotW = Math.max(120, width - PAD.left - PAD.right);
  const plotH = HEIGHT - PAD.top - PAD.bottom;
  const x = (ts: number) => PAD.left + ((ts - windowStart) / windowMs) * plotW;
  const y = (score: number) => PAD.top + (1 - Math.min(100, Math.max(0, score)) / 100) * plotH;

  // -- per-run bars ---------------------------------------------------------
  // Runs are sorted by start; x-collision resolution shifts same-minute runs
  // apart so no bar hides another (the 09:32 pair would otherwise overlap to
  // sub-pixel precision on a 24h axis).
  const barW = Math.max(3, Math.min(10, (plotW / Math.max(1, runs.length)) * 0.55));
  const bars = [...windowed]
    .sort((a, b) => new Date(a.started_at).getTime() - new Date(b.started_at).getTime())
    .map((r) => {
      const start = new Date(r.started_at).getTime();
      const score = r.risk_score ?? 0;
      return { run: r, start, score, band: riskBand(score) };
    });
  let lastX = -Infinity;
  for (const b of bars) {
    const cx = x(b.start);
    const shifted = Math.max(cx, lastX + barW + 1);
    if (shifted > cx + 0.5) b.start = windowStart + ((shifted - PAD.left) / plotW) * windowMs; // nudge right
    lastX = shifted;
  }

  // -- mean line — hourly buckets on 24h, daily buckets on 7d / all ----------
  const trendStart = windowStart;
  const buckets = new Map<number, { sum: number; n: number }>();
  for (const r of windowed) {
    const t = new Date(r.started_at).getTime();
    const key = Math.floor((t - trendStart) / cfg.bucketMs);
    const b = buckets.get(key) ?? { sum: 0, n: 0 };
    b.sum += r.risk_score ?? 0;
    b.n += 1;
    buckets.set(key, b);
  }
  const trend = [...buckets.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([key, b]) => ({
      x: x(trendStart + (key + 0.5) * cfg.bucketMs),
      y: y(b.sum / b.n),
      hour: fmtHour(trendStart + (key + 0.5) * cfg.bucketMs),
      mean: Math.round((b.sum / b.n) * 10) / 10,
      n: b.n,
    }));

  const peak = Math.max(0, ...windowed.map((r) => r.risk_score ?? 0));

  // -- axis ticks -----------------------------------------------------------
  const yTicks = [0, 30, 60, 100];
  const fmtTick = cfg.bucketMs >= DAY_MS ? fmtDayShort : fmtHour;
  const xTickCount = Math.max(2, Math.min(6, Math.floor(plotW / 130)));
  const xTicks = Array.from({ length: xTickCount + 1 }, (_, i) => {
    const t = windowStart + (i / xTickCount) * windowMs;
    return { x: x(t), label: fmtTick(t) };
  });

  const linePath = trend.map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");
  const areaPath = trend.length
    ? `${linePath} L${trend[trend.length - 1].x.toFixed(1)},${y(0)} L${trend[0].x.toFixed(1)},${y(0)} Z`
    : "";

  return (
    <Panel
      kicker="Trend"
      title="Risk timeline"
      right={
        <div className="flex flex-wrap items-center gap-3 font-mono text-[10px] text-text-faint">
          <span>
            <span className="font-semibold text-text-primary">{bars.length}</span> session{bars.length === 1 ? "" : "s"}
            <span> · {windowKey === "all" ? "all time" : windowKey}</span>
          </span>
          <span>
            peak <span className="font-semibold text-risk-malicious">{peak}</span>
          </span>
          <span title="Bars: individual sessions by risk band. Line: mean risk per bucket.">
            bars = sessions · line = {cfg.bucketMs >= DAY_MS ? "daily" : "24h"} mean
          </span>
          {/* Fill-pattern key — risk bands are pattern-encoded for color-blind
              viewers: solid = critical, diagonal hatch = elevated, vertical
              hatch = none/low. */}
          <span
            className="hidden items-center gap-3 md:flex"
            title="Fill key — solid = critical, diagonal hatch = elevated, vertical hatch = none/low"
            aria-label="Fill key — solid = critical, diagonal hatch = elevated, vertical hatch = none/low"
          >
            {([["critical", "critical"], ["elevated", "elevated"], ["low", "low"]] as [FillTone, string][]).map(([tone, label]) => (
              <span key={tone} className="inline-flex items-center gap-1">
                <span className="h-2 w-3 rounded-sm" style={toneFill(tone)} />
                {label}
              </span>
            ))}
          </span>
        </div>
      }
    >
      {windowed.length === 0 ? (
        <p className="py-10 text-center text-sm text-text-muted">
          {runs.length === 0
            ? "No sessions yet — detonate a sample from Monitor."
            : windowKey === "all"
              ? "No sessions on record."
              : `No sessions in the last ${windowKey}.`}
        </p>
      ) : (
        <div ref={setWrap} className="relative">
          <svg
            role="img"
            aria-label="Risk scores over time — each bar is a session, the line is the 24-hour mean"
            width={width}
            height={HEIGHT}
            className="block"
          >
            {/* pattern defs — the deck's fill language for the band bars */}
            <defs>
              <pattern id="op-fill-diag" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
                <line x1="0" y1="0" x2="0" y2="4" stroke={colors.suspicious} strokeWidth="1.4" />
              </pattern>
              <pattern id="op-fill-vert" width="4" height="7" patternUnits="userSpaceOnUse">
                <line x1="0" y1="0" x2="0" y2="7" stroke={colors.clean} strokeWidth="1.4" />
              </pattern>
            </defs>

            {/* grid + baseline */}
            {yTicks.map((t) => (
              <g key={t}>
                <line
                  x1={PAD.left}
                  x2={width - PAD.right}
                  y1={y(t)}
                  y2={y(t)}
                  stroke={colors.grid}
                  strokeWidth={1}
                  strokeDasharray={t === BASELINE ? "4 3" : undefined}
                  opacity={t === BASELINE ? 1 : 0.6}
                />
                <text x={PAD.left - 6} y={y(t) + 3} textAnchor="end" fontSize={9} fill={colors.faint} fontFamily="monospace">
                  {t}
                </text>
              </g>
            ))}
            <text
              x={width - PAD.right}
              y={y(BASELINE) - 4}
              textAnchor="end"
              fontSize={8}
              fill={colors.suspicious}
              fontFamily="monospace"
            >
              critical ≥ 60
            </text>

            {/* x ticks */}
            {xTicks.map((t, i) => (
              <text key={i} x={t.x} y={HEIGHT - 8} textAnchor="middle" fontSize={9} fill={colors.faint} fontFamily="monospace">
                {t.label}
              </text>
            ))}

            {/* trend area + line */}
            {areaPath && <path d={areaPath} fill={colors.accent} opacity={0.08} />}
            {trend.length > 1 && (
              <path d={linePath} fill="none" stroke={colors.accent} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
            )}
            {trend.map((p, i) => (
              <circle key={i} cx={p.x} cy={p.y} r={2.5} fill={colors.accent}>
                <title>{`${p.hour} — mean risk ${p.mean} across ${p.n} session(s)`}</title>
              </circle>
            ))}

            {/* session bars — hover for the tooltip, click to open the run */}
            {bars.map((b) => {
              const fill = bandFill(b.band, colors);
              const cx = x(b.start);
              const top = y(b.score);
              const isHovered = hover?.run.run_id === b.run.run_id;
              return (
                <g
                  key={b.run.run_id}
                  onMouseEnter={(e) => onBarMove(b.run, e)}
                  onMouseMove={(e) => onBarMove(b.run, e)}
                  onMouseLeave={clearHover}
                >
                  {/* invisible hit area — wider than the bar so thin slivers are usable */}
                  <rect
                    x={cx - (barW + 10) / 2}
                    y={PAD.top}
                    width={barW + 10}
                    height={plotH}
                    fill="transparent"
                    className="cursor-pointer"
                    role="link"
                    tabIndex={0}
                    aria-label={`${b.run.sample_name} — risk ${b.score} (${b.band.label}) — open run detail`}
                    onClick={() => navigate(`/runs/${b.run.run_id}`)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") navigate(`/runs/${b.run.run_id}`);
                    }}
                  />
                  {/* visible bar */}
                  <rect
                    x={cx - barW / 2}
                    y={top}
                    width={barW}
                    height={b.score > 0 ? Math.max(2, y(0) - top) : 3}
                    rx={1.5}
                    fill={fill}
                    opacity={isHovered ? 1 : 0.85}
                    pointerEvents="none"
                    style={{ transition: "opacity 120ms ease-out" }}
                  />
                </g>
              );
            })}

            {/* hover guide line */}
            {hover && (
              <line
                x1={hover.x}
                x2={hover.x}
                y1={PAD.top}
                y2={PAD.top + plotH}
                stroke={colors.faint}
                strokeWidth={1}
                strokeDasharray="3 3"
                pointerEvents="none"
              />
            )}
          </svg>

          {/* rich hover tooltip */}
          {tip && (
            <div
              className="pointer-events-none absolute z-10 rounded-lg border border-border-subtle bg-bg-elevated px-3 py-2 shadow-xl"
              style={{ left: tip.left, top: tip.top, width: TOOLTIP_W }}
              role="tooltip"
            >
              <p className="truncate font-mono text-xs font-medium text-text-primary">{tip.run.sample_name}</p>
              <p className="mt-0.5 font-mono text-[10px] text-text-faint">
                {tip.run.run_id.slice(0, 12)} · {tip.run.platform === "linux" ? "⎈ linux" : "⊞ windows"}
              </p>
              <div className="mt-1.5 flex items-center gap-2">
                <span
                  className="h-2 w-2 rounded-full"
                  style={toneFill(toneForRiskBand(riskBand(tip.run.risk_score ?? 0).label))}
                />
                <span className={`font-mono text-sm font-semibold ${riskBand(tip.run.risk_score ?? 0).color}`}>
                  {tip.run.risk_score ?? 0}
                </span>
                <span className="rounded border border-border-subtle px-1 py-0.5 font-mono text-[9px] uppercase tracking-wide text-text-muted">
                  {riskBand(tip.run.risk_score ?? 0).label}
                </span>
                <span className="ml-auto font-mono text-[10px] tabular-nums text-text-muted">
                  {tip.run.alert_count} alert{tip.run.alert_count === 1 ? "" : "s"}
                </span>
              </div>
              <p className="mt-0.5 font-mono text-[9px] text-text-faint">
                started {fmtDay(new Date(tip.run.started_at).getTime())}
              </p>
              <p className="mt-1.5 border-t border-border-subtle pt-1 font-mono text-[9px] text-accent">open run →</p>
            </div>
          )}

          {/* legend */}
          <div className="mt-2 flex flex-wrap items-center gap-3 font-mono text-[10px] text-text-faint">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-sm" style={{ background: colors.clean }} /> none / low
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-sm" style={{ background: colors.suspicious }} /> elevated
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-sm" style={{ background: colors.malicious }} /> critical
            </span>
            <span className="ml-auto flex items-center gap-1.5">
              <span className="inline-block h-0.5 w-4 rounded" style={{ background: colors.accent }} />{" "}
              {cfg.bucketMs >= DAY_MS ? "daily mean" : "24h mean"}
            </span>
          </div>
        </div>
      )}
    </Panel>
  );
}
