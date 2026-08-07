// Risk-over-time chart for the Overview dashboard (SOC glance view).
//
// Pure SVG — no chart library. Bars are individual sessions, colored by risk
// band; the line is the mean risk per hourly bucket over the trailing 24h.
// Colors are read from the CSS design tokens at runtime and re-read whenever
// the data-theme attribute changes, so the chart re-themes with the toggle.

import { useEffect, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Panel } from "../ui";
import { riskBand } from "../../lib/constants";
import { useThemeColors, type ThemeColors } from "../../lib/theme";
import type { RunSummary } from "../../types";

const WINDOW_HOURS = 24;
const HOUR_MS = 3_600_000;
const HEIGHT = 200;
const PAD = { top: 14, right: 12, bottom: 26, left: 34 };
const BASELINE = 60; // risk ≥ 60 is critical (see lib/constants riskBand)

function bandHex(band: { label: string }, colors: ThemeColors): string {
  if (band.label === "elevated") return colors.suspicious;
  if (band.label === "critical") return colors.malicious;
  return colors.clean; // none / low
}

function fmtHour(ts: number): string {
  return new Date(ts).toISOString().slice(11, 16) + "Z";
}

function fmtDay(ts: number): string {
  return new Date(ts).toISOString().slice(5, 16).replace("T", " ") + "Z";
}

export default function RiskTimeline({ runs }: { runs: RunSummary[] }) {
  const colors = useThemeColors();
  const wrapRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(720);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width;
      if (w) setWidth(Math.round(w));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

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

  const now = Date.now();
  const windowStart = Math.min(now - WINDOW_HOURS * HOUR_MS, ...runs.map((r) => new Date(r.started_at).getTime()));
  const windowMs = Math.max(WINDOW_HOURS * HOUR_MS, now - windowStart);

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
  const bars = [...runs]
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

  // -- rolling 24h mean (hourly buckets, populated hours only) --------------
  const trendStart = now - WINDOW_HOURS * HOUR_MS;
  const buckets = new Map<number, { sum: number; n: number }>();
  for (const r of runs) {
    const t = new Date(r.started_at).getTime();
    if (t < trendStart) continue;
    const key = Math.floor((t - trendStart) / HOUR_MS);
    const b = buckets.get(key) ?? { sum: 0, n: 0 };
    b.sum += r.risk_score ?? 0;
    b.n += 1;
    buckets.set(key, b);
  }
  const trend = [...buckets.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([key, b]) => ({
      x: x(trendStart + (key + 0.5) * HOUR_MS),
      y: y(b.sum / b.n),
      hour: fmtHour(trendStart + (key + 0.5) * HOUR_MS),
      mean: Math.round((b.sum / b.n) * 10) / 10,
      n: b.n,
    }));

  const peak = Math.max(0, ...runs.filter((r) => new Date(r.started_at).getTime() >= trendStart)
    .map((r) => r.risk_score ?? 0));

  // -- axis ticks -----------------------------------------------------------
  const yTicks = [0, 30, 60, 100];
  const xTickCount = Math.max(2, Math.min(6, Math.floor(plotW / 130)));
  const xTicks = Array.from({ length: xTickCount + 1 }, (_, i) => {
    const t = windowStart + (i / xTickCount) * windowMs;
    return { x: x(t), label: fmtHour(t) };
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
            {windowMs > WINDOW_HOURS * HOUR_MS + 60_000 && (
              <span title="Window extended to the oldest session"> · {Math.round(windowMs / HOUR_MS)}h</span>
            )}
          </span>
          <span>
            peak <span className="font-semibold text-risk-malicious">{peak}</span>
          </span>
          <span title="Bars: individual sessions by risk band. Line: mean risk per hour, trailing 24h.">
            bars = sessions · line = 24h mean
          </span>
        </div>
      }
    >
      {runs.length === 0 ? (
        <p className="py-10 text-center text-sm text-text-muted">No sessions yet — detonate a sample from Monitor.</p>
      ) : (
        <div ref={wrapRef} className="relative">
          <svg
            role="img"
            aria-label="Risk scores over time — each bar is a session, the line is the 24-hour mean"
            width={width}
            height={HEIGHT}
            className="block"
          >
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
              const hex = bandHex(b.band, colors);
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
                    fill={hex}
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
                  style={{ background: bandHex(riskBand(tip.run.risk_score ?? 0), colors) }}
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
              <p className="mt-1.5 border-t border-border-subtle pt-1 font-mono text-[9px] text-accent-amber">open run →</p>
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
              <span className="inline-block h-0.5 w-4 rounded" style={{ background: colors.accent }} /> 24h mean
            </span>
          </div>
        </div>
      )}
    </Panel>
  );
}
