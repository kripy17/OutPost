// AlertRate — per-minute alert volume for one run, as a mini bar chart.
//
// The storm guard caps *how many* alerts a rule can fire per run; this chart
// shows *how fast* they're arriving — a minute with a spike is the flood
// warning before the cap even trips. Bars are colored by the dominant
// severity of that minute (brick malicious > amber suspicious); minutes at or
// above FLOOD_PER_MIN render with a flood marker so a burst reads at a
// glance. Hover a bar for the exact time, count, and severity split.

import { useMemo, useState } from "react";
import { Panel } from "../ui";
import { useThemeColors } from "../../lib/theme";
import type { Alert } from "../../types";

// A minute at or above this many alerts is a flood minute (a live host
// legitimately produces a handful; ten in one minute is an incident).
const FLOOD_PER_MIN = 10;
const HEIGHT = 64;
const PAD = { top: 6, right: 4, bottom: 2, left: 4 };

interface Bucket {
  ts: number;
  count: number;
  malicious: number;
  suspicious: number;
}

export default function AlertRate({ alerts }: { alerts: Alert[] }) {
  const colors = useThemeColors();
  const [hover, setHover] = useState<Bucket | null>(null);

  const { buckets, peak, floodMins } = useMemo(() => {
    if (!alerts.length) return { buckets: [] as Bucket[], peak: 1, floodMins: 0 };
    const byMin = new Map<number, Bucket>();
    for (const a of alerts) {
      const t = new Date(a.triggered_at).getTime();
      const min = Math.floor(t / 60_000) * 60_000;
      const b = byMin.get(min) ?? { ts: min, count: 0, malicious: 0, suspicious: 0 };
      b.count += 1;
      if (a.severity === "malicious") b.malicious += 1;
      else b.suspicious += 1;
      byMin.set(min, b);
    }
    const sorted = [...byMin.values()].sort((a, b) => a.ts - b.ts);
    const peak = Math.max(1, ...sorted.map((b) => b.count));
    const floodMins = sorted.filter((b) => b.count >= FLOOD_PER_MIN).length;
    return { buckets: sorted, peak, floodMins };
  }, [alerts]);

  const width = 640;
  const plotW = width - PAD.left - PAD.right;
  const plotH = HEIGHT - PAD.top - PAD.bottom;
  const barW = Math.max(2, Math.min(14, plotW / Math.max(1, buckets.length)));
  const gap = buckets.length > 40 ? 1 : 2;

  const totalSpan = Math.max(1, buckets.length - 1) * (barW + gap);
  const startX = PAD.left + (plotW - totalSpan) / 2;

  return (
    <Panel
      kicker="Volume · per minute"
      title="Alert rate"
      right={
        <span className="font-mono text-[10px] text-text-faint">
          {alerts.length} alerts · peak {peak}/min
          {floodMins > 0 && (
            <span className="ml-2 text-risk-malicious">· {floodMins} flood min{floodMins === 1 ? "" : "s"} ≥{FLOOD_PER_MIN}/min</span>
          )}
        </span>
      }
    >
      {buckets.length === 0 ? (
        <p className="py-4 text-center font-mono text-[11px] text-text-faint">no alerts — nothing to plot</p>
      ) : (
        <div className="relative">
          <svg
            viewBox={`0 0 ${width} ${HEIGHT}`}
            className="h-16 w-full"
            role="img"
            aria-label={`Alert rate over time — peak ${peak} alerts per minute`}
          >
            {/* flood threshold guide line */}
            {peak > FLOOD_PER_MIN && (
              <line
                x1={PAD.left}
                x2={width - PAD.right}
                y1={PAD.top + plotH * (1 - FLOOD_PER_MIN / peak)}
                y2={PAD.top + plotH * (1 - FLOOD_PER_MIN / peak)}
                stroke={colors.malicious}
                strokeOpacity={0.35}
                strokeDasharray="3 3"
                strokeWidth={1}
              />
            )}
            {buckets.map((b, i) => {
              const h = Math.max(2, (b.count / peak) * plotH);
              const x = startX + i * (barW + gap);
              const y = PAD.top + plotH - h;
              const flood = b.count >= FLOOD_PER_MIN;
              const color = b.malicious > b.suspicious ? colors.malicious : flood ? colors.suspicious : colors.accent;
              return (
                <rect
                  key={b.ts}
                  x={x}
                  y={y}
                  width={barW}
                  height={h}
                  rx={1.5}
                  fill={color}
                  fillOpacity={flood ? 1 : 0.72}
                  stroke={flood ? colors.malicious : "none"}
                  strokeWidth={flood ? 1 : 0}
                  onMouseEnter={() => setHover(b)}
                  onMouseLeave={() => setHover(null)}
                >
                  <title>
                    {new Date(b.ts).toISOString().slice(11, 16)}Z — {b.count} alert(s) ({b.malicious} malicious / {b.suspicious} suspicious)
                  </title>
                </rect>
              );
            })}
          </svg>
          {hover && (
            <div className="pointer-events-none absolute left-1/2 top-0 z-10 -translate-x-1/2 -translate-y-full whitespace-nowrap rounded-md border border-border-subtle bg-bg-elevated px-2 py-1 font-mono text-[10px] text-text-primary shadow-lg">
              {new Date(hover.ts).toISOString().slice(11, 16)}Z · {hover.count} alert
              {hover.count === 1 ? "" : "s"}
              {hover.malicious > 0 && <span className="text-risk-malicious"> · {hover.malicious} mal</span>}
              {hover.suspicious > 0 && <span className="text-risk-suspicious"> · {hover.suspicious} sus</span>}
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}
