// Detection-volume mini-chart for the Overview — alerts fired per hour over
// the trailing 24h, stacked by kill-chain family (the user asked for
// Execution / C2 / Persistence / Impact; Evasion and the composite Chain
// round it out). Pairs with RiskTimeline: risk *score* per session on the
// left, detection *density* per hour on the right.
//
// Data comes from the same GET /alerts feed the findings list uses (a larger
// limit), bucketed client-side by rule_id → kill-chain stage → family.

import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Panel } from "../ui";
import { KILL_CHAIN_STAGE } from "../../lib/constants";
import { getRecentAlerts } from "../../lib/api";
import { useThemeColors } from "../../lib/theme";

const HOUR_MS = 3_600_000;
const HOURS = 24;
const HEIGHT = 150;
const PAD = { top: 12, right: 8, bottom: 24, left: 28 };

// kill-chain stage → chart family (KILL_CHAIN_STAGE maps rule_id → stage).
const FAMILY_OF: Record<string, string> = {
  Execution: "Execution",
  "Defense Evasion": "Evasion",
  "Command and Control": "C2",
  Persistence: "Persistence",
  Impact: "Impact",
  "Full Chain": "Chain",
};
const FAMILIES = ["Execution", "Evasion", "C2", "Persistence", "Impact", "Chain", "Other"] as const;

// Distinct hues for stacked segments; amber/teal/brick deliberately echo the
// app's semantic risk colors (Execution, C2, Impact), violet/orange/gold are
// new so the families never blur together on either theme.
const FAMILY_COLOR: Record<string, string> = {
  Execution: "#d9a441",
  Evasion: "#9d7bd8",
  C2: "#3fa796",
  Persistence: "#e0855b",
  Impact: "#c4453b",
  Chain: "#f2b632",
  Other: "#6b7280", // rules with no kill-chain stage — never silently dropped
};

function familyOf(ruleId: string): string {
  const stage = KILL_CHAIN_STAGE[ruleId];
  return stage ? (FAMILY_OF[stage] ?? "Other") : "Other";
}

function fmtHour(ts: number): string {
  return new Date(ts).toISOString().slice(11, 16) + "Z";
}

export default function DetectionVolume() {
  const colors = useThemeColors();
  const { data: alerts = [], isLoading, isError } = useQuery({
    queryKey: ["alerts", "volume"],
    queryFn: () => getRecentAlerts(200),
    refetchInterval: 30_000, // live detonations show up here too
  });

  const wrapRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(420);

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

  // -- bucket alerts into the trailing 24h, one slot per hour ----------------
  const now = Date.now();
  const start = now - HOURS * HOUR_MS;
  const buckets = new Map<number, Record<string, number>>();
  for (const a of alerts) {
    const t = new Date(a.triggered_at).getTime();
    if (t < start) continue;
    const key = Math.floor((t - start) / HOUR_MS);
    const fam = familyOf(a.rule_id);
    const b = buckets.get(key) ?? Object.fromEntries(FAMILIES.map((f) => [f, 0]));
    b[fam] = (b[fam] ?? 0) + 1;
    buckets.set(key, b);
  }

  const entries = Array.from({ length: HOURS }, (_, i) => {
    const b = buckets.get(i);
    const counts = FAMILIES.map((f) => b?.[f] ?? 0);
    return { i, hour: fmtHour(start + i * HOUR_MS), counts, total: counts.reduce((n, c) => n + c, 0) };
  });
  const maxTotal = Math.max(1, ...entries.map((e) => e.total));
  const totalAlerts = alerts.filter((a) => new Date(a.triggered_at).getTime() >= start).length;
  const peak = Math.max(0, ...entries.map((e) => e.total));
  // Legend counts come from the same 24h-windowed buckets as the bars/header,
  // so the three always agree (alerts older than 24h are excluded everywhere).
  const familyTotals = FAMILIES.map((f, fi) => [f, entries.reduce((n, e) => n + e.counts[fi], 0)] as const);

  // -- geometry ---------------------------------------------------------------
  const plotW = Math.max(120, width - PAD.left - PAD.right);
  const plotH = HEIGHT - PAD.top - PAD.bottom;
  const slotW = plotW / HOURS;
  const barW = Math.max(2, slotW * 0.72);

  return (
    <Panel
      kicker="Density"
      title="Detection volume"
      right={
        <div className="flex flex-wrap items-center gap-3 font-mono text-[10px] text-text-faint">
          <span>
            <span className="font-semibold text-text-primary">{totalAlerts}</span> alerts
          </span>
          <span>
            peak <span className="font-semibold text-accent-amber">{peak}</span>/hr
          </span>
          <span title="Alerts fired per hour over the trailing 24h, stacked by kill-chain family. Drawn from the latest 200 alerts.">per hour · 24h · latest 200</span>
        </div>
      }
    >
      {isLoading && <p className="py-10 text-center text-sm text-text-muted">Counting…</p>}
      {isError && (
        <p className="rounded border border-risk-malicious/40 px-3 py-2 text-xs text-risk-malicious">Backend unreachable.</p>
      )}

      {!isLoading && !isError && totalAlerts === 0 && (
        <p className="py-10 text-center text-sm text-text-muted">No detections in the last 24h.</p>
      )}

      {!isLoading && !isError && totalAlerts > 0 && (
        <div ref={wrapRef} className="relative">
          <svg
            role="img"
            aria-label="Detection volume — alerts per hour over 24 hours, stacked by kill-chain family"
            width={width}
            height={HEIGHT}
            className="block"
          >
            {/* baseline + top gridline */}
            <line x1={PAD.left} x2={width - PAD.right} y1={PAD.top + plotH} y2={PAD.top + plotH} stroke={colors.grid} strokeWidth={1} />
            <line x1={PAD.left} x2={width - PAD.right} y1={PAD.top} y2={PAD.top} stroke={colors.grid} strokeWidth={1} strokeDasharray="4 3" opacity={0.6} />
            <text x={PAD.left - 6} y={PAD.top + 3} textAnchor="end" fontSize={9} fill={colors.faint} fontFamily="monospace">
              {maxTotal}
            </text>
            <text x={PAD.left - 6} y={PAD.top + plotH + 3} textAnchor="end" fontSize={9} fill={colors.faint} fontFamily="monospace">
              0
            </text>

            {/* hour labels — every 6h */}
            {[0, 6, 12, 18, 23].map((i) => (
              <text
                key={i}
                x={PAD.left + i * slotW + slotW / 2}
                y={HEIGHT - 6}
                textAnchor="middle"
                fontSize={8}
                fill={colors.faint}
                fontFamily="monospace"
              >
                {entries[i].hour}
              </text>
            ))}

            {/* stacked segments */}
            {entries.map((e) => {
              let offset = 0;
              return (
                <g key={e.i}>
                  {FAMILIES.map((f, fi) => {
                    const c = e.counts[fi];
                    if (c === 0) return null;
                    const h = (c / maxTotal) * plotH;
                    const seg = (
                      <rect
                        key={f}
                        x={PAD.left + e.i * slotW + (slotW - barW) / 2}
                        y={PAD.top + plotH - offset - h}
                        width={barW}
                        height={Math.max(1, h)}
                        rx={0.5}
                        fill={FAMILY_COLOR[f]}
                      >
                        <title>{`${e.hour} — ${f}: ${c} alert${c === 1 ? "" : "s"}`}</title>
                      </rect>
                    );
                    offset += h;
                    return seg;
                  })}
                </g>
              );
            })}
          </svg>

          {/* legend */}
          <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 font-mono text-[10px] text-text-faint">
            {familyTotals.map(([f, n]) => (
              <span key={f} className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-sm" style={{ background: FAMILY_COLOR[f] }} />
                {f}
                <span className="tabular-nums text-text-muted">{n}</span>
              </span>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}
