// Topology — the run's connection graph at a glance.
//
// Processes (from the annotated process tree) stack down the left; every
// distinct destination IP (from the enriched connection table) stacks down
// the right. A bezier edge joins each process to every IP it reached, colored
// by that IP's reputation — so "this sample spawned powershell, which dialed
// 203.0.113.88:4444 (malicious)" reads in one glance, no tree walking.
//
// Clicking an IP jumps to IOC Search (the same behavior as the network
// table). Node count drives the SVG height; the viewBox scales it to the
// panel width.

import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import type { NetworkConnection, ProcessNode, Reputation } from "../../types";

interface FlatProc {
  pid: number;
  name: string;
  rep: Reputation | null;
  ips: string[];
}

interface FlatIp {
  ip: string;
  port: number | null;
  rep: Reputation;
  vt: number | null;
  abuse: number | null;
}

const REP_FILL: Record<Reputation, string> = {
  malicious: "var(--risk-malicious)",
  suspicious: "var(--risk-suspicious)",
  clean: "var(--risk-clean)",
  unknown: "var(--text-faint)",
};

const LEGEND: { rep: Reputation; label: string }[] = [
  { rep: "malicious", label: "malicious" },
  { rep: "suspicious", label: "suspicious" },
  { rep: "clean", label: "clean" },
  { rep: "unknown", label: "unknown" },
];

const ROW = 38; // vertical pitch per node
const PAD = 18;
const LX = 12;
const LW = 320;
const RX = 640;
const RW = 248;
const W = 900;

export default function Topology({
  tree,
  connections,
}: {
  tree: ProcessNode[];
  connections: NetworkConnection[];
}) {
  const nav = useNavigate();

  const { procs, ips, edges } = useMemo(() => {
    const procs: FlatProc[] = [];
    const walk = (ns: ProcessNode[]) => {
      for (const n of ns) {
        procs.push({ pid: n.pid, name: n.process_name, rep: n.flagged_reputation ?? null, ips: n.network_ips ?? [] });
        walk(n.children);
      }
    };
    walk(tree);

    const ips: FlatIp[] = connections.map((c) => ({
      ip: c.dest_ip,
      port: c.dest_port,
      rep: c.reputation ?? "unknown",
      vt: c.vt_malicious_count,
      abuse: c.abuse_score,
    }));

    // pid → the processes' destination set comes from the tree annotation
    // (network_ips); match those strings against the connection table rows.
    const ipIdx = new Map(ips.map((ip, i) => [ip.ip, i]));
    const edges: { p: number; i: number; rep: Reputation }[] = [];
    procs.forEach((p, pi) => {
      for (const ip of p.ips) {
        const ii = ipIdx.get(ip);
        if (ii !== undefined) edges.push({ p: pi, i: ii, rep: ips[ii].rep });
      }
    });
    return { procs, ips, edges };
  }, [tree, connections]);

  if (procs.length === 0 && ips.length === 0) {
    return <p className="text-sm text-text-muted">No processes or connections recorded for this run.</p>;
  }

  const H = Math.max(procs.length, ips.length, 1) * ROW + PAD * 2;
  const rowY = (idx: number) => PAD + idx * ROW + ROW / 2;
  const midX = (RX - (LX + LW)) / 2 + (LX + LW);

  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="Connection topology: processes to destination IPs">
        {/* Edges — reputation-colored bezier curves, process → IP */}
        {edges.map((e, k) => {
          const x1 = LX + LW;
          const y1 = rowY(e.p);
          const x2 = RX;
          const y2 = rowY(e.i);
          return (
            <path
              key={k}
              d={`M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`}
              fill="none"
              stroke={REP_FILL[e.rep]}
              strokeOpacity="0.5"
              strokeWidth="1.5"
            />
          );
        })}

        {/* Processes — left column */}
        {procs.map((p, i) => (
          <g key={p.pid}>
            <rect
              x={LX}
              y={rowY(i) - 13}
              width={LW}
              height={26}
              rx={6}
              fill="var(--bg-elevated)"
              stroke={p.rep ? REP_FILL[p.rep] : "var(--border-subtle)"}
              strokeOpacity={p.rep ? 0.85 : 1}
              strokeWidth={p.rep ? 1.5 : 1}
            />
            <text x={LX + 10} y={rowY(i) + 4} fontSize={11} fill="var(--text-primary)" fontFamily="var(--font-mono)" style={{ fontFamily: "var(--font-mono)" }}>
              {p.name}
            </text>
            <text x={LX + LW - 10} y={rowY(i) + 4} textAnchor="end" fontSize={9} fill="var(--text-faint)" style={{ fontFamily: "var(--font-mono)" }}>
              {p.pid}
            </text>
          </g>
        ))}

        {/* Destinations — right column, clickable to IOC search */}
        {ips.map((ip, j) => (
          <g
            key={ip.ip}
            role="link"
            tabIndex={0}
            className="cursor-pointer"
            onClick={() => nav(`/search?q=${encodeURIComponent(ip.ip)}`)}
            onKeyDown={(e) => {
              if (e.key === "Enter") nav(`/search?q=${encodeURIComponent(ip.ip)}`);
            }}
          >
            <title>{`${ip.ip}:${ip.port ?? "?"} · ${ip.rep}${ip.abuse !== null ? ` · abuse ${ip.abuse}` : ""}${ip.vt !== null ? ` · vt ${ip.vt}` : ""} — open in IOC search`}</title>
            <rect x={RX} y={rowY(j) - 13} width={RW} height={26} rx={6} fill="var(--bg-elevated)" stroke={REP_FILL[ip.rep]} strokeWidth={1.5} strokeOpacity={0.9} />
            <text x={RX + 10} y={rowY(j) + 4} fontSize={11} fill={REP_FILL[ip.rep]} style={{ fontFamily: "var(--font-mono)" }}>
              {ip.ip}
            </text>
            <text x={RX + RW - 10} y={rowY(j) + 4} textAnchor="end" fontSize={9} fill="var(--text-faint)" style={{ fontFamily: "var(--font-mono)" }}>
              :{ip.port ?? "?"}
              {ip.vt !== null && ip.vt > 0 ? ` vt${ip.vt}` : ""}
            </text>
          </g>
        ))}
      </svg>

      {/* Legend — reputation never encoded by color alone */}
      <div className="mt-2 flex flex-wrap items-center gap-3 border-t border-border-subtle pt-2">
        <span className="text-[10px] font-semibold uppercase tracking-wide text-text-faint">legend</span>
        {LEGEND.map((l) => (
          <span key={l.rep} className="inline-flex items-center gap-1.5 text-[10px] text-text-muted">
            <span className="h-2 w-2 rounded-full" style={{ background: REP_FILL[l.rep] }} aria-hidden />
            {l.label}
          </span>
        ))}
        <span className="ml-auto font-mono text-[10px] text-text-faint">
          {procs.length} process{procs.length === 1 ? "" : "es"} → {ips.length} destination{ips.length === 1 ? "" : "s"} · {edges.length} connection{edges.length === 1 ? "" : "s"}
        </span>
      </div>
    </div>
  );
}
