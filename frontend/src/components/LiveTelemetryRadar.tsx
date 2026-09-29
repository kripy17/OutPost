import { useEffect, useRef, useState, useCallback } from "react";
import { getNetworkMatrix } from "../lib/api";

interface Socket {
  protocol: string;
  local_ip: string;
  local_port: number;
  remote_ip?: string | null;
  remote_port?: number | null;
  status: string;
  pid?: number | null;
  process_name: string;
  label?: string;
  is_external?: boolean;
  is_suspicious_port?: boolean;
}

interface NetworkData {
  public_listeners: Socket[];
  loopback_listeners: Socket[];
  outbound_connections: Socket[];
  multicast_listeners: Socket[];
  summary: {
    public_listeners_count: number;
    loopback_listeners_count: number;
    outbound_count: number;
    multicast_count: number;
    total_sockets: number;
  };
}

// Colours per category
const CAT_COLOR = {
  public: "#f85149",    // red — exposed to network
  loopback: "#3fb950",  // green — local only
  outbound: "#58a6ff",  // blue — initiated by host
  multicast: "#d29922", // amber — multicast/broadcast
} as const;

type CatKey = keyof typeof CAT_COLOR;

interface RingEntry {
  cat: CatKey;
  label: string;
  port: number;
  proto: string;
  process: string;
  status: string;
  is_suspicious?: boolean;
  remote?: string;
}

function buildRing(net: NetworkData): RingEntry[] {
  const entries: RingEntry[] = [];

  for (const s of net.public_listeners) {
    entries.push({
      cat: "public",
      label: s.label || s.process_name,
      port: s.local_port,
      proto: s.protocol.toUpperCase(),
      process: s.process_name,
      status: s.status,
    });
  }
  for (const s of net.loopback_listeners) {
    entries.push({
      cat: "loopback",
      label: s.label || s.process_name,
      port: s.local_port,
      proto: s.protocol.toUpperCase(),
      process: s.process_name,
      status: s.status,
    });
  }
  for (const s of net.outbound_connections) {
    entries.push({
      cat: "outbound",
      label: s.process_name,
      port: s.local_port,
      proto: s.protocol.toUpperCase(),
      process: s.process_name,
      status: s.status,
      is_suspicious: s.is_suspicious_port,
      remote: s.remote_ip ? `${s.remote_ip}:${s.remote_port}` : undefined,
    });
  }
  for (const s of net.multicast_listeners) {
    entries.push({
      cat: "multicast",
      label: s.label || s.process_name,
      port: s.local_port,
      proto: s.protocol.toUpperCase(),
      process: s.process_name,
      status: s.status,
    });
  }

  return entries;
}

function drawRing(canvas: HTMLCanvasElement, ring: RingEntry[], frameAngle: number) {
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const W = canvas.width;
  const H = canvas.height;
  const cx = W / 2;
  const cy = H / 2;
  const outerR = Math.min(cx, cy) - 14;
  const innerR = outerR * 0.38;
  const midR = (outerR + innerR) / 2;

  ctx.clearRect(0, 0, W, H);

  // Dark background disc
  ctx.fillStyle = "rgba(7,10,16,0.96)";
  ctx.beginPath();
  ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
  ctx.fill();

  const total = ring.length;

  if (total === 0) {
    // Empty state
    ctx.strokeStyle = "rgba(99,102,241,0.18)";
    ctx.lineWidth = 1;
    ctx.setLineDash([4, 6]);
    ctx.beginPath();
    ctx.arc(cx, cy, midR, 0, Math.PI * 2);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = "rgba(148,163,184,0.4)";
    ctx.font = "11px ui-monospace,monospace";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("NO ACTIVE SOCKETS", cx, cy);
    return;
  }

  const segAngle = (Math.PI * 2) / total;
  const gap = Math.min(0.04, segAngle * 0.12);

  // ── Arc segments ──────────────────────────────────────────────
  for (let i = 0; i < total; i++) {
    const entry = ring[i];
    const startA = i * segAngle - Math.PI / 2 + gap / 2;
    const endA = startA + segAngle - gap;
    const color = CAT_COLOR[entry.cat];

    // Outer filled arc (thin band)
    const bandOuter = outerR;
    const bandInner = outerR - 10;
    ctx.beginPath();
    ctx.arc(cx, cy, bandOuter, startA, endA);
    ctx.arc(cx, cy, bandInner, endA, startA, true);
    ctx.closePath();
    ctx.fillStyle = entry.is_suspicious ? "rgba(239,68,68,0.85)" : color + "cc";
    ctx.fill();

    // Mid arc (connector line from center ring to outer band)
    const spokeMidA = startA + (endA - startA) / 2;
    const sx1 = cx + Math.cos(spokeMidA) * (innerR + 4);
    const sy1 = cy + Math.sin(spokeMidA) * (innerR + 4);
    const sx2 = cx + Math.cos(spokeMidA) * (bandInner - 2);
    const sy2 = cy + Math.sin(spokeMidA) * (bandInner - 2);
    ctx.strokeStyle = color + "55";
    ctx.lineWidth = 1;
    ctx.setLineDash([2, 3]);
    ctx.beginPath();
    ctx.moveTo(sx1, sy1);
    ctx.lineTo(sx2, sy2);
    ctx.stroke();
    ctx.setLineDash([]);

    // Port label on outer band (only when enough segments exist per arc)
    if (segAngle > 0.18) {
      const labelR = bandOuter - 5;
      const lx = cx + Math.cos(spokeMidA) * labelR;
      const ly = cy + Math.sin(spokeMidA) * labelR;
      ctx.save();
      ctx.translate(lx, ly);
      ctx.rotate(spokeMidA + Math.PI / 2);
      ctx.fillStyle = "#f0f6fc";
      ctx.font = "bold 8px ui-monospace,monospace";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(String(entry.port), 0, 0);
      ctx.restore();
    }
  }

  // ── Inner hub ring ──────────────────────────────────────────────
  // Animated sweep highlight around inner ring
  const sweepLen = Math.PI * 0.6;
  const sweepGrad = ctx.createConicGradient(frameAngle - sweepLen / 2, cx, cy);
  sweepGrad.addColorStop(0, "rgba(6,182,212,0.0)");
  sweepGrad.addColorStop(sweepLen / (Math.PI * 2), "rgba(6,182,212,0.3)");
  sweepGrad.addColorStop(sweepLen / (Math.PI * 2) + 0.001, "rgba(6,182,212,0.0)");
  sweepGrad.addColorStop(1, "rgba(6,182,212,0.0)");

  ctx.beginPath();
  ctx.arc(cx, cy, innerR + 4, 0, Math.PI * 2);
  ctx.arc(cx, cy, innerR - 4, Math.PI * 2, 0, true);
  ctx.closePath();
  ctx.fillStyle = sweepGrad;
  ctx.fill();

  // Static inner ring border
  ctx.strokeStyle = "rgba(6,182,212,0.35)";
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.arc(cx, cy, innerR, 0, Math.PI * 2);
  ctx.stroke();

  // Center hub stats
  ctx.fillStyle = "#f0f6fc";
  ctx.font = "bold 18px ui-monospace,monospace";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(String(total), cx, cy - 8);
  ctx.fillStyle = "rgba(148,163,184,0.7)";
  ctx.font = "8px ui-monospace,monospace";
  ctx.fillText("SOCKETS", cx, cy + 8);

  // Outer bezel
  ctx.strokeStyle = "rgba(99,102,241,0.3)";
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
  ctx.stroke();
}

export default function LiveTelemetryRadar({ className = "" }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const frameRef = useRef<number>(0);
  const angleRef = useRef<number>(0);
  const [net, setNet] = useState<NetworkData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [selected, setSelected] = useState<RingEntry | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const ring = net ? buildRing(net) : [];

  const fetchData = useCallback(async () => {
    try {
      setError(false);
      const data = await getNetworkMatrix();
      setNet(data);
      setLastRefresh(new Date());
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial fetch + 10s refresh
  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, 10_000);
    return () => clearInterval(id);
  }, [fetchData]);

  // Canvas animation loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const animate = () => {
      angleRef.current = (angleRef.current + 0.018) % (Math.PI * 2);
      drawRing(canvas, ring, angleRef.current);
      frameRef.current = requestAnimationFrame(animate);
    };
    frameRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frameRef.current);
  }, [ring]);

  // Click on canvas → select nearest entry
  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (ring.length === 0) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const cx = canvas.width / 2;
    const cy = canvas.height / 2;
    const angle = Math.atan2(my - cy, mx - cx) + Math.PI / 2;
    const norm = ((angle % (Math.PI * 2)) + Math.PI * 2) % (Math.PI * 2);
    const idx = Math.floor((norm / (Math.PI * 2)) * ring.length);
    setSelected(ring[idx] ?? null);
  };

  const hasSuspicious = ring.some((e) => e.is_suspicious);

  return (
    <div className={`hud-card hud-corner flex flex-col p-4 ${className}`}>
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-subtle/70 pb-3">
        <div className="flex items-center gap-2">
          <span className="led-dot led-dot-signal animate-pulse" />
          <span className="tactical-header text-text-primary">
            Live Network Topology
          </span>
        </div>
        <div className="flex items-center gap-2">
          {hasSuspicious && (
            <span className="rounded border border-risk-malicious/40 bg-risk-malicious/10 px-2 py-0.5 font-mono text-[10px] font-bold text-risk-malicious">
              ⚠ SUSPICIOUS PORT
            </span>
          )}
          <button
            onClick={fetchData}
            className="rounded px-2 py-0.5 font-mono text-[10px] text-text-faint hover:text-text-muted hover:bg-bg-elevated transition-colors"
            title="Refresh now"
          >
            ↻ REFRESH
          </button>
        </div>
      </div>

      {/* Canvas Ring */}
      <div className="relative my-3 flex items-center justify-center">
        {loading ? (
          <div className="flex h-[280px] w-[280px] items-center justify-center font-mono text-[11px] text-text-faint animate-pulse">
            SCANNING SOCKETS…
          </div>
        ) : error ? (
          <div className="flex h-[280px] w-[280px] flex-col items-center justify-center gap-2 font-mono text-[11px] text-text-faint">
            <span className="text-risk-malicious">⚠ BACKEND UNREACHABLE</span>
            <button onClick={fetchData} className="text-accent hover:underline text-[10px]">
              RETRY
            </button>
          </div>
        ) : (
          <canvas
            ref={canvasRef}
            width={280}
            height={280}
            onClick={handleCanvasClick}
            className="cursor-crosshair rounded-full border border-cyan-500/15 shadow-[0_0_20px_rgba(6,182,212,0.08)]"
          />
        )}

        {/* Overlay: summary counters */}
        {!loading && !error && net && (
          <>
            <div className="pointer-events-none absolute left-2 top-2 space-y-0.5 font-mono text-[10px] text-text-faint">
              <p>
                PUB{" "}
                <span className="font-bold" style={{ color: CAT_COLOR.public }}>
                  {net.summary.public_listeners_count}
                </span>
              </p>
              <p>
                LO{" "}
                <span className="font-bold" style={{ color: CAT_COLOR.loopback }}>
                  {net.summary.loopback_listeners_count}
                </span>
              </p>
            </div>
            <div className="pointer-events-none absolute right-2 top-2 space-y-0.5 text-right font-mono text-[10px] text-text-faint">
              <p>
                OUT{" "}
                <span className="font-bold" style={{ color: CAT_COLOR.outbound }}>
                  {net.summary.outbound_count}
                </span>
              </p>
              <p>
                MCAST{" "}
                <span className="font-bold" style={{ color: CAT_COLOR.multicast }}>
                  {net.summary.multicast_count}
                </span>
              </p>
            </div>
            {lastRefresh && (
              <div className="pointer-events-none absolute bottom-2 left-0 right-0 text-center font-mono text-[9px] text-text-faint/60">
                {lastRefresh.toLocaleTimeString()}
              </div>
            )}
          </>
        )}
      </div>

      {/* Legend */}
      <div className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[10px] text-text-faint">
        {(Object.entries(CAT_COLOR) as [CatKey, string][]).map(([k, c]) => (
          <span key={k} className="flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: c }} />
            {k.toUpperCase()}
          </span>
        ))}
      </div>

      {/* Selected socket detail */}
      {selected ? (
        <div className="mt-auto rounded border border-border-subtle/60 bg-bg-base/60 p-2 font-mono text-[11px] space-y-0.5">
          <div className="flex items-center justify-between">
            <span
              className="font-bold uppercase"
              style={{ color: CAT_COLOR[selected.cat] }}
            >
              {selected.cat}
            </span>
            {selected.is_suspicious && (
              <span className="text-risk-malicious font-bold text-[10px]">⚠ SUSPICIOUS</span>
            )}
            <button
              onClick={() => setSelected(null)}
              className="text-text-faint hover:text-text-muted ml-2"
            >
              ✕
            </button>
          </div>
          <div className="text-text-primary font-semibold truncate">{selected.process}</div>
          <div className="text-text-muted">
            {selected.proto} :{selected.port}
            {selected.remote && (
              <span className="ml-2 text-text-faint">→ {selected.remote}</span>
            )}
          </div>
          <div className="text-text-faint text-[10px] uppercase">{selected.status}</div>
        </div>
      ) : (
        /* Socket list (compact) */
        <div className="mt-auto border-t border-border-subtle/70 pt-2">
          <div className="mb-1.5 flex items-center justify-between font-mono text-[10px] text-text-faint">
            <span>SOCKET ROSTER ({ring.length})</span>
            <span>PROTO:PORT</span>
          </div>
          <div className="max-h-28 space-y-0.5 overflow-y-auto pr-1">
            {ring.slice(0, 24).map((e, i) => (
              <button
                key={i}
                onClick={() => setSelected(e)}
                className="flex w-full items-center justify-between rounded px-2 py-0.5 text-left font-mono text-[11px] transition-colors hover:bg-bg-elevated/60 text-text-muted"
              >
                <div className="flex items-center gap-2 truncate">
                  <span
                    className="h-1.5 w-1.5 shrink-0 rounded-full"
                    style={{
                      backgroundColor: e.is_suspicious
                        ? CAT_COLOR.public
                        : CAT_COLOR[e.cat],
                    }}
                  />
                  <span className="truncate">{e.process}</span>
                </div>
                <span className="ml-2 shrink-0 text-text-faint">
                  {e.proto}:{e.port}
                </span>
              </button>
            ))}
            {ring.length === 0 && (
              <div className="py-4 text-center text-[11px] text-text-faint">
                No active sockets detected
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
