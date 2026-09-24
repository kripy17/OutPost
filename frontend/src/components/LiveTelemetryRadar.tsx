import { useEffect, useRef, useState, useMemo } from "react";

export interface RadarTarget {
  id: string;
  label: string;
  distance: number; // 0.1 to 0.95 (normalized radius)
  angle: number; // 0 to 360 (degrees)
  severity: "clean" | "suspicious" | "malicious";
  type: "agent" | "threat" | "connection";
  details?: string;
}

interface LiveTelemetryRadarProps {
  targets?: RadarTarget[];
  activeThreatCount?: number;
  onlineAgentCount?: number;
  className?: string;
}

export default function LiveTelemetryRadar({
  targets: propTargets,
  activeThreatCount = 0,
  onlineAgentCount = 1,
  className = "",
}: LiveTelemetryRadarProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [selectedTarget, setSelectedTarget] = useState<RadarTarget | null>(null);
  const [rangeZoom, setRangeZoom] = useState<"LOCAL" | "FLEET" | "GLOBAL">("FLEET");

  // Fallback demo targets if none provided
  const targets = useMemo<RadarTarget[]>(() => {
    if (propTargets && propTargets.length > 0) return propTargets;
    return [
      { id: "tgt-1", label: "Primary Host (Linux 6.8)", distance: 0.25, angle: 45, severity: "clean", type: "agent", details: "PID 1492 · Normal" },
      { id: "tgt-2", label: "Gateway Node", distance: 0.55, angle: 130, severity: "clean", type: "agent", details: "192.168.1.1 · Active" },
      { id: "tgt-3", label: "SSH Ingress (Port 22)", distance: 0.72, angle: 215, severity: activeThreatCount > 0 ? "malicious" : "suspicious", type: "threat", details: "External probe detected" },
      { id: "tgt-4", label: "DNS Tunneling Probe", distance: 0.88, angle: 310, severity: activeThreatCount > 0 ? "malicious" : "clean", type: "threat", details: "UDP 53 · High entropy" },
      { id: "tgt-5", label: "Workstation Alpha", distance: 0.4, angle: 290, severity: "clean", type: "agent", details: "Telemetry Active" },
    ];
  }, [propTargets, activeThreatCount]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId: number;
    let angleRad = 0;

    const render = () => {
      const width = canvas.width;
      const height = canvas.height;
      const centerX = width / 2;
      const centerY = height / 2;
      const radius = Math.min(centerX, centerY) - 18;

      ctx.clearRect(0, 0, width, height);

      // Radar background base
      ctx.fillStyle = "rgba(7, 10, 16, 0.95)";
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
      ctx.fill();

      // Concentric Range Rings
      ctx.strokeStyle = "rgba(99, 102, 241, 0.15)";
      ctx.lineWidth = 1;
      const rings = [0.25, 0.5, 0.75, 1.0];
      for (const r of rings) {
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius * r, 0, Math.PI * 2);
        ctx.stroke();
      }

      // Range ring distance labels
      ctx.fillStyle = "rgba(148, 163, 184, 0.5)";
      ctx.font = "9px ui-monospace, monospace";
      ctx.fillText("25%", centerX + 4, centerY - radius * 0.25 + 10);
      ctx.fillText("50%", centerX + 4, centerY - radius * 0.5 + 10);
      ctx.fillText("75%", centerX + 4, centerY - radius * 0.75 + 10);
      ctx.fillText("100%", centerX + 4, centerY - radius * 1.0 + 10);

      // Crosshairs & Cardinal axes
      ctx.strokeStyle = "rgba(99, 102, 241, 0.25)";
      ctx.beginPath();
      ctx.moveTo(centerX - radius, centerY);
      ctx.lineTo(centerX + radius, centerY);
      ctx.moveTo(centerX, centerY - radius);
      ctx.lineTo(centerX, centerY + radius);
      ctx.stroke();

      // Degree Azimuth Labels
      ctx.fillStyle = "rgba(99, 102, 241, 0.7)";
      ctx.font = "10px ui-monospace, monospace";
      ctx.textAlign = "center";
      ctx.fillText("000°", centerX, centerY - radius + 12);
      ctx.fillText("090°", centerX + radius - 14, centerY + 3);
      ctx.fillText("180°", centerX, centerY + radius - 4);
      ctx.fillText("270°", centerX - radius + 14, centerY + 3);

      // Rotating Radar Beam with Phosphor Fade
      const sweepTailAngle = 0.5; // ~28 degrees
      const gradient = ctx.createConicGradient(angleRad, centerX, centerY);
      gradient.addColorStop(0, "rgba(6, 182, 212, 0.45)");
      gradient.addColorStop(sweepTailAngle / (Math.PI * 2), "rgba(6, 182, 212, 0.0)");
      gradient.addColorStop(1, "rgba(6, 182, 212, 0.0)");

      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
      ctx.fill();

      // Sharp Leading Radar Beam Line
      const beamX = centerX + Math.cos(angleRad) * radius;
      const beamY = centerY + Math.sin(angleRad) * radius;
      ctx.strokeStyle = "rgba(6, 182, 212, 0.85)";
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.lineTo(beamX, beamY);
      ctx.stroke();

      // Render Targets / Blips
      for (const tgt of targets) {
        const tgtRad = (tgt.angle * Math.PI) / 180;
        const tgtDist = tgt.distance * radius;
        const tgtX = centerX + Math.cos(tgtRad) * tgtDist;
        const tgtY = centerY + Math.sin(tgtRad) * tgtDist;

        // Angle difference to current sweep beam to calculate flash
        let diff = (angleRad - tgtRad) % (Math.PI * 2);
        if (diff < 0) diff += Math.PI * 2;
        const isSwept = diff < 0.6;

        let blipColor = "rgba(16, 185, 129, 0.85)"; // clean
        if (tgt.severity === "suspicious") blipColor = "rgba(245, 158, 11, 0.9)";
        if (tgt.severity === "malicious") blipColor = "rgba(239, 68, 68, 0.95)";

        // Blip Glow & Core
        ctx.fillStyle = blipColor;
        ctx.beginPath();
        ctx.arc(tgtX, tgtY, isSwept ? 4.5 : 3, 0, Math.PI * 2);
        ctx.fill();

        // Pulsing ring if threat or recently swept
        if (isSwept || tgt.severity === "malicious") {
          ctx.strokeStyle = blipColor;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.arc(tgtX, tgtY, isSwept ? 8 : 6, 0, Math.PI * 2);
          ctx.stroke();
        }
      }

      // Outer bezel ring
      ctx.strokeStyle = "rgba(99, 102, 241, 0.4)";
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
      ctx.stroke();

      // Advance sweep rotation (3.5 seconds per full 360 rotation)
      angleRad = (angleRad + 0.03) % (Math.PI * 2);
      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [targets]);

  return (
    <div className={`hud-card hud-corner flex flex-col p-4 ${className}`}>
      {/* HUD Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-subtle/70 pb-3">
        <div className="flex items-center gap-2">
          <span className="led-dot led-dot-signal animate-pulse" />
          <span className="tactical-header text-text-primary">
            Live Telemetry Radar // 360° Spectrum
          </span>
        </div>
        <div className="flex items-center gap-1 font-mono text-[10px]">
          {(["LOCAL", "FLEET", "GLOBAL"] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => setRangeZoom(mode)}
              className={`rounded px-2 py-0.5 transition-colors ${
                rangeZoom === mode
                  ? "bg-accent/20 text-accent font-bold border border-accent/40"
                  : "text-text-faint hover:text-text-muted hover:bg-bg-elevated"
              }`}
            >
              {mode}
            </button>
          ))}
        </div>
      </div>

      {/* Canvas Radar Container */}
      <div className="relative my-3 flex items-center justify-center">
        <canvas
          ref={canvasRef}
          width={300}
          height={300}
          className="rounded-full shadow-[0_0_24px_rgba(6,182,212,0.12)] border border-cyan-500/20"
        />

        {/* Overlay HUD Readouts */}
        <div className="pointer-events-none absolute left-3 top-3 font-mono text-[10px] text-text-faint space-y-0.5">
          <p>RANGE: <span className="text-text-primary font-bold">{rangeZoom === "LOCAL" ? "10km" : rangeZoom === "FLEET" ? "250km" : "GLOBAL"}</span></p>
          <p>AZIMUTH: <span className="text-signal font-bold">ACTIVE SCAN</span></p>
        </div>

        <div className="pointer-events-none absolute right-3 top-3 text-right font-mono text-[10px] text-text-faint space-y-0.5">
          <p>AGENTS: <span className="text-risk-clean font-bold">{onlineAgentCount} ONLINE</span></p>
          <p>THREATS: <span className={`font-bold ${activeThreatCount > 0 ? "text-risk-malicious" : "text-risk-clean"}`}>{activeThreatCount} DETECTED</span></p>
        </div>
      </div>

      {/* Target Status Roster */}
      <div className="mt-auto border-t border-border-subtle/70 pt-3">
        <div className="flex items-center justify-between font-mono text-[10px] text-text-faint mb-1.5">
          <span>TRACKED TARGETS ({targets.length})</span>
          <span>RANGE BEARING</span>
        </div>
        <div className="space-y-1 max-h-28 overflow-y-auto pr-1">
          {targets.map((tgt) => (
            <button
              key={tgt.id}
              onClick={() => setSelectedTarget(tgt)}
              className={`flex w-full items-center justify-between rounded px-2 py-1 text-left font-mono text-[11px] transition-colors ${
                selectedTarget?.id === tgt.id
                  ? "bg-accent/15 text-text-primary border border-accent/30"
                  : "hover:bg-bg-elevated/60 text-text-muted"
              }`}
            >
              <div className="flex items-center gap-2 truncate">
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    tgt.severity === "malicious"
                      ? "bg-risk-malicious"
                      : tgt.severity === "suspicious"
                        ? "bg-risk-suspicious"
                        : "bg-risk-clean"
                  }`}
                />
                <span className="truncate">{tgt.label}</span>
              </div>
              <span className="text-text-faint shrink-0 ml-2">
                {tgt.angle.toString().padStart(3, "0")}° · {Math.round(tgt.distance * 100)}%
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
