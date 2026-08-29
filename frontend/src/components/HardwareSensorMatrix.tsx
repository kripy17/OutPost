import { Icon } from "./Icon";

export interface HardwareSensorMatrixProps {
  deviceAccess?: {
    microphone?: { in_use: boolean; devices?: string[]; label?: string };
    camera?: { in_use: boolean; devices?: string[]; label?: string };
    screen_capture?: { in_use: boolean; label?: string };
    audio_capture?: { in_use: boolean; label?: string };
    audio_playback?: { in_use: boolean; devices?: string[]; label?: string };
    video_capture?: { in_use: boolean; label?: string };
    gpu?: { in_use: boolean; nodes?: string[]; client_count?: number; label?: string };
    sleep_inhibition?: { in_use: boolean; label?: string };
  };
  metrics?: {
    cpu_percent?: number;
    memory_mb?: number;
    listening_sockets?: number;
    gpu_clients?: number;
  };
}

export function HardwareSensorMatrix({ deviceAccess, metrics }: HardwareSensorMatrixProps) {
  const sensors = [
    {
      id: "mic",
      name: "Microphone & Audio Input",
      icon: "terminal" as const,
      active: !!deviceAccess?.microphone?.in_use || !!deviceAccess?.audio_capture?.in_use,
      label: deviceAccess?.microphone?.label || (deviceAccess?.microphone?.in_use ? "Active Stream" : "Standby / Silent"),
      tone: deviceAccess?.microphone?.in_use ? "border-risk-malicious bg-risk-malicious/15 text-risk-malicious" : "border-border-subtle bg-bg-surface text-text-muted",
    },
    {
      id: "camera",
      name: "Optical Camera Sensor",
      icon: "box" as const,
      active: !!deviceAccess?.camera?.in_use || !!deviceAccess?.video_capture?.in_use,
      label: deviceAccess?.camera?.label || (deviceAccess?.camera?.in_use ? "Capturing Video" : "Inactive"),
      tone: deviceAccess?.camera?.in_use ? "border-risk-malicious bg-risk-malicious/15 text-risk-malicious" : "border-border-subtle bg-bg-surface text-text-muted",
    },
    {
      id: "screen",
      name: "Screen Pipe & Display Server",
      icon: "grid" as const,
      active: !!deviceAccess?.screen_capture?.in_use,
      label: deviceAccess?.screen_capture?.label || (deviceAccess?.screen_capture?.in_use ? "Screen Recording" : "Clean"),
      tone: deviceAccess?.screen_capture?.in_use ? "border-risk-suspicious bg-risk-suspicious/15 text-risk-suspicious" : "border-border-subtle bg-bg-surface text-text-muted",
    },
    {
      id: "gpu",
      name: "GPU & Direct Rendering Node",
      icon: "activity" as const,
      active: !!deviceAccess?.gpu?.in_use || (metrics?.gpu_clients ?? 0) > 0,
      label: deviceAccess?.gpu?.label || `${metrics?.gpu_clients ?? 0} Render Client(s)`,
      tone: (deviceAccess?.gpu?.in_use || (metrics?.gpu_clients ?? 0) > 0) ? "border-accent/60 bg-accent/15 text-accent" : "border-border-subtle bg-bg-surface text-text-muted",
    },
    {
      id: "power",
      name: "Power & Sleep Lock State",
      icon: "sliders" as const,
      active: !!deviceAccess?.sleep_inhibition?.in_use,
      label: deviceAccess?.sleep_inhibition?.label || "Normal ACPI Sleep",
      tone: deviceAccess?.sleep_inhibition?.in_use ? "border-risk-suspicious bg-risk-suspicious/15 text-risk-suspicious" : "border-border-subtle bg-bg-surface text-text-muted",
    },
  ];

  return (
    <div className="space-y-3 rounded-2xl border border-border-subtle bg-bg-surface/50 p-4">
      <div className="flex items-center justify-between border-b border-border-subtle pb-3">
        <div className="flex items-center gap-2">
          <Icon name="sliders" size={16} className="text-accent" />
          <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-text-primary">
            Host Hardware & Device Sensor Matrix
          </h3>
        </div>
        <span className="font-mono text-[10px] text-text-faint">
          Real-time /dev and pipe surveillance
        </span>
      </div>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {sensors.map((s) => (
          <div
            key={s.id}
            className={`flex items-start justify-between rounded-xl border p-3 transition ${s.tone}`}
          >
            <div>
              <div className="flex items-center gap-2">
                <Icon name={s.icon} size={14} />
                <span className="text-xs font-semibold text-text-primary">{s.name}</span>
              </div>
              <p className="mt-1 font-mono text-[11px] text-text-muted">{s.label}</p>
            </div>
            <span
              className={`h-2 w-2 rounded-full ${
                s.active ? "bg-accent animate-pulse shadow-[var(--glow-accent)]" : "bg-text-faint/30"
              }`}
            />
          </div>
        ))}
      </div>
    </div>
  );
}
