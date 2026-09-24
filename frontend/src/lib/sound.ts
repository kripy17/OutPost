// OutPost SOC Audio Alert Synthesizer
// Zero external assets: uses browser Web Audio API to synthesize alert chimes.

let audioCtx: AudioContext | null = null;

function getAudioContext(): AudioContext | null {
  if (typeof window === "undefined") return null;
  const AudioContextClass = window.AudioContext || (window as any).webkitAudioContext;
  if (!AudioContextClass) return null;
  if (!audioCtx) {
    try {
      audioCtx = new AudioContextClass();
    } catch {
      return null;
    }
  }
  if (audioCtx.state === "suspended") {
    audioCtx.resume().catch(() => {});
  }
  return audioCtx;
}

export function isSocAudioEnabled(): boolean {
  if (typeof window === "undefined") return false;
  return localStorage.getItem("outpost_audio_alerts") === "true";
}

export function setSocAudioEnabled(enabled: boolean): void {
  if (typeof window === "undefined") return;
  localStorage.setItem("outpost_audio_alerts", enabled ? "true" : "false");
}

export function playSocAlertSound(severity: "suspicious" | "malicious" = "malicious"): void {
  if (!isSocAudioEnabled()) return;
  try {
    const ctx = getAudioContext();
    if (!ctx) return;

    const now = ctx.currentTime;
    const osc1 = ctx.createOscillator();
    const osc2 = ctx.createOscillator();
    const gain = ctx.createGain();

    if (severity === "malicious") {
      // Urgent dual-tone chime: 880Hz -> 587.33Hz (A5 -> D5)
      osc1.type = "sawtooth";
      osc1.frequency.setValueAtTime(880, now);
      osc1.frequency.exponentialRampToValueAtTime(587.33, now + 0.25);

      osc2.type = "sine";
      osc2.frequency.setValueAtTime(440, now);
      osc2.frequency.exponentialRampToValueAtTime(293.66, now + 0.25);

      gain.gain.setValueAtTime(0.18, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
    } else {
      // Subtle advisory chime: 523.25Hz -> 659.25Hz (C5 -> E5)
      osc1.type = "sine";
      osc1.frequency.setValueAtTime(523.25, now);
      osc1.frequency.exponentialRampToValueAtTime(659.25, now + 0.15);

      osc2.type = "triangle";
      osc2.frequency.setValueAtTime(261.63, now);
      osc2.frequency.exponentialRampToValueAtTime(329.63, now + 0.15);

      gain.gain.setValueAtTime(0.1, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
    }

    osc1.connect(gain);
    osc2.connect(gain);
    gain.connect(ctx.destination);

    osc1.start(now);
    osc2.start(now);
    osc1.stop(now + 0.36);
    osc2.stop(now + 0.36);
  } catch {
    // Browsers require a user gesture before playing audio
  }
}
