// OutPost Audio Alerts — Purged of synthetic WebAudio siren effects for SOC compliance.
// Safe no-op stubs maintained for backwards compatibility with any remaining callers.

export function isSocAudioEnabled(): boolean {
  return false;
}

export function setSocAudioEnabled(_enabled: boolean): void {
  // Purged: SOC environments enforce silent visual indicators over audible sirens.
}

export function playSocAlertSound(_severity: "suspicious" | "malicious" = "malicious"): void {
  // Purged: Zero audible alerts. All triage signals use visual badges and toasts.
}
