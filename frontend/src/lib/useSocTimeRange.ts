// Shared SOC Investigation Time Range State
// Aligned with Elastic Security / Splunk universal time picker architecture.
// Synchronizes across all workstation screens via localStorage & window storage events.

import { useEffect, useState } from "react";

export type SocTimeRangeOption = "15m" | "1h" | "6h" | "24h" | "7d" | "30d" | "all";

export interface SocTimeRangePreset {
  id: SocTimeRangeOption;
  label: string;
  seconds: number;
}

export const SOC_TIME_PRESETS: SocTimeRangePreset[] = [
  { id: "15m", label: "Last 15 minutes", seconds: 15 * 60 },
  { id: "1h", label: "Last 1 hour", seconds: 60 * 60 },
  { id: "6h", label: "Last 6 hours", seconds: 6 * 60 * 60 },
  { id: "24h", label: "Last 24 hours", seconds: 24 * 60 * 60 },
  { id: "7d", label: "Last 7 days", seconds: 7 * 24 * 60 * 60 },
  { id: "30d", label: "Last 30 days", seconds: 30 * 24 * 60 * 60 },
  { id: "all", label: "All Telemetry (Full Scope)", seconds: 0 },
];

const STORAGE_KEY = "outpost_soc_time_range";
const EVENT_NAME = "outpost-time-range-change";

export function getSavedSocTimeRange(): SocTimeRangeOption {
  if (typeof window === "undefined") return "24h";
  const saved = localStorage.getItem(STORAGE_KEY) as SocTimeRangeOption | null;
  if (saved && SOC_TIME_PRESETS.some((p) => p.id === saved)) {
    return saved;
  }
  return "24h";
}

export function saveSocTimeRange(range: SocTimeRangeOption): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(STORAGE_KEY, range);
  window.dispatchEvent(new CustomEvent(EVENT_NAME, { detail: range }));
}

export function useSocTimeRange() {
  const [range, setRangeState] = useState<SocTimeRangeOption>(getSavedSocTimeRange);

  useEffect(() => {
    const handleCustomChange = (e: Event) => {
      const customEvent = e as CustomEvent<SocTimeRangeOption>;
      if (customEvent.detail && customEvent.detail !== range) {
        setRangeState(customEvent.detail);
      }
    };

    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY && e.newValue) {
        const next = e.newValue as SocTimeRangeOption;
        if (SOC_TIME_PRESETS.some((p) => p.id === next)) {
          setRangeState(next);
        }
      }
    };

    window.addEventListener(EVENT_NAME, handleCustomChange);
    window.addEventListener("storage", handleStorageChange);
    return () => {
      window.removeEventListener(EVENT_NAME, handleCustomChange);
      window.removeEventListener("storage", handleStorageChange);
    };
  }, [range]);

  const setRange = (newRange: SocTimeRangeOption) => {
    setRangeState(newRange);
    saveSocTimeRange(newRange);
  };

  const preset = SOC_TIME_PRESETS.find((p) => p.id === range) ?? SOC_TIME_PRESETS[3];

  return {
    range,
    setRange,
    preset,
    seconds: preset.seconds,
  };
}
