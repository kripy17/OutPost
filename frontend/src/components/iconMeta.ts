// Icon metadata — event-type / platform → icon-name maps and the OS→icon
// resolver. Pure data + functions, separate from the icon components so the
// Icon.tsx module stays fast-refreshable (react-refresh/only-export-components).

import type { IconName } from "./Icon";

/** Map an event type / platform / action to its icon name. */
export const EVENT_ICON: Record<string, IconName> = {
  process_create: "process",
  network_connection: "network",
  file_write: "file",
  registry_write: "registry",
};

export function platformIconName(os: string): IconName {
  if (os === "windows") return "windows";
  if (os === "macos" || os === "darwin") return "mac";
  if (os === "linux") return "linux";
  return "terminal"; // unknown / unclassified — never fake an OS
}
