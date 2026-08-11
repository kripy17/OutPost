// Browser-notification preference + permission helpers — shared by the
// Settings toggle and the global notifier component.

export const BROWSER_NOTIFY_KEY = "outpost-browser-notify";

export function browserNotifyEnabled(): boolean {
  return typeof localStorage !== "undefined" && localStorage.getItem(BROWSER_NOTIFY_KEY) === "on";
}

export function setBrowserNotifyEnabled(on: boolean): void {
  if (on) localStorage.setItem(BROWSER_NOTIFY_KEY, "on");
  else localStorage.removeItem(BROWSER_NOTIFY_KEY);
}

export function browserPermission(): NotificationPermission {
  return typeof Notification === "undefined" ? "denied" : Notification.permission;
}
