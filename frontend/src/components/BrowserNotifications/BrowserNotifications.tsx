// BrowserNotifications — the desktop-notification equivalent for the webapp
// (spec: "browser notifications for high-severity alerts when not focused").
//
// A Layout-level listener over the same SSE alert stream the Monitor toasts
// from: while the tab is NOT focused, a fired malicious/suspicious alert
// raises a native Notification (deduped per run+rule — the browser replaces
// same-tag notifications instead of stacking). Clicking the notification
// focuses the window and jumps to the run. Purely client-side: opt-in via
// Settings (localStorage `outpost-browser-notify`), gated on
// Notification.permission === "granted" — no backend change, and a browser
// without Notification support simply never fires.

import { useNavigate } from "react-router-dom";
import { useEventStream, type StreamAlert } from "../../lib/useEventStream";
import { browserNotifyEnabled } from "./notify";

export default function BrowserNotifications() {
  const navigate = useNavigate();
  useEventStream((a: StreamAlert) => {
    if (!browserNotifyEnabled()) return;
    if (typeof Notification === "undefined" || Notification.permission !== "granted") return;
    // The whole point: only nag when the operator isn't looking.
    if (document.hasFocus()) return;
    const title = `OutPost — ${a.rule_name} (${a.severity})`;
    const body = a.details.length > 140 ? `${a.details.slice(0, 137)}…` : a.details;
    const n = new Notification(title, {
      body: `${body}\nrun ${a.run_id.slice(0, 12)}`,
      tag: `outpost-${a.run_id}-${a.rule_id}`,
    });
    n.onclick = () => {
      window.focus();
      n.close();
      navigate(`/runs/${a.run_id}`);
    };
  });
  return null;
}
