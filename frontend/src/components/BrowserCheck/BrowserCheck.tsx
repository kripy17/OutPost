// BrowserCheck — a one-line strip warning when the browser falls below the
// deck's CSS floor (Tailwind v4 + color-mix()/:has()).
//
// Mounted once in the app Layout, just under the narrow-window notice. Renders
// nothing for a fine browser; on an old/unknown engine it shows the missing
// pieces with a dismiss that sticks for the session. The check itself is pure
// (lib/browserSupport.ts, unit-tested); this component is the only place that
// touches navigator.userAgent and the CSSOM.

import { useState } from "react";
import { checkBrowserSupport, detectFeatures } from "../../lib/browserSupport";

const DISMISS_KEY = "outpost-browser-check-dismissed";

export default function BrowserCheck() {
  // Evaluate once on mount — the UA and feature set cannot change mid-session.
  const [verdict] = useState(() => checkBrowserSupport(navigator.userAgent, detectFeatures()));
  const [dismissed, setDismissed] = useState(
    () => typeof sessionStorage !== "undefined" && sessionStorage.getItem(DISMISS_KEY) === "1",
  );

  if (dismissed || verdict.ok) return null;

  return (
    <div className="browser-check" role="note">
      <span className="browser-check-icon" aria-hidden="true">
        ⚠
      </span>
      <span className="min-w-0">
        This browser ({verdict.browser.name === "unknown" ? "unrecognized engine" : verdict.browser.name}{" "}
        {verdict.browser.name === "unknown" ? "" : verdict.browser.version}) is below the deck's CSS
        floor — missing {verdict.missing.join(", ")}. Some layout and alert visuals may degrade.{" "}
        <span className="text-text-faint">Baseline: Chrome/Edge 111+, Firefox 128+, Safari 16.4+.</span>
      </span>
      <button
        type="button"
        onClick={() => {
          try {
            sessionStorage.setItem(DISMISS_KEY, "1");
          } catch {
            /* storage unavailable — just collapse for this render */
          }
          setDismissed(true);
        }}
        className="browser-check-dismiss"
        aria-label="Dismiss browser warning"
      >
        ×
      </button>
    </div>
  );
}
