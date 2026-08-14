// Deferred — render children one frame after mount.
//
// The Overview's interactive anchor (the "N sessions" text in PostureHeader)
// only needs the runs query, but the whole page mounts in one React commit —
// every section's initial render (queries + skeletons) happens before the
// anchor can appear. Wrapping the below-the-fold sections in <Deferred>
// keeps the first commit lean (header + posture), so the anchor lands after
// a small mount instead of the whole page, and the heavy sections mount on
// the next frame with zero visual difference (they were below the fold).
//
// One frame is the smallest honest delay: children mount before the user can
// scroll to them, and their queries start ~16ms later — a non-issue for data
// that was never going to arrive sooner than the anchor anyway.
import { useEffect, useState, type ReactNode } from "react";

export function Deferred({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const id = requestAnimationFrame(() => setReady(true));
    return () => cancelAnimationFrame(id);
  }, []);
  if (!ready) return null;
  return <>{children}</>;
}
