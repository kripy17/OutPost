// Catch-all 404 — a typed URL that matches no route lands here instead of the
// raw React Router error boundary. Deck-styled, with an honest way back.
import { Link } from "react-router-dom";
import { Icon } from "../components/Icon";
import { PageHeader } from "../components/ui";

export default function NotFoundPage() {
  return (
    <div className="mx-auto max-w-3xl px-6 py-16 text-center lg:px-10">
      <PageHeader
        kicker="Navigation · 404"
        title={
          <>
            Nothing on this route <span className="font-normal text-text-muted">— yet</span>
          </>
        }
        lede="The URL you hit doesn't match any page in OutPost. It might be a typo, a stale bookmark, or a route that moved. The deck below is where the live signal lives."
      />
      <div className="mt-4 flex items-center justify-center gap-3">
        <Link
          to="/"
          className="press inline-flex items-center gap-2 rounded-lg border border-accent/50 bg-accent/10 px-4 py-2 font-mono text-xs text-accent transition-colors duration-150 hover:bg-accent/15"
        >
          <Icon name="grid" size={13} />
          Overview
        </Link>
        <Link
          to="/events"
          className="press inline-flex items-center gap-2 rounded-lg border border-border-subtle px-4 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
        >
          <Icon name="list" size={13} />
          Event Log
        </Link>
        <Link
          to="/search"
          className="press inline-flex items-center gap-2 rounded-lg border border-border-subtle px-4 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
        >
          <Icon name="search" size={13} />
          IOC Search
        </Link>
      </div>
      <p className="mt-10 font-mono text-[11px] text-text-faint">
        tried path: <span className="text-text-muted">{window.location.pathname}</span>
      </p>
    </div>
  );
}
