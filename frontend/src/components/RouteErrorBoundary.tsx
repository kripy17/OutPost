import { isRouteErrorResponse, Link, useRouteError } from "react-router-dom";
import { Icon } from "./Icon";

export function RouteErrorBoundary() {
  const error = useRouteError();

  let title = "Application Workspace Error";
  let message = "An unexpected error occurred while rendering this workspace view.";
  let detail: string | undefined;

  if (isRouteErrorResponse(error)) {
    if (error.status === 404) {
      title = "Resource Not Found (404)";
      message = "The requested entity, sample, detonation run, or workspace view was not found.";
    } else {
      title = `Application Error (${error.status})`;
      message = error.statusText || message;
    }
    if (typeof error.data === "string") {
      detail = error.data;
    } else if (error.data && typeof error.data === "object") {
      detail = JSON.stringify(error.data, null, 2);
    }
  } else if (error instanceof Error) {
    message = error.message;
    detail = error.stack;
  } else if (typeof error === "string") {
    message = error;
  }

  return (
    <div className="mx-auto max-w-3xl px-6 py-16 font-mono text-xs">
      <div className="rounded-2xl border border-rose-500/30 bg-bg-surface p-6 shadow-xl space-y-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-400">
            <Icon name="alert" size={20} />
          </div>
          <div>
            <span className="text-[10px] uppercase font-bold tracking-wider text-rose-400">
              Workspace Integrity Guard
            </span>
            <h1 className="text-base font-bold text-text-primary">{title}</h1>
          </div>
        </div>

        <p className="text-xs text-text-muted leading-relaxed font-sans">
          {message}
        </p>

        {detail && (
          <details className="rounded-lg border border-border-subtle bg-bg-base/70 p-3 text-[11px] text-text-faint">
            <summary className="cursor-pointer font-semibold text-text-muted hover:text-text-primary select-none">
              ▸ Technical Diagnostics &amp; Stack Trace
            </summary>
            <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap font-mono text-[10px] text-rose-300/80">
              {detail}
            </pre>
          </details>
        )}

        <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-border-subtle/50">
          <Link
            to="/samples"
            className="press inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/15 px-3 py-1.5 font-bold text-accent hover:bg-accent/25 transition"
          >
            <Icon name="box" size={13} />
            <span>Return to Malware Vault</span>
          </Link>
          <button
            onClick={() => window.location.reload()}
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-base px-3 py-1.5 text-text-muted hover:text-text-primary hover:border-accent/40 transition"
          >
            <Icon name="refresh" size={13} />
            <span>Reload Workspace</span>
          </button>
          <Link
            to="/events"
            className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle bg-bg-base px-3 py-1.5 text-text-muted hover:text-text-primary hover:border-accent/40 transition"
          >
            <Icon name="list" size={13} />
            <span>Telemetry Stream</span>
          </Link>
        </div>
      </div>
    </div>
  );
}
