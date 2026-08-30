import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Icon } from "../components/Icon";
import { login, setAuthToken } from "../lib/api";

export default function LoginPage() {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password) return;
    setBusy(true);
    setError(null);
    try {
      const res = await login(password);
      setAuthToken(res.token);
      // The boot gate cached `me: unauthenticated` — force it to re-read with
      // the fresh token, then land on the Overview.
      await queryClient.invalidateQueries({ queryKey: ["me"] });
      navigate("/", { replace: true });
    } catch {
      setError("Invalid password — try the admin or analyst password for this server.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto flex min-h-[80vh] max-w-sm flex-col items-center justify-center px-6">
      <div className="w-full rounded-2xl border border-border-subtle bg-bg-surface p-8 shadow-[var(--shadow-raised)]">
        <div className="mb-6 flex flex-col items-center text-center">
          <span className="flex h-12 w-12 items-center justify-center rounded-xl border border-accent/40 bg-accent/10 text-accent">
            <Icon name="shield" size={22} />
          </span>
          <p className="kicker mt-4">
            {typeof window !== "undefined" ? localStorage.getItem("outpost-custom-title") || "OutPost" : "OutPost"}
          </p>
          <h1 className="display mt-1">Sign in</h1>
          <p className="mt-2 text-xs leading-relaxed text-text-muted">
            This server requires authentication. Enter the admin password for full
            access, or the analyst password for read-only triage.
          </p>
        </div>

        <form onSubmit={onSubmit} className="space-y-3">
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="password"
            autoFocus
            className="w-full rounded-lg border border-border-subtle bg-bg-base px-3 py-2.5 font-mono text-sm text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
            aria-label="Password"
          />
          {error && <p className="text-xs text-risk-malicious">{error}</p>}
          <button
            type="submit"
            disabled={busy || !password}
            className="press inline-flex w-full items-center justify-center gap-2 rounded-lg border border-accent/60 bg-accent/10 px-4 py-2.5 font-mono text-sm font-medium text-accent transition-all duration-150 hover:shadow-[var(--glow-accent)] disabled:cursor-default disabled:opacity-50"
          >
            <Icon name={busy ? "refresh" : "arrowRight"} size={13} className={busy ? "animate-spin" : ""} />
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
