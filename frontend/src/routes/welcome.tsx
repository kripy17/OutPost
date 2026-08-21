import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Icon } from "../components/Icon";
import { platformIconName } from "../components/iconMeta";
import { PageHeader, Panel } from "../components/ui";
import { copyToClipboard } from "../lib/clipboard";
import { BASE_URL, getPlatform, onboard } from "../lib/api";

/* ──────────────────────────────────────────────────────────────────────── */
// First-run welcome — the choice a fresh install makes before it shows any
// data: seed the labeled demo campaign, or start empty with a guided
// install-agent flow. Either way the choice is recorded (`/setup/onboard`),
// so the welcome never reappears — and a new install never silently shows
// demo data as real (seeded installs carry the demo banner instead).
/* ──────────────────────────────────────────────────────────────────────── */

export default function WelcomePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { data: plat } = useQuery({ queryKey: ["platform"], queryFn: getPlatform, staleTime: Infinity });
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const choose = useMutation({
    mutationFn: (choice: "demo" | "empty") => onboard(choice),
    onSuccess: (_data, choice) => {
      void queryClient.invalidateQueries({ queryKey: ["meta"] });
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
      void queryClient.invalidateQueries({ queryKey: ["campaigns"] });
      navigate(choice === "demo" ? "/" : "/monitor", { replace: true });
    },
    onError: () => setError("Couldn't reach the backend — is it running?"),
  });

  const host = plat ? (plat.os === "windows" ? "windows" : plat.os === "macos" ? "macos" : "linux") : "linux";
  const collector = plat?.os === "windows" ? "collectors\\windows\\collector_win.py" : "collectors/linux/collector_linux.py";
  const agentCmd = `python ${collector} --backend-url ${BASE_URL} --mode live`;

  return (
    <div className="mx-auto max-w-4xl px-6 py-14 lg:px-10">
      <PageHeader
        kicker="Welcome · first run"
        title={
          <>
            OutPost <span className="font-normal text-text-muted">— behavioral security monitor</span>
          </>
        }
        lede="Detect suspicious activity on this host, watch dynamic detonations land in real time, and track shared infrastructure across every session. Nothing has been seeded yet — pick how you want to start."
      />

      <div className="mt-10 grid gap-5 lg:grid-cols-2">
        {/* Path A — seed the labeled demo campaign */}
        <Panel
          kicker="Explore first"
          title="Seed the demo campaign"
          className="flex flex-col"
          bodyClassName="flex flex-1 flex-col p-5"
        >
          <p className="text-sm leading-relaxed text-text-muted">
            Load a realistic analysis campaign — a dropper detonation (macro → LOLBin → C2 → persistence),
            detection alerts, a shared-C2 cluster, and pre-populated IOC search — so you can explore every page
            before any real telemetry flows.
          </p>
          <ul className="mt-4 space-y-2 text-xs text-text-muted">
            {[
              "Synthetic samples with full process trees & kill chains",
              "Campaign clustering + ATT&CK coverage pre-populated",
              "Clearly labeled as demo — never masquerades as real host data",
            ].map((line) => (
              <li key={line} className="flex items-start gap-2">
                <Icon name="check" size={12} className="mt-0.5 shrink-0 text-accent" />
                {line}
              </li>
            ))}
          </ul>
          <div className="mt-auto pt-5">
            <button
              onClick={() => choose.mutate("demo")}
              disabled={choose.isPending}
              className="press inline-flex w-full items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2.5 text-xs font-semibold text-bg-base transition-all duration-150 hover:bg-accent-soft hover:shadow-[var(--glow-accent)] disabled:opacity-50"
            >
              <Icon name="play" size={13} />
              {choose.isPending ? "Seeding…" : "Seed demo campaign"}
            </button>
          </div>
        </Panel>

        {/* Path B — start empty, guided install-agent flow */}
        <Panel
          kicker="Monitor for real"
          title="Start empty — monitor this host"
          className="flex flex-col"
          bodyClassName="flex flex-1 flex-col p-5"
        >
          <p className="text-sm leading-relaxed text-text-muted">
            Keep the console clean and stream this machine's actual activity. Three steps:
          </p>
          <ol className="mt-4 space-y-3">
            <li className="flex items-start gap-2.5">
              <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-accent/50 font-mono text-[10px] text-accent">
                1
              </span>
              <span className="text-xs leading-relaxed text-text-muted">
                Open <Link to="/monitor" className="font-semibold text-accent hover:underline">Live Monitor</Link> and
                click <span className="font-mono text-text-primary">Start live monitoring</span>
                {plat && plat.os !== "macos" && (
                  <span className="text-text-faint"> (auto-detected {host} host)</span>
                )}
                .
              </span>
            </li>
            <li className="flex items-start gap-2.5">
              <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-accent/50 font-mono text-[10px] text-accent">
                2
              </span>
              <span className="min-w-0 flex-1 text-xs leading-relaxed text-text-muted">
                Run the collector on this machine — it streams real processes, connections, and file activity
                (auditd on Linux / Sysmon on Windows):
                <span className="mt-2 flex items-center gap-2">
                  <code className="min-w-0 flex-1 overflow-x-auto rounded-lg border border-border-subtle bg-bg-elevated/40 px-2.5 py-1.5 font-mono text-[10px] text-text-primary">
                    {agentCmd}
                  </code>
                  <button
                    onClick={() =>
                      void copyToClipboard(agentCmd).then(() => {
                        setCopied(true);
                        setTimeout(() => setCopied(false), 1600);
                      })
                    }
                    className="press inline-flex items-center gap-1 rounded-lg border border-border-subtle px-2 py-1.5 font-mono text-[10px] text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
                    aria-label="Copy the collector command"
                  >
                    <Icon name={copied ? "check" : "copy"} size={11} />
                    {copied ? "copied" : "copy"}
                  </button>
                </span>
              </span>
            </li>
            <li className="flex items-start gap-2.5">
              <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-accent/50 font-mono text-[10px] text-accent">
                3
              </span>
              <span className="text-xs leading-relaxed text-text-muted">
                Watch events land live in the Monitor's process tree and the{" "}
                <Link to="/events" className="font-semibold text-accent hover:underline">Event Log</Link> — detections
                fire the moment they happen. For a persistent service:{" "}
                <code className="font-mono text-text-primary">outpost agent install</code>.
              </span>
            </li>
          </ol>
          <div className="mt-auto pt-5">
            <button
              onClick={() => choose.mutate("empty")}
              disabled={choose.isPending}
              className="press inline-flex w-full items-center justify-center gap-2 rounded-lg border border-accent/60 bg-accent/10 px-4 py-2.5 text-xs font-semibold text-accent transition-all duration-150 hover:bg-accent/20 hover:shadow-[var(--glow-accent)] disabled:opacity-50"
            >
              <Icon name="terminal" size={13} />
              {choose.isPending ? "Starting…" : "Start empty · guided setup"}
            </button>
          </div>
        </Panel>
      </div>

      <p className="mt-6 flex flex-wrap items-center justify-center gap-x-4 gap-y-1 font-mono text-[10px] text-text-faint">
        {plat && (
          <span className="inline-flex items-center gap-1.5">
            <Icon name={platformIconName(host as "windows" | "linux" | "macos")} size={11} />
            detected {host} {plat.release}
          </span>
        )}
        <span>You can seed later anytime — <code className="text-text-muted">python -m app.seed_demo</code> from backend/</span>
      </p>

      {error && <p className="mt-4 text-center text-xs text-risk-malicious">{error}</p>}
    </div>
  );
}
