import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Chip, PageHeader, Panel, Stat } from "../components/ui";
import { getSamples } from "../lib/api";
import type { SampleRow } from "../types";

const PLATFORM_META: Record<SampleRow["detected_platform"], { label: string; tone: "accent" | "clean" | "suspicious" | "muted" }> = {
  windows: { label: "win", tone: "accent" },
  linux: { label: "nix", tone: "clean" },
  macos: { label: "mac", tone: "suspicious" },
  unknown: { label: "?", tone: "muted" },
};

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function SampleRowView({ s }: { s: SampleRow }) {
  const plat = PLATFORM_META[s.detected_platform];
  return (
    <tr className="border-b border-border-subtle/50 align-top transition-colors hover:bg-bg-elevated/30">
      <td className="px-4 py-3">
        <div className="flex items-start gap-3">
          <span
            aria-hidden
            className="mt-0.5 inline-flex h-7 w-7 shrink-0 items-center justify-center rounded border border-border-subtle bg-bg-elevated/50 font-mono text-[10px] text-text-faint"
          >
            {s.detected_platform === "windows" ? "PE" : s.detected_platform === "linux" ? "ELF" : "·"}
          </span>
          <div className="min-w-0">
            <Link
              to={`/samples/${s.sample_id}`}
              className="press block truncate font-mono text-xs font-medium text-text-primary transition-colors hover:text-accent-amber"
              title={`Open ${s.original_name} detail`}
            >
              {s.original_name}
            </Link>
            <p className="mt-0.5 truncate text-[11px] text-text-muted">{s.family ?? "untyped"}</p>
          </div>
        </div>
      </td>
      <td className="px-4 py-3">
        <Chip tone={plat.tone} dot title={`Detected ${s.detected_platform}`}>
          {plat.label}
        </Chip>
      </td>
      <td className="px-4 py-3">
        <code
          className="font-mono text-[11px] text-text-muted"
          title={s.sha256}
        >
          {s.sha256.slice(0, 16)}…
        </code>
      </td>
      <td className="px-4 py-3 font-mono text-[11px] text-text-faint">{formatBytes(s.size)}</td>
      <td className="px-4 py-3">
        {s.yara_rules.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {s.yara_rules.slice(0, 3).map((r) => (
              <span
                key={r}
                className="rounded border border-accent-amber/40 bg-accent-amber/5 px-1.5 py-0.5 font-mono text-[10px] text-accent-amber"
              >
                {r}
              </span>
            ))}
            {s.yara_rules.length > 3 && (
              <span className="rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[10px] text-text-faint">
                +{s.yara_rules.length - 3}
              </span>
            )}
          </div>
        ) : (
          <span className="font-mono text-[10px] text-text-faint">—</span>
        )}
      </td>
      <td className="px-4 py-3">
        {s.vt_detections !== null ? (
          <Chip tone={s.vt_detections > 0 ? "malicious" : "clean"} dot title="VirusTotal detections">
            {s.vt_detections}
          </Chip>
        ) : (
          <span className="font-mono text-[10px] text-text-faint">no intel</span>
        )}
        {s.malware_family && (
          <p className="mt-1 font-mono text-[10px] text-risk-malicious">{s.malware_family}</p>
        )}
      </td>
      <td className="px-4 py-3 text-right">
        {s.runs_count > 0 ? (
          <Link
            to="/history"
            className="press inline-flex items-center gap-1 rounded border border-border-subtle px-2 py-0.5 font-mono text-[10px] text-text-muted transition-colors duration-150 hover:border-accent-amber/60 hover:text-accent-amber"
            title={`${s.runs_count} detonation(s) of ${s.original_name}`}
          >
            {s.runs_count} detonat{s.runs_count === 1 ? "ion" : "ions"}
          </Link>
        ) : (
          <span className="font-mono text-[10px] text-text-faint">not detonated</span>
        )}
      </td>
    </tr>
  );
}

export default function SamplesPage() {
  const [q, setQ] = useState("");
  const [debounced, setDebounced] = useState("");

  useEffect(() => {
    const t = setTimeout(() => setDebounced(q.trim()), 300);
    return () => clearTimeout(t);
  }, [q]);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["samples", debounced],
    queryFn: () => getSamples({ q: debounced, limit: 200 }),
  });

  const samples = data?.samples ?? [];
  const withYara = samples.filter((s) => s.yara_rules.length > 0).length;
  const flagged = samples.filter((s) => (s.vt_detections ?? 0) > 0).length;
  const byPlatform = (p: SampleRow["detected_platform"]) =>
    samples.filter((s) => s.detected_platform === p).length;

  return (
    <div className="mx-auto max-w-7xl px-6 py-8 lg:px-10">
      <PageHeader
        kicker="Intelligence · samples"
        title={
          <>
            Sample vault <span className="font-normal text-text-muted">— every uploaded binary, scanned</span>
          </>
        }
        lede="The binaries submitted for detonation with their OS sniff, YARA signature hits, and VirusTotal reputation — searchable by name, hash, or family. Upload new ones from the Monitor page."
        actions={
          <Link
            to="/monitor"
            className="press rounded border border-accent-amber/60 px-4 py-2 font-mono text-xs text-accent-amber transition-colors duration-150 hover:bg-accent-amber/10"
          >
            ▸ Detonate new
          </Link>
        }
      />

      <dl className="mb-6 grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border-subtle bg-border-subtle sm:grid-cols-4">
        <div className="bg-bg-surface p-4">
          <Stat label="Samples" value={data?.total ?? "—"} tone="accent" sub={debounced ? "filtered" : "in vault"} />
        </div>
        <div className="bg-bg-surface p-4">
          <Stat label="YARA hits" value={withYara} tone="default" sub={debounced ? "filtered" : "≥1 signature matched"} />
        </div>
        <div className="bg-bg-surface p-4">
          <Stat
            label="VT flagged"
            value={flagged}
            tone={flagged > 0 ? "malicious" : "clean"}
            sub={debounced ? "filtered" : "virus-total positives"}
          />
        </div>
        <div className="bg-bg-surface p-4">
          <Stat
            label="Platform mix"
            value={`${byPlatform("windows")}/${byPlatform("linux")}/${byPlatform("macos")}`}
            tone="default"
            sub={debounced ? "filtered" : "win / nix / mac"}
          />
        </div>
      </dl>

      <Panel
        title="Library"
        right={
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-text-faint">
              {debounced ? `${samples.length} of ${data?.total ?? 0}` : data?.total ?? 0} shown
            </span>
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="filter by name / hash / family…"
              className="w-56 rounded border border-border-subtle bg-bg-base px-3 py-1.5 font-mono text-xs text-text-primary placeholder:text-text-faint focus:border-accent-amber/60 focus:outline-none"
              aria-label="Filter samples"
            />
          </div>
        }
        pad={false}
      >
        {isLoading && <p className="p-6 text-sm text-text-muted">Loading sample vault…</p>}
        {isError && (
          <p className="p-6 text-sm text-risk-malicious">Couldn't load samples — is the backend running?</p>
        )}
        {!isLoading && !isError && samples.length === 0 && (
          <p className="p-6 text-sm text-text-muted">
            {debounced ? "No samples match that filter." : "No samples uploaded yet — detonate one from Monitor."}
          </p>
        )}
        {!isLoading && !isError && samples.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="border-b border-border-subtle">
                <tr className="text-[10px] uppercase tracking-widest text-text-faint">
                  <th className="px-4 py-2.5">Sample</th>
                  <th className="px-4 py-2.5">Platform</th>
                  <th className="px-4 py-2.5">SHA-256</th>
                  <th className="px-4 py-2.5">Size</th>
                  <th className="px-4 py-2.5">YARA</th>
                  <th className="px-4 py-2.5">Reputation</th>
                  <th className="px-4 py-2.5 text-right">Detonations</th>
                </tr>
              </thead>
              <tbody>
                {samples.map((s) => (
                  <SampleRowView key={s.sample_id} s={s} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
