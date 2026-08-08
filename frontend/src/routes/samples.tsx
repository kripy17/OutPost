import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Icon, platformIconName } from "../components/Icon";
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

function SampleTile({ s }: { s: SampleRow }) {
  const plat = PLATFORM_META[s.detected_platform];
  const vt = s.vt_detections;
  return (
    <li className="tile group relative flex flex-col rounded-xl border border-border-subtle bg-bg-surface p-4">
      <div className="flex items-start gap-3">
        <span
          className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border ${
            s.detected_platform === "windows"
              ? "border-accent/30 bg-accent/10 text-accent"
              : s.detected_platform === "linux"
                ? "border-risk-clean/30 bg-risk-clean/10 text-risk-clean"
                : "border-border-subtle bg-bg-elevated/60 text-text-muted"
          }`}
        >
          <Icon name={platformIconName(s.detected_platform)} size={20} />
        </span>
        <div className="min-w-0 flex-1">
          <Link
            to={`/samples/${s.sample_id}`}
            className="press block truncate text-[13px] font-semibold text-text-primary transition-colors hover:text-accent"
            title={`Open ${s.original_name} detail`}
          >
            {s.original_name}
          </Link>
          <p className="mt-0.5 truncate text-[11px] text-text-muted">{s.family ?? "untyped sample"}</p>
        </div>
        <Chip tone={plat.tone} dot title={`Detected ${s.detected_platform}`}>
          {plat.label}
        </Chip>
      </div>

      <div className="mt-3 flex items-center gap-2 border-t border-border-subtle pt-3">
        <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-text-faint" title={s.sha256}>
          {s.sha256.slice(0, 20)}…
        </code>
        <span className="font-mono text-[10px] text-text-faint">{formatBytes(s.size)}</span>
      </div>

      <div className="mt-2 flex min-h-[22px] flex-wrap items-center gap-1">
        {s.yara_rules.length > 0 ? (
          <>
            {s.yara_rules.slice(0, 2).map((r) => (
              <span key={r} className="rounded border border-accent/40 bg-accent/5 px-1.5 py-0.5 font-mono text-[10px] text-accent">
                {r}
              </span>
            ))}
            {s.yara_rules.length > 2 && (
              <span className="rounded border border-border-subtle px-1.5 py-0.5 font-mono text-[10px] text-text-faint">
                +{s.yara_rules.length - 2}
              </span>
            )}
          </>
        ) : (
          <span className="font-mono text-[10px] text-text-faint">no signatures</span>
        )}
      </div>

      <div className="mt-auto flex items-center justify-between pt-3">
        {vt !== null ? (
          <Chip tone={vt > 0 ? "malicious" : "clean"} dot title="VirusTotal detections">
            {vt > 0 ? `${vt} detections` : "clean intel"}
          </Chip>
        ) : (
          <span className="font-mono text-[10px] text-text-faint">no intel</span>
        )}
        {s.runs_count > 0 ? (
          <Link
            to="/history"
            className="press inline-flex items-center gap-1 rounded-md border border-border-subtle px-2 py-1 font-mono text-[10px] text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
            title={`${s.runs_count} detonation(s) of ${s.original_name}`}
          >
            <Icon name="activity" size={11} />
            {s.runs_count} detonat{s.runs_count === 1 ? "ion" : "ions"}
          </Link>
        ) : (
          <span className="font-mono text-[10px] text-text-faint">not detonated</span>
        )}
      </div>
    </li>
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
  const byPlatform = (p: SampleRow["detected_platform"]) => samples.filter((s) => s.detected_platform === p).length;

  return (
    <div className="mx-auto max-w-[1400px] px-5 py-8 lg:px-8">
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
            className="press inline-flex items-center gap-2 rounded-lg border border-accent/60 px-4 py-2 font-mono text-xs font-medium text-accent transition-colors duration-150 hover:bg-accent/10"
          >
            <Icon name="plus" size={13} />
            Detonate new
          </Link>
        }
      />

      <dl className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {(
          [
            { label: "Samples", value: data?.total ?? "—", icon: "box", tone: "accent", sub: debounced ? "filtered" : "in vault" },
            { label: "YARA hits", value: withYara, icon: "shield", tone: "default", sub: debounced ? "filtered" : "≥1 signature matched" },
            { label: "VT flagged", value: flagged, icon: "alert", tone: flagged > 0 ? "malicious" : "clean", sub: debounced ? "filtered" : "virus-total positives" },
            { label: "Platform mix", value: `${byPlatform("windows")}/${byPlatform("linux")}/${byPlatform("macos")}`, icon: "globe", tone: "default", sub: debounced ? "filtered" : "win / nix / mac" },
          ] as { label: string; value: string | number; icon: "box" | "shield" | "alert" | "globe"; tone: "default" | "accent" | "malicious" | "clean"; sub: string }[]
        ).map((c) => (
          <div key={c.label} className="panel rounded-xl px-5 py-4">
            <div className="flex items-center gap-2">
              <Icon name={c.icon} size={13} className={c.tone === "malicious" ? "text-risk-malicious" : c.tone === "clean" ? "text-risk-clean" : "text-text-faint"} />
              <Stat label={c.label} value={c.value} tone={c.tone} sub={c.sub} />
            </div>
          </div>
        ))}
      </dl>

      <Panel
        title="Library"
        right={
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-text-faint">
              {debounced ? `${samples.length} of ${data?.total ?? 0}` : data?.total ?? 0} shown
            </span>
            <div className="relative">
              <Icon name="search" size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-faint" />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="filter by name / hash / family…"
                className="w-56 rounded-lg border border-border-subtle bg-bg-base py-1.5 pl-8 pr-3 font-mono text-xs text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
                aria-label="Filter samples"
              />
            </div>
          </div>
        }
      >
        {isLoading && (
          <div className="grid grid-cols-1 gap-3 p-4 sm:grid-cols-2 xl:grid-cols-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="skeleton h-40 w-full" />
            ))}
          </div>
        )}
        {isError && <p className="p-6 text-sm text-risk-malicious">Couldn't load samples — is the backend running?</p>}
        {!isLoading && !isError && samples.length === 0 && (
          <p className="p-6 text-sm text-text-muted">
            {debounced ? "No samples match that filter." : "No samples uploaded yet — detonate one from Monitor."}
          </p>
        )}
        {!isLoading && !isError && samples.length > 0 && (
          <ul className="grid grid-cols-1 gap-3 p-4 sm:grid-cols-2 xl:grid-cols-3">
            {samples.map((s) => (
              <SampleTile key={s.sample_id} s={s} />
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
