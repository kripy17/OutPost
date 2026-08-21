import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../components/Icon";
import { platformIconName } from "../components/iconMeta";
import { Chip, PageHeader, Panel, Stat } from "../components/ui";
import { deleteAllSamples, deleteSample, exportSamplesCsv, getSamples, saveBlob } from "../lib/api";
import type { SampleRow } from "../types";
import { formatBytes } from "./samplesHelpers";

const PLATFORM_META: Record<SampleRow["detected_platform"], { label: string; tone: "accent" | "clean" | "suspicious" | "muted" }> = {
  windows: { label: "win", tone: "accent" },
  linux: { label: "nix", tone: "clean" },
  macos: { label: "mac", tone: "suspicious" },
  unknown: { label: "?", tone: "muted" },
};

function SampleTile({ s, onDelete }: { s: SampleRow; onDelete: (id: string, name: string) => void }) {
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
        {s.synthetic && (
          <Chip tone="accent" dot title="Entire detonation history is demo/synthetic (seed / webapp detonation / sandbox demo)">
            demo
          </Chip>
        )}
        <button
          onClick={() => onDelete(s.sample_id, s.original_name)}
          className="press -mr-1 -mt-1 rounded p-1 text-text-faint transition-colors hover:bg-risk-malicious/10 hover:text-risk-malicious"
          title={`Delete ${s.original_name}`}
        >
          <Icon name="x" size={13} />
        </button>
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
        <div className="flex items-center gap-1.5">
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
            <Link
              to={`/samples/${s.sample_id}`}
              className="press inline-flex items-center gap-1 rounded-md border border-accent/40 bg-accent/5 px-2 py-1 font-mono text-[10px] text-accent transition-colors duration-150 hover:bg-accent/15"
              title={`Detonate ${s.original_name}`}
            >
              <Icon name="play" size={10} />
              detonate
            </Link>
          )}
        </div>
      </div>
    </li>
  );
}

export default function SamplesPage() {
  const queryClient = useQueryClient();
  const [q, setQ] = useState("");
  const [debounced, setDebounced] = useState("");
  // The vault reads as real artifacts first: binaries whose entire detonation
  // history is demo/synthetic are hidden unless the analyst asks (archive
  // parity with History / the Event Log). Persisted like the other toggles.
  const [showSynthetic, setShowSynthetic] = useState(() => {
    try {
      return localStorage.getItem("outpost-samples-synthetic") === "1";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem("outpost-samples-synthetic", showSynthetic ? "1" : "0");
    } catch {
      /* storage unavailable */
    }
  }, [showSynthetic]);

  useEffect(() => {
    const t = setTimeout(() => setDebounced(q.trim()), 300);
    return () => clearTimeout(t);
  }, [q]);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["samples", debounced, showSynthetic],
    queryFn: () => getSamples({ q: debounced, limit: 200, include_synthetic: showSynthetic || undefined }),
  });

  const samples = data?.samples ?? [];
  const [exportError, setExportError] = useState<string | null>(null);

  const onExport = async () => {
    try {
      const blob = await exportSamplesCsv({ q: debounced, include_synthetic: showSynthetic || undefined });
      saveBlob(blob, "outpost-samples.csv");
    } catch {
      setExportError("CSV export failed — is the backend running?");
    }
  };

  const handleDeleteSample = async (sampleId: string, name: string) => {
    if (!window.confirm(`Delete sample ${name} from vault?`)) return;
    try {
      await deleteSample(sampleId);
      void queryClient.invalidateQueries({ queryKey: ["samples"] });
    } catch {
      setExportError(`Failed to delete sample ${name}`);
    }
  };

  const handleClearVault = async () => {
    if (!window.confirm("Delete ALL samples in the vault? This cannot be undone.")) return;
    try {
      await deleteAllSamples();
      void queryClient.invalidateQueries({ queryKey: ["samples"] });
    } catch {
      setExportError("Failed to clear sample vault");
    }
  };

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
          <div className="flex items-center gap-2">
            {exportError && <span className="font-mono text-[10px] text-risk-malicious">{exportError}</span>}
            {samples.length > 0 && (
              <button
                onClick={() => void handleClearVault()}
                className="press rounded-lg border border-risk-malicious/40 bg-risk-malicious/5 px-3 py-2 font-mono text-xs text-risk-malicious transition-colors hover:bg-risk-malicious/15"
                title="Wipe all samples in the vault"
              >
                Clear vault
              </button>
            )}
            <button
              onClick={() => setShowSynthetic((v) => !v)}
              aria-pressed={showSynthetic}
              title={
                showSynthetic
                  ? "Hide demo/synthetic binaries again (those whose whole detonation history is demo)"
                  : "Include binaries whose entire detonation history is demo/synthetic"
              }
              className={`press rounded-lg border px-3 py-2 font-mono text-xs transition-colors duration-150 ${
                showSynthetic ? "border-accent/50 bg-accent/10 text-accent" : "border-border-subtle text-text-faint hover:text-text-primary"
              }`}
            >
              {showSynthetic ? "Show synthetic · on" : "Show synthetic"}
            </button>
            <button
              onClick={() => void onExport()}
              className="press inline-flex items-center gap-1.5 rounded-lg border border-border-subtle px-3 py-2 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent"
              title="Download the vault as CSV"
            >
              <Icon name="download" size={12} />
              Export CSV
            </button>
            <Link
              to="/monitor"
              className="press inline-flex items-center gap-2 rounded-lg border border-accent/60 px-4 py-2 font-mono text-xs font-medium text-accent transition-colors duration-150 hover:bg-accent/10"
            >
              <Icon name="plus" size={13} />
              Detonate new
            </Link>
          </div>
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
              <SampleTile key={s.sample_id} s={s} onDelete={handleDeleteSample} />
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
