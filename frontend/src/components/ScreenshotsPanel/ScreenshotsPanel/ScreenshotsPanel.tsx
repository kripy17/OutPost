import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Icon } from "../Icon";
import { Panel } from "../ui";
import { fetchScreenshotBlob, getRunScreenshots } from "../../lib/api";

/** One authenticated PNG thumbnail — blob URLs because <img src> can't send the Bearer header. */
function Shot({ runId, file, capturedAt }: { runId: string; file: string; capturedAt: string | null }) {
  const [url, setUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let objectUrl: string | null = null;
    let alive = true;
    fetchScreenshotBlob(runId, file)
      .then((blob) => {
        if (!alive) return;
        objectUrl = URL.createObjectURL(blob);
        setUrl(objectUrl);
      })
      .catch(() => {
        if (alive) setFailed(true);
      });
    return () => {
      alive = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [runId, file]);

  if (failed || !url) {
    return (
      <figure className="overflow-hidden rounded-lg border border-border-subtle bg-bg-elevated/40">
        <div className="flex h-24 items-center justify-center font-mono text-[10px] text-text-faint">{failed ? "unavailable" : "…"}</div>
        <figcaption className="border-t border-border-subtle px-2 py-1 font-mono text-[9px] text-text-faint">
          {file}
          {capturedAt ? ` · ${capturedAt.slice(11, 19)}Z` : ""}
        </figcaption>
      </figure>
    );
  }

  return (
    <figure className="group overflow-hidden rounded-lg border border-border-subtle transition-colors hover:border-accent/60">
      <a href={url} target="_blank" rel="noreferrer" title={`Open ${file} full size`}>
        <img src={url} alt={`Detonation screenshot ${file}`} className="h-24 w-full cursor-zoom-in bg-black/60 object-cover object-top transition-transform duration-150 group-hover:scale-[1.02]" loading="lazy" />
      </a>
      <figcaption className="flex items-center gap-1 border-t border-border-subtle px-2 py-1 font-mono text-[9px] text-text-faint">
        <Icon name="camera" size={9} />
        {file}
        {capturedAt ? ` · ${capturedAt.slice(11, 19)}Z` : ""}
      </figcaption>
    </figure>
  );
}

/** Detonation screenshot gallery (docs/10 #4) — only for dynamic-sandbox runs with artifacts. */
export default function ScreenshotsPanel({ runId, source }: { runId: string; source?: string | null }) {
  const enabled = source === "sandbox_dynamic";
  const query = useQuery({
    queryKey: ["run-screenshots", runId],
    queryFn: () => getRunScreenshots(runId),
    enabled,
    staleTime: Infinity,
  });

  if (!enabled || !query.data) return null;
  const { count, shots, capture_status } = query.data;
  if (count === 0) return null;

  return (
    <Panel
      kicker="Detonation · artifacts"
      title="Screenshots"
      className="mb-6"
      right={
        <span className="inline-flex items-center gap-1 font-mono text-[10px] text-text-faint" title={capture_status.error ?? `captured every ${capture_status.interval_seconds}s`}>
          <Icon name="camera" size={11} />
          {count} captured every {capture_status.interval_seconds}s
        </span>
      }
    >
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
        {shots.map((s) => (
          <Shot key={s.file} runId={runId} file={s.file} capturedAt={s.captured_at} />
        ))}
      </div>
    </Panel>
  );
}
