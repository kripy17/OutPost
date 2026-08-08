import { useMemo, useState } from "react";
import type { NetworkConnection } from "../../types";
import ReputationBadge from "./ReputationBadge";

type SortKey = "dest_ip" | "dest_port" | "first_seen" | "reputation";

export default function NetworkTable({ connections }: { connections: NetworkConnection[] }) {
  const [sortKey, setSortKey] = useState<SortKey>("reputation");
  const [asc, setAsc] = useState(true);

  const sorted = useMemo(() => {
    const rank = { malicious: 0, suspicious: 1, unknown: 2, clean: 3 };
    const val = (c: NetworkConnection): string | number => {
      if (sortKey === "reputation") return rank[c.reputation] ?? 4;
      return c[sortKey] ?? "";
    };
    return [...connections].sort((a, b) => {
      const x = val(a);
      const y = val(b);
      const cmp = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y));
      return asc ? cmp : -cmp;
    });
  }, [connections, sortKey, asc]);

  if (connections.length === 0) {
    return <p className="text-sm text-text-muted">No network connections recorded for this run.</p>;
  }

  const header = (label: string, key: SortKey) => (
    <button
      onClick={() => {
        if (sortKey === key) setAsc((v) => !v);
        else {
          setSortKey(key);
          setAsc(true);
        }
      }}
      className="text-left text-xs font-semibold text-text-muted transition-colors duration-150 hover:text-text-muted"
    >
      {label}
      {sortKey === key && <span className="ml-1 text-accent">{asc ? "↑" : "↓"}</span>}
    </button>
  );

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left">
        <thead className="border-b border-border-subtle">
          <tr>
            <th className="pb-2">{header("Destination", "dest_ip")}</th>
            <th className="pb-2">{header("Port", "dest_port")}</th>
            <th className="pb-2">Proto</th>
            <th className="pb-2">{header("Reputation", "reputation")}</th>
            <th className="pb-2">Abuse</th>
            <th className="pb-2">VT</th>
            <th className="pb-2">{header("First seen", "first_seen")}</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((c) => (
            <tr key={`${c.dest_ip}-${c.dest_port}`} className="border-b border-border-subtle/50 transition-colors hover:bg-bg-elevated">
              <td className="py-2 font-mono text-sm text-text-primary">{c.dest_ip}</td>
              <td className="py-2 font-mono text-xs tabular-nums text-text-muted">{c.dest_port ?? "-"}</td>
              <td className="py-2 font-mono text-xs text-text-muted">{c.protocol ?? "-"}</td>
              <td className="py-2">
                <ReputationBadge reputation={c.reputation} watchlist={c.watchlist === true} watchlistLabel={c.watchlist_label} />
              </td>
              <td className="py-2 font-mono text-xs text-text-muted">{c.abuse_score ?? "-"}</td>
              <td className="py-2 font-mono text-xs text-text-muted">{c.vt_malicious_count ?? "-"}</td>
              <td className="py-2 font-mono text-xs text-text-faint">{c.first_seen.slice(0, 19).replace("T", " ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
