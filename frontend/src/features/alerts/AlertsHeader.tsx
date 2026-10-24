import React from "react";
import { Search, ShieldAlert } from "lucide-react";
import { AlertStatus } from "./types";

interface AlertsHeaderProps {
  unreviewedCount: number;
  statusFilter: "all" | AlertStatus;
  onStatusChange: (status: "all" | AlertStatus) => void;
  searchQuery: string;
  onSearchChange: (query: string) => void;
}

export const AlertsHeader: React.FC<AlertsHeaderProps> = ({
  unreviewedCount,
  statusFilter,
  onStatusChange,
  searchQuery,
  onSearchChange,
}) => {
  return (
    <div className="flex h-11 shrink-0 items-center justify-between border-b border-[#26292e] bg-[#141618] px-3.5">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5 font-medium text-[13px]">
          <ShieldAlert className="h-4 w-4 text-[#58a6ff]" />
          <span>Alerts</span>
        </div>

        <span
          className="rounded-[3px] border border-[#26292e] bg-[#0c0d0e] px-2 py-0.5 font-mono text-[11px] text-[#e3b341]"
          data-testid="unreviewed-counter"
        >
          {unreviewedCount} unreviewed remaining
        </span>
      </div>

      {/* Filter and Search controls */}
      <div className="flex items-center gap-2 text-[12px]">
        {/* Status Filter Tabs */}
        <div className="flex items-center rounded-[3px] border border-[#26292e] bg-[#0c0d0e] p-0.5 font-mono text-[11px]">
          {(["open", "all", "acknowledged", "resolved"] as const).map((s) => (
            <button
              key={s}
              onClick={() => onStatusChange(s)}
              className={`rounded-[2px] px-2 py-0.5 capitalize transition ${
                statusFilter === s
                  ? "bg-[#2f81f7] text-white"
                  : "text-[#8b949e] hover:text-[#e6edf3]"
              }`}
            >
              {s}
            </button>
          ))}
        </div>

        {/* Quick Filter / Search Input */}
        <div className="relative">
          <Search className="absolute left-2 top-2 h-3 w-3 text-[#7d8590]" />
          <input
            type="text"
            placeholder="Filter alerts (/)..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="h-7 w-48 rounded-[3px] border border-[#26292e] bg-[#0c0d0e] pl-7 pr-2 text-[11px] text-[#e6edf3] placeholder-[#7d8590] outline-none focus:border-[#2f81f7]"
          />
        </div>
      </div>
    </div>
  );
};
