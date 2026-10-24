import React, { useMemo } from "react";
import { ColumnDef, RowSelectionState, OnChangeFn } from "@tanstack/react-table";
import { AlertItem } from "./types";
import { DataTable, FormattedTime, Entity, SEVERITY, normalizeSeverity } from "../../foundation";

interface AlertsTableProps {
  alerts: AlertItem[];
  isLoading: boolean;
  isError: boolean;
  error?: Error | null;
  onRetry: () => void;
  focusedIndex: number;
  onFocusChange: (index: number) => void;
  selectedAlertId?: number | null;
  onSelectAlert: (alert: AlertItem) => void;
  selectedRows: RowSelectionState;
  onSelectionChange: OnChangeFn<RowSelectionState>;
}

export const AlertsTable: React.FC<AlertsTableProps> = ({
  alerts,
  isLoading,
  isError,
  error,
  onRetry,
  focusedIndex,
  onFocusChange,
  onSelectAlert,
  selectedRows,
  onSelectionChange,
}) => {
  const columns = useMemo<ColumnDef<AlertItem, unknown>[]>(
    () => [
      {
        id: "severity",
        header: "Severity",
        size: 100,
        cell: ({ row }) => {
          const sev = normalizeSeverity(row.original.severity);
          const style = SEVERITY[sev];
          return (
            <div className="flex items-center gap-2">
              <span className={`h-4 w-1 rounded-[1px] ${style.bg.replace("bg-", "bg-opacity-100 bg-")}`} />
              <span className={`rounded-[2px] px-1.5 py-0.2 text-[10px] font-semibold uppercase ${style.bg} ${style.text}`}>
                {style.label}
              </span>
            </div>
          );
        },
      },
      {
        accessorKey: "triggered_at",
        header: "Time",
        size: 130,
        cell: ({ row }) => <FormattedTime value={row.original.triggered_at} />,
      },
      {
        accessorKey: "rule_name",
        header: "Rule / Detection",
        cell: ({ row }) => (
          <div className="truncate">
            <span className="font-medium text-[#e6edf3]">{row.original.rule_name}</span>
            <span className="ml-2 font-mono text-[10px] text-[#7d8590]">{row.original.rule_id}</span>
          </div>
        ),
      },
      {
        id: "entity",
        header: "Entity Context",
        size: 180,
        cell: ({ row }) => {
          const pid = row.original.related_pid;
          const ip = row.original.related_ip;
          const host = row.original.host_id || row.original.sample_name;

          if (pid) return <Entity type="process" value={`PID ${pid}`} />;
          if (ip) return <Entity type="ip" value={ip} defang={true} />;
          if (host) return <Entity type="host" value={host} />;
          return <span className="font-mono text-[11px] text-[#7d8590]">—</span>;
        },
      },
      {
        accessorKey: "status",
        header: "Status",
        size: 90,
        cell: ({ row }) => {
          const status = row.original.status || "open";
          const isAck = status === "acknowledged";
          const isRes = status === "resolved";
          return (
            <span
              className={`rounded-[2px] px-1.5 py-0.5 text-[10px] font-mono uppercase ${
                isRes
                  ? "bg-[#3fb950]/15 text-[#56d364]"
                  : isAck
                  ? "bg-[#d29922]/15 text-[#e3b341]"
                  : "bg-[#26292e] text-[#8b949e]"
              }`}
            >
              {status}
            </span>
          );
        },
      },
      {
        accessorKey: "occurrence_count",
        header: "Hits",
        size: 60,
        cell: ({ row }) => (
          <span className="tabular-nums font-mono text-[11px] text-[#7d8590]">
            {row.original.occurrence_count || 1}
          </span>
        ),
      },
    ],
    []
  );

  return (
    <div className="h-full flex-1 min-w-0" data-testid="alerts-table-container">
      <DataTable
        data={alerts}
        columns={columns}
        isLoading={isLoading}
        isError={isError}
        error={error}
        onRetry={onRetry}
        emptyMessage="No alerts matching the active queue filters"
        focusedIndex={focusedIndex}
        onFocusChange={onFocusChange}
        onRowClick={(alert) => onSelectAlert(alert)}
        selectedRows={selectedRows}
        onSelectionChange={onSelectionChange}
        estimateRowHeight={34}
      />
    </div>
  );
};
