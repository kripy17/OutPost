import { useRef, useEffect, useState } from "react";
import {
  useReactTable,
  getCoreRowModel,
  ColumnDef,
  flexRender,
  RowSelectionState,
  OnChangeFn,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { AlertCircle, RefreshCw, Inbox } from "lucide-react";

export interface DataTableProps<TData> {
  data: TData[];
  columns: ColumnDef<TData, any>[];
  isLoading?: boolean;
  isError?: boolean;
  error?: Error | null;
  onRetry?: () => void;
  emptyMessage?: string;
  focusedIndex?: number;
  onFocusChange?: (index: number) => void;
  onRowClick?: (row: TData, index: number) => void;
  selectedRows?: RowSelectionState;
  onSelectionChange?: OnChangeFn<RowSelectionState>;
  estimateRowHeight?: number;
}

export function DataTable<TData>({
  data,
  columns,
  isLoading = false,
  isError = false,
  error = null,
  onRetry,
  emptyMessage = "No matching records found",
  focusedIndex = 0,
  onFocusChange,
  onRowClick,
  selectedRows = {},
  onSelectionChange,
  estimateRowHeight = 36,
}: DataTableProps<TData>) {
  const [showLoading, setShowLoading] = useState(false);

  // Show loading indicator only after 300ms delay to prevent flashing
  useEffect(() => {
    if (!isLoading) {
      setShowLoading(false);
      return;
    }
    const timer = setTimeout(() => setShowLoading(true), 300);
    return () => clearTimeout(timer);
  }, [isLoading]);

  const table = useReactTable({
    data,
    columns,
    state: { rowSelection: selectedRows },
    onRowSelectionChange: onSelectionChange,
    getCoreRowModel: getCoreRowModel(),
    enableRowSelection: true,
  });

  const parentRef = useRef<HTMLDivElement>(null);
  const rows = table.getRowModel().rows;

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => estimateRowHeight,
    overscan: 10,
  });

  // Ensure focused row is scrolled into view
  useEffect(() => {
    if (focusedIndex >= 0 && focusedIndex < rows.length) {
      virtualizer.scrollToIndex(focusedIndex, { align: "auto" });
    }
  }, [focusedIndex, rows.length, virtualizer]);

  if (isError) {
    return (
      <div className="flex h-64 flex-col items-center justify-center gap-3 border border-[#26292e] bg-[#141618] p-6 text-center">
        <AlertCircle className="h-6 w-6 text-[#f85149]" />
        <div className="text-[13px] text-[#e6edf3]">
          {error?.message ?? "Failed to load table data"}
        </div>
        {onRetry && (
          <button
            onClick={onRetry}
            className="flex items-center gap-1.5 rounded-[4px] border border-[#26292e] bg-[#1a1d20] px-3 py-1.5 text-[12px] text-[#58a6ff] hover:bg-[#26292e]"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            <span>Retry</span>
          </button>
        )}
      </div>
    );
  }

  if (showLoading) {
    return (
      <div className="flex h-64 flex-col items-center justify-center gap-2 border border-[#26292e] bg-[#141618] text-center">
        <RefreshCw className="h-5 w-5 animate-spin text-[#8b949e]" />
        <span className="text-[12px] font-mono text-[#8b949e]">Loading records…</span>
      </div>
    );
  }

  if (rows.length === 0 && !isLoading) {
    return (
      <div className="flex h-64 flex-col items-center justify-center gap-2 border border-[#26292e] bg-[#141618] text-center">
        <Inbox className="h-6 w-6 text-[#5a626c]" />
        <span className="text-[12px] text-[#8b949e]">{emptyMessage}</span>
      </div>
    );
  }

  return (
    <div
      ref={parentRef}
      className="relative h-full overflow-auto border border-[#26292e] bg-[#0c0d0e]"
    >
      <table className="w-full border-collapse text-left">
        <thead className="sticky top-0 z-20 border-b border-[#26292e] bg-[#141618]">
          {table.getHeaderGroups().map((headerGroup) => (
            <tr key={headerGroup.id}>
              {headerGroup.headers.map((header) => (
                <th
                  key={header.id}
                  className="px-3 py-2 text-[11px] font-medium uppercase tracking-wider text-[#8b949e]"
                  style={{ width: header.getSize() !== 150 ? header.getSize() : undefined }}
                >
                  {header.isPlaceholder
                    ? null
                    : flexRender(header.column.columnDef.header, header.getContext())}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {virtualizer.getVirtualItems().map((virtualRow) => {
            const row = rows[virtualRow.index];
            const isFocused = virtualRow.index === focusedIndex;
            const isSelected = row.getIsSelected();

            return (
              <tr
                key={row.id}
                onClick={() => {
                  onFocusChange?.(virtualRow.index);
                  onRowClick?.(row.original, virtualRow.index);
                }}
                className={`cursor-pointer border-b border-[#26292e]/40 text-[12px] transition ${
                  isFocused
                    ? "bg-[#2f81f7]/15 ring-1 ring-inset ring-[#2f81f7]"
                    : isSelected
                    ? "bg-[#1a1d20]"
                    : "hover:bg-[#141618]"
                }`}
                style={{
                  height: `${virtualRow.size}px`,
                  transform: `translateY(${virtualRow.start - virtualRow.index * virtualRow.size}px)`,
                }}
              >
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="px-3 py-1.5 text-[#e6edf3]">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
