import React, { useState, useMemo, useCallback } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { RowSelectionState } from "@tanstack/react-table";
import { AlertItem, AlertStatus } from "./types";
import { AlertsHeader } from "./AlertsHeader";
import { AlertsTable } from "./AlertsTable";
import { AlertDetailDrawer } from "./AlertDetailDrawer";
import {
  useKeymap,
  useOptimisticAction,
  ConfirmDialog,
  SeverityLevel,
  normalizeSeverity,
} from "../../foundation";

export const AlertsView: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const queryClient = useQueryClient();

  const statusFilter = (searchParams.get("status") || "open") as "all" | AlertStatus;
  const severityFilter = (searchParams.get("severity") || "all") as "all" | SeverityLevel;
  const searchQuery = searchParams.get("q") || "";
  const selectedIdParam = searchParams.get("selected");

  const [focusedIndex, setFocusedIndex] = useState<number>(0);
  const [selectedRows, setSelectedRows] = useState<RowSelectionState>({});
  const [caseDialogOpen, setCaseDialogOpen] = useState<boolean>(false);
  const [alertToEscalate, setAlertToEscalate] = useState<AlertItem | null>(null);

  // Fetch alerts from backend
  const { data: rawAlerts = [], isLoading, isError, error, refetch } = useQuery<AlertItem[]>({
    queryKey: ["alerts", "queue"],
    queryFn: async () => {
      const res = await fetch("/alerts?limit=200");
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to load alerts`);
      return res.json();
    },
  });

  // Client-side filtering
  const filteredAlerts = useMemo(() => {
    return rawAlerts.filter((a) => {
      if (statusFilter !== "all" && a.status !== statusFilter) return false;
      if (severityFilter !== "all" && normalizeSeverity(a.severity) !== severityFilter) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const matchesRule = a.rule_name.toLowerCase().includes(q) || a.rule_id.toLowerCase().includes(q);
        const matchesDetails = (a.details || "").toLowerCase().includes(q);
        const matchesHost = (a.host_id || "").toLowerCase().includes(q) || (a.sample_name || "").toLowerCase().includes(q);
        if (!matchesRule && !matchesDetails && !matchesHost) return false;
      }
      return true;
    });
  }, [rawAlerts, statusFilter, severityFilter, searchQuery]);

  // Selected alert derived from URL or focused index
  const selectedAlert = useMemo<AlertItem | null>(() => {
    if (filteredAlerts.length === 0) return null;
    if (selectedIdParam) {
      const found = filteredAlerts.find((a) => a.id.toString() === selectedIdParam);
      if (found) return found;
    }
    const idx = Math.max(0, Math.min(focusedIndex, filteredAlerts.length - 1));
    return filteredAlerts[idx] || null;
  }, [filteredAlerts, selectedIdParam, focusedIndex]);

  // Progress counter: count unreviewed (open) alerts
  const unreviewedCount = useMemo(() => {
    return rawAlerts.filter((a) => a.status === "open").length;
  }, [rawAlerts]);

  // Sync selection to URL
  const handleSelectAlert = useCallback(
    (alert: AlertItem) => {
      const next = new URLSearchParams(searchParams);
      next.set("selected", alert.id.toString());
      setSearchParams(next, { replace: true });
    },
    [searchParams, setSearchParams]
  );

  // Advance cursor to next alert
  const advanceCursor = useCallback(() => {
    setFocusedIndex((prev) => {
      const nextIdx = Math.min(prev + 1, filteredAlerts.length - 1);
      const nextAlert = filteredAlerts[nextIdx];
      if (nextAlert) handleSelectAlert(nextAlert);
      return nextIdx;
    });
  }, [filteredAlerts, handleSelectAlert]);

  // Optimistic Acknowledge Mutation
  const { mutate: acknowledgeAlert } = useOptimisticAction<{ updated: number }, AlertItem, { prevAlerts: AlertItem[] }>({
    mutationFn: async (alert) => {
      const res = await fetch(`/alerts/bulk`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids: [alert.id], status: "acknowledged" }),
      });
      if (!res.ok) throw new Error("Acknowledge failed");
      return res.json();
    },
    optimisticUpdate: (alert) => {
      const prev = queryClient.getQueryData<AlertItem[]>(["alerts", "queue"]) || [];
      queryClient.setQueryData<AlertItem[]>(
        ["alerts", "queue"],
        prev.map((a) => (a.id === alert.id ? { ...a, status: "acknowledged" } : a))
      );
      advanceCursor();
      return { prevAlerts: prev };
    },
    rollback: (ctx) => {
      if (ctx?.prevAlerts) queryClient.setQueryData(["alerts", "queue"], ctx.prevAlerts);
    },
    successMessage: "Alert acknowledged",
    queryKeyToInvalidate: ["alerts", "queue"],
  });

  // Optimistic False Positive Mutation
  const { mutate: markFalsePositive } = useOptimisticAction<{ status: string }, AlertItem, { prevAlerts: AlertItem[] }>({
    mutationFn: async (alert) => {
      const res = await fetch(`/alerts/${alert.id}/fp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ comment: "Marked false positive from triage queue" }),
      });
      if (!res.ok) throw new Error("FP feedback failed");
      return res.json();
    },
    optimisticUpdate: (alert) => {
      const prev = queryClient.getQueryData<AlertItem[]>(["alerts", "queue"]) || [];
      queryClient.setQueryData<AlertItem[]>(
        ["alerts", "queue"],
        prev.map((a) => (a.id === alert.id ? { ...a, status: "resolved" } : a))
      );
      advanceCursor();
      return { prevAlerts: prev };
    },
    rollback: (ctx) => {
      if (ctx?.prevAlerts) queryClient.setQueryData(["alerts", "queue"], ctx.prevAlerts);
    },
    successMessage: "Marked as false positive and tuned",
    queryKeyToInvalidate: ["alerts", "queue"],
  });

  // Keyboard triage handler
  useKeymap({
    j: () => {
      setFocusedIndex((prev) => {
        const next = Math.min(prev + 1, filteredAlerts.length - 1);
        if (filteredAlerts[next]) handleSelectAlert(filteredAlerts[next]);
        return next;
      });
    },
    k: () => {
      setFocusedIndex((prev) => {
        const next = Math.max(0, prev - 1);
        if (filteredAlerts[next]) handleSelectAlert(filteredAlerts[next]);
        return next;
      });
    },
    a: () => {
      if (selectedAlert && selectedAlert.status === "open") {
        acknowledgeAlert(selectedAlert);
      }
    },
    f: () => {
      if (selectedAlert) {
        markFalsePositive(selectedAlert);
      }
    },
    e: () => {
      if (selectedAlert) {
        setAlertToEscalate(selectedAlert);
        setCaseDialogOpen(true);
      }
    },
    x: () => {
      if (selectedAlert) {
        setSelectedRows((prev) => ({
          ...prev,
          [focusedIndex]: !prev[focusedIndex],
        }));
      }
    },
  });

  return (
    <div className="flex h-full flex-col bg-[#0c0d0e] text-[#e6edf3]">
      <AlertsHeader
        unreviewedCount={unreviewedCount}
        statusFilter={statusFilter}
        onStatusChange={(s) => {
          const next = new URLSearchParams(searchParams);
          next.set("status", s);
          setSearchParams(next, { replace: true });
        }}
        searchQuery={searchQuery}
        onSearchChange={(q) => {
          const next = new URLSearchParams(searchParams);
          if (q) next.set("q", q);
          else next.delete("q");
          setSearchParams(next, { replace: true });
        }}
      />

      {/* Main Table + Docked Inspector Drawer */}
      <div className="flex flex-1 min-h-0 overflow-hidden">
        <AlertsTable
          alerts={filteredAlerts}
          isLoading={isLoading}
          isError={isError}
          error={error as Error | null}
          onRetry={() => refetch()}
          focusedIndex={focusedIndex}
          onFocusChange={(idx) => {
            setFocusedIndex(idx);
            if (filteredAlerts[idx]) handleSelectAlert(filteredAlerts[idx]);
          }}
          selectedAlertId={selectedAlert?.id ?? null}
          onSelectAlert={(a) => handleSelectAlert(a)}
          selectedRows={selectedRows}
          onSelectionChange={setSelectedRows}
        />

        {selectedAlert && (
          <AlertDetailDrawer
            alert={selectedAlert}
            onClose={() => {
              const next = new URLSearchParams(searchParams);
              next.delete("selected");
              setSearchParams(next, { replace: true });
            }}
            onAcknowledge={acknowledgeAlert}
            onFalsePositive={markFalsePositive}
            onEscalate={(a) => {
              setAlertToEscalate(a);
              setCaseDialogOpen(true);
            }}
          />
        )}
      </div>

      {/* Escalate to Case Dialog */}
      <ConfirmDialog
        open={caseDialogOpen}
        onOpenChange={setCaseDialogOpen}
        title="Open Active Case"
        description="Creates a new incident case attaching this alert and its correlated host telemetry window as immutable evidence."
        targetName={alertToEscalate ? `${alertToEscalate.rule_name} (#${alertToEscalate.id})` : undefined}
        effectDescription="Case will be created and opened in active investigation."
        confirmLabel="Create Case"
        onConfirm={async () => {
          if (!alertToEscalate) return;
          try {
            await fetch(`/cases`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                title: `Investigation: ${alertToEscalate.rule_name}`,
                severity: alertToEscalate.severity,
                alert_ids: [alertToEscalate.id],
              }),
            });
            refetch();
          } catch {
            // Error captured by error boundary / query state
          }
        }}
      />
    </div>
  );
};
