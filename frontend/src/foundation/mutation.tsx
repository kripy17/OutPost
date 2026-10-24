import React, { createContext, useContext, useState, useCallback } from "react";
import { useMutation, useQueryClient, QueryKey } from "@tanstack/react-query";
import { Check, Undo2, X } from "lucide-react";

export interface ToastItem {
  id: string;
  message: string;
  undo?: () => void;
  timeoutId: number;
}

interface ToastContextValue {
  showToast: (message: string, undo?: () => void) => void;
  dismissToast: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => {
      const target = prev.find((t) => t.id === id);
      if (target) window.clearTimeout(target.timeoutId);
      return prev.filter((t) => t.id !== id);
    });
  }, []);

  const showToast = useCallback((message: string, undo?: () => void) => {
    const id = Math.random().toString(36).substring(2, 9);
    const timeoutId = window.setTimeout(() => {
      dismissToast(id);
    }, 6000);

    setToasts((prev) => [...prev, { id, message, undo, timeoutId }]);
  }, [dismissToast]);

  return (
    <ToastContext.Provider value={{ showToast, dismissToast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className="pointer-events-auto flex items-center gap-3 rounded-[4px] border border-[#26292e] bg-[#1a1d20] px-3 py-2 text-[12px] text-[#e6edf3] shadow-lg animate-in fade-in slide-in-from-bottom-2"
          >
            <Check className="h-4 w-4 text-[#3fb950] shrink-0" />
            <span>{toast.message}</span>
            {toast.undo && (
              <button
                onClick={() => {
                  toast.undo?.();
                  dismissToast(toast.id);
                }}
                className="flex items-center gap-1 rounded-[2px] bg-[#26292e] px-1.5 py-0.5 text-[11px] font-medium text-[#58a6ff] hover:bg-[#32363d]"
              >
                <Undo2 className="h-3 w-3" />
                <span>Undo</span>
              </button>
            )}
            <button
              onClick={() => dismissToast(toast.id)}
              className="text-[#8b949e] hover:text-[#e6edf3]"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};

export const useToast = (): ToastContextValue => {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
};

export interface OptimisticMutationOptions<TData, TVariables, TContext> {
  mutationFn: (variables: TVariables) => Promise<TData>;
  queryKeyToInvalidate?: QueryKey;
  optimisticUpdate?: (variables: TVariables) => TContext;
  rollback?: (context?: TContext) => void;
  successMessage?: string | ((data: TData, variables: TVariables) => string);
  onUndo?: (variables: TVariables, context?: TContext) => void;
}

export const useOptimisticAction = <TData, TVariables, TContext = unknown>(
  options: OptimisticMutationOptions<TData, TVariables, TContext>
) => {
  const queryClient = useQueryClient();
  const { showToast } = useToast();

  return useMutation<TData, Error, TVariables, TContext>({
    mutationFn: options.mutationFn,
    onMutate: async (variables) => {
      if (options.optimisticUpdate) {
        return options.optimisticUpdate(variables);
      }
      return undefined as TContext;
    },
    onError: (_err, _variables, context) => {
      if (options.rollback) {
        options.rollback(context);
      }
      showToast("Action failed. Changes rolled back.");
    },
    onSuccess: (data, variables, context) => {
      const msg = typeof options.successMessage === "function"
        ? options.successMessage(data, variables)
        : options.successMessage ?? "Action completed";

      const undoFn = options.onUndo
        ? () => options.onUndo?.(variables, context)
        : undefined;

      showToast(msg, undoFn);
    },
    onSettled: () => {
      if (options.queryKeyToInvalidate) {
        queryClient.invalidateQueries({ queryKey: options.queryKeyToInvalidate });
      }
    },
  });
};
