import React from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { AlertTriangle, X } from "lucide-react";

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  targetName?: string;
  effectDescription?: string;
  confirmLabel?: string;
  isDestructive?: boolean;
  onConfirm: () => void;
}

export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  open,
  onOpenChange,
  title,
  description,
  targetName,
  effectDescription,
  confirmLabel = "Confirm",
  isDestructive = false,
  onConfirm,
}) => {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs animate-in fade-in" />
        <DialogPrimitive.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-[6px] border border-[#26292e] bg-[#141618] p-5 shadow-2xl animate-in zoom-in-95">
          <div className="flex items-start gap-3">
            {isDestructive && (
              <div className="rounded-[4px] bg-[#f85149]/15 p-2 text-[#ff7b72]">
                <AlertTriangle className="h-5 w-5" />
              </div>
            )}
            <div className="flex-1 min-w-0">
              <DialogPrimitive.Title className="text-[14px] font-medium text-[#e6edf3]">
                {title}
              </DialogPrimitive.Title>
              <DialogPrimitive.Description className="mt-1 text-[12px] text-[#8b949e]">
                {description}
              </DialogPrimitive.Description>

              {targetName && (
                <div className="mt-3 rounded-[3px] border border-[#26292e] bg-[#0c0d0e] p-2 text-[12px]">
                  <span className="text-[#8b949e]">Target: </span>
                  <span className="font-mono text-[#e6edf3]">{targetName}</span>
                </div>
              )}

              {effectDescription && (
                <div className="mt-2 text-[11px] text-[#db6d28]">
                  <span>Effect: {effectDescription}</span>
                </div>
              )}
            </div>
            <DialogPrimitive.Close className="text-[#8b949e] hover:text-[#e6edf3]">
              <X className="h-4 w-4" />
            </DialogPrimitive.Close>
          </div>

          <div className="mt-5 flex justify-end gap-2">
            <DialogPrimitive.Close className="rounded-[4px] border border-[#26292e] bg-[#1a1d20] px-3 py-1.5 text-[12px] font-medium text-[#8b949e] hover:text-[#e6edf3]">
              Cancel
            </DialogPrimitive.Close>
            <button
              onClick={() => {
                onConfirm();
                onOpenChange(false);
              }}
              className={`rounded-[4px] px-3 py-1.5 text-[12px] font-medium text-white transition ${
                isDestructive
                  ? "bg-[#da3633] hover:bg-[#b62324]"
                  : "bg-[#238636] hover:bg-[#2ea043]"
              }`}
            >
              {confirmLabel}
            </button>
          </div>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
};
