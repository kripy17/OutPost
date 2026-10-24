import React, { useState } from "react";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import {
  Copy,
  Check,
  ShieldAlert,
  Search,
  FolderPlus,
  ChevronDown,
} from "lucide-react";

export type EntityType = "host" | "process" | "user" | "ip" | "domain" | "hash";

export interface EntityProps {
  type: EntityType;
  value: string;
  defang?: boolean;
  className?: string;
  onPivotToEvents?: (type: EntityType, value: string) => void;
  onPivotToAlerts?: (type: EntityType, value: string) => void;
  onAddToCase?: (type: EntityType, value: string) => void;
}

export const defangIndicator = (val: string): string => {
  return val
    .replace(/\./g, "[.]")
    .replace(/http:\/\//gi, "hxxp://")
    .replace(/https:\/\//gi, "hxxps://");
};

export const Entity: React.FC<EntityProps> = ({
  type,
  value,
  defang = false,
  className = "",
  onPivotToEvents,
  onPivotToAlerts,
  onAddToCase,
}) => {
  const [copied, setCopied] = useState<boolean>(false);
  const [isDefanged, setIsDefanged] = useState<boolean>(defang);

  const displayValue = isDefanged ? defangIndicator(value) : value;

  const handleCopy = (e: React.MouseEvent, text: string) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className={`inline-flex items-center gap-1 rounded-[3px] border border-[#26292e] bg-[#141618] px-1.5 py-0.5 text-[12px] font-mono text-[#e6edf3] hover:border-[#388bfd] ${className}`}
    >
      <span className="text-[10px] uppercase tracking-wider text-[#8b949e]">
        {type}:
      </span>
      <span className="truncate max-w-[200px]" title={value}>
        {displayValue}
      </span>

      <button
        onClick={(e) => handleCopy(e, displayValue)}
        className="text-[#8b949e] hover:text-[#e6edf3] p-0.5"
        title="Copy"
      >
        {copied ? (
          <Check className="h-3 w-3 text-[#3fb950]" />
        ) : (
          <Copy className="h-3 w-3" />
        )}
      </button>

      <DropdownMenu.Root>
        <DropdownMenu.Trigger asChild>
          <button className="text-[#8b949e] hover:text-[#e6edf3] p-0.5">
            <ChevronDown className="h-3 w-3" />
          </button>
        </DropdownMenu.Trigger>

        <DropdownMenu.Portal>
          <DropdownMenu.Content
            className="z-50 min-w-[160px] rounded-[4px] border border-[#26292e] bg-[#1a1d20] p-1 text-[12px] text-[#e6edf3] shadow-xl animate-in fade-in"
            sideOffset={4}
          >
            <DropdownMenu.Item
              onClick={() => onPivotToEvents?.(type, value)}
              className="flex items-center gap-2 rounded-[2px] px-2 py-1 cursor-pointer outline-none hover:bg-[#2f81f7] hover:text-white"
            >
              <Search className="h-3.5 w-3.5" />
              <span>Pivot to Events</span>
            </DropdownMenu.Item>

            <DropdownMenu.Item
              onClick={() => onPivotToAlerts?.(type, value)}
              className="flex items-center gap-2 rounded-[2px] px-2 py-1 cursor-pointer outline-none hover:bg-[#2f81f7] hover:text-white"
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              <span>Pivot to Alerts</span>
            </DropdownMenu.Item>

            <DropdownMenu.Item
              onClick={() => onAddToCase?.(type, value)}
              className="flex items-center gap-2 rounded-[2px] px-2 py-1 cursor-pointer outline-none hover:bg-[#2f81f7] hover:text-white"
            >
              <FolderPlus className="h-3.5 w-3.5" />
              <span>Add to Case</span>
            </DropdownMenu.Item>

            <DropdownMenu.Separator className="my-1 h-[1px] bg-[#26292e]" />

            <DropdownMenu.Item
              onClick={() => setIsDefanged(!isDefanged)}
              className="flex items-center gap-2 rounded-[2px] px-2 py-1 cursor-pointer outline-none hover:bg-[#26292e]"
            >
              <span className="font-mono text-[11px] text-[#db6d28]">
                {isDefanged ? "Un-defang" : "Defang (IOC)"}
              </span>
            </DropdownMenu.Item>

            <DropdownMenu.Item
              onClick={(e) => handleCopy(e, defangIndicator(value))}
              className="flex items-center gap-2 rounded-[2px] px-2 py-1 cursor-pointer outline-none hover:bg-[#26292e]"
            >
              <span className="text-[11px] text-[#8b949e]">Copy Defanged</span>
            </DropdownMenu.Item>
          </DropdownMenu.Content>
        </DropdownMenu.Portal>
      </DropdownMenu.Root>
    </div>
  );
};
