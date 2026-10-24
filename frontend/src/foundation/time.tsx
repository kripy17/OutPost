import React, { useState } from "react";
import { TOKENS } from "./tokens";

interface FormattedTimeProps {
  value?: string | number | Date | null;
  className?: string;
  showRelative?: boolean;
}

const formatAbsoluteUTC = (date: Date): string => {
  const pad = (n: number) => n.toString().padStart(2, "0");
  const y = date.getUTCFullYear();
  const m = pad(date.getUTCMonth() + 1);
  const d = pad(date.getUTCDate());
  const hh = pad(date.getUTCHours());
  const mm = pad(date.getUTCMinutes());
  const ss = pad(date.getUTCSeconds());
  return `${y}-${m}-${d} ${hh}:${mm}:${ss} UTC`;
};

const formatRelative = (date: Date, now: Date = new Date()): string => {
  const diffMs = now.getTime() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 5) return "just now";
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 30) return `${diffDays}d ago`;
  const diffMonths = Math.floor(diffDays / 30);
  return `${diffMonths}mo ago`;
};

export const FormattedTime: React.FC<FormattedTimeProps> = ({
  value,
  className = "",
  showRelative = true,
}) => {
  const [showTooltip, setShowTooltip] = useState(false);

  if (!value) {
    return <span className={`${TOKENS.fontMonoSm} ${TOKENS.textFaint}`}>—</span>;
  }

  const d = new Date(value);
  if (Number.isNaN(d.getTime())) {
    return <span className={`${TOKENS.fontMonoSm} ${TOKENS.textFaint}`}>invalid</span>;
  }

  const abs = formatAbsoluteUTC(d);
  const rel = formatRelative(d);
  const display = showRelative ? rel : abs;

  return (
    <span
      className={`relative inline-block cursor-help ${TOKENS.fontMonoSm} tabular-nums ${className}`}
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
      title={abs}
    >
      {display}
      {showTooltip && (
        <span
          className={`absolute bottom-full left-1/2 z-50 mb-1 -translate-x-1/2 whitespace-nowrap rounded-[4px] border border-[#26292e] bg-[#1a1d20] px-2 py-0.5 text-[11px] font-mono text-[#e6edf3] shadow-lg`}
        >
          {abs}
        </span>
      )}
    </span>
  );
};
