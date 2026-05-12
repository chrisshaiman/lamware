// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { cn } from "#lib/utils";
import { SEVERITY_COLORS } from "#lib/constants";

interface SeverityBadgeProps {
  severity: string | null;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  if (!severity) return null;

  const colors = SEVERITY_COLORS[severity.toLowerCase()];
  if (!colors) {
    return (
      <span className={cn("rounded px-1.5 py-0.5 text-xs font-medium bg-gray-800 text-gray-400", className)}>
        {severity}
      </span>
    );
  }

  return (
    <span
      className={cn(
        "rounded border px-1.5 py-0.5 text-xs font-medium",
        colors.bg,
        colors.text,
        colors.border,
        className,
      )}
    >
      {severity}
    </span>
  );
}
