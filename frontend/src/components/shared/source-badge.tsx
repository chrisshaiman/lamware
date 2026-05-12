// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { cn } from "#lib/utils";
import { SOURCE_STAGE_COLORS } from "#lib/constants";

interface SourceBadgeProps {
  stage: string;
  className?: string;
}

export function SourceBadge({ stage, className }: SourceBadgeProps) {
  const colors = SOURCE_STAGE_COLORS[stage] ?? {
    bg: "bg-gray-800/50",
    text: "text-gray-400",
  };

  return (
    <span
      className={cn(
        "rounded px-1.5 py-0.5 text-xs font-medium",
        colors.bg,
        colors.text,
        className,
      )}
    >
      {stage}
    </span>
  );
}
