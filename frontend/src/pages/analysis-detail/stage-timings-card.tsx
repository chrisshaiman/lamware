// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { formatDuration } from "#lib/utils";
import { STAGE_LABELS } from "#lib/constants";

interface StageTimingsCardProps {
  timings: Record<string, number> | null;
}

export function StageTimingsCard({ timings }: StageTimingsCardProps) {
  if (!timings || Object.keys(timings).length === 0) return null;

  const maxTime = Math.max(...Object.values(timings));

  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <h3 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">
        Stage Timings
      </h3>
      <div className="space-y-2">
        {Object.entries(timings).map(([stage, seconds]) => (
          <div key={stage} className="flex items-center gap-3">
            <span className="w-16 shrink-0 text-xs text-[var(--color-text-muted)]">
              {STAGE_LABELS[stage] ?? stage}
            </span>
            <div className="flex-1">
              <div className="h-4 rounded bg-[var(--color-background)]">
                <div
                  className="h-4 rounded bg-[var(--color-accent)]/30"
                  style={{ width: `${(seconds / maxTime) * 100}%` }}
                />
              </div>
            </div>
            <span className="w-12 shrink-0 text-right text-xs tabular-nums text-[var(--color-text-secondary)]">
              {formatDuration(seconds)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
