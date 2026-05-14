// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// MITRE ATT&CK Matrix — Navigator-style grid layout.
// Tactics as columns, techniques stacked vertically underneath.
// Color intensity = analysis_count. Click to filter.

import { useMemo, useState } from "react";
import type { TechniqueBrowseItem } from "#lib/types";
import { MITRE_TACTICS, TACTIC_LABELS, type MitreTactic } from "#lib/constants";

interface MitreMatrixProps {
  techniques: TechniqueBrowseItem[];
  onTechniqueClick?: (techniqueId: string) => void;
  onTacticClick?: (tactic: string) => void;
}

interface TechniqueCell {
  technique_id: string;
  technique_name: string;
  analysis_count: number;
}

export function MitreMatrix({
  techniques,
  onTechniqueClick,
  onTacticClick,
}: MitreMatrixProps) {
  const [hoveredCell, setHoveredCell] = useState<string | null>(null);

  // Group techniques by tactic (a technique can appear in multiple columns)
  const columns = useMemo(() => {
    const map = new Map<string, TechniqueCell[]>();

    for (const tactic of MITRE_TACTICS) {
      map.set(tactic, []);
    }

    for (const tech of techniques) {
      for (const tactic of tech.tactics) {
        const col = map.get(tactic);
        if (col) {
          col.push({
            technique_id: tech.technique_id,
            technique_name: tech.technique_name,
            analysis_count: tech.analysis_count,
          });
        }
      }
    }

    // Sort each column by count descending
    for (const [, cells] of map) {
      cells.sort((a, b) => b.analysis_count - a.analysis_count);
    }

    return map;
  }, [techniques]);

  const maxCount = useMemo(() => {
    let max = 1;
    for (const tech of techniques) {
      if (tech.analysis_count > max) max = tech.analysis_count;
    }
    return max;
  }, [techniques]);

  if (techniques.length === 0) {
    return (
      <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center text-sm text-[var(--color-text-muted)]">
        No technique data available for matrix.
      </div>
    );
  }

  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] overflow-x-auto">
      <div className="inline-flex min-w-full">
        {MITRE_TACTICS.map((tactic) => {
          const cells = columns.get(tactic) ?? [];
          return (
            <div key={tactic} className="flex-1 min-w-[90px] border-r border-[var(--color-border)] last:border-r-0">
              {/* Tactic header */}
              <button
                onClick={() => onTacticClick?.(tactic)}
                className="sticky top-0 z-10 w-full border-b border-[var(--color-border)] bg-[var(--color-surface)] px-1.5 py-2 text-center hover:bg-[var(--color-surface-hover)]"
              >
                <div className="text-[10px] font-semibold leading-tight text-[var(--color-text-secondary)]">
                  {TACTIC_LABELS[tactic as MitreTactic]}
                </div>
                {cells.length > 0 && (
                  <div className="mt-0.5 text-[9px] text-[var(--color-text-muted)]">
                    {cells.length}
                  </div>
                )}
              </button>

              {/* Technique cells */}
              <div className="p-1 space-y-0.5">
                {cells.map((cell) => (
                  <button
                    key={`${tactic}-${cell.technique_id}`}
                    onClick={() => onTechniqueClick?.(cell.technique_id)}
                    onMouseEnter={() => setHoveredCell(`${tactic}-${cell.technique_id}`)}
                    onMouseLeave={() => setHoveredCell(null)}
                    className="relative block w-full rounded-sm px-1 py-1 text-left transition-all hover:ring-1 hover:ring-[var(--color-accent)]"
                    style={{
                      backgroundColor: cellColor(cell.analysis_count, maxCount),
                    }}
                    title={`${cell.technique_id}: ${cell.technique_name} (${cell.analysis_count} samples)`}
                  >
                    <div className="text-[9px] font-mono font-medium leading-tight text-[var(--color-text-primary)]">
                      {cell.technique_id}
                    </div>
                    <div className="text-[8px] leading-tight text-[var(--color-text-secondary)] truncate">
                      {cell.technique_name}
                    </div>

                    {/* Tooltip on hover */}
                    {hoveredCell === `${tactic}-${cell.technique_id}` && (
                      <div className="absolute left-full top-0 z-20 ml-2 w-52 rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-2 shadow-lg">
                        <div className="text-[10px] font-semibold text-[var(--color-text-primary)]">
                          {cell.technique_id}
                        </div>
                        <div className="text-[10px] text-[var(--color-text-secondary)]">
                          {cell.technique_name}
                        </div>
                        <div className="mt-1 text-[10px] text-[var(--color-accent)]">
                          {cell.analysis_count} sample{cell.analysis_count !== 1 ? "s" : ""}
                        </div>
                        <div className="mt-0.5 text-[9px] text-[var(--color-text-muted)]">
                          {TACTIC_LABELS[tactic as MitreTactic]}
                        </div>
                      </div>
                    )}
                  </button>
                ))}

                {cells.length === 0 && (
                  <div className="py-4 text-center text-[9px] text-[var(--color-text-muted)]">
                    --
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/** Map count to background color — dark (low) to orange (high). */
function cellColor(count: number, max: number): string {
  const intensity = Math.max(0.15, count / max);
  // Interpolate from dark surface to orange
  const r = Math.round(13 + intensity * (240 - 13));
  const g = Math.round(17 + intensity * (136 - 17));
  const b = Math.round(23 + intensity * (62 - 23));
  return `rgb(${r}, ${g}, ${b})`;
}
