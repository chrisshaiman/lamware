// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// MITRE ATT&CK Matrix — Navigator-style grid layout.
// Tactics as columns, techniques stacked vertically underneath.
// Color intensity = analysis_count. Click to filter.
// Compact layout: all 14 tactics visible without scrolling.

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

  // Group techniques by tactic
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
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)]">
      {/* CSS grid: 14 equal columns, no horizontal scroll */}
      <div
        className="grid"
        style={{ gridTemplateColumns: `repeat(${MITRE_TACTICS.length}, minmax(0, 1fr))` }}
      >
        {MITRE_TACTICS.map((tactic) => {
          const cells = columns.get(tactic) ?? [];
          return (
            <div key={tactic} className="border-r border-[var(--color-border)] last:border-r-0">
              {/* Tactic header */}
              <button
                onClick={() => onTacticClick?.(tactic)}
                className="w-full border-b border-[var(--color-border)] bg-[var(--color-surface)] px-0.5 py-1.5 text-center hover:bg-[var(--color-surface-hover)]"
              >
                <div className="text-[8px] font-semibold leading-tight text-[var(--color-text-secondary)]">
                  {TACTIC_LABELS[tactic as MitreTactic]}
                </div>
                <div className="text-[8px] text-[var(--color-text-muted)]">
                  {cells.length || "\u00A0"}
                </div>
              </button>

              {/* Technique cells — ID only, name in tooltip */}
              <div className="p-0.5 space-y-px">
                {cells.map((cell) => {
                  const cellKey = `${tactic}-${cell.technique_id}`;
                  const isHovered = hoveredCell === cellKey;
                  return (
                    <button
                      key={cellKey}
                      onClick={() => onTechniqueClick?.(cell.technique_id)}
                      onMouseEnter={() => setHoveredCell(cellKey)}
                      onMouseLeave={() => setHoveredCell(null)}
                      className="relative block w-full rounded-sm px-0.5 py-px text-center transition-all hover:ring-1 hover:ring-[var(--color-accent)]"
                      style={{ backgroundColor: cellColor(cell.analysis_count, maxCount) }}
                      title={`${cell.technique_id}: ${cell.technique_name} (${cell.analysis_count})`}
                    >
                      <div className="text-[7px] font-mono leading-tight text-[var(--color-text-primary)]">
                        {cell.technique_id}
                      </div>

                      {/* Floating tooltip */}
                      {isHovered && (
                        <div
                          className="pointer-events-none absolute z-30 w-48 rounded border border-[var(--color-border)] bg-[var(--color-background)] p-2 text-left shadow-xl"
                          style={{
                            // Position tooltip to the right, but flip left if in the right half
                            ...(shouldFlipTooltip(tactic)
                              ? { right: "100%", marginRight: "4px" }
                              : { left: "100%", marginLeft: "4px" }),
                            top: 0,
                          }}
                        >
                          <div className="text-[10px] font-bold text-[var(--color-text-primary)]">
                            {cell.technique_id}
                          </div>
                          <div className="text-[10px] text-[var(--color-text-secondary)]">
                            {cell.technique_name}
                          </div>
                          <div className="mt-1 text-[10px] font-medium text-[var(--color-accent)]">
                            {cell.analysis_count} sample{cell.analysis_count !== 1 ? "s" : ""}
                          </div>
                          <div className="text-[9px] text-[var(--color-text-muted)]">
                            {TACTIC_LABELS[tactic as MitreTactic]}
                          </div>
                        </div>
                      )}
                    </button>
                  );
                })}

                {cells.length === 0 && (
                  <div className="py-2 text-center text-[8px] text-[var(--color-text-muted)]">
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

/** Flip tooltip to the left for tactics in the right half of the matrix. */
function shouldFlipTooltip(tactic: string): boolean {
  const idx = MITRE_TACTICS.indexOf(tactic as (typeof MITRE_TACTICS)[number]);
  return idx >= MITRE_TACTICS.length / 2;
}

/** Map count to background color — dark (low) to orange (high). */
function cellColor(count: number, max: number): string {
  const intensity = Math.max(0.15, count / max);
  const r = Math.round(13 + intensity * (240 - 13));
  const g = Math.round(17 + intensity * (136 - 17));
  const b = Math.round(23 + intensity * (62 - 23));
  return `rgb(${r}, ${g}, ${b})`;
}
