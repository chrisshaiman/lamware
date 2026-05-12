// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// MITRE ATT&CK Heatmap — flagship visualization.
// Shows technique frequency across the 14 MITRE tactics as a heatmap grid.
// Color intensity = analysis_count. Click cells to filter the technique table.

import { useMemo } from "react";
import { ResponsiveHeatMap } from "@nivo/heatmap";
import type { TechniqueBrowseItem } from "#lib/types";
import { MITRE_TACTICS, TACTIC_LABELS, type MitreTactic } from "#lib/constants";

interface MitreHeatmapProps {
  techniques: TechniqueBrowseItem[];
  onTacticClick?: (tactic: string) => void;
  onTechniqueClick?: (techniqueId: string) => void;
}

interface HeatmapDatum {
  x: string;
  y: number;
  techniqueId: string;
  techniqueName: string;
}

interface HeatmapSeries {
  id: string;
  data: HeatmapDatum[];
}

export function MitreHeatmap({
  techniques,
  onTacticClick,
  onTechniqueClick,
}: MitreHeatmapProps) {
  // Transform: techniques → matrix of tactics (rows) x techniques (columns)
  // Each tactic row shows the techniques that belong to it, with color = count
  const heatmapData = useMemo(() => {
    // Group techniques by tactic
    const tacticMap = new Map<string, Map<string, { count: number; name: string; id: string }>>();

    for (const tactic of MITRE_TACTICS) {
      tacticMap.set(tactic, new Map());
    }

    for (const tech of techniques) {
      for (const tactic of tech.tactics) {
        const map = tacticMap.get(tactic);
        if (map) {
          map.set(tech.technique_id, {
            count: tech.analysis_count,
            name: tech.technique_name,
            id: tech.technique_id,
          });
        }
      }
    }

    // Build Nivo data: each tactic is a series (row), techniques are data points
    const series: HeatmapSeries[] = [];
    for (const tactic of MITRE_TACTICS) {
      const techMap = tacticMap.get(tactic)!;
      const data: HeatmapDatum[] = [];

      for (const [techId, info] of techMap) {
        data.push({
          x: techId,
          y: info.count,
          techniqueId: info.id,
          techniqueName: info.name,
        });
      }

      // Sort by count descending within each tactic
      data.sort((a, b) => b.y - a.y);

      series.push({
        id: TACTIC_LABELS[tactic as MitreTactic],
        data,
      });
    }

    return series;
  }, [techniques]);

  // Find max count for color scale
  const maxCount = useMemo(() => {
    let max = 1;
    for (const series of heatmapData) {
      for (const d of series.data) {
        if (d.y > max) max = d.y;
      }
    }
    return max;
  }, [heatmapData]);

  if (techniques.length === 0) {
    return (
      <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center text-sm text-[var(--color-text-muted)]">
        No technique data available for heatmap.
      </div>
    );
  }

  // Calculate height based on number of tactics with data
  const activeTactics = heatmapData.filter((s) => s.data.length > 0).length;
  const chartHeight = Math.max(300, activeTactics * 40 + 80);

  return (
    <div
      className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4"
      style={{ height: chartHeight }}
    >
      <ResponsiveHeatMap
        data={heatmapData}
        margin={{ top: 40, right: 20, bottom: 20, left: 120 }}
        valueFormat={(v) => `${v} samples`}
        axisTop={{
          tickSize: 0,
          tickPadding: 8,
          tickRotation: -45,
        }}
        axisLeft={{
          tickSize: 0,
          tickPadding: 8,
          renderTick: (tick) => (
            <g
              transform={`translate(${tick.x},${tick.y})`}
              style={{ cursor: onTacticClick ? "pointer" : "default" }}
              onClick={() => {
                // Find the tactic slug from the label
                const tacticSlug = MITRE_TACTICS.find(
                  (t) => TACTIC_LABELS[t] === tick.value,
                );
                if (tacticSlug && onTacticClick) onTacticClick(tacticSlug);
              }}
            >
              <text
                textAnchor="end"
                dominantBaseline="central"
                style={{ fill: "#8b949e", fontSize: 10 }}
              >
                {tick.value}
              </text>
            </g>
          ),
        }}
        colors={{
          type: "sequential",
          scheme: "oranges",
          minValue: 0,
          maxValue: maxCount,
        }}
        emptyColor="#161b22"
        borderColor="#30363d"
        borderWidth={1}
        borderRadius={2}
        theme={{
          text: { fill: "#8b949e", fontSize: 10 },
          axis: {
            ticks: { text: { fill: "#8b949e", fontSize: 9 } },
          },
          tooltip: {
            container: {
              background: "#161b22",
              color: "#e6edf3",
              border: "1px solid #30363d",
              borderRadius: "4px",
              fontSize: "11px",
            },
          },
        }}
        tooltip={({ cell }) => {
          const datum = cell.data as unknown as HeatmapDatum;
          return (
            <div className="rounded border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-xs shadow-lg">
              <div className="font-medium text-[var(--color-text-primary)]">
                {datum.techniqueId}: {datum.techniqueName}
              </div>
              <div className="text-[var(--color-text-muted)]">
                {cell.serieId} &middot; {cell.value} sample{cell.value !== 1 ? "s" : ""}
              </div>
            </div>
          );
        }}
        onClick={(cell) => {
          const datum = cell.data as unknown as HeatmapDatum;
          if (onTechniqueClick) onTechniqueClick(datum.techniqueId);
        }}
        legends={[]}
        animate={false}
      />
    </div>
  );
}
