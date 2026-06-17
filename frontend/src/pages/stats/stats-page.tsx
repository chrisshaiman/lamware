// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { BarChart3 } from "lucide-react";
import { useStats } from "#hooks/use-stats";
import { useFamiliesList } from "#hooks/use-families";
import { formatCost } from "#lib/utils";

function StatCard({ label, value, subtext }: { label: string; value: string | number; subtext?: string }) {
  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <div className="text-xs text-[var(--color-text-muted)]">{label}</div>
      <div className="mt-1 text-2xl font-bold tabular-nums text-[var(--color-text-primary)]">
        {value}
      </div>
      {subtext && <div className="mt-0.5 text-xs text-[var(--color-text-muted)]">{subtext}</div>}
    </div>
  );
}

export function StatsPage() {
  const { data: stats, isLoading } = useStats();
  const { data: families } = useFamiliesList({ limit: 10 });

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="h-24 animate-pulse rounded-md bg-[var(--color-surface)]" />
        ))}
      </div>
    );
  }

  if (!stats) return null;

  return (
    <div className="space-y-6" data-testid="stats-content">
      <div className="flex items-center gap-2">
        <BarChart3 className="h-5 w-5 text-[var(--color-text-secondary)]" />
        <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">Statistics</h1>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Total Analyses" value={stats.total_analyses} subtext={`${stats.analyses_today} today, ${stats.analyses_week} this week`} />
        <StatCard label="Total Samples" value={stats.total_samples} />
        <StatCard label="Total IOCs" value={stats.total_iocs.toLocaleString()} />
        <StatCard label="MITRE Techniques" value={stats.total_techniques} />
        <StatCard label="Families Detected" value={stats.families_detected} />
        <StatCard label="Cost Today" value={formatCost(stats.cost_today)} />
        <StatCard label="Cost This Week" value={formatCost(stats.cost_week)} />
        <StatCard label="Cost Total" value={formatCost(stats.cost_total)} />
      </div>

      {/* Top families */}
      {families && families.length > 0 && (
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
          <h3 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">
            Top Malware Families
          </h3>
          <div className="space-y-2">
            {families.map((f) => {
              const maxCount = families[0].count;
              return (
                <div key={f.family} className="flex items-center gap-3">
                  <span
                    className="w-32 shrink-0 truncate text-sm text-[var(--color-text-secondary)]"
                    title={f.family}
                  >
                    {f.family}
                  </span>
                  <div className="flex-1">
                    <div className="h-5 rounded bg-[var(--color-background)]">
                      <div
                        className="h-5 rounded bg-[var(--color-accent)]/30"
                        style={{ width: `${(f.count / maxCount) * 100}%` }}
                      />
                    </div>
                  </div>
                  <span className="w-8 shrink-0 text-right text-sm tabular-nums text-[var(--color-text-secondary)]">
                    {f.count}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Nivo charts placeholder */}
      <div className="rounded-md border border-dashed border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center text-sm text-[var(--color-text-muted)]">
        Nivo charts (analysis trends, severity breakdown, cost over time) will be added here
      </div>
    </div>
  );
}
