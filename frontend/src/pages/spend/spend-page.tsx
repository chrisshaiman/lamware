// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { DollarSign } from "lucide-react";
import { useSpend, type ModelSpend } from "#hooks/use-spend";
import { formatCost } from "#lib/utils";

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

function ModelRow({ m, maxCost }: { m: ModelSpend; maxCost: number }) {
  const totalTokens = m.input_tokens + m.output_tokens;
  const cacheRate =
    m.input_tokens > 0
      ? ((m.cache_read_tokens / m.input_tokens) * 100).toFixed(0)
      : "0";
  const avgCost = m.requests > 0 ? m.cost / m.requests : 0;

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-xs">
        <span className="font-medium text-[var(--color-text-primary)]">
          {m.model}
        </span>
        <span className="tabular-nums text-[var(--color-text-secondary)]">
          {formatCost(m.cost)}
        </span>
      </div>
      <div className="h-3 rounded bg-[var(--color-background)]">
        <div
          className="h-3 rounded bg-emerald-500/40"
          style={{ width: `${(m.cost / maxCost) * 100}%` }}
        />
      </div>
      <div className="flex gap-4 text-[10px] text-[var(--color-text-muted)]">
        <span>{m.requests} requests</span>
        <span>{formatTokens(totalTokens)} tokens</span>
        <span>avg {formatCost(avgCost)}/req</span>
        <span>cache hit {cacheRate}%</span>
      </div>
    </div>
  );
}

function DailyChart({ days }: { days: { date: string; cost: number; requests: number }[] }) {
  if (days.length === 0) return null;
  const maxCost = Math.max(...days.map((d) => d.cost), 0.01);

  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <h3 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">
        Daily Spend
      </h3>
      <div className="flex items-end gap-1" style={{ height: 120 }}>
        {days.map((d) => (
          <div
            key={d.date}
            className="group relative flex-1 min-w-0"
            title={`${d.date}: ${formatCost(d.cost)} (${d.requests} requests)`}
          >
            <div
              className="rounded-t bg-emerald-500/40 transition-colors group-hover:bg-emerald-500/60"
              style={{
                height: `${(d.cost / maxCost) * 100}%`,
                minHeight: d.cost > 0 ? 2 : 0,
              }}
            />
          </div>
        ))}
      </div>
      <div className="mt-1 flex justify-between text-[10px] text-[var(--color-text-muted)]">
        <span>{days[0]?.date}</span>
        <span>{days[days.length - 1]?.date}</span>
      </div>
    </div>
  );
}

export function SpendPage() {
  const [days, setDays] = useState(30);
  const { data, isLoading, isError } = useSpend(days);

  if (isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="h-20 animate-pulse rounded-md bg-[var(--color-surface)]"
          />
        ))}
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="rounded-md border border-red-800 bg-red-900/20 p-4 text-sm text-red-400">
        Failed to load spend data.
      </div>
    );
  }

  if (data.error) {
    return (
      <div className="rounded-md border border-yellow-800 bg-yellow-900/20 p-4 text-sm text-yellow-400">
        {data.error}
      </div>
    );
  }

  const { totals, by_model, by_day } = data;
  const maxModelCost =
    by_model.length > 0 ? by_model[0].cost : 1;

  const totalTokens = totals.total_input_tokens + totals.total_output_tokens;
  const cacheRate =
    totals.total_input_tokens > 0
      ? (
          (totals.cache_read_tokens / totals.total_input_tokens) *
          100
        ).toFixed(1)
      : "0";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <DollarSign className="h-5 w-5 text-[var(--color-text-secondary)]" />
          <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">
            LLM Spend
          </h1>
        </div>
        <select
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-1.5 text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
        >
          <option value={7}>Last 7 days</option>
          <option value={14}>Last 14 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
        </select>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <SummaryCard label="Total Spend" value={formatCost(totals.total_cost)} />
        <SummaryCard label="Requests" value={totals.total_requests.toLocaleString()} />
        <SummaryCard
          label="Tokens"
          value={formatTokens(totalTokens)}
          subtext={`${formatTokens(totals.total_input_tokens)} in / ${formatTokens(totals.total_output_tokens)} out`}
        />
        <SummaryCard
          label="Cache Hit Rate"
          value={`${cacheRate}%`}
          subtext={`${formatTokens(totals.cache_read_tokens)} cached / ${formatTokens(totals.cache_creation_tokens)} created`}
        />
      </div>

      {/* Daily chart */}
      <DailyChart days={by_day} />

      {/* Per-model breakdown */}
      {by_model.length > 0 && (
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
          <h3 className="mb-4 text-sm font-semibold text-[var(--color-text-primary)]">
            Cost by Model
          </h3>
          <div className="space-y-4">
            {by_model.map((m) => (
              <ModelRow key={m.model} m={m} maxCost={maxModelCost} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function SummaryCard({
  label,
  value,
  subtext,
}: {
  label: string;
  value: string;
  subtext?: string;
}) {
  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <div className="text-xs text-[var(--color-text-muted)]">{label}</div>
      <div className="mt-1 text-2xl font-bold tabular-nums text-[var(--color-text-primary)]">
        {value}
      </div>
      {subtext && (
        <div className="mt-0.5 text-xs text-[var(--color-text-muted)]">
          {subtext}
        </div>
      )}
    </div>
  );
}
