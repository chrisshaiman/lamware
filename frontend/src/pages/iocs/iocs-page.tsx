// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { Network } from "lucide-react";
import { useIocsList } from "#hooks/use-iocs";
import { SearchInput } from "#components/shared/search-input";
import { MonoText } from "#components/shared/mono-text";
import { formatRelativeTime } from "#lib/utils";
import { IOC_TYPES } from "#lib/constants";

const PAGE_SIZE = 50;

export function IocsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const q = searchParams.get("q") ?? "";
  const type = searchParams.get("type") ?? "";
  const offset = parseInt(searchParams.get("offset") ?? "0", 10);

  const { data: iocs, isLoading, isError } = useIocsList({
    q: q || undefined,
    type: type || undefined,
    limit: PAGE_SIZE,
    offset,
  });

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) next.set(key, value);
        else next.delete(key);
        if (key !== "offset") next.delete("offset");
        return next;
      });
    },
    [setSearchParams],
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Network className="h-5 w-5 text-[var(--color-text-secondary)]" />
        <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">IOC Browser</h1>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <SearchInput
          value={q}
          onChange={(v) => setParam("q", v)}
          placeholder="Search IOC values..."
          className="w-80"
        />
        <select
          value={type}
          onChange={(e) => setParam("type", e.target.value)}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
        >
          <option value="">All types</option>
          {IOC_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 10 }).map((_, i) => (
            <div key={i} className="h-10 animate-pulse rounded bg-[var(--color-surface)]" />
          ))}
        </div>
      ) : isError ? (
        <div className="rounded-md border border-red-800 bg-red-900/20 p-4 text-sm text-red-400">
          Failed to load IOCs.
        </div>
      ) : !iocs || iocs.length === 0 ? (
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center text-sm text-[var(--color-text-secondary)]">
          No IOCs found.
        </div>
      ) : (
        <div className="overflow-x-auto rounded-md border border-[var(--color-border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface)]">
                <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">Type</th>
                <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">Value</th>
                <th className="px-4 py-3 text-right font-medium text-[var(--color-text-secondary)]">Samples</th>
                <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">First Seen</th>
                <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {iocs.map((ioc) => (
                <tr key={ioc.id} className="border-b border-[var(--color-border-light)] transition-colors hover:bg-[var(--color-surface-hover)]">
                  <td className="px-4 py-2.5">
                    <span className="rounded bg-[var(--color-surface)] px-1.5 py-0.5 text-xs text-[var(--color-text-muted)]">
                      {ioc.type}
                    </span>
                  </td>
                  <td className="max-w-md px-4 py-2.5">
                    <MonoText className="break-all">{ioc.value}</MonoText>
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    <span className={`tabular-nums ${ioc.analysis_count > 1 ? "font-medium text-[var(--color-accent)]" : "text-[var(--color-text-secondary)]"}`}>
                      {ioc.analysis_count}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-[var(--color-text-muted)]">
                    {ioc.first_seen ? formatRelativeTime(ioc.first_seen) : "\u2014"}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-[var(--color-text-muted)]">
                    {ioc.last_seen ? formatRelativeTime(ioc.last_seen) : "\u2014"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Simple offset-based pagination */}
      {iocs && iocs.length >= PAGE_SIZE && (
        <div className="flex justify-center gap-2 text-sm">
          {offset > 0 && (
            <button
              onClick={() => setParam("offset", String(Math.max(0, offset - PAGE_SIZE)))}
              className="rounded border border-[var(--color-border)] px-3 py-1 text-[var(--color-text-secondary)] hover:bg-[var(--color-surface)]"
            >
              Previous
            </button>
          )}
          <button
            onClick={() => setParam("offset", String(offset + PAGE_SIZE))}
            className="rounded border border-[var(--color-border)] px-3 py-1 text-[var(--color-text-secondary)] hover:bg-[var(--color-surface)]"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}
